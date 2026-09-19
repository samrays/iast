#!/usr/bin/env python3
"""Unified Launcher: Start Aegis IAST Platform & Run Tests on Google Online Boutique.

This script launches the complete Aegis IAST ecosystem and executes security tests
against the instrumented Google Online Boutique vulnerable microservices:

1. Control Plane API (FastAPI on http://127.0.0.1:8000)
2. Aegis Security Dashboard (Next.js on http://localhost:3100)
3. Google Online Boutique Microservices:
   - Recommendation Service (:8091)
   - Email Service (:8092)
   - Ad Service (:8093)
   - Currency Service (:8094)
   - Storefront & ADR Sandbox (:8095)
4. Executes the OWASP vulnerability test suite across all microservices
5. Streams real-time findings to the Control Plane & Dashboard
6. (Optional) Runs continuous live e-commerce traffic & attack simulation
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BOUTIQUE_DIR = REPO_ROOT / "tests" / "online-boutique"
SCRIPTS_DIR = REPO_ROOT / "scripts"

# Locate Python virtual environment
def get_venv_python() -> str:
    """Find virtual environment python executable or fallback to sys.executable."""
    candidates = [
        REPO_ROOT / "apps" / "api" / ".venv" / "Scripts" / "python.exe",
        REPO_ROOT / "apps" / "api" / ".venv" / "bin" / "python",
        REPO_ROOT / ".venv" / "Scripts" / "python.exe",
        REPO_ROOT / ".venv" / "bin" / "python",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return sys.executable


VENV_PYTHON = get_venv_python()

# Ports and Health Endpoints
SERVICE_ENDPOINTS = {
    "Control Plane API": {"url": "http://127.0.0.1:8000/healthz", "port": 8000},
    "Next.js Dashboard": {"url": "http://127.0.0.1:3100", "port": 3100},
    "Boutique Recommendation Svc": {"url": "http://127.0.0.1:8091/openapi.json", "port": 8091},
    "Boutique Email Svc": {"url": "http://127.0.0.1:8092/openapi.json", "port": 8092},
    "Boutique Ad Svc": {"url": "http://127.0.0.1:8093/openapi.json", "port": 8093},
    "Boutique Currency Svc": {"url": "http://127.0.0.1:8094/openapi.json", "port": 8094},
    "Boutique Frontend & ADR Sandbox": {"url": "http://127.0.0.1:8095/api/protection-mode", "port": 8095},
}


def is_service_ready(url: str, timeout: float = 1.0) -> bool:
    """Check if an HTTP service endpoint is responsive."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Aegis-Demo-Probe"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status in (200, 304, 307)
    except Exception:
        return False


def wait_for_services(service_names: list[str], timeout: float = 35.0) -> bool:
    """Wait for specified services to become healthy."""
    start = time.time()
    pending = set(service_names)
    print("\n[+] Waiting for services to be online and healthy...")

    while pending and (time.time() - start) < timeout:
        for name in list(pending):
            url = SERVICE_ENDPOINTS[name]["url"]
            if is_service_ready(url):
                print(f"  [ONLINE]  {name:<35} -> {url}")
                pending.remove(name)
        if pending:
            time.sleep(0.8)

    if pending:
        for name in pending:
            print(f"  [TIMEOUT] {name:<35} -> Did not respond within {timeout}s")
        return False
    return True


class DemoProcessManager:
    """Manages subprocess lifecycles cleanly."""

    def __init__(self) -> None:
        self.spawned_processes: list[subprocess.Popen] = []

    def start_process(self, cmd: list[str], cwd: Path, name: str, env: dict | None = None) -> subprocess.Popen:
        print(f"  [STARTING] {name}...")
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)

        # On Windows, use creationflags if available for clean grouping
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

        p = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            env=merged_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )
        self.spawned_processes.append(p)
        return p

    def terminate_all(self) -> None:
        """Gracefully kill all child processes started by this script."""
        if not self.spawned_processes:
            return
        print("\n[*] Shutting down spawned demo processes...")
        for p in self.spawned_processes:
            try:
                if sys.platform == "win32":
                    subprocess.call(["taskkill", "/F", "/T", "/PID", str(p.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    p.terminate()
            except Exception:
                pass
        self.spawned_processes.clear()
        print("[*] All spawned processes terminated cleanly.")


def print_banner() -> None:
    print(r"""
==============================================================================
    ___    ______ _____ _____ _____   _____ ___   _____ _____ 
   /   |  / ____// ___//_  _// ___/  /  _//   | / ___//_  __/ 
  / /| | / __/  / (_ /  / /  \__ \   / / / /| | \__ \  / /    
 / ___ |/ /___ _\  /  _/ /  ___/ / _/ / / ___ |___/ / / /     
/_/  |_/_____//___/  /___/ /____/ /___//_/  |_/____/ /_/      

  Unified Control Plane, Next.js Dashboard & Google Online Boutique Demo
==============================================================================
""")


def print_service_directory(protection_mode: str = "MONITOR") -> None:
    print("-" * 78)
    print(" SERVICE DIRECTORY & ACCESS POINTS:")
    print("   * Aegis Security Dashboard    : http://localhost:3100")
    print("     -> Credentials               : owner@aegis.example  /  Password123!")
    print("   * Control Plane API & Docs    : http://127.0.0.1:8000/docs")
    print("   * Online Boutique Storefront  : http://localhost:8095")
    print("   * ADR Protection Sandbox Deck : http://localhost:8095  (Live UI Switch)")
    print(f"   * Active Protection Mode      : {protection_mode}")
    print("-" * 78 + "\n")


def run_vulnerability_tests(protection_mode: str = "MONITOR") -> bool:
    """Run test_boutique_harness.py against the vulnerable microservices."""
    print("=" * 78)
    print(" EXECUTING SECURITY TESTS ON VULNERABLE ONLINE BOUTIQUE")
    print("=" * 78)
    test_script = BOUTIQUE_DIR / "test_boutique_harness.py"

    cmd = [VENV_PYTHON, str(test_script)]
    res = subprocess.run(cmd, cwd=str(REPO_ROOT))
    return res.returncode == 0


def run_traffic_stream(interval: float = 1.0, attack_ratio: float = 0.15, count: int = 0) -> None:
    """Run continuous simulated e-commerce traffic against the vulnerable app."""
    traffic_script = SCRIPTS_DIR / "run_boutique_traffic.py"
    cmd = [
        VENV_PYTHON,
        str(traffic_script),
        "--interval",
        str(interval),
        "--attack-ratio",
        str(attack_ratio),
    ]
    if count > 0:
        cmd.extend(["--count", str(count)])

    print("\n[+] Starting continuous e-commerce traffic & attack simulator...")
    print(f"    Interval: {interval}s | Attack Vector Ratio: {int(attack_ratio * 100)}%")
    print("    Press Ctrl+C at any time to stop.\n")
    try:
        subprocess.run(cmd, cwd=str(REPO_ROOT))
    except KeyboardInterrupt:
        print("\n[*] Traffic stream halted.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Start Aegis IAST and run security tests on Google Online Boutique.")
    parser.add_argument("--test-only", action="store_true", help="Run the vulnerability test suite and exit without background traffic.")
    parser.add_argument("--skip-tests", action="store_true", help="Start services and immediately enter traffic mode without initial test harness run.")
    parser.add_argument("--mode", choices=["MONITOR", "BLOCK"], default="MONITOR", help="Initial ADR protection mode (default: MONITOR).")
    parser.add_argument("--interval", type=float, default=1.0, help="Traffic generation interval in seconds (default: 1.0).")
    parser.add_argument("--attack-ratio", type=float, default=0.15, help="Percentage of traffic that are attacks (0.0 to 1.0, default: 0.15).")
    parser.add_argument("--count", type=int, default=0, help="Total number of traffic requests to generate (0 for continuous until Ctrl+C).")
    parser.add_argument("--no-traffic", action="store_true", help="Keep services running after tests without generating continuous traffic.")
    args = parser.parse_args()

    print_banner()

    manager = DemoProcessManager()
    atexit.register(manager.terminate_all)
    # Ensure .env exists
    env_file = REPO_ROOT / ".env"
    env_example = REPO_ROOT / ".env.example"
    if not env_file.exists() and env_example.exists():
        import shutil
        shutil.copy(env_example, env_file)
        print("  [INIT]     Created .env from .env.example")

    # 1. Check if Control Plane API is running
    to_wait = []
    if not is_service_ready(SERVICE_ENDPOINTS["Control Plane API"]["url"]):
        db_path = (REPO_ROOT / "aegis_demo.db").resolve()
        api_env = {
            "AEGIS_DATABASE_URL": os.environ.get(
                "AEGIS_DATABASE_URL",
                f"sqlite+aiosqlite:///{str(db_path).replace(os.sep, '/')}"
            ),
        }
        manager.start_process(
            [VENV_PYTHON, "-m", "uvicorn", "aegis_api.main:app", "--host", "127.0.0.1", "--port", "8000"],
            cwd=REPO_ROOT / "apps" / "api",
            name="Control Plane API (:8000)",
            env=api_env,
        )
        to_wait.append("Control Plane API")
    else:
        print("  [ACTIVE]   Control Plane API is already running on http://127.0.0.1:8000")

    # 2. Check if Next.js Dashboard is running
    if not is_service_ready(SERVICE_ENDPOINTS["Next.js Dashboard"]["url"]):
        # Use npm.cmd on Windows, npm on Unix
        npm_bin = "npm.cmd" if sys.platform == "win32" else "npm"
        manager.start_process(
            [npm_bin, "run", "dev", "--workspace", "@aegis/dashboard"],
            cwd=REPO_ROOT,
            name="Next.js Dashboard (:3100)",
            env={"PORT": "3100"},
        )
        to_wait.append("Next.js Dashboard")
    else:
        print("  [ACTIVE]   Next.js Dashboard is already running on http://localhost:3100")

    # 3. Check if Google Online Boutique microservices are running
    boutique_running = is_service_ready(SERVICE_ENDPOINTS["Boutique Frontend & ADR Sandbox"]["url"])
    if not boutique_running:
        manager.start_process(
            [VENV_PYTHON, str(SCRIPTS_DIR / "run_online_boutique.py")],
            cwd=REPO_ROOT,
            name="Google Online Boutique Microservices (:8091 - :8095)",
        )
        to_wait.extend([
            "Boutique Recommendation Svc",
            "Boutique Email Svc",
            "Boutique Ad Svc",
            "Boutique Currency Svc",
            "Boutique Frontend & ADR Sandbox",
        ])
    else:
        print("  [ACTIVE]   Google Online Boutique cluster is already running on ports 8091-8095")

    # Wait for any newly started services
    if to_wait:
        ok = wait_for_services(to_wait)
        if not ok:
            print("[!] Warning: Some services took longer than expected to start.")

    # Apply initial protection mode
    try:
        req = urllib.request.Request(
            "http://127.0.0.1:8095/api/protection-mode",
            data=json.dumps({"mode": args.mode}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=2.0)
    except Exception:
        pass

    print_service_directory(protection_mode=args.mode)

    # 4. Execute the test suite on the vulnerable app
    if not args.skip_tests:
        success = run_vulnerability_tests(protection_mode=args.mode)
        if not success:
            print("\n[!] Notice: Some tests encountered issues. Review output above.")
        else:
            print("\n[+] All vulnerability tests completed and synced with the Aegis dashboard!")

    if args.test_only:
        print("\n[*] --test-only specified. Exiting launcher.")
        return

    if args.no_traffic:
        print("\n[*] Services are active. Press Ctrl+C to stop all services.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        return

    # 5. Continuous traffic mode
    run_traffic_stream(interval=args.interval, attack_ratio=args.attack_ratio, count=args.count)


if __name__ == "__main__":
    main()
