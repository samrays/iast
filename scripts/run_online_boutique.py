"""Master Runner for Google Online Boutique instrumented with Aegis IAST Runtime.

Launches all 5 microservices as persistent background services:
  - Recommendation Service (:8091)
  - Email Service (:8092)
  - Ad Service (:8093)
  - Currency Service (:8094)
  - Boutique Frontend & Vulnerability Lab (:8095)

Syncs findings with the Aegis IAST Control Plane for dashboard visibility.
"""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import signal
import sys
import time
import urllib.request
from pathlib import Path

# Add tests/online-boutique to sys.path
REPO_ROOT = Path(__file__).resolve().parents[1]
BOUTIQUE_DIR = REPO_ROOT / "tests" / "online-boutique"
if str(BOUTIQUE_DIR) not in sys.path:
    sys.path.insert(0, str(BOUTIQUE_DIR))

import uvicorn
from seed_online_boutique_findings import main as seed_findings_main


SERVICES = {
    "recommendationservice": 8091,
    "emailservice": 8092,
    "adservice": 8093,
    "currencyservice": 8094,
    "boutique_frontend": 8095,
}


def run_single_service(service_name: str, port: int) -> None:
    """Run a single FastAPI microservice with uvicorn in a child process."""
    if str(BOUTIQUE_DIR) not in sys.path:
        sys.path.insert(0, str(BOUTIQUE_DIR))

    from recommendation_service import app as rec_app
    from email_service import app as email_app
    from ad_service import app as ad_app
    from currency_service import app as currency_app
    from boutique_frontend import app as frontend_app

    apps_map = {
        "recommendationservice": rec_app,
        "emailservice": email_app,
        "adservice": ad_app,
        "currencyservice": currency_app,
        "boutique_frontend": frontend_app,
    }

    app_instance = apps_map[service_name]
    uvicorn.run(app_instance, host="127.0.0.1", port=port, log_level="warning")


def wait_for_all_services(timeout: float = 20.0) -> bool:
    """Verify that all 5 microservices have started and respond on their health/openapi endpoints."""
    all_ready = True
    for name, port in SERVICES.items():
        start = time.time()
        url = f"http://127.0.0.1:{port}/openapi.json"
        ready = False
        while time.time() - start < timeout:
            try:
                with urllib.request.urlopen(url, timeout=1.0) as resp:
                    if resp.status == 200:
                        ready = True
                        break
            except Exception:
                time.sleep(0.4)
        if ready:
            print(f"  [ONLINE] {name:<22} -> http://127.0.0.1:{port}")
        else:
            print(f"  [FAILED] {name:<22} -> Did not respond on port {port}")
            all_ready = False
    return all_ready


def main():
    print("=" * 70)
    print("   STARTING GOOGLE ONLINE BOUTIQUE (AEGIS IAST VULNERABLE APP)       ")
    print("=" * 70)

    processes = []
    for name, port in SERVICES.items():
        p = multiprocessing.Process(
            target=run_single_service,
            args=(name, port),
            name=name,
            daemon=True,
        )
        p.start()
        processes.append(p)

    print("\nWaiting for microservices to initialize...")
    if not wait_for_all_services():
        print("\n[WARNING] Some microservices did not start promptly.")
    else:
        print("\n[SUCCESS] All 5 Google Online Boutique microservices are running!")

    print("\nSyncing findings with Aegis IAST Control Plane...")
    try:
        asyncio.run(seed_findings_main())
        print("[SUCCESS] Findings seeded and visible in Aegis Dashboard!")
    except Exception as exc:
        print(f"[WARNING] Seeding encountered: {exc}")

    print("\n" + "=" * 70)
    print(" Google Online Boutique Storefront & Attack Lab : http://localhost:8095")
    print(" Aegis IAST Security Console                    : http://localhost:3100")
    print(" Aegis IAST Control Plane API                   : http://localhost:8000")
    print("=" * 70 + "\n")
    print("Services are running. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down Google Online Boutique microservices...")
    finally:
        for p in processes:
            p.terminate()
        print("Done.")


if __name__ == "__main__":
    main()
