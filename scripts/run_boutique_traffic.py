"""Google Online Boutique - Realistic E-Commerce Traffic & Chaos Generator.

Generates realistic background traffic against the instrumented Online Boutique microservices:
- 85-90% Benign operations: catalog browsing, currency conversion, email order confirmations, ad context queries.
- 10-15% Security attack probes: SQLi, Path Traversal, CMDi, Reflected XSS, SSRF, XXE, Deserialization.

Synchronizes detected findings with the Aegis IAST Control Plane for live dashboard visibility.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# Add tests/online-boutique to sys.path
REPO_ROOT = Path(__file__).resolve().parents[1]
BOUTIQUE_DIR = REPO_ROOT / "tests" / "online-boutique"
if str(BOUTIQUE_DIR) not in sys.path:
    sys.path.insert(0, str(BOUTIQUE_DIR))

try:
    from seed_online_boutique_findings import main as seed_findings_main
except ImportError:
    seed_findings_main = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("TrafficGen")

BENIGN_OPERATIONS = [
    {
        "name": "Browse Vintage Products",
        "url": "http://127.0.0.1:8091/api/recommendations?category=vintage",
        "method": "GET",
        "payload": None,
        "headers": {},
    },
    {
        "name": "Browse Cookware Products",
        "url": "http://127.0.0.1:8091/api/recommendations?category=cookware",
        "method": "GET",
        "payload": None,
        "headers": {},
    },
    {
        "name": "Browse Gardening Catalog",
        "url": "http://127.0.0.1:8091/api/recommendations?category=gardening",
        "method": "GET",
        "payload": None,
        "headers": {},
    },
    {
        "name": "Calculate Currency Conversion (USD -> EUR)",
        "url": "http://127.0.0.1:8094/api/currency/convert?from_curr=USD&to_curr=EUR&amount=67.99",
        "method": "GET",
        "payload": None,
        "headers": {},
    },
    {
        "name": "Calculate Currency Conversion (USD -> GBP)",
        "url": "http://127.0.0.1:8094/api/currency/convert?from_curr=USD&to_curr=GBP&amount=149.50",
        "method": "GET",
        "payload": None,
        "headers": {},
    },
    {
        "name": "Request Targeted Ad (Context: photography)",
        "url": "http://127.0.0.1:8093/api/ads?context_keys=photography",
        "method": "GET",
        "payload": None,
        "headers": {},
    },
    {
        "name": "Request Targeted Ad (Context: vintage)",
        "url": "http://127.0.0.1:8093/api/ads?context_keys=vintage",
        "method": "GET",
        "payload": None,
        "headers": {},
    },
    {
        "name": "Dispatch Benign Order Confirmation Email",
        "url": "http://127.0.0.1:8092/api/email/send",
        "method": "POST",
        "payload": json.dumps({"email": "shopper@example.com", "order_id": "ORD-1204", "note": "Standard shipping requested"}).encode("utf-8"),
        "headers": {"Content-Type": "application/json"},
    },
    {
        "name": "Benign Shopping Cart Checkout",
        "url": "http://127.0.0.1:8095/api/cart/checkout?return_url=%2Fconfirmation",
        "method": "GET",
        "payload": None,
        "headers": {},
    },
]

ATTACK_PROBES = [
    {
        "id": "sql-injection",
        "name": "SQL Injection (CWE-89)",
        "severity": "CRITICAL",
        "url": "http://127.0.0.1:8091/api/recommendations/raw_search?category=vintage%27%20OR%20%271%27%3D%271",
        "method": "GET",
        "payload": None,
        "headers": {},
    },
    {
        "id": "path-traversal",
        "name": "Path Traversal (CWE-22)",
        "severity": "HIGH",
        "url": "http://127.0.0.1:8091/api/recommendations/catalog?asset_name=../../../../etc/passwd",
        "method": "GET",
        "payload": None,
        "headers": {},
    },
    {
        "id": "log-injection",
        "name": "Log Injection / CRLF (CWE-117)",
        "severity": "MEDIUM",
        "url": "http://127.0.0.1:8092/api/email/send",
        "method": "POST",
        "payload": json.dumps({"email": "attacker@evil.com", "order_id": "ORD-9999", "note": "Delivered\nADMIN STATUS: ACCESS GRANTED"}).encode("utf-8"),
        "headers": {"Content-Type": "application/json"},
    },
    {
        "id": "xxe",
        "name": "XML External Entity XXE (CWE-611)",
        "severity": "CRITICAL",
        "url": "http://127.0.0.1:8092/api/email/template",
        "method": "POST",
        "payload": b"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "headers": {"Content-Type": "application/xml"},
    },
    {
        "id": "reflected-xss",
        "name": "Reflected XSS (CWE-79)",
        "severity": "HIGH",
        "url": "http://127.0.0.1:8093/api/ads?context_keys=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
        "method": "GET",
        "payload": None,
        "headers": {},
    },
    {
        "id": "command-injection",
        "name": "OS Command Injection (CWE-78)",
        "severity": "CRITICAL",
        "url": "http://127.0.0.1:8093/api/ads/telemetry?host=127.0.0.1%3B%20whoami",
        "method": "GET",
        "payload": None,
        "headers": {},
    },
    {
        "id": "ssrf",
        "name": "Server-Side Request Forgery SSRF (CWE-918)",
        "severity": "HIGH",
        "url": "http://127.0.0.1:8094/api/currency/rates?provider_url=http://169.254.169.254/latest/meta-data/",
        "method": "GET",
        "payload": None,
        "headers": {},
    },
    {
        "id": "header-injection",
        "name": "HTTP Header Injection (CWE-113)",
        "severity": "MEDIUM",
        "url": "http://127.0.0.1:8094/api/currency/convert?from_curr=USD&to_curr=EUR&amount=10.0&custom_header=val%0d%0aSet-Cookie:%20session=stolen",
        "method": "GET",
        "payload": None,
        "headers": {},
    },
    {
        "id": "open-redirect",
        "name": "Open Redirect (CWE-601)",
        "severity": "MEDIUM",
        "url": "http://127.0.0.1:8095/api/cart/checkout?return_url=http://attacker-controlled-phishing.com",
        "method": "GET",
        "payload": None,
        "headers": {},
    },
    {
        "id": "unsafe-deserialization",
        "name": "Unsafe Deserialization (CWE-502)",
        "severity": "CRITICAL",
        "url": "http://127.0.0.1:8095/api/cart/restore",
        "method": "POST",
        "payload": b"cos\nsystem\n(S'whoami'\ntR.",
        "headers": {"Content-Type": "application/octet-stream"},
    },
]


def send_request(req_info: dict) -> tuple[int, bool, bool, str]:
    """Execute request and return (status_code, iast_detected, is_blocked, trace_id)."""
    url = req_info["url"]
    method = req_info.get("method", "GET")
    data = req_info.get("payload")
    headers = req_info.get("headers", {})

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            trace_id = resp.headers.get("X-Aegis-Trace-ID", "N/A")
            try:
                res_data = json.loads(body)
                is_detected = bool(res_data.get("iast_finding_detected"))
            except Exception:
                is_detected = "iast_finding_detected" in body
            return resp.status, is_detected, False, trace_id
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", errors="replace")
        trace_id = err.headers.get("X-Aegis-Trace-ID", "N/A")
        is_blocked = err.code == 403
        try:
            res_data = json.loads(body)
            is_detected = bool(res_data.get("iast_finding_detected")) or is_blocked
        except Exception:
            is_detected = is_blocked or "iast_finding_detected" in body
        return err.code, is_detected, is_blocked, trace_id
    except Exception as exc:
        return 0, False, False, str(exc)


async def sync_control_plane():
    """Sync findings to the Aegis Control Plane DB."""
    if seed_findings_main:
        try:
            await seed_findings_main()
            logger.info("--> Synced detected findings to Aegis Control Plane DB.")
        except Exception as exc:
            logger.warning("Control plane sync error: %s", exc)


async def main():
    parser = argparse.ArgumentParser(description="Google Online Boutique Traffic & Chaos Generator")
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between requests (default: 1.0s)")
    parser.add_argument("--attack-ratio", type=float, default=0.15, help="Probability of generating an attack probe (default: 0.15)")
    parser.add_argument("--count", type=int, default=0, help="Total number of requests to generate, 0 for continuous (default: 0)")
    parser.add_argument("--sync-every", type=int, default=10, help="Sync findings to DB every N requests (default: 10)")
    args = parser.parse_args()

    print("=" * 72)
    print("   AEGIS IAST - GOOGLE ONLINE BOUTIQUE TRAFFIC GENERATOR            ")
    print(f"   Interval: {args.interval}s | Attack Ratio: {args.attack_ratio*100:.0f}% | Mode: Auto (Fleet Policy)")
    print("=" * 72)

    req_count = 0
    benign_count = 0
    attack_count = 0
    detected_count = 0
    blocked_count = 0

    try:
        while True:
            req_count += 1
            is_attack = random.random() < args.attack_ratio

            if is_attack:
                attack_count += 1
                item = random.choice(ATTACK_PROBES)
                status, detected, blocked, trace = send_request(item)
                if detected:
                    detected_count += 1
                if blocked:
                    blocked_count += 1

                if blocked:
                    tag = "[ADR BLOCKED 403]"
                elif detected:
                    tag = "[IAST DETECT 200]"
                else:
                    tag = f"[ATTACK HTTP {status}]"

                logger.warning(
                    "%-17s %-32s -> Status: %d | Trace: %s",
                    tag,
                    item["name"],
                    status,
                    trace,
                )
            else:
                benign_count += 1
                item = random.choice(BENIGN_OPERATIONS)
                status, detected, blocked, trace = send_request(item)
                logger.info(
                    "%-17s %-32s -> Status: %d | Trace: %s",
                    "[BENIGN FLOW]",
                    item["name"],
                    status,
                    trace,
                )

            # Periodic Control Plane sync
            if req_count % args.sync_every == 0:
                await sync_control_plane()

            if args.count > 0 and req_count >= args.count:
                break

            await asyncio.sleep(args.interval)

    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\nStopping traffic generator...")

    print("-" * 72)
    print(f"Traffic Session Completed:")
    print(f"  Total Requests:  {req_count}")
    print(f"  Benign Traffic:  {benign_count}")
    print(f"  Attack Vectors:  {attack_count}")
    print(f"  IAST Flagged:    {detected_count}")
    print(f"  ADR Blocked:     {blocked_count}")
    print("-" * 72)

    await sync_control_plane()


if __name__ == "__main__":
    asyncio.run(main())
