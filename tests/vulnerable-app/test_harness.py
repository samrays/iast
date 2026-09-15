"""Automated test harness verifying all OWASP Top 10 vulnerability detections in Aegis IAST agent."""

from __future__ import annotations

import json
import urllib.request


TEST_CASES = [
    {
        "category": "1. SQL Injection (CWE-89)",
        "url": "http://127.0.0.1:8095/api/users/search?name=admin%27%20OR%20%271%27%3D%271",
        "method": "GET",
        "payload": None,
        "expected_rule": "sql-injection",
        "expected_severity": "CRITICAL",
    },
    {
        "category": "2. OS Command Injection (CWE-78)",
        "url": "http://127.0.0.1:8095/api/system/ping?host=127.0.0.1%3B%20whoami",
        "method": "GET",
        "payload": None,
        "expected_rule": "command-injection",
        "expected_severity": "CRITICAL",
    },
    {
        "category": "3. Unsafe Deserialization (CWE-502)",
        "url": "http://127.0.0.1:8095/api/data/deserialize",
        "method": "POST",
        "payload": b"cos\nsystem\n(S'id'\ntR.",
        "expected_rule": "unsafe-deserialization",
        "expected_severity": "CRITICAL",
    },
    {
        "category": "4. XML External Entity XXE (CWE-611)",
        "url": "http://127.0.0.1:8095/api/xml/parse",
        "method": "POST",
        "payload": b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        "expected_rule": "xxe",
        "expected_severity": "CRITICAL",
    },
    {
        "category": "5. Path Traversal (CWE-22)",
        "url": "http://127.0.0.1:8095/api/files/read?filename=../../../../etc/passwd",
        "method": "GET",
        "payload": None,
        "expected_rule": "path-traversal",
        "expected_severity": "HIGH",
    },
    {
        "category": "6. Reflected XSS (CWE-79)",
        "url": "http://127.0.0.1:8095/api/render/html?user_input=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        "method": "GET",
        "payload": None,
        "expected_rule": "reflected-xss",
        "expected_severity": "HIGH",
    },
    {
        "category": "7. Server-Side Request Forgery SSRF (CWE-918)",
        "url": "http://127.0.0.1:8095/api/fetch/url?target=http://169.254.169.254/latest/meta-data/",
        "method": "GET",
        "payload": None,
        "expected_rule": "ssrf",
        "expected_severity": "HIGH",
    },
    {
        "category": "8. Open Redirect (CWE-601)",
        "url": "http://127.0.0.1:8095/api/navigate/redirect?url=http://example.com",
        "method": "GET",
        "payload": None,
        "expected_rule": "open-redirect",
        "expected_severity": "MEDIUM",
    },
    {
        "category": "9. HTTP Header Injection (CWE-113)",
        "url": "http://127.0.0.1:8095/api/headers/set?custom_header=val%0d%0aSet-Cookie:%20session=stolen",
        "method": "GET",
        "payload": None,
        "expected_rule": "header-injection",
        "expected_severity": "MEDIUM",
    },
    {
        "category": "10. Log Injection (CWE-117)",
        "url": "http://127.0.0.1:8095/api/system/log?msg=User%20logged%20in%0aADMIN%20GRANTED",
        "method": "GET",
        "payload": None,
        "expected_rule": "log-injection",
        "expected_severity": "MEDIUM",
    },
]


def run_owasp_top10_tests() -> None:
    passed_count = 0
    print("======================================================================")
    print("          AEGIS IAST PLATFORM - OWASP TOP 10 SUITE")
    print("======================================================================\n")

    for tc in TEST_CASES:
        category = tc["category"]
        url = tc["url"]
        method = tc["method"]
        payload = tc["payload"]

        req = urllib.request.Request(url, data=payload, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode())
                detected = data.get("iast_finding_detected", False)
                finding = data.get("finding", {})

                rule_key = finding.get("rule_key") if finding else None
                severity = finding.get("severity") if finding else None

                assert detected is True, f"Detection failed for {category}"
                assert rule_key == tc["expected_rule"], f"Rule key mismatch for {category}: got {rule_key}"
                assert severity == tc["expected_severity"], f"Severity mismatch for {category}: got {severity}"

                print(f"[PASS] {category}")
                print(f"       -> Rule Key : {rule_key}")
                print(f"       -> Severity : {severity}")
                print(f"       -> Sink Sig : {finding.get('sink_signature')}\n")
                passed_count += 1
        except Exception as exc:
            print(f"[FAIL] {category}: {exc}\n")

    print(f"Summary: {passed_count}/{len(TEST_CASES)} OWASP Top 10 Vulnerabilities Detected Successfully!")
    assert passed_count == len(TEST_CASES)


if __name__ == "__main__":
    run_owasp_top10_tests()
