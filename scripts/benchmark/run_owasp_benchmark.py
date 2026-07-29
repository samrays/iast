"""Drive the OWASP Benchmark against the agent and score the result.

The Benchmark is 2,740 deliberately written test cases with a published answer key, roughly half
of them true vulnerabilities and half near-miss variants that look vulnerable and are not. It is
the only detection measurement in this repository we did not write ourselves, which is precisely
what makes it worth running: our own corpus can only ever confirm that the engine does what we
built it to do.

Two subcommands:

    drive <crawler.xml> <base-url>      issue every request, so the agent observes every case
    score <expected.csv> <events.ndjson>  compare what the agent reported against the answer key

Scoring follows the Benchmark's own definition: true positive rate minus false positive rate,
per category. Reported per category rather than as one number because the agent implements
dataflow rules only — scoring it against the configuration and cryptography categories it makes
no claim to would produce a headline figure that is arithmetically true and completely
misleading.
"""

from __future__ import annotations

import argparse
import csv
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

# Our rule keys, mapped to the Benchmark's category names.
RULE_TO_CATEGORY = {
    "sql-injection": "sqli",
    "command-injection": "cmdi",
    "path-traversal": "pathtraver",
    "reflected-xss": "xss",
    "ldap-injection": "ldapi",
    "xpath-injection": "xpathi",
}

# Categories the agent implements a detection for. The rest are configuration, cryptography and
# randomness families it does not attempt — see docs/05-runtime-agent-design.md §4.
IN_SCOPE = set(RULE_TO_CATEGORY.values())


def drive(crawler_xml: Path, base_url: str, timeout: float) -> int:
    """Issue every Benchmark request. Failures are counted, not fatal."""
    tests = ET.parse(crawler_xml).getroot().findall("benchmarkTest")

    # The Benchmark ships a self-signed certificate. Verification is deliberately disabled: the
    # endpoint is localhost, chosen by us, and refusing to talk to it proves nothing.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    failures = 0
    for index, test in enumerate(tests, start=1):
        url = test.get("URL", "")
        path = urllib.parse.urlsplit(url).path
        target = base_url.rstrip("/") + path

        form = {c.get("name"): c.get("value") for c in test.findall("formparam")}
        query = {c.get("name"): c.get("value") for c in test.findall("getparam")}
        headers = {c.get("name"): c.get("value") for c in test.findall("header")}
        cookies = [f"{c.get('name')}={c.get('value')}" for c in test.findall("cookie")]
        if cookies:
            headers["Cookie"] = "; ".join(cookies)

        if query:
            target = f"{target}?{urllib.parse.urlencode(query)}"

        data = None
        if form:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        request = urllib.request.Request(target, data=data, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context):
                pass
        except urllib.error.HTTPError:
            # A test case that returns 500 still executed its sink, which is all we need.
            pass
        except Exception:
            failures += 1

        if index % 250 == 0:
            print(f"  {index}/{len(tests)} driven ({failures} unreachable)", flush=True)

    print(f"driven {len(tests)} cases, {failures} unreachable")
    return 0 if failures < len(tests) // 10 else 1


def _findings_by_test(events_ndjson: Path) -> dict[str, set[str]]:
    """Test case name → the set of Benchmark categories the agent reported for it."""
    import json

    reported: dict[str, set[str]] = defaultdict(set)
    for line in events_ndjson.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if event.get("type") != "EVENT_TYPE_TAINT_HIT":
            continue
        hit = event["taint_hit"]
        category = RULE_TO_CATEGORY.get(hit["rule_key"])
        if category is None:
            continue
        # The path is /benchmark/<category>-NN/BenchmarkTestNNNNN.
        name = hit.get("request", {}).get("path", "").rstrip("/").rsplit("/", 1)[-1]
        if name.startswith("BenchmarkTest"):
            reported[name].add(category)
    return reported


def score(expected_csv: Path, events_ndjson: Path) -> int:
    reported = _findings_by_test(events_ndjson)

    counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0}
    )
    with expected_csv.open(encoding="utf-8") as handle:
        for row in csv.reader(handle):
            if not row or row[0].startswith("#"):
                continue
            name, category, is_real = row[0].strip(), row[1].strip(), row[2].strip() == "true"
            flagged = category in reported.get(name, set())
            bucket = counts[category]
            if is_real and flagged:
                bucket["tp"] += 1
            elif is_real:
                bucket["fn"] += 1
            elif flagged:
                bucket["fp"] += 1
            else:
                bucket["tn"] += 1

    print(f"{'category':<14}{'cases':>7}{'TP':>7}{'FN':>7}{'FP':>7}{'TN':>7}{'TPR':>8}{'FPR':>8}{'score':>8}")
    print("-" * 74)

    in_scope_totals = {"tp": 0, "fn": 0, "fp": 0, "tn": 0}
    for category in sorted(counts):
        bucket = counts[category]
        total = sum(bucket.values())
        tpr = bucket["tp"] / max(bucket["tp"] + bucket["fn"], 1)
        fpr = bucket["fp"] / max(bucket["fp"] + bucket["tn"], 1)
        marker = "" if category in IN_SCOPE else "   (not implemented)"
        print(
            f"{category:<14}{total:>7}{bucket['tp']:>7}{bucket['fn']:>7}"
            f"{bucket['fp']:>7}{bucket['tn']:>7}{tpr:>7.1%}{fpr:>8.1%}{tpr - fpr:>8.2f}{marker}"
        )
        if category in IN_SCOPE:
            for key in in_scope_totals:
                in_scope_totals[key] += bucket[key]

    print("-" * 74)
    tpr = in_scope_totals["tp"] / max(in_scope_totals["tp"] + in_scope_totals["fn"], 1)
    fpr = in_scope_totals["fp"] / max(in_scope_totals["fp"] + in_scope_totals["tn"], 1)
    total = sum(in_scope_totals.values())
    print(
        f"{'IN SCOPE':<14}{total:>7}{in_scope_totals['tp']:>7}{in_scope_totals['fn']:>7}"
        f"{in_scope_totals['fp']:>7}{in_scope_totals['tn']:>7}{tpr:>7.1%}{fpr:>8.1%}{tpr - fpr:>8.2f}"
    )
    print(
        "\nScore is the Benchmark's own: true positive rate minus false positive rate, where 0.00"
        "\nis the diagonal a coin flip would achieve. Categories the agent does not implement are"
        "\nlisted for completeness and excluded from the total; folding them in would report a"
        "\nnumber that is arithmetically true and thoroughly misleading."
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    driver = sub.add_parser("drive", help="issue every Benchmark request")
    driver.add_argument("crawler_xml", type=Path)
    driver.add_argument("base_url")
    driver.add_argument("--timeout", type=float, default=30.0)

    scorer = sub.add_parser("score", help="score the agent's findings against the answer key")
    scorer.add_argument("expected_csv", type=Path)
    scorer.add_argument("events_ndjson", type=Path)

    args = parser.parse_args()
    if args.command == "drive":
        return drive(args.crawler_xml, args.base_url, args.timeout)
    return score(args.expected_csv, args.events_ndjson)


if __name__ == "__main__":
    sys.exit(main())
