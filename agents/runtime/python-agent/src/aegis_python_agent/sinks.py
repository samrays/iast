"""Sink inspection module for Python runtime agent.

Checks security-sensitive operations across OWASP Top 10 rule categories:
- SQL Injection (CWE-89)
- OS Command Injection (CWE-78)
- Unsafe Deserialization (CWE-502)
- XML External Entity (XXE) (CWE-611)
- Path Traversal (CWE-22)
- Reflected XSS (CWE-79)
- Server-Side Request Forgery (SSRF) (CWE-918)
- Open Redirect (CWE-601)
- HTTP Header Injection (CWE-113)
- Log Injection (CWE-117)
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any, Callable

from .taint import get_current_trace, is_tainted

logger = logging.getLogger(__name__)


@dataclass
class FindingEvent:
    rule_key: str
    severity: str
    sink_signature: str
    source_kind: str
    sink_argument: str
    trace_id: str


def inspect_generic_sink(
    val: str | list[str],
    rule_key: str,
    severity: str,
    sink_signature: str,
    trigger_condition: Callable[[str], bool] | None = None,
) -> dict[str, Any] | None:
    """Inspect sensitive operation argument for tainted data and evaluate sink rules."""
    try:
        val_str = val if isinstance(val, str) else " ".join(val)
        tainted, record = is_tainted(val_str)
        if not tainted or record is None:
            return None
        if trigger_condition and not trigger_condition(val_str):
            return None

        trace = get_current_trace()
        trace_id = trace["trace_id"] if trace else "unknown-trace"
        source_kind = record.ranges[0].source_kind if record.ranges else "PARAMETER"

        return {
            "rule_key": rule_key,
            "severity": severity,
            "sink_signature": sink_signature,
            "source_kind": source_kind,
            "sink_argument": val_str[:2000],
            "trace_id": trace_id,
        }
    except Exception as exc:
        logger.debug("Error inspecting sink %s: %s", sink_signature, exc)
        return None


def check_sql_sink(sql: str, sink_signature: str = "sqlite3.Cursor.execute") -> dict[str, Any] | None:
    return inspect_generic_sink(sql, "sql-injection", "CRITICAL", sink_signature)


def check_command_sink(cmd: str | list[str], sink_signature: str = "subprocess.Popen") -> dict[str, Any] | None:
    return inspect_generic_sink(cmd, "command-injection", "CRITICAL", sink_signature)


def check_deserialization_sink(data: str | bytes, sink_signature: str = "pickle.loads") -> dict[str, Any] | None:
    val_str = data.decode("utf-8", errors="ignore") if isinstance(data, bytes) else str(data)
    return inspect_generic_sink(val_str, "unsafe-deserialization", "CRITICAL", sink_signature)


def check_xxe_sink(xml_data: str, sink_signature: str = "xml.etree.ElementTree.fromstring") -> dict[str, Any] | None:
    return inspect_generic_sink(
        xml_data,
        "xxe",
        "CRITICAL",
        sink_signature,
        trigger_condition=lambda x: "<!ENTITY" in x.upper() or "<!DOCTYPE" in x.upper() or "SYSTEM" in x.upper(),
    )


def check_path_traversal_sink(path: str, sink_signature: str = "builtins.open") -> dict[str, Any] | None:
    return inspect_generic_sink(
        path,
        "path-traversal",
        "HIGH",
        sink_signature,
        trigger_condition=lambda p: ".." in p or p.startswith("/") or "\\" in p,
    )


def check_xss_sink(content: str, sink_signature: str = "fastapi.responses.HTMLResponse") -> dict[str, Any] | None:
    return inspect_generic_sink(
        content,
        "reflected-xss",
        "HIGH",
        sink_signature,
        trigger_condition=lambda c: "<script" in c.lower() or "javascript:" in c.lower() or "onerror=" in c.lower(),
    )


def check_ssrf_sink(target_url: str, sink_signature: str = "urllib.request.urlopen") -> dict[str, Any] | None:
    return inspect_generic_sink(
        target_url,
        "ssrf",
        "HIGH",
        sink_signature,
        trigger_condition=lambda u: u.startswith("http://") or u.startswith("https://"),
    )


def check_open_redirect_sink(url: str, sink_signature: str = "fastapi.responses.RedirectResponse") -> dict[str, Any] | None:
    return inspect_generic_sink(
        url,
        "open-redirect",
        "MEDIUM",
        sink_signature,
        trigger_condition=lambda u: u.startswith("http://") or u.startswith("https://") or u.startswith("//"),
    )


def check_header_injection_sink(header_val: str, sink_signature: str = "fastapi.responses.Response.headers") -> dict[str, Any] | None:
    return inspect_generic_sink(
        header_val,
        "header-injection",
        "MEDIUM",
        sink_signature,
        trigger_condition=lambda h: "\r" in h or "\n" in h or "%0d" in h.lower() or "%0a" in h.lower(),
    )


def check_log_injection_sink(msg: str, sink_signature: str = "logging.Logger.info") -> dict[str, Any] | None:
    return inspect_generic_sink(
        msg,
        "log-injection",
        "MEDIUM",
        sink_signature,
        trigger_condition=lambda m: "\n" in m or "\r" in m or "%0a" in m.lower() or "%0d" in m.lower(),
    )
