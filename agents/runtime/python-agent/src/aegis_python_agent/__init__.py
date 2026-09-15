"""Aegis IAST Python Agent package."""

from .agent import AegisAgent
from .sinks import (
    check_command_sink,
    check_deserialization_sink,
    check_header_injection_sink,
    check_log_injection_sink,
    check_open_redirect_sink,
    check_path_traversal_sink,
    check_sql_sink,
    check_ssrf_sink,
    check_xss_sink,
    check_xxe_sink,
)
from .taint import mark_tainted, start_request_trace

__all__ = [
    "AegisAgent",
    "check_command_sink",
    "check_deserialization_sink",
    "check_header_injection_sink",
    "check_log_injection_sink",
    "check_open_redirect_sink",
    "check_path_traversal_sink",
    "check_sql_sink",
    "check_ssrf_sink",
    "check_xss_sink",
    "check_xxe_sink",
    "mark_tainted",
    "start_request_trace",
]
