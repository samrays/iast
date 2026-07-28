"""Structured logging and metrics setup."""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

from .config import Environment, Settings

#: Keys whose values are never written to a log line, wherever they appear.
_REDACT_KEYS = frozenset(
    {
        "password",
        "current_password",
        "new_password",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "challenge_token",
        "agent_token",
        "authorization",
        "cookie",
        "api_key",
        "secret_hash",
        "password_hash",
        "recovery_codes",
    }
)


def _redact(_logger: object, _method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """Strip credential-shaped values before they reach a log sink.

    Logs travel further than anyone expects — into aggregators, tickets and screenshots.
    Redaction happens here, once, rather than relying on every call site to remember.
    """
    for key in list(event_dict):
        if key.lower() in _REDACT_KEYS:
            event_dict[key] = "<redacted>"
    return event_dict


def configure_logging(settings: Settings) -> None:
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, settings.log_level),
        force=True,
    )
    # SQLAlchemy and asyncio are chatty at INFO and add nothing operationally useful.
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        _redact,
    ]
    # Human-readable locally, JSON everywhere a log aggregator is listening.
    if settings.environment is Environment.LOCAL:
        processors.append(structlog.dev.ConsoleRenderer(colors=True))
    else:
        processors.append(structlog.processors.JSONRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, settings.log_level)),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
