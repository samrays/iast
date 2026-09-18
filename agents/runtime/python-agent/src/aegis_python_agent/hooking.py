"""Transparent runtime sink hooking and ADR active blocking engine.

Hooks standard library sinks with zero code modifications to user application code.
Supports fail-open safety: internal agent errors are caught and logged so that
application execution is never unintentionally broken.
"""

from __future__ import annotations

import builtins
import functools
import logging
import pickle
import sqlite3
import subprocess
from typing import TYPE_CHECKING, Any

from .sinks import (
    check_command_sink,
    check_deserialization_sink,
    check_path_traversal_sink,
    check_sql_sink,
)

if TYPE_CHECKING:
    from .agent import AegisAgent

logger = logging.getLogger("AegisPythonAgent.Hooking")


class AegisSecurityBlockException(RuntimeError):
    """Raised when Aegis ADR is in BLOCK mode and an active exploit payload reaches a sensitive sink."""

    def __init__(self, message: str, rule_key: str = "", sink_signature: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.rule_key = rule_key
        self.sink_signature = sink_signature


class SqliteCursorProxy:
    """Proxy around sqlite3.Cursor that inspects queries for SQL Injection."""

    def __init__(self, cursor: sqlite3.Cursor, agent: AegisAgent) -> None:
        self._cursor = cursor
        self._agent = agent

    def execute(self, sql: str, *args: Any, **kwargs: Any) -> Any:
        try:
            finding = check_sql_sink(sql, sink_signature="sqlite3.Cursor.execute")
            if finding:
                self._agent.event_buffer.append(finding)
                logger.warning("IAST Sink Triggered [SQLi]: %s", sql[:100])
                if getattr(self._agent, "protection_mode", "MONITOR") == "BLOCK":
                    logger.error("Aegis ADR BLOCK active: Aborting SQL Injection execution!")
                    raise AegisSecurityBlockException(
                        "Aegis ADR Block: Blocked SQL Injection attack vector.",
                        rule_key="sql-injection",
                        sink_signature="sqlite3.Cursor.execute",
                    )
        except AegisSecurityBlockException:
            raise
        except Exception as exc:
            logger.debug("Aegis fail-open in sqlite3 hook: %s", exc)

        return self._cursor.execute(sql, *args, **kwargs)

    def executemany(self, sql: str, seq_of_parameters: Any) -> Any:
        return self._cursor.executemany(sql, seq_of_parameters)

    def executescript(self, sql_script: str) -> Any:
        return self._cursor.executescript(sql_script)

    def fetchone(self) -> Any:
        return self._cursor.fetchone()

    def fetchall(self) -> Any:
        return self._cursor.fetchall()

    def fetchmany(self, size: int = 1) -> Any:
        return self._cursor.fetchmany(size)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._cursor, name)

    def __iter__(self) -> Any:
        return iter(self._cursor)


class SqliteConnectionProxy:
    """Proxy around sqlite3.Connection returning proxied cursors."""

    def __init__(self, conn: sqlite3.Connection, agent: AegisAgent) -> None:
        self._conn = conn
        self._agent = agent

    def cursor(self, *args: Any, **kwargs: Any) -> SqliteCursorProxy:
        real_cur = self._conn.cursor(*args, **kwargs)
        return SqliteCursorProxy(real_cur, self._agent)

    def execute(self, sql: str, *args: Any, **kwargs: Any) -> SqliteCursorProxy:
        cur = self.cursor()
        cur.execute(sql, *args, **kwargs)
        return cur

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> SqliteConnectionProxy:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._conn.__exit__(exc_type, exc_val, exc_tb)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)


_ORIGINAL_CONNECT = sqlite3.connect
_ORIGINAL_SUBPROCESS_POPEN = subprocess.Popen
_ORIGINAL_PICKLE_LOADS = pickle.loads


def hook_sqlite3(agent: AegisAgent) -> None:
    """Intercept sqlite3 connections and cursor execution."""
    @functools.wraps(_ORIGINAL_CONNECT)
    def wrapped_connect(*args: Any, **kwargs: Any) -> Any:
        conn = _ORIGINAL_CONNECT(*args, **kwargs)
        return SqliteConnectionProxy(conn, agent)

    sqlite3.connect = wrapped_connect
    logger.info("Hooked sqlite3.connect with SqliteConnectionProxy")



def hook_subprocess(agent: AegisAgent) -> None:
    """Intercept subprocess.Popen process spawning."""
    @functools.wraps(_ORIGINAL_SUBPROCESS_POPEN)
    def wrapped_popen(args: Any, *pos_args: Any, **kwargs: Any) -> Any:
        try:
            cmd_str = args if isinstance(args, str) else " ".join(str(a) for a in args)
            finding = check_command_sink(cmd_str, sink_signature="subprocess.Popen")
            if finding:
                agent.event_buffer.append(finding)
                logger.warning("IAST Sink Triggered [Command Injection]: %s", cmd_str[:100])
                if getattr(agent, "protection_mode", "MONITOR") == "BLOCK":
                    logger.error("Aegis ADR BLOCK active: Aborting OS Command execution!")
                    raise AegisSecurityBlockException(
                        "Aegis ADR Block: Blocked OS Command Injection attack vector.",
                        rule_key="command-injection",
                        sink_signature="subprocess.Popen",
                    )
        except AegisSecurityBlockException:
            raise
        except Exception as exc:
            logger.debug("Aegis fail-open in subprocess hook: %s", exc)

        return _ORIGINAL_SUBPROCESS_POPEN(args, *pos_args, **kwargs)

    subprocess.Popen = wrapped_popen  # type: ignore[misc]
    logger.info("Hooked subprocess.Popen")


def hook_pickle(agent: AegisAgent) -> None:
    """Intercept pickle deserialization."""
    @functools.wraps(_ORIGINAL_PICKLE_LOADS)
    def wrapped_loads(data: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            str_repr = data.decode("utf-8", errors="ignore") if isinstance(data, (bytes, bytearray)) else str(data)
            finding = check_deserialization_sink(str_repr, sink_signature="pickle.loads")
            if finding:
                agent.event_buffer.append(finding)
                logger.warning("IAST Sink Triggered [Deserialization]: %s", str_repr[:100])
                if getattr(agent, "protection_mode", "MONITOR") == "BLOCK":
                    logger.error("Aegis ADR BLOCK active: Aborting Unsafe Deserialization!")
                    raise AegisSecurityBlockException(
                        "Aegis ADR Block: Blocked Unsafe Deserialization attack vector.",
                        rule_key="unsafe-deserialization",
                        sink_signature="pickle.loads",
                    )
        except AegisSecurityBlockException:
            raise
        except Exception as exc:
            logger.debug("Aegis fail-open in pickle hook: %s", exc)

        return _ORIGINAL_PICKLE_LOADS(data, *args, **kwargs)

    pickle.loads = wrapped_loads
    logger.info("Hooked pickle.loads")


def hook_all_sinks(agent: AegisAgent) -> None:
    """Install all transparent runtime hooks for the agent."""
    hook_sqlite3(agent)
    hook_subprocess(agent)
    hook_pickle(agent)
