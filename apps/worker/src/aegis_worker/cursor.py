"""Where the file-mode consumer left off.

A plain integer byte offset, persisted next to the source file. The two things that matter:
the write is atomic (a crash mid-write must not corrupt the cursor into an unreadable or, worse,
silently wrong value), and it is advanced only after a batch has been durably committed to the
database — never before. Reversing that order is the difference between "a crash loses at most
one unprocessed batch" and "a crash loses at most one *processed* batch that never advanced",
and only one of those is recoverable by just restarting.
"""

from __future__ import annotations

import os
from pathlib import Path


class FileCursor:
    """Persists a byte offset into one file."""

    def __init__(self, path: Path) -> None:
        self._path = path

    @staticmethod
    def for_source(source_path: Path, override: str = "") -> FileCursor:
        """The cursor file for a source, honouring an explicit override."""
        if override:
            return FileCursor(Path(override))
        return FileCursor(source_path.with_name(source_path.name + ".cursor"))

    def read(self) -> int:
        """Bytes already consumed. Zero for a source the worker has never seen."""
        try:
            raw = self._path.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            return 0
        if not raw:
            return 0
        try:
            offset = int(raw)
        except ValueError:
            # A corrupt cursor must not crash the worker on every restart — it must re-derive
            # a safe value, and "re-read everything" is the safe direction to be wrong in.
            return 0
        return max(offset, 0)

    def advance(self, offset: int) -> None:
        """Persist ``offset``, atomically.

        Write-then-rename: ``os.replace`` is atomic on both POSIX and Windows, so a reader (or
        a crash) never observes a partially written value — it sees either the old offset or
        the new one, never a truncated file in between.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp_path.write_text(str(offset), encoding="utf-8")
        os.replace(tmp_path, self._path)
