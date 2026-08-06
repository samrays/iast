"""The persisted position — correctness matters more here than anywhere else in the worker.

A wrong answer from :class:`FileCursor` is either silent data loss (advances too far) or
silent reprocessing (does not advance far enough), and neither shows up until someone notices
a finding that should exist does not, or an occurrence count that is implausibly high.
"""

from __future__ import annotations

from pathlib import Path

from aegis_worker.cursor import FileCursor


class TestRead:
    def test_a_cursor_that_has_never_been_written_reads_as_zero(self, tmp_path: Path) -> None:
        cursor = FileCursor(tmp_path / "events.ndjson.cursor")
        assert cursor.read() == 0

    def test_reads_back_what_was_written(self, tmp_path: Path) -> None:
        cursor = FileCursor(tmp_path / "events.ndjson.cursor")
        cursor.advance(4096)
        assert cursor.read() == 4096

    def test_a_corrupt_cursor_reads_as_zero_rather_than_crashing(self, tmp_path: Path) -> None:
        # Zero is the *safe* wrong answer: it re-reads from the start rather than skipping
        # data the worker has never actually confirmed processing.
        path = tmp_path / "events.ndjson.cursor"
        path.write_text("not-a-number", encoding="utf-8")
        assert FileCursor(path).read() == 0

    def test_an_empty_cursor_file_reads_as_zero(self, tmp_path: Path) -> None:
        path = tmp_path / "events.ndjson.cursor"
        path.write_text("", encoding="utf-8")
        assert FileCursor(path).read() == 0

    def test_a_negative_value_is_clamped_to_zero(self, tmp_path: Path) -> None:
        # Should never happen, but a negative seek offset would crash the reader far from
        # here — clamp at the boundary rather than trust the file's contents blindly.
        path = tmp_path / "events.ndjson.cursor"
        path.write_text("-5", encoding="utf-8")
        assert FileCursor(path).read() == 0


class TestAdvance:
    def test_advancing_creates_the_parent_directory(self, tmp_path: Path) -> None:
        cursor = FileCursor(tmp_path / "nested" / "events.ndjson.cursor")
        cursor.advance(10)
        assert cursor.read() == 10

    def test_advancing_overwrites_rather_than_appends(self, tmp_path: Path) -> None:
        cursor = FileCursor(tmp_path / "events.ndjson.cursor")
        cursor.advance(10)
        cursor.advance(20)
        assert cursor.read() == 20

    def test_no_temp_file_is_left_behind(self, tmp_path: Path) -> None:
        cursor_path = tmp_path / "events.ndjson.cursor"
        FileCursor(cursor_path).advance(10)
        leftovers = list(tmp_path.glob("*.tmp"))
        assert leftovers == [], f"atomic write left a temp file: {leftovers}"


class TestForSource:
    def test_defaults_to_a_sibling_of_the_source_file(self, tmp_path: Path) -> None:
        source = tmp_path / "events.ndjson"
        cursor = FileCursor.for_source(source)
        assert cursor._path == tmp_path / "events.ndjson.cursor"

    def test_an_explicit_override_wins(self, tmp_path: Path) -> None:
        source = tmp_path / "events.ndjson"
        override = tmp_path / "elsewhere" / "position.txt"
        cursor = FileCursor.for_source(source, str(override))
        assert cursor._path == override
