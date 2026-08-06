"""FileTailSource: reading an NDJSON file the way the gateway's FileEventSink writes one."""

from __future__ import annotations

from pathlib import Path

from aegis_worker.consumer import FileTailSource
from aegis_worker.cursor import FileCursor


def _source(tmp_path: Path) -> tuple[Path, FileTailSource]:
    path = tmp_path / "events.ndjson"
    return path, FileTailSource(path, FileCursor.for_source(path))


class TestPoll:
    async def test_a_missing_file_polls_as_empty(self, tmp_path: Path) -> None:
        _, source = _source(tmp_path)
        assert await source.poll(10) == []

    async def test_reads_lines_written_since_the_last_commit(self, tmp_path: Path) -> None:
        path, source = _source(tmp_path)
        path.write_text('{"a":1}\n{"a":2}\n', encoding="utf-8")
        assert await source.poll(10) == ['{"a":1}', '{"a":2}']

    async def test_a_batch_size_smaller_than_whats_available_is_respected(
        self, tmp_path: Path
    ) -> None:
        path, source = _source(tmp_path)
        path.write_text('{"a":1}\n{"a":2}\n{"a":3}\n', encoding="utf-8")
        assert await source.poll(2) == ['{"a":1}', '{"a":2}']

    async def test_an_incomplete_final_line_is_held_back(self, tmp_path: Path) -> None:
        # No trailing newline: either EOF mid-line or the writer has not finished this append.
        # Either way it is not safe to parse yet.
        path, source = _source(tmp_path)
        path.write_bytes(b'{"a":1}\n{"a":2}')
        assert await source.poll(10) == ['{"a":1}']

    async def test_polling_again_before_commit_returns_the_same_batch(self, tmp_path: Path) -> None:
        path, source = _source(tmp_path)
        path.write_text('{"a":1}\n', encoding="utf-8")
        first = await source.poll(10)
        # More data arrives, but the caller has not confirmed it processed the first batch —
        # polling again must not silently skip ahead of unprocessed work.
        with path.open("a", encoding="utf-8") as handle:
            handle.write('{"a":2}\n')
        second = await source.poll(10)
        assert first == second == ['{"a":1}']

    async def test_blank_lines_are_skipped(self, tmp_path: Path) -> None:
        path, source = _source(tmp_path)
        path.write_text('{"a":1}\n\n{"a":2}\n', encoding="utf-8")
        assert await source.poll(10) == ['{"a":1}', '{"a":2}']


class TestCommit:
    async def test_commit_advances_past_the_polled_batch(self, tmp_path: Path) -> None:
        path, source = _source(tmp_path)
        path.write_text('{"a":1}\n{"a":2}\n', encoding="utf-8")
        await source.poll(10)
        await source.commit()
        with path.open("a", encoding="utf-8") as handle:
            handle.write('{"a":3}\n')
        assert await source.poll(10) == ['{"a":3}']

    async def test_committing_with_nothing_pending_is_a_no_op(self, tmp_path: Path) -> None:
        _, source = _source(tmp_path)
        await source.commit()  # must not raise

    async def test_the_position_survives_a_restart(self, tmp_path: Path) -> None:
        path = tmp_path / "events.ndjson"
        path.write_text('{"a":1}\n{"a":2}\n', encoding="utf-8")

        first_run = FileTailSource(path, FileCursor.for_source(path))
        await first_run.poll(10)
        await first_run.commit()

        with path.open("a", encoding="utf-8") as handle:
            handle.write('{"a":3}\n')

        # A fresh instance, as a process restart would create — reads its position from the
        # same cursor file rather than starting from byte zero.
        second_run = FileTailSource(path, FileCursor.for_source(path))
        assert await second_run.poll(10) == ['{"a":3}']
