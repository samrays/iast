"""KafkaSource and the URI dispatch that picks it — mocked, deliberately.

Nothing here talks to a real broker. What matters at the unit level is the wiring: that a
``kafka://`` URI is parsed into the right servers and topic, and that commit is only ever
called on the underlying consumer when a batch is actually pending — never on an empty poll,
never twice for the same batch. A real broker belongs in a live run, not this suite.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aegis_worker.consumer import FileTailSource, KafkaSource, build_source


@pytest.fixture
def mock_consumer_class() -> MagicMock:
    """Patches the name ``aiokafka.AIOKafkaConsumer`` where ``KafkaSource`` imports it."""
    with patch("aiokafka.AIOKafkaConsumer") as mock_class:
        instance = MagicMock()
        instance.start = AsyncMock()
        instance.stop = AsyncMock()
        instance.commit = AsyncMock()
        instance.getmany = AsyncMock(return_value={})
        mock_class.return_value = instance
        yield mock_class


class TestKafkaSourceWiring:
    async def test_starts_the_consumer_lazily_on_first_poll(
        self, mock_consumer_class: MagicMock
    ) -> None:
        source = KafkaSource("broker:9092", "runtime-events", "aegis-worker")
        mock_consumer_class.return_value.start.assert_not_called()
        await source.poll(100)
        mock_consumer_class.return_value.start.assert_awaited_once()

    async def test_constructs_with_manual_commit_and_earliest_offset(
        self, mock_consumer_class: MagicMock
    ) -> None:
        KafkaSource("broker:9092", "runtime-events", "aegis-worker")
        _, kwargs = mock_consumer_class.call_args
        assert kwargs["enable_auto_commit"] is False
        assert kwargs["auto_offset_reset"] == "earliest"
        assert kwargs["group_id"] == "aegis-worker"

    async def test_poll_decodes_message_values_across_partitions(
        self, mock_consumer_class: MagicMock
    ) -> None:
        message_a = MagicMock(value=b'{"a":1}')
        message_b = MagicMock(value=b'{"a":2}')
        mock_consumer_class.return_value.getmany = AsyncMock(
            return_value={"partition-0": [message_a], "partition-1": [message_b]}
        )
        source = KafkaSource("broker:9092", "runtime-events", "aegis-worker")
        records = await source.poll(100)
        assert sorted(records) == ['{"a":1}', '{"a":2}']

    async def test_polling_again_before_commit_does_not_ask_the_broker_for_more(
        self, mock_consumer_class: MagicMock
    ) -> None:
        message = MagicMock(value=b'{"a":1}')
        mock_consumer_class.return_value.getmany = AsyncMock(
            return_value={"partition-0": [message]}
        )
        source = KafkaSource("broker:9092", "runtime-events", "aegis-worker")
        await source.poll(100)
        second = await source.poll(100)
        assert second == []
        mock_consumer_class.return_value.getmany.assert_awaited_once()

    async def test_commit_only_touches_the_broker_when_a_batch_is_pending(
        self, mock_consumer_class: MagicMock
    ) -> None:
        source = KafkaSource("broker:9092", "runtime-events", "aegis-worker")
        await source.commit()
        mock_consumer_class.return_value.commit.assert_not_awaited()

        mock_consumer_class.return_value.getmany = AsyncMock(
            return_value={"p": [MagicMock(value=b'{"a":1}')]}
        )
        await source.poll(100)
        await source.commit()
        mock_consumer_class.return_value.commit.assert_awaited_once()

    async def test_close_stops_a_started_consumer_and_is_a_no_op_otherwise(
        self, mock_consumer_class: MagicMock
    ) -> None:
        source = KafkaSource("broker:9092", "runtime-events", "aegis-worker")
        await source.close()
        mock_consumer_class.return_value.stop.assert_not_awaited()

        await source.poll(100)
        await source.close()
        mock_consumer_class.return_value.stop.assert_awaited_once()

    def test_a_missing_kafka_extra_raises_a_clear_error(self) -> None:
        with (
            patch.dict("sys.modules", {"aiokafka": None}),
            pytest.raises(RuntimeError, match=r"kafka.*extra"),
        ):
            KafkaSource("broker:9092", "runtime-events", "aegis-worker")


class TestBuildSource:
    def test_a_kafka_uri_builds_a_kafka_source_with_servers_and_topic_split_out(
        self, mock_consumer_class: MagicMock
    ) -> None:
        source = build_source(
            "kafka://broker1:9092,broker2:9092/runtime-events", consumer_group="my-group"
        )
        assert isinstance(source, KafkaSource)
        _, kwargs = mock_consumer_class.call_args
        assert kwargs["bootstrap_servers"] == "broker1:9092,broker2:9092"
        assert kwargs["group_id"] == "my-group"
        assert mock_consumer_class.call_args[0][0] == "runtime-events"

    def test_a_kafka_uri_without_a_topic_falls_back_to_the_default(
        self, mock_consumer_class: MagicMock
    ) -> None:
        build_source("kafka://broker:9092", consumer_group="my-group")
        assert mock_consumer_class.call_args[0][0] == "runtime-events"

    def test_a_file_uri_builds_a_file_tail_source(self, tmp_path: Path) -> None:
        source = build_source(f"file:{tmp_path / 'events.ndjson'}", consumer_group="")
        assert isinstance(source, FileTailSource)

    def test_an_unrecognised_scheme_is_rejected_rather_than_silently_ignored(self) -> None:
        with pytest.raises(ValueError, match="unrecognised"):
            build_source("memory://", consumer_group="")
