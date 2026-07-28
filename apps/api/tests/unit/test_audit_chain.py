"""The tamper-evident audit chain (threat T-11)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aegis_api.domain.entities import ActorType, AuditEvent, AuditOutcome
from aegis_api.domain.entities.audit import GENESIS_HASH
from aegis_api.domain.value_objects import new_id

NOW = datetime(2026, 7, 28, tzinfo=UTC)


def _event(org, sequence: int, previous: str, action: str = "test.action") -> AuditEvent:
    event = AuditEvent(organization_id=org, action=action, actor_type=ActorType.USER)
    event.seal(previous, NOW + timedelta(seconds=sequence), sequence)
    return event


pytestmark = pytest.mark.security


class TestAuditChain:
    def test_first_entry_links_to_genesis(self) -> None:
        event = _event(new_id(), 1, GENESIS_HASH)
        assert event.verify(GENESIS_HASH)
        assert len(event.entry_hash) == 64

    def test_chain_verifies_end_to_end(self) -> None:
        org = new_id()
        previous = GENESIS_HASH
        for sequence in range(1, 20):
            event = _event(org, sequence, previous)
            assert event.verify(previous)
            previous = event.entry_hash

    def test_altering_a_field_breaks_the_entry(self) -> None:
        event = _event(new_id(), 1, GENESIS_HASH)
        event.action = "something.else"
        assert not event.verify(GENESIS_HASH)

    def test_altering_metadata_breaks_the_entry(self) -> None:
        event = _event(new_id(), 1, GENESIS_HASH)
        event.metadata["injected"] = True
        assert not event.verify(GENESIS_HASH)

    def test_removing_a_predecessor_breaks_the_link(self) -> None:
        org = new_id()
        first = _event(org, 1, GENESIS_HASH)
        second = _event(org, 2, first.entry_hash)
        # Pretend the first entry was deleted: the second no longer links to genesis.
        assert not second.verify(GENESIS_HASH)

    def test_hash_is_deterministic(self) -> None:
        org = new_id()
        one = _event(org, 1, GENESIS_HASH)
        recomputed = one.compute_hash()
        assert recomputed == one.entry_hash

    def test_distinct_actions_produce_distinct_hashes(self) -> None:
        org = new_id()
        a = _event(org, 1, GENESIS_HASH, action="auth.login_succeeded")
        b = _event(org, 1, GENESIS_HASH, action="auth.login_failed")
        assert a.entry_hash != b.entry_hash

    def test_outcome_is_covered_by_the_hash(self) -> None:
        event = _event(new_id(), 1, GENESIS_HASH)
        original = event.entry_hash
        event.outcome = AuditOutcome.DENIED
        assert event.compute_hash() != original
