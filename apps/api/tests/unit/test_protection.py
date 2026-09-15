"""Unit tests for protection policy and soak duration enforcement."""

from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from aegis_api.domain.entities.protection import ProtectionMode, ProtectionPolicy
from aegis_api.domain.errors import InvalidStateError


def test_protection_policy_creation() -> None:
    now = datetime(2026, 8, 1, 12, 0, 0)
    policy = ProtectionPolicy.create(
        organization_id=uuid4(),
        application_id=uuid4(),
        mode=ProtectionMode.MONITOR,
        now=now,
    )
    assert policy.mode == ProtectionMode.MONITOR
    assert policy.would_block_count == 0
    assert policy.soak_started_at == now


def test_soak_period_enforcement_blocks_premature_transition() -> None:
    start_time = datetime(2026, 8, 1, 12, 0, 0)
    policy = ProtectionPolicy.create(
        organization_id=uuid4(),
        application_id=uuid4(),
        mode=ProtectionMode.MONITOR,
        now=start_time,
    )

    # Attempt transition to BLOCK after only 5 hours
    check_time = start_time + timedelta(hours=5)
    with pytest.raises(InvalidStateError, match="Soak period incomplete"):
        policy.transition_to(ProtectionMode.BLOCK, check_time)


def test_transition_to_block_allowed_after_soak() -> None:
    start_time = datetime(2026, 8, 1, 12, 0, 0)
    policy = ProtectionPolicy.create(
        organization_id=uuid4(),
        application_id=uuid4(),
        mode=ProtectionMode.MONITOR,
        now=start_time,
    )

    # Transition to BLOCK after 337 hours (14 days + 1 hour)
    check_time = start_time + timedelta(hours=337)
    policy.transition_to(ProtectionMode.BLOCK, check_time)
    assert policy.mode == ProtectionMode.BLOCK


def test_direct_off_to_block_fails() -> None:
    now = datetime(2026, 8, 1, 12, 0, 0)
    policy = ProtectionPolicy.create(
        organization_id=uuid4(),
        application_id=uuid4(),
        mode=ProtectionMode.OFF,
        now=now,
    )

    with pytest.raises(InvalidStateError, match="Enable MONITOR mode first"):
        policy.transition_to(ProtectionMode.BLOCK, now)
