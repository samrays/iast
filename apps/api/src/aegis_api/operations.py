"""Operator procedures, as plain async functions.

Separated from ``cli.py`` so the behaviour can be tested directly and reused by scheduled
jobs. The CLI module is then only argument parsing and terminal output — the part with
nothing worth testing.
"""

from __future__ import annotations

import json
import secrets
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

import anyio.to_thread

from .application.auth import RegisterOrganization
from .application.context import RequestContext
from .application.findings import ProcessingResult, ProcessRuntimeEvents
from .application.rules import PublishRuleBundle
from .container import Container
from .domain.entities import LicenseTier
from .domain.entities.rules import RuleBundle
from .domain.errors import NotFoundError
from .domain.value_objects import Slug
from .infrastructure.security.bundle_signing import verifier_for


@dataclass(frozen=True, slots=True)
class SeedResult:
    organization_id: UUID
    organization_name: str
    organization_slug: str
    user_id: UUID
    email: str
    password: str
    password_was_generated: bool


@dataclass(frozen=True, slots=True)
class ChainStatus:
    intact: bool
    entries_checked: int
    first_broken_sequence: int | None


def generate_password(length: int = 24) -> str:
    """A strong password for a bootstrap account, printed once and never stored."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


async def seed_organization(
    container: Container,
    *,
    organization: str,
    email: str,
    full_name: str,
    password: str = "",
    tier: LicenseTier = LicenseTier.ENTERPRISE,
) -> SeedResult:
    """Create the first organization and its Owner.

    Fails rather than overwrites when the address already exists — a bootstrap command that
    silently resets an existing owner's password would be a fine backdoor.
    """
    generated = not password
    chosen = password or generate_password()
    result = await RegisterOrganization(
        container.unit_of_work(), container.auth, allow_signup=True
    ).execute(
        organization_name=organization,
        email=email,
        password=chosen,
        full_name=full_name,
        context=RequestContext(request_id="cli-seed"),
        tier=tier,
    )
    return SeedResult(
        organization_id=result.organization.id,
        organization_name=result.organization.name,
        organization_slug=result.organization.slug,
        user_id=result.user_id,
        email=result.email,
        password=chosen,
        password_was_generated=generated,
    )


async def verify_audit_chain(container: Container, *, organization_slug: str) -> ChainStatus:
    """Walk a tenant's audit chain from genesis and report the first break, if any."""
    async with container.unit_of_work() as uow:
        organization = await uow.organizations.get_by_slug(Slug(organization_slug))
        if organization is None:
            raise NotFoundError("Organization", organization_slug)
        await uow.bind_tenant(organization.id)
        intact, checked, broken_at = await uow.audit.verify_chain()
    return ChainStatus(intact=intact, entries_checked=checked, first_broken_sequence=broken_at)


async def sweep_offline_agents(container: Container, *, organization_slug: str) -> int:
    """Demote agents whose heartbeats have stopped. Returns how many changed state.

    Runs on a schedule in production. Paginates rather than loading the fleet at once,
    because a large tenant can have tens of thousands of agents.
    """
    now = container.auth.clock.now()
    demoted = 0
    async with container.unit_of_work() as uow:
        organization = await uow.organizations.get_by_slug(Slug(organization_slug))
        if organization is None:
            raise NotFoundError("Organization", organization_slug)
        await uow.bind_tenant(organization.id)

        cursor: str | None = None
        while True:
            agents, cursor = await uow.agents.list_all(limit=200, cursor=cursor)
            for agent in agents:
                previous = agent.status
                agent.evaluate_liveness(now)
                if agent.status is not previous:
                    await uow.agents.update(agent)
                    demoted += 1
            if cursor is None:
                break
        await uow.commit()
    return demoted


async def purge_expired_sessions(container: Container) -> int:
    """Delete sessions that expired more than a day ago.

    Every stale session row is a credential someone might still hold, and the table is the
    fastest-growing one in the schema.
    """
    from datetime import timedelta

    from sqlalchemy import text

    cutoff = container.auth.clock.now() - timedelta(days=1)
    async with container.unit_of_work() as uow:
        result = await uow.session.execute(
            text("DELETE FROM sessions WHERE expires_at < :cutoff"), {"cutoff": cutoff}
        )
        await uow.commit()
        return int(result.rowcount or 0)  # type: ignore[attr-defined]


def describe_routes(app: object) -> list[tuple[str, str]]:
    """Every registered route as ``(methods, full_path)``.

    Derived from the OpenAPI document rather than by walking ``app.routes``: FastAPI wraps
    included routers, and the nested route objects carry paths *relative* to their router,
    so a naive walk reports ``/agents`` where the real path is ``/api/v1/agents``. For an
    authorization audit, the wrong path is worse than no path.
    """
    schema: dict[str, Any] = app.openapi()  # type: ignore[attr-defined]
    described: list[tuple[str, str]] = []
    for path, operations_by_method in schema.get("paths", {}).items():
        methods = sorted(
            method.upper()
            for method in operations_by_method
            if method.lower() not in {"head", "options", "parameters"}
        )
        if methods:
            described.append((",".join(methods), path))
    return sorted(described, key=lambda item: (item[1], item[0]))


async def process_runtime_events(
    container: Container, *, source: str, batch_size: int = 500
) -> ProcessingResult:
    """Fold a runtime event stream into findings.

    The source is a file of NDJSON as written by the gateway's file sink — the same format
    its Kafka sink produces, so an air-gapped capture replays through exactly this path.
    Reading the whole file and processing in batches is deliberate for now: the file sink is
    a bounded artefact, and a streaming consumer belongs with the Kafka source rather than
    bolted onto this one.
    """
    path = Path(source.removeprefix("file:"))
    # Off the event loop: a large capture would otherwise stall every other coroutine in the
    # process while it is read.
    lines = await anyio.to_thread.run_sync(_read_stream, path)

    pipeline = ProcessRuntimeEvents(uow_factory=container.unit_of_work)
    total = ProcessingResult()

    batch: list[dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            batch.append(json.loads(line))
        except json.JSONDecodeError:
            total.rejected += 1
            continue
        if len(batch) >= batch_size:
            _merge(total, await pipeline.execute(batch))
            batch = []
    if batch:
        _merge(total, await pipeline.execute(batch))
    return total


def _read_stream(path: Path) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError(f"no event stream at {path}")
    return path.read_text(encoding="utf-8").splitlines()


def _merge(into: ProcessingResult, batch: ProcessingResult) -> None:
    into.findings_created += batch.findings_created
    into.findings_updated += batch.findings_updated
    into.regressions += batch.regressions
    into.occurrences_stored += batch.occurrences_stored
    into.rejected += batch.rejected
    into.ignored += batch.ignored
    for rejection in batch.rejections:
        if len(into.rejections) < 50:
            into.rejections.append(rejection)


async def publish_rule_bundle(
    container: Container, *, canonical_bytes: bytes, signature: bytes, public_key: str
) -> RuleBundle:
    """Verify a signed catalogue and install it.

    Takes bytes rather than paths: reading files is the caller's job, and doing it here would
    block the event loop as well as making the operation trust a path it cannot verify.
    """
    return await PublishRuleBundle(container.unit_of_work(), verifier_for(public_key)).execute(
        canonical_bytes=canonical_bytes, signature=signature
    )
