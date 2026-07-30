"""Operator CLI.

Thin by design: argument parsing and terminal output only. Every procedure lives in
``operations.py`` where it can be tested without a subprocess.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TypeVar

import typer

from . import operations
from .config import get_settings
from .container import Container, build_container
from .domain.entities import LicenseTier
from .domain.entities.rules import RuleBundle
from .domain.errors import DomainError
from .infrastructure.security.bundle_signing import generate_keypair, sign_with

app = typer.Typer(help="Aegis IAST control-plane operations.", no_args_is_help=True)

T = TypeVar("T")


def _run(procedure: Callable[[Container], Awaitable[T]]) -> T:
    """Build a container, run one procedure, and always dispose the engine."""

    async def _main() -> T:
        container = build_container(get_settings())
        try:
            return await procedure(container)
        finally:
            await container.aclose()

    try:
        return asyncio.run(_main())
    except DomainError as exc:
        typer.secho(f"Failed: {exc.message}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc


@app.command()
def seed(
    organization: str = typer.Option("Aegis Demo", help="Organization display name."),
    # `.example` rather than `.local`: an IANA-reserved TLD that can never collide with a real
    # domain, and — the part that actually matters — one the login endpoint's EmailStr accepts.
    # The previous default seeded an owner who could not sign in, which is the first thing a new
    # user hits and the last thing they should have to debug.
    email: str = typer.Option("owner@aegis.example", help="Owner email address."),
    password: str = typer.Option("", help="Owner password. Generated when omitted."),
    full_name: str = typer.Option("Platform Owner", help="Owner display name."),
    tier: str = typer.Option("ENTERPRISE", help="Licence tier for the seeded organization."),
) -> None:
    """Create the first organization and Owner."""
    result = _run(
        lambda container: operations.seed_organization(
            container,
            organization=organization,
            email=email,
            full_name=full_name,
            password=password,
            tier=LicenseTier(tier.upper()),
        )
    )
    typer.secho("Organization created.", fg=typer.colors.GREEN)
    typer.echo(f"  organization : {result.organization_name} ({result.organization_slug})")
    typer.echo(f"  owner        : {result.email}")
    if result.password_was_generated:
        typer.secho(f"  password     : {result.password}", fg=typer.colors.YELLOW)
        typer.echo("  (shown once - store it in a password manager now)")


@app.command("verify-audit")
def verify_audit(organization_slug: str = typer.Argument(..., help="Organization slug.")) -> None:
    """Verify a tenant's audit hash chain end to end."""
    status = _run(
        lambda container: operations.verify_audit_chain(
            container, organization_slug=organization_slug
        )
    )
    if status.intact:
        typer.secho(
            f"Chain intact - {status.entries_checked} entries verified.", fg=typer.colors.GREEN
        )
        return
    typer.secho(
        f"CHAIN BROKEN at sequence {status.first_broken_sequence} "
        f"after {status.entries_checked} entries.",
        fg=typer.colors.RED,
    )
    raise typer.Exit(code=2)


@app.command("sweep-agents")
def sweep_agents(organization_slug: str = typer.Argument(..., help="Organization slug.")) -> None:
    """Mark agents offline when their heartbeats stop."""
    demoted = _run(
        lambda container: operations.sweep_offline_agents(
            container, organization_slug=organization_slug
        )
    )
    typer.secho(f"{demoted} agent(s) marked offline.", fg=typer.colors.GREEN)


@app.command("purge-sessions")
def purge_sessions() -> None:
    """Delete sessions that expired more than a day ago."""
    purged = _run(operations.purge_expired_sessions)
    typer.secho(f"{purged} expired session(s) purged.", fg=typer.colors.GREEN)


@app.command("process-events")
def process_events(
    source: str = typer.Argument(..., help="NDJSON event stream, e.g. file:events.ndjson."),
    batch_size: int = typer.Option(500, help="Events per transaction."),
) -> None:
    """Fold a runtime event stream into findings."""
    result = _run(
        lambda container: operations.process_runtime_events(
            container, source=source, batch_size=batch_size
        )
    )
    typer.secho(
        f"{result.findings_created} finding(s) created, "
        f"{result.findings_updated} updated, "
        f"{result.regressions} regression(s), "
        f"{result.occurrences_stored} evidence sample(s).",
        fg=typer.colors.GREEN,
    )
    if result.ignored:
        typer.echo(f"{result.ignored} event(s) were not taint hits.")
    if result.rejected:
        # Loud, but not fatal. A malformed event is a bug in an agent or a corrupt stream,
        # and neither is a reason to leave the rest of the batch unprocessed.
        typer.secho(f"{result.rejected} event(s) rejected:", fg=typer.colors.YELLOW)
        for rejection in result.rejections[:10]:
            typer.echo(f"  - {rejection}")


@app.command("rules-keygen")
def rules_keygen() -> None:
    """Generate a rule-signing keypair.

    The private half is printed once and never stored by this service. It belongs wherever
    bundles are published from, which should not be a machine that also serves traffic.
    """
    private, public = generate_keypair()
    typer.secho("Rule signing keypair generated.", fg=typer.colors.GREEN)
    typer.secho(f"  private : {private}", fg=typer.colors.YELLOW)
    typer.echo(f"  public  : {public}")
    typer.echo(
        "  (set AEGIS_RULE_SIGNING_PUBLIC_KEY to the public half; keep the private half offline)"
    )


@app.command("rules-sign")
def rules_sign(
    bundle: Path = typer.Argument(..., help="Canonical bundle JSON to sign."),
    private_key: str = typer.Option(..., help="Base64 Ed25519 private key."),
    out: Path = typer.Option(None, help="Signature file. Defaults to <bundle>.sig."),
) -> None:
    """Sign a bundle. Run this where the signing key lives, not on a server."""
    payload = bundle.read_bytes()
    # Refuse to sign anything that is not already canonical: a signature over a
    # pretty-printed document would fail verification later and be maddening to diagnose.
    parsed = RuleBundle.from_canonical_bytes(payload)
    if parsed.canonical_bytes() != payload:
        typer.secho("Refusing to sign: the bundle is not in canonical form.", fg=typer.colors.RED)
        raise typer.Exit(code=2)

    target = out or bundle.with_suffix(bundle.suffix + ".sig")
    target.write_bytes(sign_with(private_key, payload))
    typer.secho(f"Signed version {parsed.version} -> {target}", fg=typer.colors.GREEN)


@app.command("rules-publish")
def rules_publish(
    bundle: Path = typer.Argument(..., help="Canonical bundle JSON."),
    signature: Path = typer.Argument(..., help="Detached signature."),
) -> None:
    """Verify and install a signed catalogue."""
    settings = get_settings()
    payload = bundle.read_bytes()
    signature_bytes = signature.read_bytes()
    try:
        installed = _run(
            lambda container: operations.publish_rule_bundle(
                container,
                canonical_bytes=payload,
                signature=signature_bytes,
                public_key=settings.rule_signing_public_key,
            )
        )
    except Exception as rejected:
        # Loud and specific. A rejected bundle is either tampering or an operator mistake, and
        # both need the reason rather than a stack trace.
        typer.secho(f"Bundle rejected: {rejected}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from rejected

    typer.secho(
        f"Installed rule bundle version {installed.version} " f"({len(installed.rules)} rules).",
        fg=typer.colors.GREEN,
    )


@app.command()
def routes() -> None:
    """Print every registered route - useful when auditing authorization coverage."""
    from .main import create_app

    for methods, path in operations.describe_routes(create_app()):
        typer.echo(f"{methods:<20} {path}")


def main() -> None:  # pragma: no cover - console-script entry point
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
