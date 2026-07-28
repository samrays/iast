# Contributing

## Ground rules

1. **No placeholders.** If a function is in the codebase, it is implemented. No `TODO`, no `pass  #
   implement later`, no stubbed return values. If something cannot be finished, it does not merge.
2. **Phases are gates.** Work belongs to the current phase in [docs/07-roadmap.md](docs/07-roadmap.md).
   A phase closes only when every exit criterion is met.
3. **Decisions are written down.** Any change to the architecture table in `docs/01-architecture.md`
   requires an ADR in `docs/adr/`.
4. **Every user-visible change gets a CHANGELOG entry.** CI fails without one on `apps/` or `agents/`
   diffs.

## Layering

Dependencies point inward only:

```
interfaces  →  infrastructure  →  application  →  domain
```

| Layer | May import | Must not import |
|---|---|---|
| `domain` | stdlib, `packages/shared` | anything third-party |
| `application` | `domain` | `sqlalchemy`, `fastapi`, `redis`, `kafka`, `httpx` |
| `infrastructure` | `domain`, `application` | `interfaces` |
| `interfaces` | everything inward | — |

Enforced by `python scripts/check_layering.py`, which runs in CI and as a pre-commit hook.

**Authorization belongs in the application layer.** A router-level dependency is a convenience for
returning a fast 403; it is never the only check. Every use case authorizes independently.

## Local setup

```bash
python -m venv apps/api/.venv && . apps/api/.venv/Scripts/activate && pip install -e "apps/api[dev]"
```

```bash
docker compose -f docker/docker-compose.yml up -d postgres redis
```

```bash
cd apps/api && cp .env.example .env && alembic upgrade head && python -m aegis_api.cli seed
```

## Quality gates

| Gate | Command |
|---|---|
| Format | `black apps/api && ruff format apps/api` |
| Lint | `ruff check apps/api` |
| Types | `mypy apps/api/src` |
| Layering | `python scripts/check_layering.py` |
| Tests + coverage | `pytest` (fails under 90%) |
| Secrets | `gitleaks detect --no-banner` |

Run everything with `make check`.

## Testing conventions

| Suite | Location | Requires |
|---|---|---|
| Domain unit | `apps/api/tests/unit/` | nothing — no I/O, runs in under a second |
| Application | `apps/api/tests/application/` | in-memory fakes for ports |
| Integration | `apps/api/tests/integration/` | PostgreSQL |
| Security | `apps/api/tests/security/` | PostgreSQL — cross-tenant isolation, escalation, token reuse |

Every new route requires a corresponding entry in the cross-tenant isolation suite. The suite
enumerates registered routes and fails if one is unclassified.

## Commits and pull requests

Conventional Commits:

```
feat(auth): add TOTP recovery codes
fix(rbac): prevent privilege escalation via role update
docs(adr): record finding identity decision
```

A pull request must state what changed, why, which phase it belongs to, and how it was verified. It
must pass every gate above. Security-relevant changes require a second reviewer.
