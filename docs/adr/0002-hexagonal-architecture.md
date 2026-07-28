# ADR-0002: Hexagonal architecture with enforced layer boundaries

- **Status:** Accepted
- **Date:** 2026-07-27
- **Deciders:** Platform architecture

## Context

The control plane will accumulate a large amount of security-critical business logic: permission
resolution, tenant isolation, finding lifecycle transitions, licence entitlement. That logic must be
testable without a database, must survive infrastructure changes (PostgreSQL today, a sharded variant
later; Celery today, something else later), and must be readable by an auditor who does not know
FastAPI.

The failure mode we are avoiding is the one every FastAPI/Django codebase drifts into: authorization
implemented as a decorator on a route, business rules embedded in ORM model methods, and a test suite
that cannot run without spinning up the world.

## Decision

Four layers per service, with dependencies pointing strictly inward:

```
interfaces/      →  infrastructure/  →  application/  →  domain/
(HTTP, gRPC, CLI)   (SQLAlchemy,        (use cases)      (entities, VOs,
                     Redis, Kafka)                        ports, invariants)
```

- `domain` imports only the standard library and `packages/shared` contracts. No SQLAlchemy, no
  Pydantic, no FastAPI. Ports are declared as `typing.Protocol`.
- `application` contains one class per business operation (`AuthenticateUser`, `CreateApplication`,
  `TransitionFindingStatus`), depends on ports, and is where **every** authorization decision is made.
- `infrastructure` implements ports: SQLAlchemy repositories, the Argon2 hasher, the JWT codec, the
  Kafka producer.
- `interfaces` translates transport to application DTOs and back, and maps domain errors to HTTP
  status codes exactly once.

Composition happens in a single container module wired at startup.

## Alternatives considered

| Option | Why not |
|---|---|
| Standard FastAPI layout (routers + services + models) | Authorization ends up in decorators; the domain becomes the ORM; unit tests require a database |
| Full CQRS with event sourcing | Correct for the *findings* stream, over-engineered for identity and inventory. We use an event log for finding transitions and audit without adopting event sourcing wholesale |
| Clean architecture without enforcement | Layer discipline decays within months unless CI fails on violations |

## Consequences

### Positive
- Domain logic is unit-testable with no I/O; the Phase 2 domain suite runs in under a second.
- Authorization lives in one layer and is therefore auditable and impossible to bypass by adding a
  new router.
- Swapping an adapter (e.g. ClickHouse for a different columnar store) touches one package.

### Negative
- More files and more indirection than a two-layer app. This is a real cost and is only justified
  because the codebase is large and security-critical.
- DTO mapping between layers is boilerplate; mitigated with dataclass-to-Pydantic helpers, not by
  leaking domain objects into the HTTP layer.

### Neutral
- The dashboard (Next.js) does not follow this structure; it has no business logic to protect.

## Compliance

- `scripts/check_layering.py` walks the AST of every module and fails the build on a forbidden import.
  It runs in CI and as a pre-commit hook.
- Code review checklist: "Is this authorization check in the application layer?"
- A test asserts that importing `aegis_api.domain` does not transitively import `sqlalchemy` or
  `fastapi`.
