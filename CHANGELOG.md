# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed — repository review

- Local agent ingest now defaults to the worker's durable file stream instead of volatile memory;
  the vulnerable-app demo fails unless its finding is persisted and readable through the dashboard
  API.
- Java agents mark authentication failures as retryable so an enabled offline spool can replay them
  after credential renewal, while still dropping permanently malformed or oversized payloads.
- Gateway sink configuration now fails closed instead of silently falling back to volatile memory
  for an unknown or malformed destination, and file URIs preserve absolute paths and escapes.
- Kafka producers are created inside the running event loop, restoring compatibility with current
  `aiokafka`; the missing `StreamOrigin` type import no longer breaks Ruff and mypy.
- Patched four high-severity npm dependency paths without a framework-major upgrade; CI now permits
  only the exact remaining PostCSS advisories that require the deferred Next.js 16 migration.

### Changed — repository review

- Local setup now installs and exposes the API, ingest gateway and findings worker together, with
  documented commands for the complete agent-to-dashboard pipeline.
- CI now tests and type-checks the worker, treats lockfile-only changes as dashboard changes, audits
  JavaScript plus all Python runtime dependencies, applies read-only workflow permissions, and pins
  current Node 24 GitHub Actions releases by commit SHA.
- Dashboard formatting ignores generated output and accepts the checkout's native line endings;
  Next.js build tracing is anchored to this repository instead of a parent lockfile.

### Added — Phase 4 (in progress): Java runtime agent

- **Agent wire contracts** in `packages/proto/agent/v1/` — registration, heartbeat, config and
  the runtime event envelope, additive-only within v1 (ADR-0005).
- **`agents/runtime/java-agent`**: a working JVM agent that loads via `-javaagent`, tracks
  range-based taint from source to sink, and reports findings with evidence.
  - Range algebra with per-rule-class sanitizer awareness (ADR-0007): concat, substring,
    insert, case folding and trimming, with a range cap that collapses to a covering range
    rather than growing without bound.
  - Byte Buddy instrumentation of `java.lang.String`, `StringBuilder`/`StringBuffer`,
    `java.sql.Statement` and `Runtime.exec`, with a fail-open wrapper on every hook.
  - Bounded ring buffer that drops rather than blocks, and a resource governor that degrades
    the agent through sampling → config-only → heartbeat → self-uninstall.
  - In-process redaction before anything crosses the network (threat T-04).
  - NDJSON transport over HTTP or to a file, drained by one low-priority daemon thread.
- **64 tests**: 61 unit (including randomised range round-trips) and 3 integration tests that
  launch a real JVM with the packaged agent against a real H2 database.

### In-process result (agent alone)

A genuine SQL injection through a `StringBuilder` and a plain `Statement` is detected and
reported as `sql-injection / CRITICAL / EXPLOITED`, with the tainted range pinpointing
`' OR 1=1--` at offset 37 of the executed SQL. The same query bound through a
`PreparedStatement` produces **nothing**. Zero hook failures.

### Notable implementation decisions

- **Bootstrap injection is surgical.** Advice inlined into `java.lang.StringBuilder` runs as
  bootstrap-loaded code and cannot see the system class path, so the runtime classes are
  copied into a generated bootstrap jar — but *not* Byte Buddy, and *not* `AgentConfig`.
  Copying the whole agent jar puts Byte Buddy under two loaders and the JVM refuses to link;
  copying `AgentConfig` splits it from its own `Builder`, because the verifier resolves it
  before injection can run.
- **`AegisAgent` reaches the runtime reflectively.** A direct call would make the verifier
  define a second copy of `AgentRuntime` on the system loader; the advice would then set its
  static instance on one copy while the agent read the other, and every hook would silently
  find `null` and report nothing.
- **Hooks carry a re-entrancy guard.** The agent's own code uses `StringBuilder` — the class
  it instruments — so without the guard a hook re-enters itself into `StackOverflowError`, or
  into `ClassCircularityError` while a runtime class is still loading. Runtime classes are
  also warmed before instrumentation goes live.
- JDBC driver packages are excluded from the stack fingerprint, so a driver upgrade does not
  resurrect closed findings.

### Added — `apps/gateway`, the ingest hot path

- Stateless FastAPI service: agent authentication, wire-schema validation, per-tenant quota,
  deduplication and fan-out to the durable stream. **No database writes**, which is what lets
  it scale independently of the control plane.
- **Agent authentication is a signature check, not a lookup.** Verifying the `aegis:agent`
  audience JWT locally is what keeps the control plane's PostgreSQL off the ingest path.
- **Hostile-input parsing.** Every field is bounded and unknown event types are rejected
  rather than ignored — a taint trace literally contains the payload an attacker sent.
- **The tenant is stamped from the verified token**, never from the agent's payload, so an
  agent cannot write into another organization's stream by lying about who it is.
- **Security signal is never shed.** Under quota pressure the gateway drops route, dependency
  and coverage telemetry — which the next heartbeat regenerates — and returns `429` for a
  finding so the agent retries instead of losing it.
- **Idempotent ingest.** The agent transport is at-least-once and replays its spool after a
  reconnect, so a bounded LRU of event ids stops every network blip inflating a tenant's
  findings. Duplicates are acknowledged so the spool still advances.
- Credit-based backpressure via `X-Aegis-Credit`, retryable `503` on sink failure, pluggable
  Kafka / file / memory sinks, RFC 9457 errors, Prometheus metrics.
- **72 tests at 92.9% coverage**, including one that replays the exact NDJSON the Java agent
  emitted — so agent/gateway wire drift fails the build.

### End-to-end result (Phase 4)

A real SQL injection in a JVM, through live bytecode instrumentation, over HTTP, into the
authenticated gateway and out to the durable stream:

```
organization_id : org-tenant-1   (from the verified token, not the payload)
rule            : sql-injection | SEVERITY_CRITICAL | CONFIDENCE_EXPLOITED
sink            : java.sql.Statement#execute(String)
argument        : SELECT name FROM users WHERE name = '' OR 1=1--'
tainted range   : (37, 10, 'name')
```

### Fixed during implementation

- `max_batch_events` was never enforced: the check read `result.processed`, which does not
  include accepted events until after the publish, so one request could carry unbounded
  events.
- The agent's HTTP transport used `java.net.http.HttpClient`, which lives in its own module
  and is invisible to the bootstrap class loader. It reported the agent as installed and then
  died with `NoClassDefFoundError`. Rewritten on `HttpURLConnection` — bootstrap-published
  code may depend on `java.base` and nothing else.
- A failed agent install logged the reflection wrapper instead of the cause, making a
  bootstrap failure undiagnosable.

### Added — the agent finds requests on its own

- **HTTP entry point and sources.** `HttpServlet.service` opens and closes the request context;
  `getParameter`, `getParameterValues`, `getHeader`, `getQueryString`, `getPathInfo`,
  `getRequestURI` and `Cookie.getValue` are sources. Both the `jakarta` and `javax` API
  generations. Nothing names a servlet type at compile time — the instrumented classes live on
  the application's loader while the runtime they call lives on bootstrap, so matching is by name
  and reading is by reflection, cached per concrete request class in a `ClassValue`.
- **`invokedynamic` string concatenation.** Since Java 9, `a + b` compiles to a
  `StringConcatFactory` call site, not to `StringBuilder`. The agent rewrites the call site when
  it links, so the most common shape of SQL injection in Java is tracked. Offsets come from the
  concat recipe, not from searching the result — searching would attribute a repeated value's
  taint to whichever copy came first.
- **Async context propagation** across `Executor.execute` and `submit(Runnable|Callable)`.
- **`java.io.File` as the path-traversal sink**, at construction rather than at open: the stack
  there names the line a developer has to change.
- **Durable offline spool**, bounded and segmented, so a control-plane outage on our side does not
  become a blind spot on the customer's. Retry backs off on failure and snaps back on recovery.
- **TLS certificate pinning** over the SHA-256 SubjectPublicKeyInfo, matching anywhere in the
  chain so a leaf can rotate without a fleet-wide agent update. Pinning adds to path validation
  rather than replacing it, and a pinned agent refuses to send over plaintext rather than
  downgrade.
- **Per-request finding deduplication** on rule plus stack fingerprint. One vulnerable line hit in
  a loop is one defect, not a thousand.
- **Route discovery**, announced once per route rather than once per request.

### Added — two gates in CI

- **Detection.** A corpus of paired vulnerable and safe cases modelled on the OWASP Benchmark
  categories, driven over real HTTP through a real servlet container: **6/6 defects found across
  SQL injection, command injection and path traversal, 0/6 false positives**. Writing it
  immediately exposed three misses, all the `invokedynamic` gap above — which is the argument for
  having it.
- **Overhead.** The same workload with and without `-javaagent`, failing the build past a ceiling.

### Fixed during implementation

- `StringBuilder.append`'s hook called `toString()` to learn the builder's length, allocating a
  String and copying the buffer on **every append in the process**, making long-string assembly
  quadratic.
- Every hook did two `ThreadLocal` lookups, one for the re-entrancy guard and one for the request
  context, on a path that runs for every concatenation in the process. Collapsed into one.
- The propagation hooks now return on an empty taint table before doing two identity lookups that
  were always going to miss.

  Together those took the agent's added cost from ~64µs to ~28µs per request.

- Skipping concatenation call sites in `dev.aegis.` classes — added so the agent would not
  instrument itself — silently excluded the test fixtures, which shared that namespace, and three
  defects went undetected. Caught by the corpus. The fixtures now live in `com.example.*`, which
  is what a customer's application looks like anyway.

### Known and measured, not claimed away

- **Overhead is ~30–60µs added per request.** On the synthetic workload, whose requests cost
  ~250µs, that reads as 11–26%. The same absolute cost is under 1% of a realistic 10ms request.
  The roadmap's "< 5% on Spring PetClinic" is **not verified** — PetClinic has not been run.
- **The corpus is ours, not OWASP's.** WebGoat and the real OWASP Benchmark have not been run;
  they are the actual exit criterion.
- **Request bodies are not tracked.** Reading one is reported as a coverage gap, because an
  application with poor coverage and no findings must read as unknown, never as secure (ADR-0007).

### Still open in Phase 4

- gRPC transport. See **ADR-0010**: bootstrap-published code may depend on `java.base` and nothing
  else, which makes gRPC a restructuring of the reporting path rather than an addition to it.
- Spring WebFlux and non-servlet JAX-RS sources; `CompletableFuture` and Reactor propagation.
- WebGoat and OWASP Benchmark corpora; a PetClinic overhead run.

## [0.3.0] — 2026-07-28

### Added — Phase 3: the console

- **`packages/ui`**: the design system as tokens plus a Tailwind preset. Severity (five steps) and
  fleet status are first-class token families, so "critical" cannot be amber on one screen and red on
  another. Both themes are authored; **light is the default**, dark is a first-class toggle.
- **`apps/dashboard`**: Next.js 15 / React 19 / TypeScript strict console covering every Phase 2
  endpoint — sign-in with MFA challenge and recovery codes, application inventory and detail,
  environment protection mode, agent fleet with overhead budget, members, roles with a permission
  matrix, API keys, and the audit log with chain verification.
- **Typed API client** for all 35 routes, with RFC 9457 problem documents surfaced as field-level form
  errors.
- **Session handling that matches ADR-0006 exactly**: the access token lives in memory only — never
  `localStorage`, never `sessionStorage` — and the refresh token is an `HttpOnly` `SameSite=Strict`
  cookie the client cannot read. A hard reload recovers the session through that cookie alone.
- **Single-flight refresh.** Concurrent 401s share one refresh promise, because two parallel refreshes
  would replay the same cookie and the API would revoke the whole token family as reuse.
- Console shell: command palette (⌘K) with server-side application search, fleet-derived notifications,
  tenant-aware navigation that hides what the principal cannot reach, and a responsive mobile drawer.
- **Tests**: 32 unit tests (Vitest) and 14 end-to-end tests (Playwright) that run against a live API
  and a real database — no mocked backend, because the contract details most likely to break are
  exactly what a mock would paper over.

### Changed

- The console listens on **port 3100**; port 3000 is occupied by another local application. The API's
  `AEGIS_CORS_ORIGINS` default moved with it.

### Fixed during implementation

- `Button` passed two children to Radix `Slot` whenever `asChild` was used, throwing
  "Slot failed to slot onto its children" and crashing every page with a `<Button asChild><Link/></Button>`.
- A lock icon carrying `aria-label` sat *inside* an `<h3>`, so the accessible name of every system-role
  heading was "Owner System role" rather than "Owner" — wrong for screen readers, not only for tests.
- An unquoted `pulse-ring:` key in the Tailwind preset was a JavaScript syntax error that surfaced as
  an unrelated CSS build failure.

## [0.2.0] — 2026-07-27

### Added — Phase 2: Identity, tenancy, RBAC, control-plane API

- **Domain layer** (`apps/api/src/aegis_api/domain/`) with zero framework dependencies: `Organization`,
  `User`, `Membership`, `Role`, `Session`, `ApiKey`, `AuditEvent`, `Application`,
  `ApplicationEnvironment`, `Agent`, plus value objects (`EmailAddress`, `Slug`, `PasswordHash`,
  `TokenHash`) and the `Permission` catalogue.
- **Password security**: Argon2id hashing (64 MiB / t=3 / p=4), configurable complexity policy,
  failed-attempt lockout with exponential backoff, constant-time comparison for unknown users.
- **Token strategy** (ADR-0006): 15-minute access JWTs with audience separation, opaque 256-bit refresh
  tokens rotated on every use, token families, and reuse detection that revokes the whole family and
  writes a `security.token_reuse` audit event. Includes a configurable rotation grace window for
  concurrent-tab races.
- **TOTP multi-factor authentication**: enrolment with provisioning URI, confirmation, challenge tokens,
  single-use recovery codes, and encrypted secret storage.
- **Multi-tenant RBAC**: 24 permissions across 8 resource families, five seeded system roles (Owner,
  Admin, Security Analyst, Developer, Viewer), custom organization roles, and privilege-escalation
  prevention (a member can never grant a permission they do not themselves hold).
- **Tenant isolation** (ADR-0003): `TenantScopedRepository` base class that makes an unscoped query
  impossible to express, PostgreSQL row-level security on every tenant table as defence in depth, and
  `404`-not-`403` responses for cross-tenant access.
- **API keys** for CI and agent registration: `ak_<prefix>.<secret>` format, Argon2 secret hashing,
  constant-time prefix lookup, per-key permission subsets and expiry.
- **Application inventory**: applications, environments, criticality, tags, protection mode.
- **Agent fleet**: registration with fingerprint deduplication, heartbeat with health and overhead
  telemetry, status lifecycle (`REGISTERED → ONLINE → DEGRADED → OFFLINE`), configuration versioning.
- **Hash-chained audit log**: append-only, tamper-evident (each entry hashes its predecessor), with a
  verification endpoint and no `UPDATE`/`DELETE` grant for the application role.
- **HTTP layer**: RFC 9457 `application/problem+json` errors, cursor pagination, request-id
  propagation, security headers, per-principal rate limiting, `/healthz`, `/readyz`, `/metrics`.
- **Operations** (`aegis_api/operations.py` + a thin `cli.py`): organization seeding, audit-chain
  verification, offline-agent sweep, expired-session purge and route listing — each an async function
  that is unit-testable and reusable by scheduled jobs.
- **Least-privilege database role**: `scripts/postgres/app-role.sql`. The API checks `pg_roles.rolsuper`
  at startup, warns in development and **refuses to start** in staging or production, because
  PostgreSQL superusers bypass row-level security unconditionally.
- **Alembic migrations** with a matching `alembic check` (no model/migration drift), structured JSON
  logging with credential redaction, and Prometheus instrumentation.
- **Tests**: 260 tests across unit, integration and security suites at 90.68% coverage, run against a
  `NOSUPERUSER` PostgreSQL role so the isolation assertions mean something.

### Notable implementation decisions

- **Middleware is pure ASGI**, not `BaseHTTPMiddleware`. The latter wraps every request in an anyio
  task group and a pair of memory streams, which costs latency and makes `sys.settrace` tooling blind
  to endpoint bodies.
- **Coverage runs with `concurrency = ["greenlet", "thread"]`.** Without it, SQLAlchemy's async
  greenlet bridge drops the trace function at the first database call and everything after it is
  reported as untested — an apparent 79% that was really 91%.
- **Audit append uses a per-tenant advisory lock**, not `SELECT ... FOR UPDATE`, because the
  application role deliberately lacks `UPDATE` on `audit_events`.
- **`eager_defaults` on the ORM base**, so server-generated timestamps come back via `RETURNING`
  instead of triggering lazy IO that raises `MissingGreenlet` under asyncio.

### Fixed during implementation

- Row-level security rejected a licence `INSERT` issued before the tenant was bound during
  registration — a real ordering bug the repository layer alone would have accepted.
- MFA recovery codes were hashed with their display separator but verified without it, so no recovery
  code would ever have worked. Both paths now go through `normalize_recovery_code`.
- `ApiKeyPrefix.LENGTH` was annotated `Final`, which dataclasses treat as a field, making the constant
  a required constructor argument.

## [0.1.0] — 2026-07-27

### Added — Phase 1: Design foundation

- Product overview, personas and capability map (`docs/00-product-overview.md`).
- Architecture: C4 context and container views, hexagonal layering, bounded contexts, class model and
  four key sequence diagrams (`docs/01-architecture.md`).
- Threat model: STRIDE per trust boundary, agent supply-chain controls, blocking-mode risk, and eight
  derived testable security requirements (`docs/02-threat-model.md`).
- Data model: ERDs for Phase 2 and Phase 5+, finding identity algorithm, ClickHouse event schema,
  indexing strategy, row-level security and retention policy (`docs/03-data-model.md`).
- API specification: conventions, error envelope, pagination, authentication principals, and the full
  route surface by phase (`docs/04-api-specification.md`).
- Runtime agent design: range-based taint model, per-language instrumentation mechanics, resource
  governor, transport and offline behaviour (`docs/05-runtime-agent-design.md`).
- AI architecture: ten-agent topology, LangGraph orchestration with human approval gates, RAG design,
  guardrails and evaluation gates (`docs/06-ai-architecture.md`).
- Roadmap with per-phase exit criteria (`docs/07-roadmap.md`).
- ADRs 0001–0009 covering the monorepo, hexagonal architecture, multi-tenancy, polyglot persistence,
  agent transport, token strategy, taint model, AI orchestration and finding identity.
- Monorepo scaffold, local Docker stack, GitHub Actions CI, and the layering-enforcement script.
