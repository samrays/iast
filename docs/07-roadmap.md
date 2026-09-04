# Roadmap

Development is strictly phased. A phase is not "done" until every exit criterion is met, the test suite
is green at the coverage gate, and the documentation and CHANGELOG are updated. No phase begins before
its predecessor's gate passes.

Legend: ✅ complete · 🚧 in progress · ⬜ not started

---

## Phase 1 — Design foundation ✅

**Goal:** every subsequent decision has a written, reviewable basis.

| Deliverable | Status |
|---|---|
| Product overview, personas, capability map | ✅ `docs/00-product-overview.md` |
| Architecture: C4 context/container, hexagonal layering, sequence + class diagrams | ✅ `docs/01-architecture.md` |
| Threat model: STRIDE per boundary, agent supply chain, blocking-mode risk | ✅ `docs/02-threat-model.md` |
| Data model: ERD, tenancy strategy, ClickHouse schema, retention | ✅ `docs/03-data-model.md` |
| API specification: conventions, error envelope, full surface by phase | ✅ `docs/04-api-specification.md` |
| Runtime agent design: taint model, per-language mechanics, governor | ✅ `docs/05-runtime-agent-design.md` |
| AI architecture: agent topology, LangGraph, RAG, guardrails, evaluation | ✅ `docs/06-ai-architecture.md` |
| Monorepo scaffold, tooling, CI, local Docker stack | ✅ |
| ADRs 0001–0009 | ✅ `docs/adr/` |

**Exit criteria:** all documents written; layering rules encoded in `scripts/check_layering.py`; CI
pipeline runs lint, type-check and tests on every push.

---

## Phase 2 — Identity, tenancy, RBAC, control-plane API ✅

**Goal:** a production-grade multi-tenant control plane that everything else plugs into.

| Deliverable | Status |
|---|---|
| Domain layer: `Organization`, `User`, `Membership`, `Role`, `Permission`, `Session`, `ApiKey`, `AuditEvent` with invariants  | ✅ |
| Password security: Argon2id, policy, lockout with backoff, breach check hook  | ✅ |
| Token strategy: 15-min access JWT + rotating opaque refresh with family reuse detection  | ✅ |
| TOTP MFA: enrolment, confirmation, challenge, recovery codes  | ✅ |
| Multi-tenant RBAC: system roles, custom roles, permission resolution, privilege-escalation prevention  | ✅ |
| Tenant isolation: repository predicate + Postgres RLS + cross-tenant test suite  | ✅ |
| API keys for CI and agent registration  | ✅ |
| Application inventory: applications, environments, routes, dependencies  | ✅ |
| Agent fleet: registration, heartbeat, config distribution, status lifecycle  | ✅ |
| Hash-chained audit log with a verification endpoint  | ✅ |
| Alembic migrations, seed CLI, health/readiness/metrics endpoints  | ✅ |
| Test suite: unit + integration + security, ≥ 90% coverage  | ✅ |

**Exit criteria met:** every route authorized in the application layer; the cross-tenant suite is
green against a `NOSUPERUSER` role; refresh reuse revokes the family and writes a `security.token_reuse`
audit entry; `alembic upgrade head` and `downgrade base` both run clean; **260 tests pass at 90.66%
coverage**.

Notes from implementation worth carrying forward:

- Row-level security caught a real ordering bug (a licence insert before the tenant was bound) that
  the repository layer alone would have accepted — see ADR-0003.
- The API refuses to start in staging or production when its database role is a superuser, because
  superusers bypass RLS unconditionally.
- Middleware is pure ASGI rather than `BaseHTTPMiddleware`; the latter runs handlers inside an anyio
  task group, which costs latency and makes `sys.settrace` tooling (including coverage) blind to
  endpoint bodies.
- Coverage is configured with `concurrency = ["greenlet", "thread"]`. Without it, SQLAlchemy's async
  greenlet bridge drops the trace function at the first database call and every line after it is
  reported as untested.

---

## Phase 3 — Dashboard ✅

**Goal:** the console shell, with real data from Phase 2 and mocked data for later phases.

- Next.js 15 App Router, React 19, TypeScript strict, Tailwind, ShadCN UI.
- Design system in `packages/ui`: dark-first with a light theme, density controls, accessible (WCAG 2.2 AA).
- Auth flows: login, MFA challenge, refresh in an `HttpOnly` cookie, access token in memory only.
- Shell: global search, command palette, tenant switcher, saved views, notifications.
- Screens: application inventory, application detail, agent fleet health, members and roles, API keys,
  audit log, settings.
- Real-time: SSE client with reconnection and optimistic cache updates via TanStack Query.
- Playwright end-to-end suite; Vitest for components; visual regression on the design system.

**Exit criteria met:** the console drives the Phase 2 API end to end — sign-in with MFA challenge,
application inventory, agent fleet, members, roles, API keys and the audit log. **32 unit tests and 14
Playwright end-to-end tests pass against a live API and a real database**; `tsc --noEmit`, ESLint at
zero warnings and `next build` are all green.

Notes from implementation worth carrying forward:

- The console talks to the API directly rather than through a Next BFF, so the token model in ADR-0006
  is the one the browser actually uses: access token in memory, refresh in an `HttpOnly` `SameSite=Strict`
  cookie. An E2E test asserts both storages stay empty and the cookie carries those flags.
- Refresh is **single-flight**. Two parallel 401s would present the same refresh cookie twice, and the
  API would revoke the whole token family as reuse — the client would have caused its own sign-out.
- The console runs on **port 3100**, not 3000, which is occupied by another local application.
- Light is the default theme; dark is a first-class toggle rather than an afterthought.
- Nothing is mocked. The overview shows agent coverage and "unobserved applications" because those are
  real Phase 2 facts; there are no placeholder findings or invented metrics anywhere.

---

## Phase 4 — Java runtime agent + ingest gateway 🚧

**Goal:** first end-to-end signal — a real vulnerability in a real application appears in the console.

**Delivered**

- ✅ Bootstrap (`premain`), Byte Buddy transformer, bootstrap helper injection with a re-entrancy
  guard — the agent instruments `StringBuilder`, which it also uses itself.
- ✅ Range-based taint engine with per-rule-class sanitizer awareness (ADR-0007), propagating through
  `String`, `StringBuilder`/`StringBuffer` append, replace and reverse, `String.split`,
  `String.format`/`formatted`, Base64 and **`invokedynamic` string concatenation** — since Java 9 the
  `+` operator compiles to a `StringConcatFactory` call site, which is how most Java injection is
  written.
- ✅ HTTP entry point and sources for both servlet API generations: `getParameter`,
  `getParameterValues`, `getHeader`, `getHeaders`, `getHeaderNames`, `getQueryString`, `getPathInfo`,
  request-body streams/readers and `Cookie.getValue`. Spring's matched route pattern is read from the
  request attribute, so findings group by route rather than by path.
- ✅ Sinks for **all eleven declared rule classes**: SQL, command, path, reflected XSS, open redirect,
  header injection, SSRF, LDAP, XPath, log injection and unsafe deserialization — with per-rule
  sanitizer recognition, so a URL encoder clears the URL-context rules and leaves SQL alone.
- ✅ Async context propagation across `Executor.execute` and `submit(Runnable|Callable)`.
- ✅ Redaction in-process, bounded ring buffer, resource governor, fail-open hooks, per-request
  finding deduplication.
- ✅ Durable offline spool, retry backoff, TLS with SPKI certificate pinning.
- ✅ `apps/gateway`: agent auth, schema validation, per-tenant quota, dedup, Kafka/file/memory sinks.
- ✅ **Detection gate in CI:** a 54-case paired vulnerable/safe corpus modelled on the OWASP Benchmark
  categories — **27/27 recall, 0/27 false positives**, no duplicate findings, and every declared rule
  class proven reachable. Enforced by `CorpusIT`.
- ✅ **Overhead gate in CI:** the same workload measured with and without the agent, enforced by
  `OverheadIT`. Measured cost is ~30–60µs added per request depending on machine load.

**Still open before the exit criteria are met**

- ⬜ **The overhead criterion is not the one this measures.** The gate runs a synthetic Jetty + H2
  workload whose requests cost ~250µs, where the agent's ~30–60µs reads as 11–26%. The same absolute
  cost is under 1% of a realistic 10ms request, but "< 5% on Spring PetClinic" remains unverified
  because PetClinic has not been run.
- ✅ **The OWASP Benchmark has been run** — the real thing, all 2,740 cases, against Tomcat 9 with the
  agent attached. The corrected driver measured **53.6% recall and 0.0% false positives** across the
  in-scope categories. The full suite has not yet been rerun after the Base64, request-body,
  `String.split`, builder replace/reverse and header-name work, so no uplift is claimed yet.
- ⬜ WebGoat has not been run.
- ⬜ **Benchmark recall is below the required target.** Several measured buckets are now implemented,
  but the 2,740-case suite must be rerun and the remaining misses in
  `docs/05-runtime-agent-design.md` closed without regressing the zero-false-positive invariant.
- ⬜ gRPC transport (see ADR-0010 — the bootstrap loader confines the agent runtime to `java.base`,
  which makes gRPC a restructuring rather than an addition).
- ⬜ Sources for non-servlet stacks: Spring WebFlux, JAX-RS outside a servlet container.
- ⬜ Context propagation through `CompletableFuture` chains and Reactor.

**Exit criteria — not yet met.**

| Criterion | Result |
|---|---|
| Zero false positives on the sanitized control set | ✅ **0 of 1,572** in-scope OWASP Benchmark cases |
| Agent survives a control-plane outage | ✅ verified by `ServletIT` against a refused port |
| Benchmark produces the expected true positives | ❌ corrected baseline is **53.6% recall**; rerun pending |
| WebGoat run | ❌ not run |
| Overhead budget met on PetClinic | ❌ measured on a synthetic Jetty + H2 workload instead (+5.8%) |

Phase 4 remains in progress until the benchmark, WebGoat and PetClinic evidence above is green. The
worker now carries gateway events into durable findings, so the end-to-end product goal is reachable;
that does not waive the explicit quality gates or the repository rule that a phase closes only after
all exit criteria pass.

---

## Phase 5 — Vulnerability engine, risk scoring, attack response ⬜

**Goal:** turn raw events into managed, scored, respondable findings.

- Worker pipeline: trace assembly → dedup identity → finding upsert → risk scoring → compliance mapping.
- Detection rule catalogue as versioned, signed data bundles; per-tenant rule enablement.
- Risk scoring engine with an explainable score breakdown.
- Finding lifecycle: status transitions, comments, exceptions with expiry, bulk triage.
- Attack detection: payload classification, exploitation confirmation, campaign correlation.
- Protection policies: OFF/MONITOR/BLOCK with mandatory soak and "would have blocked" counters.
- ClickHouse ingestion, materialized rollups, trace explorer API.
- SIEM export (OCSF + CEF), SARIF export for code scanning.

### Debt carried in from Phase 4

- **Agent recall.** The corrected OWASP Benchmark baseline is 53.6%. Base64, request-body,
  `String.split`, builder replace/reverse and header-name gaps have since been implemented, but a
  full rerun is required before claiming their uplift or recategorizing the remaining misses.
- WebGoat unrun; overhead unverified on Spring PetClinic; WebFlux and Reactor sources absent.

### The recall target, revised — and why

An earlier version of this section set the gate at **≥ 80% Benchmark recall**. That number was chosen
when the remaining misses were assumed to share a dominant cause. They do not, and the assumption has
since been tested to destruction: five separate hypotheses for the largest single bucket — collections
and arrays, a broken cookie sink, `Cookie` not being instrumented under Tomcat, no request context
during `doPost`, and `URLDecoder` breaking the chain — were each investigated and each turned out to be
wrong. The corpus now reproduces the Benchmark's exact cookie shape and **detects it**.

What the 366 remaining misses actually look like, measured rather than assumed:

| bucket | cases | status |
|---|---|---|
| Cookie-sourced | ~60 | cause unknown after five eliminated theories |
| `StringBuilder.replace/reverse` | ~40 | propagators not implemented |
| `String.split` | ~25 | propagator not implemented |
| `getHeaderNames()` | ~14 | source not implemented |
| **no identified cause** | **~227** | not yet characterised |

Closing every identified bucket takes recall from 52% to roughly 61%. Reaching 80% requires finding
causes for ~227 cases that currently have none — which is not a commitment that can honestly be made
from here. Keeping the number would not make the work happen faster; it would only make the gate
something to miss quietly or quietly drop.

**Revised exit criteria:**

1. **Zero false positives on the OWASP Benchmark — a hard invariant, not a target.** Currently 0 of
   1,572 in-scope cases. This is the property that decides whether a customer leaves the product
   switched on, and no recall improvement may be traded against it.
2. **Recall ≥ 65%**, reachable by closing the four identified buckets above.
3. **The ~227 uncharacterised misses are categorised**, with a named cause for each group — the
   deliverable is the analysis, not a number. A target set on an uncharacterised tail is how 80% got
   written down in the first place.
4. Dedup stable across restarts and refactors; 1M-event replay produces a deterministic finding set;
   blocking verified to trigger only on confirmed exploitation; overhead budget verified on Spring
   PetClinic.

The original instinct — that "improve detection" without a number never happens — was right. The error
was picking the number before knowing what stood behind it.

---

## Phase 6 — AI engine + remaining agents ⬜

**Goal:** explanation and remediation, plus .NET, Node.js and Python agents.

- LangGraph graphs for RCA, remediation, prioritization, correlation, executive summary.
- RAG corpora and tenant-scoped memory; hybrid retrieval with strict pre-filtering.
- Guardrail node, human approval gates, SSE streaming, cost governance.
- Evaluation harness and nightly quality gates.
- .NET (CLR profiler), Node.js (module hooking), Python (`sys.monitoring`) agents to Java parity for
  the top-ten rule set.
- IDE plugins (VS Code, IntelliJ) and CI/CD integrations (GitHub Actions, GitLab, Jenkins) surfacing
  findings at the PR.

**Exit criteria:** evaluation suite passes its gates; zero uncited factual claims; prompt-injection
corpus produces zero instruction-following; each new agent passes its language's vulnerable-app corpus.

---

## Phase 7 — Reporting, compliance, Go agent ⬜

- Report engine: scheduled and on-demand, PDF/CSV/JSON/SARIF, attestation-grade templates.
- Compliance dashboards for PCI DSS 4.0, SOC 2, ISO 27001, NIST 800-53, OWASP ASVS.
- Executive dashboard with trend, MTTR, coverage and portfolio risk.
- Notification engine: Slack, Teams, email, PagerDuty, webhooks with HMAC signing.
- Go agent via compile-time instrumentation.
- Plugin marketplace and public SDKs (TypeScript, Python).

---

## Phase 8 — Cloud deployment and hardening ⬜

- Helm chart with production defaults, HPA/KEDA autoscaling, PodSecurity restricted, network policies.
- Terraform modules for AWS, Azure and GCP.
- Blue/green and canary deployment; automated rollback on SLO breach.
- Disaster recovery: backup, restore drills, RPO 15 min / RTO 1 h.
- SLSA level 3 build provenance, Cosign signing, CycloneDX SBOM per artifact.
- Load testing to target throughput; chaos experiments.
- SOC 2 evidence automation; penetration test remediation.

---

## Standing engineering commitments

| Commitment | Mechanism |
|---|---|
| Test coverage ≥ 90% for `apps/api` | `pytest --cov-fail-under=90` in CI |
| Type safety | `mypy --strict`, `tsc --noEmit` |
| Lint and format | Ruff, Black, ESLint, Prettier — enforced, not advisory |
| Layering | `scripts/check_layering.py` fails the build on inward-pointing violations |
| Every decision recorded | ADR required for any change to the architecture table in `docs/01-architecture.md` |
| Every change logged | CHANGELOG entry required by CI on any `apps/` or `agents/` diff |
| Dependency hygiene | Dependabot + `pip-audit` + `npm audit` gates |
| Secrets | `gitleaks` pre-commit and CI scan |
| Dogfooding | The platform runs its own Python agent against `apps/api` from Phase 6 onward |
