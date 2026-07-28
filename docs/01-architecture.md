# Architecture

## 1. Architectural drivers

| Driver | Consequence |
|---|---|
| Agents run inside customer production processes | Agent must be fail-open, bounded-resource, and independently versioned from the control plane |
| Runtime event volume is 3–4 orders of magnitude above finding volume | Split hot path (append-only, columnar) from control plane (relational, transactional) |
| Multi-tenant SaaS *and* on-prem/air-gap | No cloud-managed-service lock-in; every dependency has a self-hostable form |
| Findings are evidence for compliance | Immutable audit trail, deterministic dedup identity, no destructive updates |
| Detection rules evolve weekly | Rules are data, shipped independently of agent binaries, versioned per tenant |
| AI is assistive, not authoritative | AI output is a separate, attributed, human-approvable artifact — never mutates a finding silently |

## 2. System context (C4 level 1)

```mermaid
graph TB
    subgraph Customer["Customer environment"]
        APP["Instrumented application<br/>(JVM / CLR / Node / Python / Go)"]
        AGENT["Aegis runtime agent"]
        APP --- AGENT
    end

    subgraph Platform["Aegis IAST platform"]
        GW["Ingest gateway"]
        API["Control-plane API"]
        WORK["Analysis workers"]
        AI["AI orchestrator"]
        DASH["Web console"]
    end

    subgraph External["External systems"]
        SIEM["SIEM<br/>Splunk / Sentinel / QRadar"]
        CICD["CI/CD<br/>GitHub / GitLab / Jenkins"]
        IDE["IDE plugins"]
        CHAT["Slack / Teams / PagerDuty"]
        LLM["LLM providers<br/>Anthropic / OpenAI / self-hosted vLLM"]
    end

    DEV(["Developer"]) --> DASH
    SOC(["SOC analyst"]) --> DASH
    EXEC(["Executive"]) --> DASH

    AGENT -->|"mTLS gRPC<br/>runtime events"| GW
    AGENT -->|"config poll / heartbeat"| GW
    GW --> WORK
    WORK --> API
    AI --> LLM
    API --> AI
    DASH --> API
    API --> SIEM
    API --> CHAT
    CICD --> API
    IDE --> API
```

## 3. Container view (C4 level 2)

```mermaid
graph TB
    subgraph Edge
        LB["Ingress / TLS termination"]
    end

    subgraph Services
        GW["gateway<br/><i>Python / FastAPI + grpclib</i><br/>agent auth, schema validation,<br/>backpressure, sampling"]
        API["api<br/><i>Python / FastAPI</i><br/>REST + GraphQL, RBAC,<br/>policy, inventory"]
        WORK["worker<br/><i>Celery</i><br/>taint assembly, dedup, scoring,<br/>correlation, reports"]
        AIO["ai-orchestrator<br/><i>LangGraph</i><br/>RCA, remediation, summary"]
        DASH["dashboard<br/><i>Next.js 15 / React 19</i>"]
    end

    subgraph Data
        PG[("PostgreSQL<br/>tenants, users, apps,<br/>findings, policy, audit")]
        CH[("ClickHouse<br/>runtime events, traces,<br/>attack telemetry, metrics")]
        RD[("Redis<br/>cache, rate limits,<br/>Celery broker, sessions")]
        KF[["Kafka<br/>runtime-events, findings,<br/>attacks, agent-lifecycle"]]
        OS[("OpenSearch<br/>full-text over findings,<br/>traces, runbooks")]
        S3[("MinIO / S3<br/>agent artifacts, reports,<br/>raw trace blobs")]
        VDB[("pgvector<br/>RAG corpus")]
    end

    LB --> GW
    LB --> API
    LB --> DASH
    GW --> KF
    KF --> WORK
    WORK --> CH
    WORK --> PG
    WORK --> OS
    WORK --> KF
    API --> PG
    API --> CH
    API --> RD
    API --> OS
    API --> S3
    API --> AIO
    AIO --> VDB
    AIO --> PG
    DASH --> API
    WORK --> S3
```

### Container responsibilities

| Container | Responsibility | Explicitly not responsible for |
|---|---|---|
| `gateway` | Authenticate agents, validate wire schema, apply per-tenant quota and sampling, publish to Kafka. Stateless, horizontally scaled, no database writes on the hot path. | Business logic, correlation, storage |
| `api` | All user-facing reads and writes. Owns the relational model, RBAC, policy, licensing, audit. | Ingest, heavy computation |
| `worker` | Everything asynchronous: assembling traces into findings, deduplication, risk scoring, attack correlation, compliance rollups, report rendering, notifications. | Serving user requests |
| `ai-orchestrator` | LangGraph workflows. Stateless between runs; checkpoints in Postgres. | Being on any synchronous critical path |
| `dashboard` | Presentation. Server components for first paint, TanStack Query for live data, SSE/WebSocket for streaming. | Holding business rules |

## 4. Application architecture — hexagonal + DDD

Every Python service uses the same four-layer structure. Dependencies point strictly inward.

```
┌───────────────────────────────────────────────────────────────┐
│ interfaces/      HTTP routers, GraphQL resolvers, gRPC        │
│                  servicers, CLI, Celery task entrypoints      │
│                  → translate transport ⇄ application DTOs     │
├───────────────────────────────────────────────────────────────┤
│ infrastructure/  SQLAlchemy repositories, Redis cache, Kafka   │
│                  producer, ClickHouse client, Argon2 hasher,  │
│                  JWT codec, SMTP/Slack senders                │
│                  → implement the ports defined in domain      │
├───────────────────────────────────────────────────────────────┤
│ application/     Use cases (one class per business operation), │
│                  unit-of-work orchestration, authorization     │
│                  decisions, DTOs, application-level errors     │
├───────────────────────────────────────────────────────────────┤
│ domain/          Entities, value objects, aggregates, domain   │
│                  services, domain events, ports (Protocols),   │
│                  invariants. Zero third-party imports.         │
└───────────────────────────────────────────────────────────────┘
```

Rules enforced in CI (`scripts/check_layering.py`):

- `domain` may import only the standard library and `packages/shared` contracts.
- `application` may import `domain`. It may not import `sqlalchemy`, `fastapi`, `redis`, `kafka`.
- `infrastructure` and `interfaces` may import everything inward.
- Nothing imports `interfaces`.

### 4.1 Bounded contexts

```mermaid
graph LR
    IAM["Identity & Access<br/><small>Organization, User, Membership,<br/>Role, Permission, Session, ApiKey</small>"]
    INV["Application Inventory<br/><small>Application, Environment,<br/>Route, Dependency, Server</small>"]
    FLEET["Agent Fleet<br/><small>Agent, AgentRelease, AgentConfig,<br/>Heartbeat, HealthSnapshot</small>"]
    DET["Detection<br/><small>Rule, TaintFlow, Finding,<br/>Evidence, Sanitizer, Dedup identity</small>"]
    RISK["Risk & Compliance<br/><small>RiskScore, ComplianceControl,<br/>Mapping, Exception, Policy</small>"]
    ADR["Attack Response<br/><small>AttackEvent, Campaign,<br/>ProtectionPolicy, BlockAction</small>"]
    AI["AI Assistance<br/><small>AnalysisRun, Artifact,<br/>Approval, Feedback</small>"]
    REP["Reporting & Notification<br/><small>Report, Schedule, Channel,<br/>Subscription, Delivery</small>"]

    IAM --> INV
    INV --> FLEET
    FLEET --> DET
    DET --> RISK
    DET --> ADR
    DET --> AI
    RISK --> REP
    ADR --> REP
```

Context relationships use published-language contracts in `packages/shared`; no context reaches into
another context's tables. Cross-context reads go through an application service or a Kafka event.

### 4.2 Identity & Access class model (implemented in Phase 2)

```mermaid
classDiagram
    class Organization {
        +UUID id
        +str name
        +str slug
        +OrganizationStatus status
        +dict settings
        +activate()
        +suspend(reason)
    }
    class User {
        +UUID id
        +EmailAddress email
        +PasswordHash password_hash
        +bool is_platform_admin
        +int failed_login_count
        +datetime locked_until
        +bool mfa_enabled
        +record_failed_login(policy) 
        +record_successful_login()
        +is_locked(now) bool
    }
    class Membership {
        +UUID id
        +UUID organization_id
        +UUID user_id
        +MembershipStatus status
        +set~Role~ roles
        +permissions() set~Permission~
        +has_permission(p) bool
    }
    class Role {
        +UUID id
        +UUID organization_id
        +str name
        +bool is_system
        +set~Permission~ permissions
    }
    class Permission {
        <<enumeration>>
        org:read org:write
        app:read app:write
        finding:read finding:triage
        agent:read agent:write
        policy:write report:read
        user:invite role:write
        audit:read settings:write
    }
    class Session {
        +UUID id
        +UUID user_id
        +str refresh_token_hash
        +UUID family_id
        +datetime expires_at
        +datetime revoked_at
        +is_active(now) bool
        +revoke(reason)
    }
    class ApiKey {
        +UUID id
        +UUID organization_id
        +str prefix
        +str secret_hash
        +set~Permission~ permissions
        +datetime expires_at
        +verify(secret) bool
    }
    class AuditEvent {
        +UUID id
        +UUID organization_id
        +UUID actor_id
        +str action
        +str resource_type
        +str resource_id
        +AuditOutcome outcome
        +dict metadata
    }

    Organization "1" o-- "*" Membership
    User "1" o-- "*" Membership
    Membership "*" --> "*" Role
    Role "*" --> "*" Permission
    User "1" o-- "*" Session
    Organization "1" o-- "*" ApiKey
    Organization "1" o-- "*" AuditEvent
```

## 5. Key sequences

### 5.1 Agent registration and configuration

```mermaid
sequenceDiagram
    autonumber
    participant A as Runtime agent
    participant G as Gateway
    participant API as Control-plane API
    participant PG as PostgreSQL
    participant K as Kafka

    A->>G: POST /v1/agents/register {api_key, app_name, env, language, version, host}
    G->>G: Verify API key prefix + Argon2 secret, check licence entitlement
    G->>API: internal RegisterAgent(org_id, fingerprint, metadata)
    API->>PG: upsert Application (by org+name+env)
    API->>PG: upsert Agent (by fingerprint), issue agent credential
    API-->>G: {agent_id, agent_token, config_version}
    G-->>A: 201 {agent_id, agent_token(24h), config, rules_etag}
    A->>A: Install instrumentation for enabled rule set
    loop every 30s
        A->>G: Heartbeat {agent_id, health, overhead_pct, rules_etag}
        G->>K: publish agent.heartbeat
        alt rules_etag stale
            G-->>A: 200 {config_version, rules_url}
            A->>G: GET /v1/agents/config (If-None-Match)
            G-->>A: 200 signed rule bundle
            A->>A: Hot-swap rule set, no restart
        else current
            G-->>A: 204
        end
    end
```

### 5.2 Vulnerability detection — source to finding

```mermaid
sequenceDiagram
    autonumber
    participant U as HTTP request
    participant APP as Application code
    participant AG as Agent (in-process)
    participant G as Gateway
    participant K as Kafka
    participant W as Worker
    participant CH as ClickHouse
    participant PG as PostgreSQL
    participant D as Dashboard

    U->>APP: GET /search?q=' OR 1=1--
    APP->>AG: source hook: HttpServletRequest.getParameter
    AG->>AG: Create taint range over returned String,<br/>tag source=PARAMETER, key=q
    APP->>AG: propagator hook: StringBuilder.append / concat
    AG->>AG: Shift and merge taint ranges
    APP->>AG: sink hook: Statement.executeQuery(sql)
    AG->>AG: Overlap(taint ranges, sink argument)?<br/>Any sanitizer on path?
    AG->>AG: HIT — capture stack, request, taint path,<br/>redact per data-policy
    AG->>G: RuntimeEvent{type=TAINT_HIT, rule=sql-injection, trace}
    G->>G: authn agent, validate schema, quota
    G->>K: produce runtime-events
    K->>W: consume
    W->>CH: insert raw trace + spans
    W->>W: compute dedup identity =<br/>hash(app, rule, sink signature, normalized stack)
    alt new identity
        W->>PG: INSERT Finding (status=OPEN, first_seen=now)
        W->>K: produce finding.created
    else known identity
        W->>PG: UPDATE Finding SET last_seen, occurrence_count+1
    end
    W->>W: Risk score = f(severity, exploitability,<br/>exposure, asset criticality, data sensitivity)
    W->>PG: upsert RiskScore, compliance mappings
    K->>D: SSE finding.created
    D->>U: Live finding appears with full trace
```

### 5.3 Attack detection and response

```mermaid
sequenceDiagram
    autonumber
    participant ATT as Attacker
    participant AG as Agent
    participant APP as Application
    participant G as Gateway
    participant W as Worker
    participant SOC as SOC dashboard
    participant SIEM as SIEM

    ATT->>APP: POST /login {user: "admin' --"}
    APP->>AG: source hook
    AG->>AG: Classify payload against attack signatures → SQLI probe
    AG->>G: AttackEvent{phase=PROBED, confidence=0.6}
    APP->>AG: sink hook with tainted argument
    AG->>AG: Exploitation confirmed — payload reached sink
    alt policy = BLOCK for this rule/app/env
        AG-->>APP: throw SecurityException (request aborted)
        AG->>G: AttackEvent{phase=BLOCKED, confidence=1.0}
    else policy = MONITOR
        AG->>G: AttackEvent{phase=EXPLOITED, confidence=1.0}
    end
    G->>W: via Kafka
    W->>W: Correlate by source IP / session / payload family → Campaign
    W->>SOC: SSE attack.detected
    W->>SIEM: forward OCSF/CEF event
```

### 5.4 AI root cause and remediation (human-in-the-loop)

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant API as API
    participant AIO as AI orchestrator (LangGraph)
    participant RAG as pgvector + OpenSearch
    participant LLM as LLM provider
    participant PG as PostgreSQL

    U->>API: POST /findings/{id}/analysis {kind: REMEDIATION}
    API->>PG: create AnalysisRun(status=QUEUED)
    API-->>U: 202 {run_id, stream_url}
    API->>AIO: dispatch(run_id)
    AIO->>PG: load finding, trace, route, dependencies, framework
    AIO->>RAG: retrieve CWE guidance, framework-idiomatic fixes,<br/>this tenant's accepted past remediations
    AIO->>LLM: RootCauseAgent (structured output: RootCause schema)
    LLM-->>AIO: root cause + confidence + evidence citations
    AIO->>LLM: RemediationAgent (structured output: Patch schema)
    LLM-->>AIO: unified diff + regression test + rollout notes
    AIO->>AIO: Guardrails — diff applies cleanly? test compiles?<br/>no secrets leaked? scope limited to cited files?
    AIO->>PG: store Artifact(status=AWAITING_APPROVAL)
    AIO-->>U: stream tokens over SSE
    U->>API: POST /analysis/{run_id}/approve
    API->>PG: Artifact.status=APPROVED, emit audit event
    API->>API: optional: open PR via SCM integration
```

## 6. Data architecture

| Store | Contents | Why this store |
|---|---|---|
| PostgreSQL | Tenancy, identity, RBAC, applications, findings, policy, licensing, audit, AI runs, LangGraph checkpoints | Transactional integrity, relational queries, mature RLS |
| ClickHouse | Runtime events, taint traces, spans, attack telemetry, agent metrics | Columnar, 100k+ inserts/sec, cheap TTL tiering, fast aggregate scans |
| Redis | Session cache, rate limiting, idempotency keys, Celery broker, live-view fan-out | Sub-ms latency, expiring keys |
| Kafka | `runtime-events`, `findings`, `attacks`, `agent-lifecycle`, `notifications` | Durable buffer that decouples ingest spikes from analysis capacity |
| OpenSearch | Findings, trace text, runbooks, docs | Full-text and fuzzy search; RAG keyword leg |
| pgvector | Embeddings for RAG corpus | Keeps vector data inside the existing Postgres operational envelope |
| MinIO / S3 | Agent binaries, signed rule bundles, rendered reports, cold trace blobs | Cheap large-object storage; presigned distribution |

### Multi-tenancy

Shared-schema with a mandatory `organization_id` discriminator on every tenant-owned table
(see [ADR-0003](adr/0003-multi-tenancy-strategy.md)). Three enforcement layers:

1. **Repository layer** — `TenantScopedRepository` injects the predicate; no query builder is exposed
   that can omit it.
2. **PostgreSQL row-level security** — `app.current_organization_id` session GUC set per transaction,
   defence in depth against a repository bug.
3. **Test layer** — a cross-tenant isolation suite runs every endpoint as tenant B against tenant A's
   resource identifiers and asserts 404 (not 403 — we do not confirm existence).

## 7. Cross-cutting concerns

| Concern | Approach |
|---|---|
| Observability | OpenTelemetry traces/metrics/logs everywhere; `trace_id` propagated from agent through Kafka to worker; Prometheus `/metrics`; structured JSON logs with tenant and actor fields |
| Configuration | Pydantic Settings, 12-factor env vars, no secrets in images; Vault/KMS in production |
| Errors | RFC 9457 `application/problem+json`; domain errors mapped once, at the interface boundary |
| Idempotency | `Idempotency-Key` header on all unsafe API operations; agent events carry a client-side ULID |
| Versioning | URL-versioned API (`/v1`), additive-only within a major; agent wire protocol versioned in protobuf |
| Rate limiting | Token bucket per API key and per user in Redis; per-tenant ingest quota in the gateway |
| Backpressure | Gateway sheds by sampling low-value events first (heartbeats, metrics) and never drops findings or attacks |
| Fail-open | Any agent internal error disables the offending hook, reports it, and lets the application proceed |
| Secrets in evidence | Redaction runs *in the agent* before transmission, driven by tenant data policy |

## 8. Deployment topology

```mermaid
graph TB
    subgraph K8s["Kubernetes cluster"]
        subgraph ns1["namespace: aegis-edge"]
            ING["Ingress-NGINX + cert-manager"]
            GWP["gateway (HPA 3–50)"]
        end
        subgraph ns2["namespace: aegis-core"]
            APIP["api (HPA 3–20)"]
            WKP["worker (KEDA on Kafka lag)"]
            AIP["ai-orchestrator (HPA 2–10)"]
            DSH["dashboard (HPA 2–10)"]
        end
        subgraph ns3["namespace: aegis-data"]
            PGO["PostgreSQL (CloudNativePG)"]
            CHO["ClickHouse (Altinity operator)"]
            KFO["Kafka (Strimzi)"]
            RDO["Redis (Sentinel)"]
            OSO["OpenSearch"]
            MIN["MinIO"]
        end
    end
    ING --> GWP
    ING --> APIP
    ING --> DSH
    GWP --> KFO
    KFO --> WKP
    WKP --> PGO
    WKP --> CHO
    APIP --> PGO
    APIP --> RDO
    AIP --> PGO
```

Environments: `local` (docker compose) → `dev` → `staging` → `production`. Terraform provisions cloud
infrastructure; Helm deploys workloads; GitHub Actions promotes immutable, signed images.

## 9. Architectural decisions

| ADR | Decision |
|---|---|
| [0001](adr/0001-monorepo.md) | Monorepo with per-app toolchains |
| [0002](adr/0002-hexagonal-architecture.md) | Hexagonal architecture with enforced layer boundaries |
| [0003](adr/0003-multi-tenancy-strategy.md) | Shared-schema tenancy with discriminator + RLS |
| [0004](adr/0004-polyglot-persistence.md) | PostgreSQL + ClickHouse split |
| [0005](adr/0005-agent-transport.md) | gRPC + protobuf agent transport with mTLS and pinning |
| [0006](adr/0006-token-strategy.md) | Short-lived JWT access + rotating opaque refresh with reuse detection |
| [0007](adr/0007-taint-model.md) | Range-based taint tracking with sanitizer awareness |
| [0008](adr/0008-ai-orchestration.md) | LangGraph orchestration with human approval gates |
| [0009](adr/0009-finding-identity.md) | Deterministic finding identity and deduplication |
