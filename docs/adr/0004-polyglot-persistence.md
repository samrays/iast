# ADR-0004: PostgreSQL for the control plane, ClickHouse for runtime telemetry

- **Status:** Accepted
- **Date:** 2026-07-27
- **Deciders:** Platform architecture, Data

## Context

Two workloads with incompatible shapes share the product:

| | Control plane | Runtime telemetry |
|---|---|---|
| Write rate | tens/sec | 100,000/sec target |
| Row lifetime | years | 30 days hot |
| Access pattern | point reads, joins, transactions | wide aggregate scans, time-bucketed |
| Consistency need | strict — RBAC, licensing, audit | eventual is fine |
| Cardinality | thousands of rows per tenant | billions |

Forcing both into PostgreSQL means either a table that ingests a hundred thousand rows per second (it
will not, without partition management that becomes a full-time job) or throwing telemetry away.

## Decision

- **PostgreSQL 16+** owns everything transactional: tenancy, identity, RBAC, applications, agents,
  findings, policies, licences, audit, AI runs, LangGraph checkpoints, and pgvector embeddings.
- **ClickHouse** owns the append-only telemetry: runtime events, taint traces, spans, attack events and
  agent metrics — partitioned by day, `ORDER BY (organization_id, application_id, occurred_at)`, with
  TTL tiering to cold storage at 30 days and deletion at 365.
- **Kafka** sits between ingest and both stores, so a ClickHouse outage delays analysis rather than
  losing data.
- A **finding** (PostgreSQL) references its **evidence** (ClickHouse + object storage) by id. The
  authoritative, long-lived, user-managed object is relational; the high-volume proof is columnar.

pgvector rather than a dedicated vector database: the RAG corpus is modest, and keeping embeddings in
the existing operational envelope avoids a fifth datastore to back up, secure and monitor.

## Alternatives considered

| Option | Why not |
|---|---|
| PostgreSQL + TimescaleDB for everything | Simpler operationally, but compressed hypertables do not match ClickHouse on the wide-scan aggregate queries the trace explorer needs, and ingest ceiling arrives too early |
| Elasticsearch/OpenSearch for telemetry | Excellent for search, expensive per ingested byte at this volume; we use OpenSearch for text search over findings, not as the telemetry store |
| ClickHouse for everything | No usable transactional semantics; RBAC and audit demand real transactions and constraints |
| Cloud-managed only (BigQuery/Snowflake) | Blocks the on-premises and air-gapped deployment requirement |

## Consequences

### Positive
- Each store runs the workload it was designed for; neither is the other's bottleneck.
- Telemetry retention is a TTL setting, not a data-management project.
- Kafka decouples ingest spikes from analysis capacity and gives replay for free.

### Negative
- Four stateful systems to operate (Postgres, ClickHouse, Kafka, Redis) plus object storage and
  OpenSearch. This is the main operational cost of the architecture and is why every one of them has
  a Kubernetes operator in the Helm chart.
- Cross-store queries must be assembled in application code; there are no joins between a finding and
  its trace.
- Eventual consistency between the two is user-visible for a few seconds after a sink hit.

### Neutral
- A small on-premises deployment can run ClickHouse single-node and Kafka in KRaft mode; the Helm
  chart ships a `profile: compact` values file for this.

## Compliance

- No SQLAlchemy model may be created for telemetry tables; ClickHouse DDL lives in `packages/database`.
- A test asserts findings carry only references to evidence, never inlined trace payloads.
