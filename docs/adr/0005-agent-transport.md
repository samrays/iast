# ADR-0005: gRPC + protobuf agent transport, independently versioned from the control plane

- **Status:** Accepted
- **Date:** 2026-07-27
- **Deciders:** Platform architecture, Agent engineering, Security

## Context

Agents run inside customer production processes, often behind restrictive egress policies, sometimes
in air-gapped networks, and frequently at versions the customer chose months ago and will not upgrade
on our schedule. The transport must be efficient (hundreds of events per second per agent), safe (it is
a channel into a production process), and tolerant of version skew in both directions.

## Decision

- **Primary transport: gRPC bidirectional streaming over mTLS 1.3**, with protobuf schemas authored
  once in `packages/proto/agent/v1/` and generated into all five languages.
- **Fallback: HTTP/1.1 + newline-delimited JSON** at `POST /ingest/v1/events` for environments where
  gRPC cannot traverse the proxy. Same schema, same auth, higher overhead — the agent negotiates at
  startup and falls back automatically.
- **Certificate pinning** in the agent over the SPKI hash, with a primary and a rollover pin shipped
  together so certificate rotation never bricks a fleet.
- **Compression:** zstd, negotiated, gzip fallback.
- **Flow control:** the server's `IngestAck` carries a credit window; the agent throttles to it. The
  agent never blocks the application to satisfy backpressure — it drops from its bounded buffer.
- **Version skew policy:** the wire protocol is additive-only within `v1`. A newer agent may send
  fields an older gateway ignores; an older agent must always be accepted by a newer gateway. Agents
  are supported for 18 months from release. The gateway records the agent version on every event so
  the effect of a schema addition is measurable before it is depended upon.
- **Independent release trains.** Agent versions are not tied to control-plane versions. Customers pin
  agent versions; auto-update is opt-in and staged.

## Alternatives considered

| Option | Why not |
|---|---|
| Plain HTTPS + JSON only | 3–5× the bytes and significant CPU for JSON encoding on the customer's hot path; no native streaming flow control |
| Kafka client embedded in the agent | Exposes the broker to customer networks, fat client dependency in five languages, and a credential blast radius we will not accept |
| OTLP (OpenTelemetry protocol) as the primary wire | Attractive for interoperability, but taint traces are structurally unlike spans; forcing them into span attributes loses fidelity. We export *to* OTLP, we do not ingest over it |
| MQTT | Good for constrained devices, poor library maturity across our five runtimes |

## Consequences

### Positive
- Compact binary encoding keeps agent CPU cost inside the overhead budget.
- One schema source generates all five languages, so contract drift is a build failure rather than a
  production surprise.
- Streaming with credit-based flow control gives real backpressure without blocking the application.

### Negative
- Two transports to maintain and test (gRPC and the JSON fallback).
- Protobuf codegen must be checked in and verified in CI, adding a build step.
- gRPC library maturity varies across the five runtimes; the Go and .NET stories are excellent, the
  Node story is heavier than ideal.

### Neutral
- The user-facing REST/GraphQL API is entirely separate and shares nothing with this transport.

## Compliance

- `packages/proto` is the sole protobuf source; a CI job regenerates and fails on a diff.
- A compatibility test suite replays recorded payloads from every supported agent version against the
  current gateway.
- The pin set is asserted to contain at least two pins at build time.
