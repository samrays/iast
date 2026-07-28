# ADR-0009: Deterministic finding identity and deduplication

- **Status:** Accepted
- **Date:** 2026-07-27
- **Deciders:** Detection research, Platform architecture

## Context

A single unfixed SQL injection on a busy endpoint produces millions of sink hits per day. The user must
see **one** finding with an occurrence count, not millions of rows. Getting the identity function wrong
fails in one of two directions, both bad:

- **Too coarse:** two genuinely different vulnerabilities collapse into one, and fixing one closes the
  other while it remains exploitable.
- **Too fine:** a line-number shift from an unrelated edit resurrects a finding the team already
  triaged and closed, destroying trust in the tool and the triage history along with it.

## Decision

Finding identity is a deterministic hash computed by the worker at ingest:

```
identity_hash = sha256(
    organization_id,
    application_id,           # not environment — the same flaw in staging and production is one flaw
    rule_key,                 # e.g. "sql-injection"
    normalize(sink_signature),      # Class#method(descriptor) — no line numbers
    normalize(source_kind),         # PARAMETER | HEADER | COOKIE | BODY | ...
    stack_fingerprint,              # see below
)
```

`stack_fingerprint` is built from the stack captured at the sink:

1. Drop all frames belonging to the framework, the standard library and third-party packages —
   keep only frames in the application's own package roots (discovered by the agent, overridable).
2. Keep the **top 5** remaining application frames.
3. Reduce each frame to `package.Class#method` — **line numbers are deliberately excluded**.
4. Hash the ordered list.

Explicitly excluded from identity: line numbers, environment, agent id, host, timestamp, request path
parameters, payload content, dependency versions.

Explicitly included: application, rule, sink method, source kind, application call path.

**Consequences of a match:** `occurrence_count += 1`, `last_seen_at = now`, environment added to the
observed set, a new evidence sample stored (rate-limited to one per hour per finding).

**Consequences of a miss:** a new `Finding` row in status `OPEN`.

**Reopening:** a finding in `REMEDIATED` whose identity recurs transitions to `OPEN` with a
`regression` flag and a `finding.regressed` event. A finding in `FALSE_POSITIVE` or `ACCEPTED_RISK`
does not reopen; it increments a suppressed counter, so a user can see that a suppression is still
absorbing traffic and revisit it.

## Alternatives considered

| Option | Why not |
|---|---|
| Include line numbers | Every refactor resurrects every finding and orphans its triage history |
| Include the full stack | Two call paths to the same vulnerable sink become two findings; the developer fixes one line and sees the other stay open |
| Route + rule only | Too coarse: two different sinks reached from one endpoint collapse into one finding |
| Fuzzy/similarity clustering | Non-deterministic across restarts; the same event stream must always produce the same finding set, or replay and audit become impossible |
| Payload-derived identity | Attacker-controlled input would control our data model — an obvious injection vector for finding-table flooding |

## Consequences

### Positive
- Deterministic and idempotent: replaying an event stream produces exactly the same finding set,
  which makes disaster recovery and pipeline testing tractable.
- Survives refactors, formatting changes and dependency bumps; triage history persists.
- The upsert is a single statement against a unique index — cheap at ingest rate.

### Negative
- Two distinct flaws that share a rule, a sink method and the top five application frames merge. This
  is rare and is accepted; the evidence samples for the merged finding show both call paths.
- Renaming a method or moving a class creates a new identity and closes the old finding as stale. A
  nightly job flags "closed as stale, similar new finding appeared" pairs for review.
- Package-root discovery must be right; a misconfigured root turns framework frames into identity
  input. The agent reports its detected roots and the value is overridable per application.

### Neutral
- The same algorithm runs for attack-event campaign signatures with a different field set.

## Compliance

- A golden-corpus test replays a recorded event stream twice and asserts an identical finding set.
- A refactor test applies formatting and line-shift changes to a fixture and asserts identity is
  unchanged.
- A distinct-sink test asserts two different sinks on one route produce two findings.
