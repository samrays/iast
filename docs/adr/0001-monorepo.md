# ADR-0001: Monorepo with per-app toolchains

- **Status:** Accepted
- **Date:** 2026-07-27
- **Deciders:** Platform architecture

## Context

The product spans a Python control plane, a TypeScript dashboard, and five runtime agents in five
different languages (Java, C#, JavaScript, Python, Go). These components share contracts that must not
drift: the agent wire protocol, the detection-rule schema, severity and CWE catalogues, and the finding
identity algorithm. A protocol change that lands in the gateway but not in the Java agent is a
production incident in a customer's process.

## Decision

A single Git repository containing all applications, agents, shared packages, infrastructure and
documentation. Each application keeps its own native toolchain (`pyproject.toml`, `package.json`,
`pom.xml`, `go.mod`); there is no attempt to impose one build system across languages. Cross-cutting
contracts live in `packages/` and are code-generated into each language from a single source (protobuf
and JSON Schema) rather than hand-maintained per language.

CI uses path filters so a dashboard-only change does not run the Java agent's benchmark suite.

## Alternatives considered

| Option | Why not |
|---|---|
| Polyrepo, one repo per component | Contract drift becomes the default failure mode; an atomic protocol change requires coordinated releases across six repositories |
| Monorepo with a unified build system (Bazel/Nx) | Real benefits at much larger scale, but the setup and maintenance cost is not justified for a team of this size, and it makes each language's idiomatic tooling harder to use |
| Monorepo with vendored copies of shared contracts | Reintroduces drift, just inside one repository |

## Consequences

### Positive
- Atomic cross-component changes: a protocol change and all five agent updates land in one commit.
- One source of truth for shared contracts, generated rather than transcribed.
- Shared CI, shared quality gates, shared documentation adjacency.

### Negative
- Repository size grows quickly once agent test fixtures and vulnerable-app corpora land; requires
  Git LFS for binary fixtures.
- CI must be carefully path-filtered or every push becomes a full-matrix build.
- Access control is repository-wide; a customer-facing SDK extraction would need a separate publish
  pipeline.

### Neutral
- Release versioning is per-component, not repository-wide. Agents version independently of the
  control plane by design (see ADR-0005).

## Compliance

- `.github/workflows/ci.yml` uses `paths` filters per job.
- `packages/proto` is the only place protobuf is authored; generated code is checked in and a CI job
  fails if regeneration produces a diff.
