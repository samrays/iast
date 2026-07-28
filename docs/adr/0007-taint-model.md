# ADR-0007: Range-based taint tracking with sanitizer awareness

- **Status:** Accepted
- **Date:** 2026-07-27
- **Deciders:** Agent engineering, Detection research

## Context

Taint tracking is the detection engine. Its design determines both the false-positive rate (the single
most important product property) and the agent's overhead budget (the single most important adoption
barrier).

The naive design tags a value as "tainted: yes/no". It is cheap, and it is wrong often enough to be
unusable: a query built from a safe prefix plus a bound parameter is flagged identically to a query
built by concatenating a raw parameter, and the user is given no way to see the difference.

## Decision

Taint is a **set of ranges over a value**, each carrying a source tag and a set of rule classes for
which it remains dangerous.

```
TaintRange { start: int, length: int, source: SourceTag, cleared_for: set[RuleClass] }
TaintedValue { ranges: list[TaintRange] }   # stored in a weak side table, keyed by identity
```

Propagators transform ranges rather than copying a boolean:

| Operation | Transform |
|---|---|
| `a + b` | `ranges(a) ∪ shift(ranges(b), len(a))` |
| `a.substring(i, j)` | `clip(ranges(a), i, j)` then shift by `−i` |
| `a.replace(x, y)` | recompute offsets around each replacement |
| `a.toUpperCase()` | offsets preserved, tags preserved |
| `encodeHtml(a)` | `ranges(a)` with `XSS` added to `cleared_for` |
| `preparedStatement.setString(i, a)` | `ranges(a)` with `SQLI` added to `cleared_for` |

A sink fires only when a tainted range **overlaps the security-relevant span of the sink argument** and
that range does not have the sink's rule class in `cleared_for`.

Confidence is a first-class output, not a heuristic score:

| Path | Confidence | Reported |
|---|---|---|
| No sanitizer, no validator on path | `CONFIRMED` | yes, full severity |
| Validator only (regex, length, enum) on path | `OBSERVED` | yes, reduced severity, flagged as "validated but not sanitized" |
| Payload matched an attack signature and reached the sink | `EXPLOITED` | yes, escalated, feeds ADR |
| Sanitizer for this rule class on path | — | no |

**Coverage is reported, not assumed.** Where taint cannot be followed — native/C-extension boundaries,
reflection through dynamic proxies, bundled or minified code, values crossing a serialization boundary
we do not instrument — the agent emits a `coverage_gap` event. An application with low instrumentation
coverage and zero findings is displayed as *unknown*, never as *clean*.

## Alternatives considered

| Option | Why not |
|---|---|
| Boolean taint | Cannot distinguish a bound parameter from a concatenated one; unacceptable false-positive rate; cannot show the user which characters are attacker-controlled |
| Full symbolic/dataflow analysis in-process | Overhead orders of magnitude beyond the budget; unusable in production |
| Character-level tag arrays (one tag per character) | Precise but memory-prohibitive on large payloads; ranges give the same precision at a fraction of the cost for realistic values |
| Taint stored on the value (subclassing `String`) | Impossible for final built-in types on most runtimes and would change application behaviour |

## Consequences

### Positive
- Very low false-positive rate: a sanitized flow is provably distinguishable from an unsanitized one.
- The UI can highlight the exact attacker-controlled characters inside the executed query — this is
  the evidence that makes a developer accept the finding immediately.
- Range algebra is pure and exhaustively testable with property-based tests.

### Negative
- Every propagator needs a hand-written, correct range transform. This is the bulk of per-language
  agent work and the most likely source of subtle bugs.
- Range sets can fragment on pathological string manipulation; capped at 32 ranges per value, merging
  adjacent ranges, then degrading to a single covering range with a `imprecise=true` flag.
- Side-table lookups cost a hash on every propagator call; mitigated by fast-pathing values with no
  ranges and by the resource governor.

### Neutral
- The sanitizer catalogue is per-language data in the rule bundle, so new sanitizers ship without an
  agent release.

## Compliance

- Range algebra has property-based tests asserting invariants (ranges never exceed value length, never
  overlap after merge, offsets survive round-trips through each propagator).
- Every release runs the vulnerable-app corpus (WebGoat, OWASP Benchmark, Juice Shop and per-language
  equivalents) and gates on true-positive and false-positive rates.
- The sanitized control set must produce **zero** findings; any regression blocks the release.
