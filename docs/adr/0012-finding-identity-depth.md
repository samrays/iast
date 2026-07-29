# ADR-0012: Finding identity uses the innermost application frame, not the top five

- **Status:** Accepted
- **Amends:** [ADR-0009](0009-finding-identity.md)
- **Date:** 2026-07-29
- **Deciders:** Agent engineering, Platform architecture

## Context

ADR-0009 defines finding identity and, in its alternatives table, rejects including the full stack
with this reason:

> Two call paths to the same vulnerable sink become two findings; the developer fixes one line and
> sees the other stay open

It then chose to hash the **top five** application frames. That choice does not avoid the outcome it
just rejected. Two call paths through the same vulnerable line have different callers, so they
produce different fingerprints, so they produce two findings — the developer fixes one line and
watches the second stay open, exactly as described.

The live end-to-end run produced this: one vulnerable line reached from two paths, two findings.

So the ADR is internally inconsistent. It rejected an option for a consequence that also follows
from the option it picked, and the inconsistency was invisible until the system ran.

## Decision

**Identity uses the innermost application frame only** — depth 1 rather than 5.

The reasoning ADR-0009 was reaching for maps onto a specific frame. "One line, one finding" is a
claim about *the line the developer edits*, and that is the innermost application frame: the one
containing the concatenation, the `exec`, the file open. Frames above it describe **how the line was
reached**, which is context worth showing on the finding and wrong to put in its identity.

Identity therefore remains:

```
sha256(organization_id, application_id, rule_key, sink_signature, source_kind, innermost_app_frame)
```

Everything else in ADR-0009 stands: line numbers still excluded, environment still excluded,
nothing attacker-controlled included, application rather than environment as the key.

## Consequences

### Positive
- A helper like `UserRepository.buildQuery` called from three controllers is **one** finding. Fixing
  it closes one row, which is what a developer expects and what ADR-0009 intended.
- Deeper frames become evidence rather than identity, so they can be shown per occurrence — where
  they are genuinely useful — without fragmenting the finding.
- Fewer findings for the same defects, which is the correct direction: the count should track
  broken lines, not paths through them.

### Negative
- **Two distinct vulnerable lines in the same method collapse into one finding**, since they share
  an innermost frame and, usually, a sink signature. This is a real loss of resolution. It is
  accepted because both defects sit in one method that one person will open and fix together, and
  because the alternative — the previous behaviour — splits *one* defect across multiple rows, which
  is worse: it inflates the count and leaves rows open after the fix.
- **Existing identities change.** Any findings already stored were keyed at depth 5, so they will
  not match new events and will appear as new findings while the old rows go stale. There is no
  production data yet, so this is being taken now precisely because it is free today and a migration
  later.

### Neutral
- The `depth` parameter stays on `stack_fingerprint`, defaulted to 1. Keeping it as a parameter is
  what let the trade-off be demonstrated in a test rather than argued about.

## Compliance

- `apps/api/tests/unit/test_findings.py` asserts both directions: two call paths through one
  vulnerable line produce **one** identity, and the same line reached via a genuinely different
  sink still produces two.
- The next live run should be checked for the specific case that prompted this — one line, two
  paths, one finding. It has not yet been re-verified end to end.
