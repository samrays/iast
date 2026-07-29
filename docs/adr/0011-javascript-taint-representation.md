# ADR-0011: JavaScript cannot key taint on identity, and what that costs

- **Status:** Accepted
- **Date:** 2026-07-29
- **Deciders:** Agent engineering, Platform architecture, Security

## Context

The JVM agent holds **zero false positives across 1,572 OWASP Benchmark cases**. Three properties
produce that, and the load-bearing one is that taint is keyed on **object identity** — an
`IdentityHashMap<Object, TaintedValue>`. Two equal strings are not the same value, so the
application's own literal `"alice"` is a different key from a request parameter that happens to
contain `alice`.

`agents/runtime/node-agent/spike/taint-key-spike.mjs` establishes that JavaScript cannot offer
this:

```
 FAIL  WeakMap accepts a string primitive as a key    primitives cannot be weakly keyed
 FAIL  a value-keyed table can tell them apart        the app's own constant reads as tainted
 FAIL  two equal primitives are distinguishable       === is value equality for primitives
```

Boxed `String` objects have identity, but no real application produces them.

This is not an implementation gap to engineer around. It is a property of the language, and it
means the JVM design cannot be ported — only re-derived.

## Options considered

| Option | Why not |
|---|---|
| **Sources return boxed `String` objects** | Gives identity, and breaks the application. `typeof x` becomes `"object"`, `x === "alice"` becomes false, `JSON.stringify` output changes. Violates the first non-negotiable — never break the host application — which outranks detection quality by design. |
| **Value-keyed table** (`Map<string, Taint>`) | The application's own constants collide with user input by construction. Fails the corpus identity case directly. |
| **Sink-side provenance matching** — no propagation tracking; at the sink, look for any value this request received from a source | Genuinely attractive: no `String.prototype` patching, no per-concatenation overhead, ranges fall out for free, escaping breaks the match automatically, and parameterised queries produce no match because the value is never in the query text. But it is still value comparison, so it fails the identity case for the same reason. |
| **Native addon attaching hidden state to primitives** | V8 exposes no such facility. Primitives have no slot to attach to. |

The first two were rejected outright. The third and fourth are the interesting ones, and the third
is what we adopt — but only after being explicit that it does not preserve the invariant.

## Decision

1. **The Node agent uses sink-side provenance matching.** Values returned by sources are recorded
   in the request context; at each sink the argument is searched for those values. Matches yield
   the finding and its ranges.

2. **§1.2 of the conformance spec is amended from mechanism to outcome.** Identity keying was the
   JVM's means of achieving zero false positives, not the requirement itself. Each agent reaches
   the outcome by whatever means its runtime allows, and is judged on the outcome.

3. **The corpus identity case is a known, recorded limitation for JavaScript.** Where a request
   parameter's value also appears in the sink argument as an application constant, the Node agent
   will report it and the JVM agent will not. This is written into the Node corpus as an expected
   divergence with this ADR cited, **not** quietly dropped from the suite.

4. **Two mitigations, both to be tuned against the corpus rather than guessed:**
   - a minimum matched length, since short values (`"1"`, `"true"`, `"admin"`) collide constantly
     and carry almost no evidence;
   - a minimum count of matched source values before a finding is raised on a common literal.

   Both trade recall for precision, and that is the correct direction: one false positive on
   correct code costs more trust than ten true positives earn.

5. **Node's false-positive number will not match the JVM's, and that is reported as a property of
   the language rather than smoothed over.** A per-agent Benchmark score is published per agent.

## Consequences

### Positive
- The Node agent needs no propagation instrumentation at all — no `String.prototype` patching, no
  hook on every concatenation. Overhead should be materially lower than the JVM agent's.
- Ranges are produced by construction, since a match has a position.
- Escaping is handled for free: an HTML-escaped value no longer matches its source, so no finding.
  Parameterised queries likewise produce no match, because the value never enters the query text.

### Negative
- **The zero-false-positive invariant does not hold for JavaScript in the form it holds for Java.**
  This is the real cost, and it is stated plainly here so that nobody later reports a Node number
  as though it were comparable.
- Sanitizer *recognition* becomes implicit rather than explicit. The agent will not be able to say
  *which* encoder made a value safe, only that the value no longer matches.
- Second-order flows through storage are harder: a value read back from a database was not
  received from a source this request, so it will not match.

### Neutral
- Python, whose strings are also immutable but which does have `id()` and object identity for
  `str`, may be able to use the JVM approach. That must be established by its own spike rather than
  assumed from this ADR.

## Compliance

- `agents/runtime/node-agent/spike/taint-key-spike.mjs` is the evidence for the constraint and must
  keep passing as a regression check on the premise.
- The Node corpus must contain the identity case, marked as an expected divergence citing this ADR.
  A corpus that omits it would hide the one thing this decision costs.
