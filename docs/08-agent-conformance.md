# Agent conformance specification

Four more runtime agents are planned — .NET, Node, Python and Go. This document is what stops
them being four independent interpretations of the same product.

The JVM agent was built first and its behaviour was discovered rather than specified: the
re-entrancy guard, the fail-open contract, the bootstrap loader constraint and the
zero-false-positive invariant were all learned by hitting them. Writing that down once means the
next four do not each rediscover it, and — more usefully — it means a new agent can be judged
against something other than "does it look finished".

Everything here is a requirement on the **agent**. Nothing in it depends on the language.

---

## 1. The three non-negotiables

These are ranked. Where they conflict, the earlier one wins.

### 1.1 The agent must never break the application

It runs inside a business-critical process it does not own. Every hook is wrapped so that an
internal failure disables that hook, increments a counter and returns control immediately. There
is no path in which an agent exception propagates into customer code.

A conforming agent proves this by reporting `HOOK_FAILURES=0` across the corpus **and** by
surviving a deliberately broken hook without the host application observing anything.

Bootstrap must not abort startup either. A security tool that prevents a service from booting is
worse than no security tool: the failure path logs one line and lets the application come up
uninstrumented.

### 1.2 The agent must not report vulnerabilities that are not there

One false positive on correct code costs more trust than ten true positives earn. The JVM agent
holds **0 false positives across 1,572 OWASP Benchmark cases**, and that number is the product,
not a statistic.

Three implementation properties produce it, and a conforming agent needs all three:

- **Taint is tracked by object identity, not by value.** Two equal strings are not the same value.
  An engine keyed on equality reports every query containing a word a user happened to type.
- **Sanitization is per rule class.** HTML-escaping makes a value safe to render and does nothing
  to make it safe in SQL. A single global "sanitized" flag is how an engine misses the injection
  that matters.
- **A finding requires an application frame.** A tainted value reaching a sink entirely within
  framework code is not something the customer can fix.

### 1.3 The agent must stay inside its overhead budget

Default 5% CPU. When overhead rises the agent degrades itself in ordered steps — full, sampled,
configuration-only, heartbeat-only, uninstalled — rather than continuing to cost what it is not
allowed to cost. Degradation requires sustained breach and recovery requires sustained calm, so a
single GC pause cannot flap it.

---

## 2. What every agent must emit

The wire contract is `packages/proto/agent/v1/events.proto`, serialized as NDJSON over HTTP to
`POST /ingest/v1/events` (ADR-0005, amended by ADR-0010). An agent is conformant when the ingest
gateway accepts its output unmodified and the worker produces the expected findings from it.

Two rules about the envelope that are easy to get wrong:

- **The agent never states its own tenant or application.** `organization_id`, `agent_id` and
  `environment_id` are stamped by the gateway from the verified credential. An agent that sent
  them would be asserting an identity it cannot prove.
- **Redaction happens inside the customer process, before anything crosses the network.** The
  agent is the last place that can guarantee a secret never leaves.

`event_id` must be unique per agent and time-ordered. The gateway deduplicates on it, which is
what makes an at-least-once transport safe to replay after an outage.

---

## 3. The detection corpus

`agents/runtime/java-agent/src/test/java/com/example/corpus/BenchmarkApp.java` is the reference
implementation: 31 paired cases, each vulnerable case sitting beside a sibling that differs only
in the one thing that makes it safe.

Every agent reimplements this corpus in its own language and must reach **100% recall and 0%
false positives** on it before it is considered to work at all. The pairing is the design — a
scanner that reports everything catches every vulnerability and is worthless.

Minimum coverage per agent, in priority order:

| Rule class | Sink | Paired safe case |
|---|---|---|
| `sql-injection` | concatenated query | bound parameters |
| `command-injection` | shell/exec with input | constant command |
| `path-traversal` | file open with input | constant path |
| `reflected-xss` | response body write | escaped output |
| `unsafe-deserialization` | native deserializer | constant payload |

Two corpus cases exist specifically because they catch mistakes an implementation makes rather
than a customer:

- **The identity case.** The parameter's *value* also appears in the query as a constant. An
  engine keyed on equality reports it; a correct one stays silent.
- **The sanitizer case.** A URL encoder clears open redirect, header injection and SSRF, and
  deliberately leaves XSS and SQL tainted.

---

## 4. Language-specific mechanisms

`docs/05-runtime-agent-design.md` §5 covers these. The constraint each language imposes differs,
and it is the first thing to establish, because it decides what is instrumentable at all:

| Agent | Mechanism | The constraint to establish first |
|---|---|---|
| .NET | CLR Profiler API + Harmony | Profiler attach vs. startup-only instrumentation |
| Node | Module hooking + `async_hooks` | Context propagation across the event loop |
| Python | `sys.monitoring` + import hooks | C-extension calls the interpreter cannot see |
| Go | Compile-time source rewriting | No runtime instrumentation exists at all |

The JVM equivalent of that column was the bootstrap class loader confining the runtime to
`java.base` (ADR-0010), and it was discovered three linkage failures in. Establishing it *first*
for each new agent is the single highest-value thing to do, because it determines the shape of
everything else.

---

## 5. What "done" means

An agent is not done when it detects something. It is done when:

1. Its corpus passes at 100% recall and 0% false positives, in CI.
2. Overhead is measured with and without the agent on the same workload, in CI, against a stated
   budget.
3. It survives a control-plane outage — findings spool and replay rather than being dropped.
4. Its output is accepted by the gateway and produces findings in the console, verified by
   running the chain rather than by testing the parts.

Point 4 is stated separately because it has caught real bugs twice. Fixtures written from the
same assumption as the code cannot catch that assumption being wrong.
