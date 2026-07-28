# ADR-0010: The JVM agent's runtime is confined to `java.base`, and what that costs

- **Status:** Proposed
- **Date:** 2026-07-28
- **Deciders:** Agent engineering, Platform architecture, Security

## Context

ADR-0005 chose gRPC bidirectional streaming over mTLS as the agent's primary transport, with
NDJSON over HTTP as a fallback for environments where gRPC cannot traverse the proxy. That
decision was made before the JVM agent existed. Implementing it surfaced a constraint the ADR
could not have anticipated, and the constraint is not a detail of our design — it is a property
of how the JVM loads classes.

Byte Buddy `Advice` is **inlined** into the method it instruments. A hook placed in
`java.lang.StringBuilder` therefore executes as bootstrap-loaded code. Bootstrap code cannot see
the system class path, so every class the hook reaches — `AgentRuntime`, the taint engine, the
detector, the redactor, the reporter — must be published to the bootstrap class loader or the
first instrumented call dies with `NoClassDefFoundError` inside the customer's process.

Publishing to bootstrap is not free. Three failures were hit in sequence while getting it to
work, each of which took a working agent and broke it in a different way:

- Appending the whole agent jar put the shaded Byte Buddy on both the bootstrap and the system
  path. The JVM then saw two distinct `AgentBuilder` types and refused to link:
  `LinkageError: loader constraint violation`.
- Copying `AgentConfig` across split it from its own nested `Builder`, because the verifier
  resolves the types named in `AegisAgent.install` before injection can run —
  `IllegalAccessError`.
- Reaching `AgentRuntime` with a direct call rather than reflectively made the verifier define a
  *second* copy on the system loader. The inlined advice then set its static instance on one
  copy while the agent read the other, so every hook silently found `null` and reported nothing.
  This one produced no error at all: a fully installed agent that detected nothing.

The surviving rule is narrow and absolute: **anything published to bootstrap may depend on
`java.base` and nothing else**, and the boundary between bootstrap code and the rest of the agent
may only carry types both loaders resolve identically.

This was learned the expensive way. `Transport.Http` was originally written on
`java.net.http.HttpClient`, which lives in its own module loaded by the platform loader. The
agent reported itself installed and then died with
`NoClassDefFoundError: java/net/http/HttpClient` on the first flush.

gRPC is `java.net.http`'s problem several times over. `grpc-java` pulls in Netty and
protobuf-java — tens of thousands of classes across several modules, none of them `java.base`.

## Decision

1. **Bootstrap-published packages depend on `java.base` only.** Enforced by the fact that
   anything else fails at runtime, and documented at the top of `BootstrapInjector`.
2. **The bootstrap boundary carries `java.base` types only.** `AgentRuntime.bootstrap` takes a
   single `Map<String, String>` rather than a reflected signature that has to be edited in two
   places and whose mismatch would surface at runtime in a customer's process.
3. **NDJSON over HTTP is the JVM agent's shipping transport**, not its fallback. It is built on
   `HttpURLConnection`, carries TLS with SPKI certificate pinning (primary and rollover pins,
   per ADR-0005), backs off on failure, and spools to disk when the control plane is unreachable.
4. **gRPC is deferred, not cancelled**, and would require an explicit restructuring: move the
   transport and reporting thread off the bootstrap path so they load on the system loader, have
   the bootstrap-side `Reporter` hand over serialized lines through a `java.base`-only interface,
   and shade gRPC + Netty + protobuf into the agent jar. The gateway would additionally need a
   gRPC server and generated Python stubs.

## Alternatives considered

| Option | Why not |
|---|---|
| Publish the whole agent, gRPC included, to bootstrap | Puts Netty and protobuf on the bootstrap path of the customer's JVM, ahead of their own copies. This is the single most hostile thing an agent can do to a process it does not own. |
| Keep the runtime off bootstrap and skip JDK-core instrumentation | Abandons `String`, `StringBuilder` and `StringConcatFactory` — that is the taint engine. What remains is not an IAST product. |
| Split the transport onto the system loader now and ship gRPC | The correct eventual design, and the deferral above describes it. It is a substantial change to a component that currently works, verified end to end, and it also requires a gRPC server on the gateway. Not a change to make alongside five others. |
| Use a separate isolated class loader for the transport | Same restructuring, plus a loader we would then have to maintain. Worth revisiting when gRPC is picked up. |

## Consequences

### Positive
- The failure mode is now understood and documented rather than rediscovered. The three linkage
  errors above cost more time than any other part of the agent.
- The agent adds **no** third-party classes to the customer's bootstrap path beyond its own
  runtime. Byte Buddy stays on the system loader, shaded.
- A `Map`-based bootstrap boundary means adding a setting can no longer produce a signature
  mismatch discovered in production.

### Negative
- **ADR-0005's primary transport is not what ships.** Efficiency and streaming are worse than
  gRPC would give: HTTP/1.1 request-response per batch, JSON rather than protobuf on the wire.
  At current batch sizes this is not the bottleneck, but it is a real gap against the design.
- Bidirectional streaming — and with it server-initiated configuration push — is unavailable.
  Remote configuration must be polled on the heartbeat instead.
- Contributors touching `dev.aegis.agent.{taint,runtime,detect,redact,report}` must know this
  rule. It is not enforced by the compiler; it fails at runtime, in someone else's process.

### Neutral
- The other four agents (.NET, Node, Python, Go) have no equivalent constraint. Nothing here
  binds their transport choice, and the protobuf contracts in `packages/proto` remain the shared
  source of truth for the wire schema regardless of framing.

## Compliance

- `BootstrapInjector.BOOTSTRAP_PACKAGES` is the enumerated list; anything added to it inherits
  the constraint.
- `AgentIT` and `ServletIT` launch a real JVM with the packaged jar, which is the only way this
  class of failure appears at all — none of it reproduces in a unit test running from a
  directory.
- **Open:** a build-time check that no bootstrap-published class references a type outside
  `java.base`. Today the integration suite catches it, but only after the fact.
