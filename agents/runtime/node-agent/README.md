# Aegis IAST Node.js Runtime Agent

Language-native Node.js IAST & RASP agent leveraging `async_hooks` for context propagation.

## Features

- **Async Context Tracking**: Uses Node.js native `AsyncLocalStorage` (`async_hooks`) to propagate request context across async calls, callbacks, and Promises.
- **Taint Engine**: Marks untrusted HTTP parameters, query strings, and headers; tracks taint flow to critical sinks.
- **Fail-Open Safety**: All sink inspectors operate inside try-catch boundaries to guarantee application code never crashes due to telemetry processing.
- **Sink Monitoring**: Inspects SQL queries, `child_process.exec`, and file path access.

## Quick Start

```typescript
import { AegisAgent } from "@aegis/node-agent";

// Initialize agent
const agent = AegisAgent.start({
  agentId: "node-agent-1",
  organizationId: "org-1",
});
```
