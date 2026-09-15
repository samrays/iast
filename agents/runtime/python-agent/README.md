# Aegis IAST Python Runtime Agent

Language-native IAST & RASP agent for Python 3.11+ applications.

## Features

- **Taint Tracking**: Tracks dataflow from untrusted sources (query parameters, headers, body) to security sinks (SQL statements, subprocess execution, file path operations).
- **Zero-Crash Safety (Fail-Open)**: All instrumentation wrappers catch internal exceptions to ensure application code never crashes due to agent execution.
- **Async & Thread-Local Context**: Leverages `contextvars` for non-interfering request trace propagation across `asyncio` tasks.
- **Sanitizer Awareness**: Recognizes URL encoding, SQL parameterization, and HTML escaping sanitizers to reduce false positives.

## Quick Start

```python
from aegis_python_agent import AegisAgent

# Start runtime instrumentation
agent = AegisAgent.start(
    agent_id="00000000-0000-0000-0000-000000000001",
    organization_id="00000000-0000-0000-0000-000000000002",
    gateway_url="http://localhost:8081",
)
```
