"""Application layer.

One class per business operation. Every use case:

* receives its dependencies as ports (never concrete adapters),
* performs its **own** authorization — a router guard is a convenience, never the control,
* owns exactly one transaction boundary,
* writes an audit entry for anything that changes state or is denied.

May import ``domain``. May not import SQLAlchemy, FastAPI, Redis or Kafka (ADR-0002).
"""
