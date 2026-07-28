"""Aegis IAST ingest gateway.

The hot path: agent authentication, wire-schema validation, per-tenant quota and fan-out to
the durable event stream. Stateless and horizontally scalable — it performs no database
writes, which is what lets it absorb ingest spikes the control plane could not (docs/01 §3).
"""

__version__ = "0.4.0"
