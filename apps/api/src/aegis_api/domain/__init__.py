"""Domain layer.

Pure business model: entities, value objects, policies, ports and errors. This package
imports nothing but the Python standard library — no SQLAlchemy, no FastAPI, no Pydantic.
The rule is enforced by ``scripts/check_layering.py`` (see ADR-0002).
"""
