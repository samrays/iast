"""HTTP routers, one module per resource family."""

from fastapi import APIRouter

from . import (
    agents,
    ai,
    api_keys,
    applications,
    audit,
    auth,
    benchmark,
    export,
    findings,
    organizations,
    protection,
    reporting,
    rules,
)


def build_api_router(prefix: str) -> APIRouter:
    router = APIRouter(prefix=prefix)
    router.include_router(auth.router)
    router.include_router(organizations.router)
    router.include_router(api_keys.router)
    router.include_router(applications.router)
    router.include_router(applications.environments_router)
    router.include_router(agents.router)
    router.include_router(findings.router)
    router.include_router(ai.router)
    router.include_router(export.router)
    router.include_router(protection.router)
    router.include_router(reporting.router)
    router.include_router(rules.router)
    router.include_router(audit.router)
    router.include_router(benchmark.router)
    return router



__all__ = ["build_api_router"]
