"""Gateway configuration.

Same twelve-factor posture as the control plane, and the same refusal to start with a
placeholder secret in a production-like environment.
"""

from __future__ import annotations

import secrets
from enum import StrEnum
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    LOCAL = "local"
    TEST = "test"
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

    @property
    def is_production_like(self) -> bool:
        return self in (Environment.STAGING, Environment.PRODUCTION)


_INSECURE_DEFAULTS = frozenset(
    {
        "",
        "change-me",
        "changeme",
        "secret",
        "change-me-a-64-byte-random-value-for-local-development-only",
    }
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AEGIS_GATEWAY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    environment: Environment = Environment.LOCAL
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    service_name: str = "aegis-gateway"
    version: str = "0.4.0"

    # --- agent credential verification --------------------------------------
    # Shared with the control plane, which issues the tokens this service verifies.
    jwt_secret: str = ""
    jwt_algorithm: Literal["HS256", "HS512", "RS256", "EdDSA"] = "HS256"
    jwt_issuer: str = "https://api.aegis.local"
    jwt_public_key: str | None = None

    # --- ingest ---------------------------------------------------------------
    #: Where accepted events go. `kafka://`, `file:` or `memory://`.
    event_sink: str = "memory://"
    max_batch_bytes: Annotated[int, Field(ge=1024)] = 8 * 1024 * 1024
    max_batch_events: Annotated[int, Field(ge=1)] = 512
    #: Strict mode fails the whole batch on one malformed event. Useful when developing an
    #: agent; wrong in production, where it would cost a tenant real findings.
    reject_batch_on_invalid: bool = False

    # --- quota ----------------------------------------------------------------
    quota_events_per_second: Annotated[float, Field(gt=0)] = 5_000.0
    quota_burst_multiplier: Annotated[float, Field(ge=1)] = 10.0
    dedup_cache_size: Annotated[int, Field(ge=1_000)] = 100_000

    metrics_enabled: bool = True

    @model_validator(mode="after")
    def _validate_secrets(self) -> Settings:
        if self.environment.is_production_like:
            if self.jwt_algorithm.startswith("HS"):
                if self.jwt_secret.strip().lower() in _INSECURE_DEFAULTS:
                    raise ValueError(
                        "AEGIS_GATEWAY_JWT_SECRET must be set outside local development."
                    )
                if len(self.jwt_secret) < 32:
                    raise ValueError("AEGIS_GATEWAY_JWT_SECRET must be at least 32 characters.")
            elif not self.jwt_public_key:
                raise ValueError("Asymmetric verification requires AEGIS_GATEWAY_JWT_PUBLIC_KEY.")
            if self.event_sink.startswith("memory://"):
                raise ValueError(
                    "The in-memory sink discards events on restart and must not be used "
                    "outside local development."
                )
        elif self.jwt_secret.strip().lower() in _INSECURE_DEFAULTS:
            # A fresh clone runs without ceremony; tokens simply will not verify against a
            # separately-started control plane until both share a secret.
            object.__setattr__(self, "jwt_secret", secrets.token_urlsafe(64))
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
