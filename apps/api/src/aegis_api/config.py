"""Application configuration.

Twelve-factor: everything comes from the environment, nothing is baked into an image, and
production refuses to start with a development default in a security-relevant field.

This module sits outside the layered packages deliberately — settings are a composition
concern, read at startup and injected downward as plain policy objects, so the domain never
imports it.
"""

from __future__ import annotations

import secrets
from enum import StrEnum
from functools import lru_cache
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from .domain.policies import InventoryPolicy, LockoutPolicy, MfaPolicy, PasswordPolicy, TokenPolicy


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
    """Runtime configuration, populated from ``AEGIS_*`` environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="AEGIS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Application ---------------------------------------------------------
    environment: Environment = Environment.LOCAL
    debug: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    service_name: str = "aegis-api"
    version: str = "0.2.0"
    api_prefix: str = "/api/v1"
    product_name: str = "Aegis IAST"

    # --- Database ------------------------------------------------------------
    database_url: str = "postgresql+asyncpg://aegis:aegis_local_dev@localhost:5433/aegis"
    test_database_url: str | None = None
    database_pool_size: Annotated[int, Field(ge=1, le=100)] = 10
    database_max_overflow: Annotated[int, Field(ge=0, le=100)] = 20
    database_pool_timeout: int = 30
    database_echo: bool = False
    enforce_row_level_security: bool = True

    # --- Redis ---------------------------------------------------------------
    redis_url: str = "redis://localhost:6379/0"

    # --- Tokens and crypto ---------------------------------------------------
    jwt_secret: str = ""
    jwt_algorithm: Literal["HS256", "HS512", "RS256", "EdDSA"] = "HS256"
    #: Base64 Ed25519 public key that rule bundles must be signed with. Empty means no bundle
    #: can be installed, which is the safe default: the built-in catalogue still applies.
    rule_signing_public_key: str = ""
    jwt_issuer: str = "https://api.aegis.local"
    jwt_private_key: str | None = None
    jwt_public_key: str | None = None
    access_token_ttl_seconds: Annotated[int, Field(ge=60, le=3600)] = 900
    refresh_token_ttl_seconds: Annotated[int, Field(ge=3600)] = 2_592_000
    refresh_rotation_grace_seconds: Annotated[int, Field(ge=0, le=120)] = 10
    mfa_challenge_ttl_seconds: Annotated[int, Field(ge=60, le=900)] = 300
    max_sessions_per_user: Annotated[int, Field(ge=1, le=100)] = 10
    secret_encryption_key: str = ""

    # --- Password and lockout ------------------------------------------------
    password_min_length: Annotated[int, Field(ge=8, le=128)] = 12
    password_require_uppercase: bool = False
    password_require_digit: bool = False
    password_require_symbol: bool = False
    max_failed_logins: Annotated[int, Field(ge=3, le=20)] = 5
    lockout_base_seconds: Annotated[int, Field(ge=5)] = 60
    lockout_max_seconds: Annotated[int, Field(ge=60)] = 3600

    # Argon2id parameters. Defaults follow OWASP's recommendation of 64 MiB / t=3 / p=4;
    # they are tunable because memory cost must be balanced against pod memory limits.
    argon2_time_cost: Annotated[int, Field(ge=1)] = 3
    argon2_memory_cost_kib: Annotated[int, Field(ge=8192)] = 65536
    argon2_parallelism: Annotated[int, Field(ge=1, le=16)] = 4

    # --- MFA -----------------------------------------------------------------
    mfa_issuer: str = "Aegis IAST"
    mfa_valid_window: Annotated[int, Field(ge=0, le=4)] = 1
    mfa_recovery_code_count: Annotated[int, Field(ge=4, le=20)] = 10
    require_mfa_for_privileged_roles: bool = False

    # --- Features ------------------------------------------------------------
    allow_self_service_signup: bool = True

    # --- HTTP ----------------------------------------------------------------
    # ``NoDecode`` stops pydantic-settings from attempting to JSON-parse the raw env value;
    # the validator below accepts the far friendlier comma-separated form.
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://localhost:3100",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:3100",
        ]
    )
    rate_limit_anonymous_per_minute: int = 10
    rate_limit_user_per_minute: int = 600
    rate_limit_api_key_per_minute: int = 6000
    max_page_size: int = 200
    default_page_size: int = 50

    # --- Observability -------------------------------------------------------
    otel_enabled: bool = False
    otel_endpoint: str = "http://localhost:4317"
    metrics_enabled: bool = True

    # --- Validation ----------------------------------------------------------

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @model_validator(mode="after")
    def _validate_secrets(self) -> Settings:
        """Refuse to start production-like environments with placeholder secrets.

        In local and test environments a random secret is generated instead, so a fresh
        clone runs without ceremony. That is safe there and unacceptable anywhere else —
        a rotating secret would invalidate tokens on every restart in production.
        """
        if self.environment.is_production_like:
            if self.jwt_algorithm.startswith("HS"):
                if self.jwt_secret.strip().lower() in _INSECURE_DEFAULTS:
                    raise ValueError(
                        "AEGIS_JWT_SECRET must be set to a strong random value outside local use."
                    )
                if len(self.jwt_secret) < 32:
                    raise ValueError("AEGIS_JWT_SECRET must be at least 32 characters.")
            elif not (self.jwt_private_key and self.jwt_public_key):
                raise ValueError(
                    "Asymmetric JWT algorithms require AEGIS_JWT_PRIVATE_KEY "
                    "and AEGIS_JWT_PUBLIC_KEY."
                )
            if not self.secret_encryption_key:
                raise ValueError(
                    "AEGIS_SECRET_ENCRYPTION_KEY must be set so MFA secrets are encrypted at rest."
                )
            if self.debug:
                raise ValueError("Debug mode must not be enabled outside development.")
            if "*" in self.cors_origins:
                raise ValueError("A wildcard CORS origin is not permitted outside development.")
        else:
            if self.jwt_secret.strip().lower() in _INSECURE_DEFAULTS:
                object.__setattr__(self, "jwt_secret", secrets.token_urlsafe(64))
        return self

    # --- Derived policy objects ----------------------------------------------

    @property
    def password_policy(self) -> PasswordPolicy:
        return PasswordPolicy(
            min_length=self.password_min_length,
            require_uppercase=self.password_require_uppercase,
            require_digit=self.password_require_digit,
            require_symbol=self.password_require_symbol,
        )

    @property
    def lockout_policy(self) -> LockoutPolicy:
        return LockoutPolicy(
            max_failed_attempts=self.max_failed_logins,
            base_seconds=self.lockout_base_seconds,
            max_seconds=self.lockout_max_seconds,
        )

    @property
    def token_policy(self) -> TokenPolicy:
        return TokenPolicy(
            access_ttl_seconds=self.access_token_ttl_seconds,
            refresh_ttl_seconds=self.refresh_token_ttl_seconds,
            mfa_challenge_ttl_seconds=self.mfa_challenge_ttl_seconds,
            rotation_grace_seconds=self.refresh_rotation_grace_seconds,
            max_sessions_per_user=self.max_sessions_per_user,
        )

    @property
    def mfa_policy(self) -> MfaPolicy:
        return MfaPolicy(
            valid_window=self.mfa_valid_window,
            recovery_code_count=self.mfa_recovery_code_count,
            require_for_privileged_roles=self.require_mfa_for_privileged_roles,
        )

    @property
    def inventory_policy(self) -> InventoryPolicy:
        return InventoryPolicy()

    @property
    def effective_database_url(self) -> str:
        if self.environment is Environment.TEST and self.test_database_url:
            return self.test_database_url
        return self.database_url


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton. Cleared by the test suite between configurations."""
    return Settings()
