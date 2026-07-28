"""Token adapters — the opaque refresh token generator and the access-token JWT codec."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Any, Final
from uuid import UUID, uuid4

import jwt
from jwt.exceptions import InvalidTokenError

from ...domain.errors import TokenError
from ...domain.value_objects import TokenHash

#: 32 bytes = 256 bits of entropy. Guessing is not a threat model at this size; theft is,
#: which is what rotation and reuse detection address (ADR-0006).
_REFRESH_TOKEN_BYTES: Final = 32

#: Audience per principal type. Separation is what stops an agent token from being
#: replayed against a user endpoint (threat T-06).
AUDIENCES: Final[dict[str, str]] = {
    "user": "aegis:user",
    "agent": "aegis:agent",
    "mfa": "aegis:mfa_challenge",
    "reset": "aegis:password_reset",
}


class OpaqueTokenGenerator:
    """Generates refresh tokens and hashes them for storage.

    SHA-256 rather than Argon2: the input already has 256 bits of entropy, so key
    stretching adds latency to every refresh and buys nothing against a brute-force attack
    that was never feasible.
    """

    def generate(self) -> tuple[str, TokenHash]:
        token = secrets.token_urlsafe(_REFRESH_TOKEN_BYTES)
        return token, self.hash(token)

    def hash(self, token: str) -> TokenHash:
        return TokenHash(hashlib.sha256(token.encode("utf-8")).hexdigest())


class JwtAccessTokenCodec:
    """Issues and verifies access tokens and narrow-purpose challenge tokens.

    Symmetric HS256 is the default for a single-deployment control plane. When the gateway
    verifies tokens in a separate process, configure an asymmetric algorithm so the
    verifier never holds a signing key.
    """

    def __init__(
        self,
        *,
        secret: str,
        algorithm: str = "HS256",
        issuer: str = "https://api.aegis.local",
        private_key: str | None = None,
        public_key: str | None = None,
        leeway_seconds: int = 10,
    ) -> None:
        self._algorithm = algorithm
        self._issuer = issuer
        self._leeway = leeway_seconds
        asymmetric = not algorithm.startswith("HS")
        if asymmetric and not (private_key and public_key):
            raise ValueError(f"{algorithm} requires both a private and a public key.")
        # Non-optional by construction: the branch above rejects an asymmetric algorithm
        # without both keys, and the symmetric branch always has the shared secret.
        self._signing_key: str = (private_key or "") if asymmetric else secret
        self._verifying_key: str = (public_key or "") if asymmetric else secret

    # --- issuing -------------------------------------------------------------

    def issue(
        self,
        *,
        subject: UUID,
        organization_id: UUID,
        session_id: UUID,
        permissions: frozenset[str],
        mfa_satisfied: bool,
        ttl_seconds: int,
        now: datetime,
    ) -> tuple[str, datetime]:
        expires_at = now + timedelta(seconds=ttl_seconds)
        claims: dict[str, Any] = {
            "iss": self._issuer,
            "aud": AUDIENCES["user"],
            "sub": str(subject),
            "org": str(organization_id),
            "sid": str(session_id),
            # Advisory only: the application layer re-resolves permissions from the
            # database on every request so revocation is immediate (ADR-0006 §1.4).
            "perms": sorted(permissions),
            "mfa": mfa_satisfied,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": uuid4().hex,
        }
        return jwt.encode(claims, self._signing_key, algorithm=self._algorithm), expires_at

    def issue_challenge(
        self,
        *,
        subject: UUID,
        organization_id: UUID,
        ttl_seconds: int,
        now: datetime,
        purpose: str,
    ) -> str:
        """Issue a single-purpose token (MFA completion, agent credential, reset)."""
        audience = AUDIENCES.get(purpose)
        if audience is None:
            raise ValueError(f"Unknown token purpose: {purpose!r}")
        claims: dict[str, Any] = {
            "iss": self._issuer,
            "aud": audience,
            "sub": str(subject),
            "org": str(organization_id),
            "purpose": purpose,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
            "jti": uuid4().hex,
        }
        return jwt.encode(claims, self._signing_key, algorithm=self._algorithm)

    # --- verifying -----------------------------------------------------------

    def decode(self, token: str, *, audience: str) -> dict[str, Any]:
        try:
            return dict(
                jwt.decode(
                    token,
                    self._verifying_key,
                    algorithms=[self._algorithm],
                    audience=audience,
                    issuer=self._issuer,
                    leeway=self._leeway,
                    options={"require": ["exp", "iat", "sub", "aud", "iss"]},
                )
            )
        except InvalidTokenError as exc:
            # The specific reason (expired, wrong audience, bad signature) is deliberately
            # not surfaced to the caller; it is logged server-side instead.
            raise TokenError from exc
