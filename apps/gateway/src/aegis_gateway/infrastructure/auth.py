"""Agent credential verification.

Stateless by design. The agent token is a JWT signed by the control plane with the
``aegis:agent`` audience; verifying it is a signature check and nothing more. If this needed a
database round trip, the control plane's PostgreSQL would become the ceiling on ingest
throughput — which is exactly what the gateway exists to avoid (docs/01 §3).
"""

from __future__ import annotations

import jwt
from jwt.exceptions import InvalidTokenError

from ..application.context import AgentPrincipal
from ..domain.errors import AgentAuthenticationError

AGENT_AUDIENCE = "aegis:agent"


class JwtAgentAuthenticator:
    """Verifies agent tokens issued by the control plane."""

    def __init__(
        self,
        *,
        secret: str,
        algorithm: str = "HS256",
        issuer: str = "https://api.aegis.local",
        public_key: str | None = None,
        leeway_seconds: int = 30,
    ) -> None:
        self._algorithm = algorithm
        self._issuer = issuer
        # Asymmetric verification is the right production posture: the gateway is the most
        # exposed service in the platform and has no business holding a signing key.
        self._key = public_key if public_key and not algorithm.startswith("HS") else secret
        # A little more clock leeway than the API allows: agents run on customer hosts whose
        # clocks the platform does not control.
        self._leeway = leeway_seconds

    def authenticate(self, credential: str) -> AgentPrincipal:
        token = self._strip_scheme(credential)
        try:
            claims = jwt.decode(
                token,
                self._key,
                algorithms=[self._algorithm],
                audience=AGENT_AUDIENCE,
                issuer=self._issuer,
                leeway=self._leeway,
                options={"require": ["exp", "iat", "sub", "aud", "iss"]},
            )
        except InvalidTokenError as exc:
            # The specific reason is never returned to the caller — it would tell an attacker
            # probing with forged tokens exactly which check they still need to pass.
            raise AgentAuthenticationError from exc

        if claims.get("purpose") != "agent":
            raise AgentAuthenticationError("This token is not an agent credential.")

        agent_id = str(claims.get("sub", ""))
        organization_id = str(claims.get("org", ""))
        if not agent_id or not organization_id:
            raise AgentAuthenticationError

        return AgentPrincipal(
            agent_id=agent_id,
            organization_id=organization_id,
            environment_id=str(claims.get("env", "")),
        )

    @staticmethod
    def _strip_scheme(credential: str) -> str:
        value = (credential or "").strip()
        if not value:
            raise AgentAuthenticationError
        if value.lower().startswith("bearer "):
            return value[7:].strip()
        return value
