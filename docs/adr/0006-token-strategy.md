# ADR-0006: Short-lived access JWT with rotating opaque refresh tokens and reuse detection

- **Status:** Accepted
- **Date:** 2026-07-27
- **Deciders:** Security, Platform architecture

## Context

Session credentials for this product grant access to a complete inventory of a customer's unfixed
vulnerabilities. Stolen-token persistence is the threat we most need to bound. At the same time, the
console is a data-dense SPA making many requests per view, so per-request database session lookups are
a real cost, and permission revocation must take effect promptly rather than at token expiry.

## Decision

Two credentials with different properties:

**Access token — JWT, 15 minutes, stateless.**
- `HS256` in single-deployment mode; `RS256`/`EdDSA` with rotating keys and a JWKS endpoint when the
  gateway and API are separately deployed.
- Claims: `iss`, `aud: aegis:user`, `sub`, `org`, `sid`, `perms`, `mfa`, `iat`, `exp`, `jti`.
- Held **in memory only** in the browser. Never in `localStorage`.
- The `perms` claim is an optimization for cheap early rejection. **The application layer re-resolves
  permissions from the database on every authorization decision**, so a revoked role takes effect on
  the next request, not in fifteen minutes.

**Refresh token — opaque, 30-day absolute lifetime, stateful, rotating.**
- 256 bits of CSPRNG entropy, stored only as a SHA-256 hash (it is high-entropy, so a slow KDF buys
  nothing here — unlike passwords).
- Delivered in an `HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth` cookie.
- **Rotated on every use.** The old token is immediately marked consumed.
- Each token belongs to a **family** (`family_id`), created at login and inherited by every rotation.

**Reuse detection.** If a consumed refresh token is presented again, the only explanations are token
theft or a client race. We treat it as theft: the entire family is revoked, every session in it dies,
a `security.token_reuse` audit event is written, and the user is notified. The legitimate user
re-authenticates; the attacker's stolen token is dead.

Separate audiences isolate principal types: `aegis:user`, `aegis:agent`, `aegis:mfa_challenge`. An
agent token is rejected by user endpoints and vice versa.

## Alternatives considered

| Option | Why not |
|---|---|
| Server-side sessions only (cookie + Redis lookup) | Simplest and genuinely secure, but a Redis round trip on every request, and it does not translate to the agent and CI principals that also need bearer credentials |
| Long-lived JWT, no refresh | Revocation becomes impossible without a blocklist, which reintroduces the state we were avoiding while keeping all the risk |
| Refresh token without rotation | A stolen refresh token is valid for its full lifetime with no detection signal |
| Rotation without family revocation | Detects theft but does nothing about it — the attacker simply keeps the newest token |
| OAuth2/OIDC against an external IdP as the only path | Required for enterprise SSO and is on the Phase 3 roadmap, but the platform still needs first-party credentials for trials, break-glass access, and on-premises deployments with no IdP |

## Consequences

### Positive
- A stolen access token is useful for at most fifteen minutes.
- A stolen refresh token is detected on first concurrent use and kills the attacker's access.
- No database round trip to *validate* a token; the database round trip that does happen (permission
  resolution) is one we need anyway and is cache-friendly.
- `SameSite=Strict` on a narrow path largely removes CSRF exposure on the refresh endpoint.

### Negative
- Rotation is stateful, so the sessions table is written on every refresh — roughly one write per user
  per fifteen minutes. Acceptable, and the table is partition-friendly.
- A client race (two tabs refreshing simultaneously) can trigger a false-positive revocation. Mitigated
  with a 10-second grace window during which the immediate predecessor token is accepted without
  triggering family revocation, and a single-flight refresh mutex in the dashboard client.
- Access tokens cannot be revoked mid-life. Accepted, because permissions are re-resolved server-side
  and the window is fifteen minutes.

### Neutral
- Enterprise SSO (SAML/OIDC) will federate into the same session model: the IdP assertion produces a
  session and the same token pair.

## Compliance

- Tests assert: rotation issues a new token and invalidates the old; reuse revokes the family and
  writes the audit event; the grace window works; agent-audience tokens are rejected on user routes.
- A test asserts refresh tokens are never returned in a JSON body when cookie mode is enabled.
- A lint rule forbids `localStorage` in the dashboard's auth module.
