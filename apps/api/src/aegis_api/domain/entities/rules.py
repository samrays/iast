"""The detection rule catalogue: what the agent looks for, and who decided it should.

Rules are shipped as **versioned, signed bundles** rather than rows an operator edits. That is
a security decision, not an operational preference. The catalogue drives what gets detected
and — once blocking exists — what gets stopped, so an attacker who can write to it can turn
detection off for the flaw they intend to exploit, and do it quietly. A row in a table is
writable by anything holding a database credential; a signed bundle is only writable by
whoever holds the signing key, which is nobody in the serving path.

Three properties follow, and each exists because of a specific attack:

* **Signed** — a modified bundle fails verification rather than loading. Guards against a
  tampered catalogue silently disabling a rule class.
* **Monotonic** — a bundle older than the one installed is refused. Guards against rollback:
  re-presenting a genuinely signed *old* bundle to remove a rule added since.
* **Canonical** — the signature covers a byte-exact serialization, so re-encoding cannot
  change meaning while keeping the signature valid.

Tenants may disable rules, and that is deliberately a *separate* concept from the bundle. A
customer switching off log injection for their own reasons must not look like the catalogue
changing, and must not survive into anybody else's tenant.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from ..errors import InvalidStateError, ValidationError
from ..value_objects import new_id
from .findings import Severity


@dataclass(frozen=True, slots=True)
class Rule:
    """One detection rule, as published in a bundle."""

    key: str
    title: str
    severity: Severity
    cwe_id: int | None = None
    description: str = ""
    remediation: str = ""

    def __post_init__(self) -> None:
        if not self.key or not self.key.strip():
            raise ValidationError("A rule must have a key.", field="key")
        if self.key != self.key.strip().lower():
            # Keys reach the finding identity hash. A key differing only in case would mint a
            # second identity for the same defect.
            raise ValidationError("A rule key must be lower-case and trimmed.", field="key")

    def to_canonical(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "severity": self.severity.value,
            "cwe_id": self.cwe_id,
            "description": self.description,
            "remediation": self.remediation,
        }

    @classmethod
    def from_canonical(cls, raw: dict[str, Any]) -> Rule:
        return cls(
            key=str(raw["key"]),
            title=str(raw.get("title", "")),
            severity=Severity(str(raw.get("severity", "MEDIUM"))),
            cwe_id=int(raw["cwe_id"]) if raw.get("cwe_id") is not None else None,
            description=str(raw.get("description", "")),
            remediation=str(raw.get("remediation", "")),
        )


@dataclass(frozen=True, slots=True)
class RuleBundle:
    """A published, signable set of rules."""

    version: int
    rules: tuple[Rule, ...]
    published_at: datetime

    def __post_init__(self) -> None:
        if self.version < 0:
            raise ValidationError("A bundle version may not be negative.", field="version")
        keys = [rule.key for rule in self.rules]
        if len(keys) != len(set(keys)):
            # Two rules with one key means the second silently wins, and which one that is
            # depends on iteration order.
            raise ValidationError("A bundle may not repeat a rule key.", field="rules")

    def canonical_bytes(self) -> bytes:
        """The exact bytes that get signed.

        Sorted keys, no insignificant whitespace, UTF-8. Signing a pretty-printed document
        would let a re-indent invalidate a valid signature — or worse, let two different
        documents share one.
        """
        document = {
            "version": self.version,
            "published_at": self.published_at.isoformat(),
            "rules": [rule.to_canonical() for rule in sorted(self.rules, key=lambda r: r.key)],
        }
        return json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    @classmethod
    def from_canonical_bytes(cls, raw: bytes) -> RuleBundle:
        document = json.loads(raw.decode("utf-8"))
        return cls(
            version=int(document["version"]),
            rules=tuple(Rule.from_canonical(item) for item in document["rules"]),
            published_at=datetime.fromisoformat(str(document["published_at"])),
        )

    def rule(self, key: str) -> Rule | None:
        return next((rule for rule in self.rules if rule.key == key), None)


class BundleRejectedError(InvalidStateError):
    """The bundle is not one this deployment will load."""


def accept_bundle(
    *,
    candidate: RuleBundle,
    signature: bytes,
    verify: Any,
    installed_version: int | None,
) -> RuleBundle:
    """Verify and admit a bundle, or refuse it.

    :param verify: a callable taking ``(message, signature)`` that raises on mismatch. Passed
        in rather than imported so the domain stays free of a crypto library — the algorithm
        is an infrastructure decision, the *policy* below is not.

    Order matters. Signature first, because an unverified bundle's version number is just as
    forged as the rest of it, and comparing it before checking the signature would let an
    attacker probe the installed version.
    """
    try:
        verify(candidate.canonical_bytes(), signature)
    except Exception as exc:
        raise BundleRejectedError("The rule bundle's signature is not valid.") from exc

    if installed_version is not None and candidate.version <= installed_version:
        # A genuinely signed older bundle is still an attack when re-presented: it removes
        # every rule added since. Signatures alone cannot catch this, which is why the check
        # is here and not in the verifier.
        raise BundleRejectedError(
            f"Bundle version {candidate.version} is not newer than the installed "
            f"version {installed_version}."
        )
    return candidate


@dataclass(slots=True)
class TenantRuleSettings:
    """Which rules one organization has turned off, and why.

    Separate from the bundle on purpose. A customer disabling a rule is not the catalogue
    changing — it must not affect any other tenant, and it must survive the next bundle
    upgrade rather than being silently re-enabled by it.
    """

    organization_id: UUID
    disabled: dict[str, str] = field(default_factory=dict)
    id: UUID = field(default_factory=new_id)
    updated_at: datetime | None = None

    #: A tenant with everything switched off is a tenant with no product. Past this, the UI
    #: should be asking whether they want to uninstall rather than accepting another opt-out.
    MAX_DISABLED = 64

    def disable(self, rule_key: str, *, reason: str) -> None:
        """Turn a rule off for this tenant.

        A reason is required for the same purpose it is on a suppressed finding: somebody will
        find this switched off months later and need to know whether it still should be.
        """
        if not reason.strip():
            raise InvalidStateError("Disabling a rule requires a reason.")
        if rule_key not in self.disabled and len(self.disabled) >= self.MAX_DISABLED:
            raise InvalidStateError(
                f"At most {self.MAX_DISABLED} rules may be disabled for one organization."
            )
        self.disabled[rule_key] = reason.strip()[:500]

    def enable(self, rule_key: str) -> None:
        self.disabled.pop(rule_key, None)

    def is_enabled(self, rule_key: str) -> bool:
        """Default on.

        A rule absent from this map is active. A catalogue that defaulted to off would ship a
        product that detects nothing until somebody configures it, and the first thing anybody
        would notice is a clean report.
        """
        return rule_key not in self.disabled

    def effective_rules(self, bundle: RuleBundle) -> tuple[Rule, ...]:
        return tuple(rule for rule in bundle.rules if self.is_enabled(rule.key))


#: The catalogue compiled into this build.
#:
#: Shipping a product whose detection is empty until an operator publishes a bundle would be a
#: product that reports nothing on day one — and a clean report is the most dangerous output
#: this system has. The built-in is the floor; signed bundles raise it.
#:
#: Version 0 deliberately: every published bundle is version >= 1, so the monotonic check in
#: :func:`accept_bundle` admits the first real bundle without a special case.
BUILTIN_BUNDLE_VERSION = 0


def builtin_catalogue(published_at: datetime) -> RuleBundle:
    """The rules this build knows about, independent of anything in the database."""
    return RuleBundle(
        version=BUILTIN_BUNDLE_VERSION,
        published_at=published_at,
        rules=tuple(
            Rule(
                key=key,
                title=title,
                severity=severity,
                cwe_id=cwe,
                description=description,
            )
            for key, title, severity, cwe, description in _BUILTIN_RULES
        ),
    )


_BUILTIN_RULES: tuple[tuple[str, str, Severity, int, str], ...] = (
    (
        "sql-injection",
        "SQL injection",
        Severity.CRITICAL,
        89,
        "Untrusted input reaches a SQL statement without being bound as a parameter.",
    ),
    (
        "command-injection",
        "OS command injection",
        Severity.CRITICAL,
        78,
        "Untrusted input reaches an operating-system command.",
    ),
    (
        "unsafe-deserialization",
        "Unsafe deserialization",
        Severity.CRITICAL,
        502,
        "An attacker-controlled stream reaches a native deserializer.",
    ),
    (
        "xxe",
        "XML External Entity (XXE) injection",
        Severity.CRITICAL,
        611,
        "Untrusted XML reaches a parser without external entity or DTD processing disabled.",
    ),
    (
        "path-traversal",
        "Path traversal",
        Severity.HIGH,
        22,
        "Untrusted input reaches a filesystem path without being confined to a base directory.",
    ),
    (
        "reflected-xss",
        "Reflected cross-site scripting",
        Severity.HIGH,
        79,
        "Untrusted input reaches the response body without contextual escaping.",
    ),
    (
        "ssrf",
        "Server-side request forgery",
        Severity.HIGH,
        918,
        "Untrusted input decides the destination of an outbound request.",
    ),
    (
        "ldap-injection",
        "LDAP injection",
        Severity.HIGH,
        90,
        "Untrusted input reaches an LDAP search filter.",
    ),
    (
        "xpath-injection",
        "XPath injection",
        Severity.HIGH,
        643,
        "Untrusted input reaches an XPath expression.",
    ),
    (
        "open-redirect",
        "Open redirect",
        Severity.MEDIUM,
        601,
        "Untrusted input decides a redirect destination.",
    ),
    (
        "header-injection",
        "HTTP header injection",
        Severity.MEDIUM,
        113,
        "Untrusted input reaches a response header name or value.",
    ),
    (
        "log-injection",
        "Log injection",
        Severity.MEDIUM,
        117,
        "Untrusted input reaches a log record without newline neutralization.",
    ),
)
