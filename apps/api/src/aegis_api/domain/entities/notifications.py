"""Outbound notifications, and the two ways a webhook feature becomes a vulnerability.

A webhook looks like the simplest feature in a product: the customer gives you a URL, you POST
to it. Both halves of that sentence are dangerous.

**The URL is attacker-reachable.** A tenant chooses it, and our infrastructure dials it. Anyone
who can create a webhook can therefore make our servers issue HTTP requests to addresses of
their choosing — the cloud metadata endpoint, an internal admin panel, a database on a private
subnet. That is server-side request forgery with our credentials and our network position, and
it is the single most common way a webhook feature gets exploited. :func:`validate_destination`
is the control.

**The payload is a security notification.** A receiver that cannot tell a genuine alert from a
forged one has a notification channel an attacker can use to say "all clear", or to flood with
noise until the real alert is ignored. :func:`sign_payload` is the control, and it signs the
timestamp as well as the body so a captured delivery cannot be replayed later.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from urllib.parse import urlsplit
from uuid import UUID

from ..errors import InvalidStateError, ValidationError
from ..value_objects import new_id


class NotificationEvent(StrEnum):
    """What a customer can subscribe to.

    Deliberately few. A webhook that fires on everything is one nobody reads, and the point of
    this feature is that the message arriving means something.
    """

    FINDING_OPENED = "finding.opened"
    FINDING_REGRESSED = "finding.regressed"
    ATTACK_DETECTED = "attack.detected"
    AGENT_OFFLINE = "agent.offline"


class DeliveryStatus(StrEnum):
    PENDING = "PENDING"
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"
    #: Too many consecutive failures. Kept distinct from FAILED so a dead endpoint stops
    #: costing us delivery attempts without looking like a transient error.
    DISABLED = "DISABLED"


#: Signature scheme version, sent alongside the digest. Without it there is no way to rotate
#: the algorithm without breaking every receiver at once.
SIGNATURE_VERSION = "v1"

#: How old a delivery may be before a receiver should refuse it. Advisory — enforced by the
#: receiver, which is why it is documented in the header rather than only here.
REPLAY_TOLERANCE_SECONDS = 300


def sign_payload(secret: str, *, timestamp: int, body: bytes) -> str:
    """The value of the signature header.

    The timestamp is inside the signed material, not merely beside it. Signing only the body
    would let anyone who captured one delivery replay it forever; a receiver that checks the
    timestamp is then checking a value the attacker could edit freely.

    Constant-time comparison is the receiver's job, but the format makes it easy: a single
    hex digest, prefixed with a version so the algorithm can change later.
    """
    material = f"{timestamp}.".encode() + body
    digest = hmac.new(secret.encode("utf-8"), material, hashlib.sha256).hexdigest()
    return f"{SIGNATURE_VERSION}={digest}"


def verify_signature(secret: str, *, timestamp: int, body: bytes, signature: str) -> bool:
    """Reference implementation, for our tests and for the documentation we hand receivers."""
    expected = sign_payload(secret, timestamp=timestamp, body=body)
    # compare_digest, not ==: a timing-variable comparison on a MAC is how a forgery gets
    # brute-forced one byte at a time.
    return hmac.compare_digest(expected, signature)


def generate_secret() -> str:
    """A fresh signing secret. Shown once, at creation, and never retrievable."""
    return secrets.token_urlsafe(32)


#: Hosts a tenant may not point us at, beyond the IP checks below. Cloud metadata services are
#: the classic SSRF target: reachable only from inside, unauthenticated, and full of
#: credentials.
_FORBIDDEN_HOSTS = frozenset({"metadata.google.internal", "metadata", "instance-data", "localhost"})


def validate_destination(url: str, *, allow_private: bool = False) -> str:
    """Reject a webhook URL our infrastructure should not dial.

    :param allow_private: only for local development, where the receiver genuinely is on
        localhost. Never true in a deployed environment.

    This is a partial control and worth being honest about: it validates the URL, and DNS can
    resolve differently by the time the request is made. Closing that gap needs resolution
    pinning at the HTTP client, which belongs with the client rather than here. What this stops
    is the direct, overwhelmingly common case — someone typing an internal address in.
    """
    parts = urlsplit(url.strip())

    if parts.scheme != "https":
        # Not merely good practice: the payload says which of the customer's applications is
        # vulnerable and how, which is a map for anybody reading the wire.
        raise ValidationError("A webhook URL must use https.", field="url")
    if not parts.hostname:
        raise ValidationError("A webhook URL must include a host.", field="url")

    host = parts.hostname.lower()
    if host in _FORBIDDEN_HOSTS:
        raise ValidationError("That host is not a permitted webhook destination.", field="url")

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # A name rather than a literal. Resolution happens at delivery time; see the caveat
        # above.
        return url.strip()

    if not allow_private and (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    ):
        # 169.254.169.254 lands here via is_link_local, which is the one that matters most.
        raise ValidationError(
            "A webhook may not target a private, loopback or link-local address.", field="url"
        )
    return url.strip()


@dataclass(slots=True)
class WebhookEndpoint:
    """One place a tenant wants to be told about things."""

    organization_id: UUID
    url: str
    secret: str
    events: tuple[NotificationEvent, ...]
    description: str = ""
    enabled: bool = True
    consecutive_failures: int = 0
    last_delivered_at: datetime | None = None
    last_failure_reason: str = ""
    id: UUID = field(default_factory=new_id)
    created_at: datetime | None = None

    #: After this many consecutive failures the endpoint is switched off. A receiver that has
    #: been gone for a day should stop costing us a delivery attempt per finding, and the
    #: customer should be told rather than left with silent success.
    FAILURES_BEFORE_DISABLE = 20

    def __post_init__(self) -> None:
        if not self.events:
            raise ValidationError("A webhook must subscribe to at least one event.", field="events")
        self.description = (self.description or "").strip()[:200]

    def subscribes_to(self, event: NotificationEvent) -> bool:
        return self.enabled and event in self.events

    def record_success(self, now: datetime) -> None:
        self.consecutive_failures = 0
        self.last_failure_reason = ""
        self.last_delivered_at = now

    def record_failure(self, reason: str) -> bool:
        """:returns: True when this failure switched the endpoint off."""
        self.consecutive_failures += 1
        self.last_failure_reason = reason.strip()[:500]
        if self.consecutive_failures >= self.FAILURES_BEFORE_DISABLE:
            self.enabled = False
            return True
        return False

    def rotate_secret(self) -> str:
        """Issue a new signing secret and return it once."""
        if not self.enabled:
            raise InvalidStateError("Enable the endpoint before rotating its secret.")
        self.secret = generate_secret()
        return self.secret
