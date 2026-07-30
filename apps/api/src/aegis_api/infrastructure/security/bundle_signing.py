"""Ed25519 verification for rule bundles.

The algorithm lives here rather than in the domain: which curve we use is an infrastructure
decision, while *what the signature protects* is policy and belongs with the rules.

Ed25519 rather than RSA because the keys and signatures are small, there is no padding mode to
get wrong, and there are no parameters an operator can accidentally weaken.
"""

from __future__ import annotations

import base64
from collections.abc import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class SigningKeyUnavailableError(RuntimeError):
    """No usable public key, so nothing can be verified."""


def verifier_for(public_key_b64: str) -> Callable[[bytes, bytes], None]:
    """Build a verify callable from a base64 raw Ed25519 public key.

    Raises rather than returning a permissive verifier when the key is missing or malformed. A
    deployment with a broken key must fail to install bundles, not install them unchecked —
    the failure mode of a silently-accepting verifier is a catalogue an attacker can rewrite.
    """
    raw = (public_key_b64 or "").strip()
    if not raw:
        raise SigningKeyUnavailableError(
            "No rule-signing public key is configured; bundles cannot be verified."
        )
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(raw, validate=True))
    except Exception as exc:
        raise SigningKeyUnavailableError("The rule-signing public key is not usable.") from exc

    def verify(message: bytes, signature: bytes) -> None:
        key.verify(signature, message)

    return verify


def generate_keypair() -> tuple[str, str]:
    """A private/public pair, base64-encoded. For bootstrapping a publisher, not for serving.

    :returns: ``(private_b64, public_b64)``. The private half is never stored by this service;
        it belongs wherever bundles are published from, which should not be a machine that
        also serves traffic.
    """
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    private = Ed25519PrivateKey.generate()
    return (
        base64.b64encode(
            private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        ).decode(),
        base64.b64encode(
            private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode(),
    )


def sign_with(private_key_b64: str, message: bytes) -> bytes:
    """Sign, for the publishing tool. The serving process never calls this."""
    private = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(private_key_b64.strip(), validate=True)
    )
    return private.sign(message)
