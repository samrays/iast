"""Authenticated encryption for secrets stored at rest."""

from __future__ import annotations

import base64
import contextlib
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from ...domain.errors import DomainError


class SecretDecryptionError(DomainError):
    code = "secret_decryption_failed"
    message = "A stored secret could not be decrypted."


class FernetCipher:
    """Fernet (AES-128-CBC + HMAC-SHA256) for TOTP seeds and similar small secrets.

    Fernet is chosen over hand-rolled AES because it is authenticated by construction and
    has no mode, padding or nonce choices to get wrong. It supports key rotation: decryption
    tries each key in turn, encryption always uses the first.
    """

    def __init__(self, keys: list[str]) -> None:
        if not keys or not keys[0]:
            raise ValueError("At least one encryption key is required.")
        self._fernets = [Fernet(self._normalize(k)) for k in keys if k]

    @staticmethod
    def _normalize(key: str) -> bytes:
        """Accept either a real Fernet key or an arbitrary passphrase.

        A passphrase is stretched to a 32-byte key with SHA-256 so that a deployment which
        set a plain string still gets a valid key rather than a startup crash. Production
        configuration should supply a generated Fernet key.
        """
        raw = key.strip()
        # A decode failure simply means the value is a passphrase, not a Fernet key.
        with contextlib.suppress(Exception):
            decoded = base64.urlsafe_b64decode(raw)
            if len(decoded) == 32:
                return raw.encode()
        return base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest())

    def encrypt(self, plaintext: str) -> str:
        return self._fernets[0].encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        for fernet in self._fernets:
            try:
                return fernet.decrypt(ciphertext.encode()).decode()
            except InvalidToken:
                continue
        raise SecretDecryptionError
