"""TOTP (RFC 6238) second factor."""

from __future__ import annotations

from datetime import datetime

import pyotp


class PyOtpTotpService:
    """Standard 6-digit, 30-second TOTP compatible with every mainstream authenticator."""

    def __init__(self, *, digits: int = 6, period_seconds: int = 30, valid_window: int = 1) -> None:
        self._digits = digits
        self._period = period_seconds
        # One period of drift either side. Wider windows are a real weakening: each extra
        # period multiplies the number of codes an attacker's guess could match.
        self._valid_window = valid_window

    def generate_secret(self) -> str:
        return pyotp.random_base32()

    def provisioning_uri(self, secret: str, *, account: str, issuer: str) -> str:
        return pyotp.TOTP(secret, digits=self._digits, interval=self._period).provisioning_uri(
            name=account, issuer_name=issuer
        )

    def verify(self, secret: str, code: str, *, now: datetime) -> bool:
        candidate = (code or "").strip().replace(" ", "")
        if not candidate.isdigit() or len(candidate) != self._digits:
            return False
        totp = pyotp.TOTP(secret, digits=self._digits, interval=self._period)
        # pyotp compares in constant time internally.
        return bool(totp.verify(candidate, for_time=now, valid_window=self._valid_window))
