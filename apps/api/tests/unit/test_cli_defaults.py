"""The defaults a first-time user actually gets.

The seeded owner email is the first credential anyone types into this product. Its default was
`owner@aegis.local`, which the login endpoint's `EmailStr` rejects — so `aegis-api seed` produced
an account that could not sign in, and the failure surfaced at login rather than at seed time.

A one-line default is exactly the kind of thing no test covers because it looks too simple to get
wrong.
"""

from __future__ import annotations

import inspect

import pytest
from pydantic import BaseModel, EmailStr, ValidationError

from aegis_api import cli


class _Login(BaseModel):
    """Mirrors the constraint the login endpoint applies."""

    email: EmailStr


def _default(command, parameter: str) -> object:
    return inspect.signature(command).parameters[parameter].default.default


def test_the_seeded_owner_can_actually_log_in() -> None:
    _Login(email=_default(cli.seed, "email"))


def test_the_constraint_being_guarded_is_real() -> None:
    # Without this, the test above would still pass if EmailStr ever stopped validating, and the
    # guard would quietly become decoration.
    with pytest.raises(ValidationError):
        _Login(email="owner@aegis.local")
