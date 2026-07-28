"""Architectural constraints from ADR-0002, asserted as tests.

Layer discipline decays the moment it stops being enforced, so it is enforced here as well
as in ``scripts/check_layering.py``.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]


def test_domain_does_not_import_frameworks() -> None:
    """Importing the domain must not drag in SQLAlchemy, FastAPI or Pydantic.

    Run in a subprocess because the test session itself has already imported all three;
    checking ``sys.modules`` in-process would prove nothing.
    """
    script = (
        "import sys;"
        "import aegis_api.domain.entities, aegis_api.domain.ports,"
        " aegis_api.domain.policies, aegis_api.domain.permissions;"
        "leaked=[m for m in ('sqlalchemy','fastapi','starlette','pydantic','redis','jwt')"
        " if m in sys.modules];"
        "print(','.join(leaked))"
    )
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=True,
        cwd=REPO_ROOT / "apps" / "api",
    )
    assert result.stdout.strip() == "", f"domain leaked imports: {result.stdout.strip()}"


def test_application_layer_does_not_import_infrastructure_libraries() -> None:
    application = REPO_ROOT / "apps" / "api" / "src" / "aegis_api" / "application"
    forbidden = ("import sqlalchemy", "from sqlalchemy", "import fastapi", "from fastapi")
    offenders = [
        f"{path.name}: {line}"
        for path in application.rglob("*.py")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith(forbidden)
    ]
    assert not offenders, offenders


@pytest.mark.skipif(
    not (REPO_ROOT / "scripts" / "check_layering.py").exists(),
    reason="layering script not present",
)
def test_layering_script_passes() -> None:
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(REPO_ROOT / "scripts" / "check_layering.py")],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stdout + result.stderr
