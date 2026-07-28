#!/usr/bin/env python
"""Enforce the hexagonal layering rules from ADR-0002.

Dependencies must point inward only:

    interfaces -> infrastructure -> application -> domain

Run from the repository root::

    python scripts/check_layering.py

Exits non-zero and prints every violation when a module imports outward or when an
inner layer reaches for a framework it is forbidden to know about.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Package roots that follow the layered structure, relative to the repository root.
LAYERED_PACKAGES = (
    Path("apps/api/src/aegis_api"),
    Path("apps/gateway/src/aegis_gateway"),
    Path("apps/worker/src/aegis_worker"),
)

LAYERS = ("domain", "application", "infrastructure", "interfaces")

# A layer may import from itself and from every layer to its left.
ALLOWED_INWARD: dict[str, frozenset[str]] = {
    "domain": frozenset({"domain"}),
    "application": frozenset({"domain", "application"}),
    "infrastructure": frozenset({"domain", "application", "infrastructure"}),
    "interfaces": frozenset({"domain", "application", "infrastructure", "interfaces"}),
}

# Third-party top-level packages each layer is forbidden to import.
FORBIDDEN_THIRD_PARTY: dict[str, frozenset[str]] = {
    "domain": frozenset(
        {
            "sqlalchemy",
            "fastapi",
            "starlette",
            "pydantic",
            "redis",
            "aiokafka",
            "kafka",
            "httpx",
            "requests",
            "celery",
            "alembic",
            "jose",
            "jwt",
            "argon2",
            "clickhouse_connect",
            "opensearchpy",
            "boto3",
        }
    ),
    "application": frozenset(
        {
            "sqlalchemy",
            "fastapi",
            "starlette",
            "redis",
            "aiokafka",
            "kafka",
            "httpx",
            "requests",
            "celery",
            "alembic",
            "clickhouse_connect",
            "opensearchpy",
            "boto3",
        }
    ),
    "infrastructure": frozenset({"fastapi", "starlette"}),
    "interfaces": frozenset(),
}


@dataclass(frozen=True)
class Violation:
    path: Path
    line: int
    layer: str
    imported: str
    reason: str

    def __str__(self) -> str:
        rel = self.path.relative_to(REPO_ROOT).as_posix()
        return f"{rel}:{self.line}: [{self.layer}] imports {self.imported!r} — {self.reason}"


def _layer_of(path: Path, package_root: Path) -> str | None:
    """Return the layer a module belongs to, or None if it sits outside the layers."""
    try:
        parts = path.relative_to(package_root).parts
    except ValueError:
        return None
    return parts[0] if parts and parts[0] in LAYERS else None


def _imported_names(tree: ast.AST) -> list[tuple[str, int]]:
    """Collect absolute dotted module names from every import statement."""
    names: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend((alias.name, node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            # Relative imports stay within the current package and are checked by
            # resolving them against the module's own position below.
            if node.level == 0 and node.module:
                names.append((node.module, node.lineno))
    return names


def _resolve_relative(module_path: Path, package_root: Path, node: ast.ImportFrom) -> str | None:
    """Resolve a relative ImportFrom to a dotted path under the package root."""
    package_parts = list(module_path.relative_to(package_root).parts[:-1])
    up = node.level - 1
    if up > len(package_parts):
        return None
    base = package_parts[: len(package_parts) - up] if up else package_parts
    tail = node.module.split(".") if node.module else []
    return ".".join([package_root.name, *base, *tail])


def check_file(path: Path, package_root: Path) -> list[Violation]:
    layer = _layer_of(path, package_root)
    if layer is None:
        return []

    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:  # pragma: no cover - a syntax error fails elsewhere too
        return [Violation(path, exc.lineno or 0, layer, "<unparseable>", str(exc))]

    package_name = package_root.name
    allowed = ALLOWED_INWARD[layer]
    forbidden = FORBIDDEN_THIRD_PARTY[layer]
    violations: list[Violation] = []

    candidates: list[tuple[str, int]] = _imported_names(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level > 0:
            resolved = _resolve_relative(path, package_root, node)
            if resolved:
                candidates.append((resolved, node.lineno))

    for module, lineno in candidates:
        head = module.split(".")[0]

        if head == package_name:
            parts = module.split(".")
            target_layer = parts[1] if len(parts) > 1 and parts[1] in LAYERS else None
            if target_layer and target_layer not in allowed:
                violations.append(
                    Violation(
                        path,
                        lineno,
                        layer,
                        module,
                        f"{layer!r} may not depend on {target_layer!r} (dependencies point inward)",
                    )
                )
        elif head in forbidden:
            violations.append(
                Violation(
                    path,
                    lineno,
                    layer,
                    module,
                    f"{head!r} is a forbidden dependency for the {layer!r} layer",
                )
            )

    return violations


def main() -> int:
    violations: list[Violation] = []
    checked = 0

    for rel_root in LAYERED_PACKAGES:
        package_root = REPO_ROOT / rel_root
        if not package_root.is_dir():
            continue
        for path in sorted(package_root.rglob("*.py")):
            checked += 1
            violations.extend(check_file(path, package_root))

    if violations:
        print(f"Layering check FAILED — {len(violations)} violation(s) in {checked} file(s):\n")
        for violation in violations:
            print(f"  {violation}")
        print("\nSee docs/adr/0002-hexagonal-architecture.md")
        return 1

    print(f"Layering check passed — {checked} file(s) inspected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
