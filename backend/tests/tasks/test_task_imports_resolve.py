# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Ratchet: every deferred import inside a Celery task module must resolve.

``app/tasks/bulk_operations.py`` contained, in three separate functions::

    from app.adapters import adapter_factory  # type: ignore[attr-defined]

``adapter_factory`` has never existed in this codebase. Because the import sat
INSIDE the function body it did not fail at collection or at worker start-up --
it failed on first execution, where the broad ``except Exception`` in
``_execute_on_device`` swallowed it and recorded the device as "failed". Every
bulk operation (fleet config push, reboot, firmware update) therefore completed
as FAILED having touched nothing, and the feature had never worked. The
``# type: ignore[attr-defined]`` on each line is precisely what stopped mypy
from reporting it.

Function-level imports are common and legitimate in this tree -- they break
circular dependencies and keep worker start-up light. This test keeps that
pattern safe by resolving every one of them.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

TASKS_DIR = Path(__file__).resolve().parents[2] / "app" / "tasks"

#: Modules we must not import for a name check (side effects / optional deps).
SKIP_MODULE_PREFIXES: tuple[str, ...] = ()


def _first_party_from_imports(path: Path) -> list[tuple[str, str, int]]:
    """Every ``from app... import name`` in the file, at any nesting depth."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: list[tuple[str, str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        mod = node.module or ""
        if node.level or not mod.startswith("app."):
            continue  # relative or third-party: not ours to police here
        for alias in node.names:
            if alias.name == "*":
                continue
            out.append((mod, alias.name, node.lineno))
    return out


def _task_modules() -> list[Path]:
    return sorted(p for p in TASKS_DIR.glob("*.py") if p.name != "__init__.py")


def test_task_directory_is_readable() -> None:
    """Guard the guard: an empty scan must not read as a pass."""
    assert TASKS_DIR.is_dir(), f"tasks dir not found: {TASKS_DIR}"
    assert len(_task_modules()) > 5, "task module scan looks truncated"


@pytest.mark.parametrize("path", _task_modules(), ids=lambda p: p.name)
def test_every_first_party_import_in_task_module_resolves(path: Path) -> None:
    """Import each ``from app.x import y`` target and assert ``y`` exists.

    Fails before the fix with:
      bulk_operations.py:497 `from app.adapters import adapter_factory` --
      'adapter_factory' is not exported by app.adapters
    """
    broken: list[str] = []

    for module_name, symbol, lineno in _first_party_from_imports(path):
        if module_name.startswith(SKIP_MODULE_PREFIXES):
            continue
        try:
            mod = importlib.import_module(module_name)
        except Exception as exc:  # pragma: no cover - a broken module is its own bug
            broken.append(f"{path.name}:{lineno} cannot import {module_name!r} ({exc})")
            continue
        if not hasattr(mod, symbol):
            # A submodule is a valid target for `from pkg import submodule`.
            try:
                importlib.import_module(f"{module_name}.{symbol}")
            except Exception:
                broken.append(
                    f"{path.name}:{lineno} `from {module_name} import {symbol}` -- "
                    f"{symbol!r} is not exported by {module_name}"
                )

    assert not broken, (
        "Unresolvable import(s) in a Celery task module. A deferred import that "
        "does not resolve fails only at execution time, where a broad except "
        "records it as a device/job failure and the feature silently never "
        "works:\n  " + "\n  ".join(broken)
    )
