# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Ratchet: a solo-lock lease must outlive the task it guards.

``acquire_solo_lock(name, ttl_seconds=N)`` stops a beat-scheduled task from
running twice at once -- but only for N seconds. Several leases were SHORTER than
the task's own hard ``time_limit`` (firewall/hypervisor/Omada/storage health:
180 s lease, 300 s limit; controller health 180 vs 360; device status 120 vs
360; stale marking 90 vs 180). With a 2-minute beat, a run slowed past its lease
by one struggling device got a twin at the next tick, doubling the load on
exactly the device that was struggling (2026-11 soak; architecture review
2026-11, topic 1). The release is token-checked, so a lease that outlives a run
only matters when the run is killed, and then it expires at the limit.

This scans every ``@celery_app.task`` that calls ``acquire_solo_lock`` with a
literal lease and requires lease >= the task's hard time limit (or Celery's
``task_time_limit`` default when the decorator sets none).
"""

from __future__ import annotations

import ast
from pathlib import Path

APP = Path(__file__).resolve().parents[2] / "app"


def _default_time_limit() -> int:
    from app.core.celery_app import celery_app

    return int(celery_app.conf.task_time_limit)


def _literal(node: ast.AST | None) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int | float):
        return int(node.value)
    return None


def _task_time_limit(fn: ast.AST) -> tuple[bool, int | None]:
    """(is a celery task, its decorator time_limit if literal)."""
    for deco in getattr(fn, "decorator_list", []):
        call = deco if isinstance(deco, ast.Call) else None
        target = call.func if call else deco
        text = ast.unparse(target)
        if not text.endswith(".task") and text != "shared_task":
            continue
        limit = None
        for kw in call.keywords if call else []:
            if kw.arg == "time_limit":
                limit = _literal(kw.value)
        return True, limit
    return False, None


def _leases(fn: ast.AST) -> list[tuple[int, int]]:
    out = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call) or ast.unparse(node.func) != "acquire_solo_lock":
            continue
        ttl = None
        for kw in node.keywords:
            if kw.arg == "ttl_seconds":
                ttl = _literal(kw.value)
        if ttl is None and len(node.args) > 1:
            ttl = _literal(node.args[1])
        out.append((node.lineno, 300 if ttl is None else ttl))  # function default 300
    return out


def _violations() -> tuple[int, list[str]]:
    default_limit = _default_time_limit()
    checked = 0
    bad: list[str] = []
    for path in sorted(APP.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            is_task, limit = _task_time_limit(fn)
            if not is_task:
                continue
            for lineno, ttl in _leases(fn):
                checked += 1
                need = limit if limit is not None else default_limit
                if ttl < need:
                    rel = path.relative_to(APP.parent).as_posix()
                    bad.append(f"{rel}:{lineno} {fn.name}: lease {ttl}s < time_limit {need}s")
    return checked, bad


def test_every_task_solo_lock_outlives_the_task() -> None:
    checked, bad = _violations()
    assert checked >= 10, f"scan looks truncated: only {checked} task leases found"
    assert not bad, "solo-lock lease shorter than the task's hard time limit:\n  " + "\n  ".join(
        bad
    )
