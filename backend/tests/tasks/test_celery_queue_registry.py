# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Meta-test: Celery task/queue wiring must be internally consistent.

Background
----------
`app.tasks.webhooks.retry_webhook_delivery` shipped in 26.06.1 declaring
``queue="webhooks"`` while (a) no such queue was declared in ``task_queues``,
(b) no worker in any tier consumed it, and (c) the module was absent from the
Celery ``include=`` list so no worker even registered the task. Every dispatch
site imports the module lazily inside a function, so the API process imported it
happily and the breakage was invisible: failed deliveries flipped to RETRYING,
enqueued into the void, and never reached the dead-letter table.

These tests turn each leg of that failure into a red build.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from app.core.celery_app import celery_app

APP_DIR = Path(__file__).resolve().parents[2] / "app"
ENV_EXAMPLES = sorted((APP_DIR.parent.parent).glob(".env.*.example"))


def _declared_queues() -> set[str]:
    return {q.name for q in (celery_app.conf.task_queues or [])}


def _worker_queues_from_env_examples() -> dict[str, set[str]]:
    """
    Map each .env.<tier>.example to the queue set its workers consume.

    The .env examples live one level above backend/, so they are absent when the
    suite runs against a container that mounts only backend/ (scripts/ci-gate.sh
    does exactly this). Callers must skip rather than fail in that case.
    """
    tiers: dict[str, set[str]] = {}
    for path in ENV_EXAMPLES:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("WORKER_QUEUES="):
                value = line.split("=", 1)[1].strip()
                tiers[path.name] = {q.strip() for q in value.split(",") if q.strip()}
    return tiers


def _tasks_declaring_a_queue() -> list[tuple[str, str, int]]:
    """Find every @celery_app.task(..., queue="X") in app/. Returns (file, queue, lineno)."""
    found: list[tuple[str, str, int]] = []
    for py in APP_DIR.rglob("*.py"):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - a parse failure is its own bug
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for deco in node.decorator_list:
                if not isinstance(deco, ast.Call):
                    continue
                for kw in deco.keywords:
                    if kw.arg == "queue" and isinstance(kw.value, ast.Constant):
                        if isinstance(kw.value.value, str):
                            found.append(
                                (str(py.relative_to(APP_DIR)), kw.value.value, deco.lineno)
                            )
    return found


def _dispatch_sites_naming_a_queue() -> list[tuple[str, str, int]]:
    """
    Find every ``.apply_async(..., queue="X")`` / ``.delay`` sibling in app/.

    This is the leg the first version of this test missed. An explicit ``queue=``
    kwarg on apply_async overrides BOTH the task's decorator routing and
    ``task_routes``, so fixing the decorator alone changes nothing observable if a
    dispatch site still names the old queue. Returns (file, queue, lineno).
    """
    found: list[tuple[str, str, int]] = []
    for py in APP_DIR.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in {"apply_async", "delay", "send_task"}:
                continue
            for kw in node.keywords:
                if kw.arg == "queue" and isinstance(kw.value, ast.Constant):
                    if isinstance(kw.value.value, str):
                        found.append((str(py.relative_to(APP_DIR)), kw.value.value, node.lineno))
    return found


def test_every_dispatch_site_queue_is_actually_declared() -> None:
    """
    An explicit queue= on apply_async wins over every other routing mechanism.

    Regression guard for the webhook lane: the decorator and include= were fixed
    first, the suite went green, and the bug stayed live because three
    apply_async sites still passed queue="webhooks" explicitly.
    """
    declared = _declared_queues()
    offenders = [
        f"{path}:{lineno} dispatches to queue={queue!r}"
        for path, queue, lineno in _dispatch_sites_naming_a_queue()
        if queue not in declared
    ]
    assert not offenders, (
        "Dispatch site(s) publish to an undeclared queue. An explicit queue= on "
        "apply_async overrides the task's routing AND task_routes, and Celery's "
        "task_create_missing_queues defaults True, so the producer will happily "
        "declare the queue and the messages will sit in it unconsumed.\n"
        f"Declared queues: {sorted(declared)}\n" + "\n".join(offenders)
    )


def test_every_task_declared_queue_is_actually_declared() -> None:
    """A task may not route to a queue that ``task_queues`` never declares."""
    declared = _declared_queues()
    offenders = [
        f"{path}:{lineno} routes to queue={queue!r}"
        for path, queue, lineno in _tasks_declaring_a_queue()
        if queue not in declared
    ]
    assert not offenders, (
        "Task(s) route to an undeclared queue. Declare it in "
        "app/core/celery_app.py task_queues, or drop the queue= kwarg so the "
        f"task routes to 'default'.\nDeclared queues: {sorted(declared)}\n" + "\n".join(offenders)
    )


def test_every_declared_queue_is_consumed_by_some_tier() -> None:
    """A declared queue nobody consumes is a silent message sink."""
    tiers = _worker_queues_from_env_examples()
    if not tiers:
        pytest.skip("No .env.*.example reachable (backend-only mount); cannot verify consumption.")
    consumed: set[str] = set().union(*tiers.values())
    orphans = sorted(_declared_queues() - consumed)
    assert not orphans, (
        f"Queue(s) declared but consumed by no tier: {orphans}. "
        f"Add them to WORKER_QUEUES in the relevant .env.*.example, or remove "
        f"the queue. Tier config: { {k: sorted(v) for k, v in tiers.items()} }"
    )


def test_default_queue_is_consumed_by_every_tier() -> None:
    """'default' is the fallback for any task without an explicit queue."""
    tiers = _worker_queues_from_env_examples()
    if not tiers:
        pytest.skip("No .env.*.example reachable (backend-only mount).")
    for tier, queues in tiers.items():
        assert "default" in queues, (
            f"{tier} does not consume the 'default' queue. Any task without an "
            f"explicit queue= would be stranded in that tier."
        )


@pytest.mark.parametrize("module", sorted(set(celery_app.conf.include or [])))
def test_included_modules_are_importable(module: str) -> None:
    """Every module in ``include=`` must import — an unimportable one is silently skipped."""
    __import__(module)


def test_task_modules_defining_tasks_are_in_the_include_list() -> None:
    """
    A module defining @celery_app.task must be in ``include=``.

    Otherwise workers never register the task, and any lazy (function-level)
    import from the API process hides the breakage — exactly the webhook bug.
    """
    include = set(celery_app.conf.include or [])
    # Column 0 only: an INDENTED @celery_app.task sits inside a factory/class and
    # is registered when that code runs, not at import time, so it does not need
    # an include= entry. Matching those produced false positives on
    # app/tasks/base.py and app/modules/ai/governance.py.
    module_level_task = re.compile(r"^@(?:celery_app\.task|shared_task)\b", re.MULTILINE)
    # The module that DEFINES celery_app is loaded by every worker by definition.
    always_loaded = {"app.core.celery_app"}
    missing: list[str] = []

    for py in APP_DIR.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        if not module_level_task.search(py.read_text(encoding="utf-8")):
            continue
        dotted = "app." + ".".join(py.relative_to(APP_DIR).with_suffix("").parts)
        if dotted not in include and dotted not in always_loaded:
            missing.append(dotted)

    assert not missing, (
        "Module(s) define Celery tasks but are absent from the include= list in "
        "app/core/celery_app.py, so no worker registers them:\n  " + "\n  ".join(sorted(missing))
    )
