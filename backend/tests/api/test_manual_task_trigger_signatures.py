# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Ratchet: every manually-triggerable task must accept what the endpoint sends.

``POST /tasks/trigger`` scoped each run to the caller's organization by doing::

    task_kwargs["organization_id"] = str(organization_id)

unconditionally. Every entry in ``MANUALLY_TRIGGERABLE_TASKS`` is a global
scheduled sweep with a zero-argument signature, so the worker raised
``TypeError: unexpected keyword argument 'organization_id'`` before entering the
task body -- for all 17 entries. The API returned ``queued`` and nothing ever
ran, so the manual-trigger feature had never worked.

The kwarg is now injected only where the signature accepts it (and stripped
otherwise, so a caller cannot smuggle it in). This test pins the invariant that
matters: whatever the endpoint constructs must be callable against the task it
dispatches to.
"""

from __future__ import annotations

import inspect

import pytest

from app.api.v1.endpoints.tasks import (
    MANUALLY_TRIGGERABLE_TASKS,
    _task_accepts_organization_id,
    build_task_kwargs,
)
from app.core.celery_app import celery_app


def _resolved_tasks() -> list[tuple[str, object]]:
    out = []
    for name in MANUALLY_TRIGGERABLE_TASKS:
        task = celery_app.tasks.get(name)
        if task is not None:
            out.append((name, task))
    return out


def test_allowlist_is_not_empty_and_resolves() -> None:
    """Guard the guard: an empty resolution must not read as a pass."""
    assert MANUALLY_TRIGGERABLE_TASKS, "the allowlist is empty"
    resolved = _resolved_tasks()
    assert resolved, "no allowlisted task resolved against the Celery registry"


@pytest.mark.parametrize("name,task", _resolved_tasks(), ids=lambda v: v if isinstance(v, str) else "")
def test_endpoint_kwargs_are_callable_against_the_task(name: str, task: object) -> None:
    """The kwargs the endpoint builds must bind to the task's signature.

    Fails before the fix: ``organization_id`` was injected into every task, and
    none of them accept it, so ``bind`` raises exactly the ``TypeError`` the
    worker would have raised.
    """
    run = getattr(task, "run", task)
    try:
        sig = inspect.signature(run)
    except (TypeError, ValueError):  # pragma: no cover
        pytest.skip(f"{name}: signature not introspectable")

    # Ask the ENDPOINT what it would dispatch -- do not re-derive it here, or the
    # test keeps passing when the endpoint stops consulting the helper.
    kwargs = build_task_kwargs(task, {}, "00000000-0000-0000-0000-000000000000")

    try:
        sig.bind(**kwargs)
    except TypeError as exc:
        pytest.fail(
            f"{name}{sig} cannot be called with the kwargs the trigger endpoint "
            f"builds ({kwargs!r}): {exc}. The task would raise before its body runs "
            "and the trigger would silently do nothing."
        )


def test_helper_detects_a_signature_that_takes_the_scope() -> None:
    """A task that DOES take an org scope must still receive it."""

    class _Scoped:
        @staticmethod
        def run(organization_id: str) -> None:  # pragma: no cover - shape only
            ...

    class _Unscoped:
        @staticmethod
        def run() -> None:  # pragma: no cover - shape only
            ...

    class _Kwargs:
        @staticmethod
        def run(**kwargs: object) -> None:  # pragma: no cover - shape only
            ...

    assert _task_accepts_organization_id(_Scoped) is True
    assert _task_accepts_organization_id(_Unscoped) is False
    assert _task_accepts_organization_id(_Kwargs) is True
