# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Structural guard against the catastrophic-op confirmation bypass.

``bool(payload.get("confirmed"))`` is unsafe: every non-empty string is truthy in
Python, so ``bool("false")`` is ``True`` and ``{"confirmed": "false"}`` bypasses the
gate. The fix routes every confirm check through ``payload_confirmed`` (strict).
This test fails the build if anyone reintroduces the ``bool(...confirmed...)``
anti-pattern, so the whole bug class can't come back.

SCOPE, and why it is the whole of ``app/``: this guard was written scanning only
``app/services``, and for that entire time there was a LIVE instance of the exact
anti-pattern it exists to forbid sitting in ``app/api/v1/endpoints/agents.py`` --
the confirm gate on ``POST /agents/{id}/tasks``, which dispatches config pushes,
credential rotations and agent self-updates to a remote agent. A gate that can
only see one directory does not gate a bug CLASS, it gates a directory. The scan
root is now ``app``; re-pointing it anywhere narrower re-opens the same hole.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from fastapi import HTTPException

_APP = Path(__file__).resolve().parents[2] / "app"

# The helper module documents the anti-pattern in its own docstring, so it is
# the one legitimate textual match in the tree.
_EXEMPT = {_APP / "services" / "adapter_preflight_common.py"}

# bool( ... confirmed within a short window — catches both the one-line
# bool(payload.get("confirmed")) and the multi-line bool(\n (payload).get("confirmed")) forms.
_ANTIPATTERN = re.compile(r"bool\([\s\S]{0,80}?confirmed", re.IGNORECASE)


def _sources() -> list[Path]:
    return [f for f in sorted(_APP.rglob("*.py")) if f not in _EXEMPT]


def test_scan_actually_covers_the_app() -> None:
    """Guard the guard: a broken path must not read as a clean result.

    The original defect here was scope, not pattern. If ``_APP`` is ever
    mistyped or narrowed, ``rglob`` returns nothing and the test below passes
    vacuously -- which is indistinguishable from "no offenders".
    """
    assert _APP.is_dir(), f"scan root not found: {_APP}"
    files = _sources()
    assert len(files) > 500, f"the scan looks truncated -- only {len(files)} files under {_APP}"
    # The directory that actually held the live bypass must be in scope.
    assert any(f.name == "agents.py" and f.parent.name == "endpoints" for f in files), (
        "app/api/v1/endpoints is not being scanned -- that is where the live bypass was"
    )


def test_no_bool_confirmed_antipattern() -> None:
    offenders: list[str] = []
    for f in _sources():
        text = f.read_text(encoding="utf-8")
        rel = f.relative_to(_APP).as_posix()
        # Report where the regex ACTUALLY matched. The previous reporter
        # re-derived the location with a separate line-level heuristic
        # ("confirmed" and "bool(" on one line), which cannot see the
        # multi-line form that is the whole reason the pattern spans newlines --
        # so it named a nearby comment instead of the offending expression.
        for m in _ANTIPATTERN.finditer(text):
            line_no = text.count(chr(10), 0, m.start()) + 1
            snippet = " ".join(m.group(0).split())
            offenders.append(f"{rel}:{line_no}: {snippet}")
    assert not offenders, (
        "Confirmation gates must use payload_confirmed() "
        "(app.services.adapter_preflight_common), NOT bool(...confirmed) — "
        "bool('false') is True, a catastrophic-op confirmation bypass:\n" + "\n".join(offenders)
    )


# ---------------------------------------------------------------------------
# The behaviour, not just the shape.
#
# The structural guard above forbids the ANTI-PATTERN. This section proves the
# GATE actually refuses the payload, on the one endpoint where the bypass was
# live. It lives next to the guard on purpose -- the two are a pair, and the
# endpoint had a confirm gate and NO test of any kind:
# ``_CONFIRM_REQUIRED_TASK_TYPES`` occurred exactly once in the repo, its own
# definition.
#
# No DB: the endpoint function is driven directly with its two DB touchpoints
# (``_verify_agent_org``, ``PersistentAgentService``) stubbed, so the gate, the
# real TaskCreate schema and the real AgentTaskType enum run unmocked.
# ---------------------------------------------------------------------------


class _RecordingAgentService:
    """Stands in for PersistentAgentService; records what got created."""

    created: list[dict[str, Any]] = []

    def __init__(self, session: object) -> None:
        self._session = session

    async def create_task(self, **kwargs: Any) -> SimpleNamespace:
        _RecordingAgentService.created.append(kwargs)
        return SimpleNamespace(id=uuid4(), task_type=kwargs["task_type"], status="pending")


async def _noop_commit() -> None:
    return None


async def _call_create_task(
    monkeypatch: pytest.MonkeyPatch, task_type: Any, task_data: dict[str, Any]
) -> tuple[HTTPException, list[dict[str, Any]]]:
    """Drive the real endpoint function; return (raised HTTPException, tasks created)."""
    from app.api.v1.endpoints import agents as agents_mod
    from app.schemas.agents import TaskCreate

    org_id, site_id, agent_id = uuid4(), uuid4(), uuid4()
    agent = SimpleNamespace(
        id=agent_id,
        site_id=site_id,
        organization_id=org_id,
        is_approved=True,
        status="online",
    )

    async def _verify(*_a: object, **_kw: object) -> SimpleNamespace:
        return agent

    async def _registry(*_a: object, **_kw: object) -> SimpleNamespace:
        # No live socket, so anything that gets PAST the gate stops here with a
        # DIFFERENT 409. That is how these tests tell "refused" from "accepted"
        # without a DB or a WebSocket.
        return SimpleNamespace(get_connection_for_site=lambda _site: None)

    _RecordingAgentService.created = []
    monkeypatch.setattr(agents_mod, "_verify_agent_org", _verify)
    monkeypatch.setattr(agents_mod, "PersistentAgentService", _RecordingAgentService)
    monkeypatch.setattr(agents_mod, "get_agent_registry", _registry)

    with pytest.raises(HTTPException) as excinfo:
        await agents_mod.create_task(
            agent_id=agent_id,
            data=TaskCreate(task_type=task_type, task_data=task_data),
            current_user=SimpleNamespace(organization_id=org_id),
            session=SimpleNamespace(commit=_noop_commit),
        )
    return excinfo.value, list(_RecordingAgentService.created)


@pytest.mark.parametrize("declined", ["false", "False", "FALSE", "no", "off", "0", ""])
async def test_stringified_decline_does_not_confirm_a_catastrophic_agent_task(
    monkeypatch: pytest.MonkeyPatch, declined: str
) -> None:
    """``{"confirmed": "false"}`` is a DECLINE, and it used to dispatch the task.

    ``task_data`` is an untyped ``dict[str, Any]``, so the string survives
    pydantic intact and ``bool("false")`` was ``True``. An automation layer that
    stringifies booleans therefore turned an explicit refusal into a live config
    push / credential rotation on the edge agent: created, committed and sent
    over the agent socket, with no second confirm check downstream.

    Mutation this catches: restoring
    ``not bool((data.task_data or {}).get("confirmed"))``.
    """
    from app.models.agents import AgentTaskType

    exc, created = await _call_create_task(
        monkeypatch, AgentTaskType.PUSH_CONFIG, {"confirmed": declined}
    )
    assert exc.status_code == 409
    assert "confirmed=true" in str(exc.detail), exc.detail
    assert created == [], "the task was created despite an explicit decline"


async def test_missing_confirmation_refuses_a_catastrophic_agent_task(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No ``confirmed`` key at all must not be enough. Mutation: dropping the gate."""
    from app.models.agents import AgentTaskType

    exc, created = await _call_create_task(monkeypatch, AgentTaskType.UPDATE_CREDENTIALS, {})
    assert exc.status_code == 409
    assert "confirmed=true" in str(exc.detail), exc.detail
    assert created == []


@pytest.mark.parametrize("affirmed", [True, "true", "True", "yes", "on", "1", 1])
async def test_a_genuine_confirmation_still_gets_through(
    monkeypatch: pytest.MonkeyPatch, affirmed: Any
) -> None:
    """The gate must not be a blanket refusal.

    Without this, a mutation making ``payload_confirmed`` return False for
    everything would look like a passing fix while the endpoint became
    unusable. Getting past the gate is observable here as the OTHER 409 (no
    live agent socket) plus a recorded create_task call.
    """
    from app.models.agents import AgentTaskType

    exc, created = await _call_create_task(
        monkeypatch, AgentTaskType.PUSH_CONFIG, {"confirmed": affirmed}
    )
    assert exc.status_code == 409
    assert "no active WebSocket connection" in str(exc.detail), exc.detail
    assert len(created) == 1, "a confirmed task was refused by the confirmation gate"


async def test_a_read_only_task_type_is_not_gated(monkeypatch: pytest.MonkeyPatch) -> None:
    """scan_network and friends are deliberately NOT in the confirm set.

    Mutation this catches: widening ``_CONFIRM_REQUIRED_TASK_TYPES`` to every
    task type, which would break discovery while every "is it refused?" test
    above still passed.
    """
    from app.models.agents import AgentTaskType

    exc, created = await _call_create_task(monkeypatch, AgentTaskType.SCAN_NETWORK, {})
    assert "no active WebSocket connection" in str(exc.detail), exc.detail
    assert len(created) == 1


def test_the_confirm_set_still_covers_every_state_changing_task_type() -> None:
    """Pin WHICH task types are gated, so one cannot quietly fall out of the set.

    Derived from nothing in the module under test: the four names are written
    out here. Mutation this catches: deleting ``AgentTaskType.UPDATE_AGENT``
    from ``_CONFIRM_REQUIRED_TASK_TYPES`` (agent self-update -- unreversible
    from FreeSDN's side once the agent picks it up).
    """
    from app.api.v1.endpoints.agents import _CONFIRM_REQUIRED_TASK_TYPES

    assert set(_CONFIRM_REQUIRED_TASK_TYPES) == {
        "execute_action",
        "push_config",
        "update_credentials",
        "update_agent",
    }
