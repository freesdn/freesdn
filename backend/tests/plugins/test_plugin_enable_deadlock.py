# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Two plugin-lifecycle defects that each ended in a plugin nobody could turn on.

1. ENABLE DEADLOCKED ON ITS OWN LOCK
   ``lifecycle_lock`` is documented non-reentrant -- "callers MUST NOT
   re-acquire it from within an already-held block". ``enable_plugin`` held it
   and then, inside the block, called the start path::

       _start_plugin_everywhere -> _start_plugin_for_org
         -> plugin_loader.load_plugin  ->  async with await self._lock_for(...)

   ``asyncio.Lock`` has no owner and no re-entrancy, so the coroutine waited on
   a lock only it could release. Not slow -- permanently stopped, with no
   exception, no timeout and no log line. The request simply never returned.

   It only fired when the plugin was absent from the loader's in-process
   ``_loaded`` map, which is exactly what ``load_all_plugins`` guarantees for a
   globally-disabled plugin after a restart. So the ordinary "disable it,
   restart the API, re-enable it" flow hung a worker every time, while enabling
   a plugin that happened to still be loaded returned instantly.

   Every sibling endpoint already had this right: install, the install-retry
   path and upgrade all start the plugin outside any lock. Enable was the sole
   offender; disable is fine because the ``stop_*`` methods take no lock.

2. A FAILED UPGRADE DISABLED THE PLUGIN FOREVER
   ``upgrade_plugin`` COMMITTED ``status = "upgrading"`` and then ran the
   install. If the install raised -- corrupt archive, bad manifest, failed
   validation -- the exception propagated with the row still reading
   "upgrading", and nothing ever put it back. ``load_all_plugins`` only loads
   rows whose status is ``"installed"``, so from the next restart onward the
   plugin did not exist. One bad upload permanently removed a working plugin,
   and the operator's only clue was that it was gone.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import textwrap
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.api.v1.endpoints import plugins as ep
from app.plugins.loader import PluginLoader, plugin_loader

PLUGIN_ID = "acme-widget"


def _code(obj) -> str:
    """Source with comments stripped -- the fix quotes the old code in comments."""
    src = inspect.getsource(obj)
    return "\n".join(line for line in src.splitlines() if not line.strip().startswith("#"))


# ── 1. the deadlock ──────────────────────────────────────────────


class _Session:
    def __init__(self, plugin) -> None:
        self._plugin = plugin
        self.commits = 0

    async def execute(self, _query):
        plugin = self._plugin
        return SimpleNamespace(scalar_one_or_none=lambda: plugin, scalars=lambda: [])

    async def commit(self) -> None:
        self.commits += 1

    def add(self, _obj) -> None:  # pragma: no cover - audit path is stubbed out
        pass


def _plugin_row(*, is_active: bool = False, status: str = "disabled"):
    return SimpleNamespace(
        plugin_id=PLUGIN_ID,
        name="Acme Widget",
        version="1.0.0",
        description="",
        author="acme",
        is_active=is_active,
        status=status,
    )


def _superuser():
    return SimpleNamespace(
        id=uuid4(),
        organization_id=None,
        role="super_admin",
        is_superuser=True,
        email="root@example.com",
        has_permission=lambda _perm: True,
    )


def _org_admin():
    return SimpleNamespace(
        id=uuid4(),
        organization_id=uuid4(),
        role="org_admin",
        is_superuser=False,
        email="admin@example.com",
        has_permission=lambda perm: perm == "plugins.admin",
    )


@pytest.fixture
def wired(monkeypatch):
    """
    Drive the REAL enable_plugin, with the start path replaced by a stand-in
    that takes the same lifecycle lock the real chain takes three frames down.
    That re-acquisition is the entire mechanism of the bug, and reproducing it
    here is what makes this a behavioural test rather than a source assertion.
    """
    state: dict = {"started": False, "held_during_start": None}

    async def _fake_start_everywhere(plugin_id, session, app=None):
        # Exactly what load_plugin does: re-acquire the per-plugin lock.
        state["held_during_start"] = plugin_loader.lifecycle_lock(plugin_id).locked()
        async with plugin_loader.lifecycle_lock(plugin_id):
            state["started"] = True

    async def _fake_start_for_org(plugin_id, org_id, session, app=None):
        await _fake_start_everywhere(plugin_id, session, app)

    async def _no_audit(*_args, **_kwargs):
        return None

    monkeypatch.setattr(ep, "_start_plugin_everywhere", _fake_start_everywhere)
    monkeypatch.setattr(ep, "_start_plugin_for_org", _fake_start_for_org)
    monkeypatch.setattr(ep, "_audit_plugin_lifecycle", _no_audit)
    # A fresh lock per test, so a lock leaked by one test cannot decide another.
    plugin_loader._lifecycle_locks.pop(PLUGIN_ID, None)
    yield state
    plugin_loader._lifecycle_locks.pop(PLUGIN_ID, None)


async def _enable(user, session) -> object:
    return await asyncio.wait_for(
        ep.enable_plugin(PLUGIN_ID, SimpleNamespace(app=None), user, session),
        timeout=5,
    )


async def test_enable_completes_instead_of_hanging_forever(wired) -> None:
    """
    The whole bug in one assertion. Pre-fix this call never returns: wait_for
    fires and the test fails with TimeoutError -- which is the good outcome the
    operator's HTTP request never got, because it had no timeout at all.
    """
    row = _plugin_row()
    summary = await _enable(_superuser(), _Session(row))

    assert summary.is_active is True
    assert row.is_active is True
    assert row.status == "installed"


async def test_the_plugin_is_actually_started(wired) -> None:
    """
    Moving the call out of the lock must not have quietly dropped it. An enable
    that flips a database flag but never loads the plugin is a different bug
    wearing the same symptom.
    """
    await _enable(_superuser(), _Session(_plugin_row()))
    assert wired["started"] is True


async def test_the_lock_is_free_by_the_time_the_start_runs(wired) -> None:
    """
    Names the mechanism rather than the symptom: if this is ever True again the
    endpoint is re-entering its own non-reentrant lock, whatever the timing
    happens to look like on the day.
    """
    await _enable(_superuser(), _Session(_plugin_row()))
    assert wired["held_during_start"] is False


async def test_the_lock_is_released_after_a_successful_enable(wired) -> None:
    """A lock left held would deadlock the NEXT lifecycle call instead."""
    await _enable(_superuser(), _Session(_plugin_row()))
    assert plugin_loader.lifecycle_lock(PLUGIN_ID).locked() is False


async def test_the_lock_still_covers_the_database_flip(wired) -> None:
    """
    The lock was not simply deleted. Hold it from outside and the enable must
    block -- that is what serialises the DB flip against a concurrent
    install / upgrade / uninstall of the same plugin.
    """
    async with plugin_loader.lifecycle_lock(PLUGIN_ID):
        task = asyncio.create_task(
            ep.enable_plugin(
                PLUGIN_ID, SimpleNamespace(app=None), _superuser(), _Session(_plugin_row())
            )
        )
        await asyncio.sleep(0.05)
        assert not task.done(), "enable no longer serialises against other lifecycle ops"

    await asyncio.wait_for(task, timeout=5)


async def test_an_org_scoped_enable_also_completes(wired, monkeypatch) -> None:
    """The org branch took the same lock and called the same start path."""

    async def _set_enabled(*_args, **_kwargs):
        return None

    monkeypatch.setattr(ep, "_set_org_plugin_enabled", _set_enabled)

    # Globally enabled, disabled for this one org.
    row = _plugin_row(is_active=True, status="installed")
    await _enable(_org_admin(), _Session(row))
    assert wired["started"] is True


async def test_a_globally_disabled_plugin_is_still_refused_for_an_org(wired, monkeypatch) -> None:
    """The 409 guard sits inside the lock block and must still fire."""
    from fastapi import HTTPException

    async def _set_enabled(*_args, **_kwargs):  # pragma: no cover - must not run
        raise AssertionError("should not have reached the write")

    monkeypatch.setattr(ep, "_set_org_plugin_enabled", _set_enabled)

    with pytest.raises(HTTPException) as exc:
        await _enable(_org_admin(), _Session(_plugin_row()))
    assert exc.value.status_code == 409
    assert wired["started"] is False
    assert plugin_loader.lifecycle_lock(PLUGIN_ID).locked() is False, (
        "an early raise inside the block must still release the lock"
    )


async def test_the_lock_really_is_non_reentrant() -> None:
    """
    Negative control for the premise. If asyncio.Lock ever became reentrant the
    tests above would pass for the wrong reason, so pin the assumption.
    """
    lock = asyncio.Lock()
    async with lock:
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(lock.acquire(), timeout=0.1)


def _lock_block_nodes(fn):
    """Every AST node inside the `async with plugin_loader.lifecycle_lock(...)` block."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncWith):
            continue
        if "lifecycle_lock" not in ast.dump(node.items[0].context_expr):
            continue
        return [n for stmt in node.body for n in ast.walk(stmt)]
    return []


def test_no_start_call_survives_inside_the_lock_block() -> None:
    """
    Structural backstop, parsed rather than grepped. The behavioural tests use
    a stand-in for the start path; this pins the real source, so a refactor
    that moves the call back inside is caught even if the stand-in drifts.
    """
    called = {
        node.func.id
        for node in _lock_block_nodes(ep.enable_plugin)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not called & {"_start_plugin_everywhere", "_start_plugin_for_org"}, (
        "the plugin start is back inside the non-reentrant lifecycle lock"
    )


def test_the_db_flip_is_still_inside_the_lock_block() -> None:
    """The other half: the fix must not have emptied the block."""
    body = _lock_block_nodes(ep.enable_plugin)
    assert any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "commit"
        for n in body
    ), "the commit escaped the lifecycle lock; the flip is no longer serialised"


def test_sibling_lifecycle_endpoints_do_not_hold_the_lock_over_a_start() -> None:
    """
    Guard the class, not the one endpoint. Any handler that both holds the
    lifecycle lock and starts a plugin inside it has the same deadlock.
    """
    offenders = []
    for name, fn in vars(ep).items():
        if not inspect.isfunction(fn) or not name.endswith("_plugin"):
            continue
        called = {
            node.func.id
            for node in _lock_block_nodes(fn)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        if called & {"_start_plugin_everywhere", "_start_plugin_for_org"}:
            offenders.append(name)
    assert not offenders, f"{offenders} start a plugin while holding the lifecycle lock"


# ── 2. the failed upgrade ────────────────────────────────────────


class _UpgradeSession:
    def __init__(self, row) -> None:
        self.row = row
        self.commits = 0
        self.rollbacks = 0

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


@pytest.fixture
def upgrade_row(monkeypatch):
    row = SimpleNamespace(plugin_id=PLUGIN_ID, version="1.0.0", status="installed", is_active=True)

    async def _get(_db, plugin_id):
        return row if plugin_id == PLUGIN_ID else None

    monkeypatch.setattr("app.plugins.loader._get_installed_plugin", _get)
    return row


def _loader_that_fails(message: str) -> PluginLoader:
    loader = PluginLoader.__new__(PluginLoader)

    async def _boom(*_args, **_kwargs):
        raise ValueError(message)

    loader.install_plugin = _boom  # type: ignore[method-assign]
    return loader


async def test_a_failed_upgrade_leaves_the_plugin_installed(upgrade_row) -> None:
    """
    The regression. Pre-fix the row stayed at "upgrading", load_all_plugins
    skipped it at the next restart, and the plugin was gone.
    """
    with pytest.raises(ValueError, match="corrupt archive"):
        await _loader_that_fails("corrupt archive").upgrade_plugin(
            PLUGIN_ID, b"junk", _UpgradeSession(upgrade_row), uuid4()
        )

    assert upgrade_row.status == "installed", (
        "a failed upgrade left the plugin at 'upgrading'; load_all_plugins only "
        "loads 'installed', so it disappears from the next restart onward"
    )
    assert upgrade_row.is_active is True


async def test_the_marker_was_really_written_before_the_install(upgrade_row) -> None:
    """
    Premise check. The restore is only necessary because "upgrading" is
    COMMITTED first -- if that ever stops being true, this fix is dead weight
    and should be revisited rather than silently kept.
    """
    seen: list[str] = []
    loader = PluginLoader.__new__(PluginLoader)

    async def _observe(*_args, **_kwargs):
        seen.append(upgrade_row.status)
        raise ValueError("stop here")

    loader.install_plugin = _observe  # type: ignore[method-assign]

    with pytest.raises(ValueError):
        await loader.upgrade_plugin(PLUGIN_ID, b"junk", _UpgradeSession(upgrade_row), uuid4())
    assert seen == ["upgrading"]


async def test_the_original_error_is_not_swallowed(upgrade_row) -> None:
    """
    The operator must still be told the upgrade failed. A restore that ate the
    exception would turn a loud failure into a silent no-op.
    """
    with pytest.raises(ValueError, match="bad manifest"):
        await _loader_that_fails("bad manifest").upgrade_plugin(
            PLUGIN_ID, b"junk", _UpgradeSession(upgrade_row), uuid4()
        )


async def test_a_broken_rollback_still_reraises_the_real_error(upgrade_row) -> None:
    """
    The restore is best-effort by design. If the session itself is unusable the
    caller must still see the upgrade failure, not a confusing secondary error
    about the connection.
    """

    class _BrokenSession(_UpgradeSession):
        async def rollback(self) -> None:
            raise RuntimeError("connection is gone")

    with pytest.raises(ValueError, match="original failure"):
        await _loader_that_fails("original failure").upgrade_plugin(
            PLUGIN_ID, b"junk", _BrokenSession(upgrade_row), uuid4()
        )


async def test_a_successful_upgrade_is_unchanged(upgrade_row) -> None:
    """The happy path must not have picked up a rollback it does not need."""
    loader = PluginLoader.__new__(PluginLoader)
    loader._loaded = {}
    sentinel = SimpleNamespace(plugin_id=PLUGIN_ID, version="2.0.0")

    async def _ok(*_args, **_kwargs):
        upgrade_row.status = "installed"
        upgrade_row.version = "2.0.0"
        return sentinel

    loader.install_plugin = _ok  # type: ignore[method-assign]
    session = _UpgradeSession(upgrade_row)

    assert await loader.upgrade_plugin(PLUGIN_ID, b"ok", session, uuid4()) is sentinel
    assert session.rollbacks == 0
    assert upgrade_row.status == "installed"


def test_load_all_plugins_only_loads_installed_rows() -> None:
    """
    Pin the premise that makes defect 2 fatal rather than cosmetic. If that
    filter ever widens, the severity of a stuck status changes with it.
    """
    code = _code(PluginLoader.load_all_plugins)
    assert '"installed"' in code and "status" in code
