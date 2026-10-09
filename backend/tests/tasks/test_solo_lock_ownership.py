# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A lock release belongs to an acquisition, including after expiration."""

import asyncio
import importlib
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core import celery_app as locks


class RedisDouble:
    def __init__(self):
        self.rows = {}
        self.calls = []

    def set(self, key, value, *, nx, ex):
        assert nx is True
        self.calls.append((key, value, ex))
        if key in self.rows:
            return None
        self.rows[key] = value
        return True

    def eval(self, _script, count, key, token):
        assert count == 1
        if self.rows.get(key) == token:
            del self.rows[key]
            return 1
        return 0


@pytest.fixture
def redis(monkeypatch):
    value = RedisDouble()
    monkeypatch.setattr(locks, "_get_solo_redis", lambda: value)
    return value


def test_acquisition_returns_its_own_persisted_token(redis):
    token = locks.acquire_solo_lock("same", ttl_seconds=37)
    assert isinstance(token, str) and len(token) == 32
    assert redis.rows["freesdn:solo:same"] == token
    assert redis.calls[0][2] == 37


def test_held_lock_does_not_return_another_owner_token(redis):
    token = locks.acquire_solo_lock("same")
    assert locks.acquire_solo_lock("same") is None
    assert redis.rows["freesdn:solo:same"] == token


def test_expired_run_cannot_release_its_successor(redis):
    first = locks.acquire_solo_lock("same")
    del redis.rows["freesdn:solo:same"]  # Model expiration, not an application release.
    second = locks.acquire_solo_lock("same")
    locks.release_solo_lock("same", first)
    assert redis.rows["freesdn:solo:same"] == second
    locks.release_solo_lock("same", second)
    assert "freesdn:solo:same" not in redis.rows


def test_multiple_expired_generations_release_out_of_order(redis):
    tokens = []
    for _ in range(3):
        redis.rows.pop("freesdn:solo:same", None)
        tokens.append(locks.acquire_solo_lock("same"))
    for token in reversed(tokens[:-1]):
        locks.release_solo_lock("same", token)
        assert redis.rows["freesdn:solo:same"] == tokens[-1]
    locks.release_solo_lock("same", tokens[-1])
    assert not redis.rows


def test_a_token_cannot_release_a_different_key(redis):
    left = locks.acquire_solo_lock("left")
    right = locks.acquire_solo_lock("right")
    locks.release_solo_lock("right", left)
    assert redis.rows["freesdn:solo:right"] == right
    assert redis.rows["freesdn:solo:left"] == left


def test_duplicate_release_does_not_release_reacquired_lock(redis):
    first = locks.acquire_solo_lock("same")
    locks.release_solo_lock("same", first)
    second = locks.acquire_solo_lock("same")
    locks.release_solo_lock("same", first)
    assert redis.rows["freesdn:solo:same"] == second


@pytest.mark.parametrize("invalid", [None, True, 1, ""])
def test_missing_or_boolean_token_cannot_release_a_lease(redis, invalid):
    token = locks.acquire_solo_lock("same")
    with pytest.raises(ValueError, match="token"):
        locks.release_solo_lock("same", invalid)
    assert redis.rows["freesdn:solo:same"] == token


@pytest.mark.parametrize("stage", ["client", "eval"])
def test_release_error_is_safe_and_does_not_mask_task_outcome(redis, monkeypatch, caplog, stage):
    token = locks.acquire_solo_lock("same")
    marker = "synthetic-private-release-marker"
    broken = MagicMock(side_effect=RuntimeError(marker))
    if stage == "client":
        monkeypatch.setattr(locks, "_get_solo_redis", broken)
    else:
        redis.eval = broken
    locks.release_solo_lock("same", token)
    assert redis.rows["freesdn:solo:same"] == token
    assert caplog.records and marker not in caplog.text


def test_ambiguous_acquisition_does_not_start_work(redis):
    def unavailable(*_args, **_kwargs):
        raise RuntimeError("synthetic broker uncertainty")

    redis.set = unavailable
    with pytest.raises(RuntimeError, match="uncertainty"):
        locks.acquire_solo_lock("same")


# Exercise every migrated wrapper, with only its DB/hardware body substituted.
CALLERS = [
    ("app.tasks.hypervisor", "poll_health", "_poll_hypervisor_health"),
    ("app.tasks.omada_monitor", "poll_health", "_poll_omada_health"),
    ("app.tasks.overlay_monitor", "poll_health", "_poll_overlay_health"),
    ("app.tasks.storage", "poll_health", "_poll_storage_health"),
    ("app.tasks.firewall_monitor", "poll_health", "_poll_firewall_health"),
    ("app.tasks.reconciliation", "reconcile_all_devices", "_reconcile_all_devices"),
    ("app.tasks.reconciliation", "recompute_all_health", "_recompute_all_health"),
    ("app.tasks.reconciliation", "snapshot_daily_health", "_snapshot_daily_health"),
    ("app.tasks.sync", "sync_all_device_statuses", "_sync_all_device_statuses"),
    ("app.tasks.sync", "mark_stale_devices_offline", "_mark_stale_devices_offline"),
    ("app.tasks.sync", "check_controller_health", "_check_controller_health"),
    (
        "app.tasks.discovery",
        "_discover_devices_for_controller",
        "_discover_devices_for_controller_impl",
    ),
    ("app.modules.gateway.tasks.sync_tasks", "sync_all_gateways", "_sync_all_brain_gateways"),
    ("app.tasks.metrics", "collect_all_device_metrics", None),
    ("app.api.v1.endpoints.events", "replay_events", None),
]


@pytest.mark.parametrize(
    "module_name,name,body_name", CALLERS, ids=[r[0] + "." + r[1] for r in CALLERS]
)
@pytest.mark.parametrize("outcome", ["success", "busy", "failure"])
def test_each_wrapper_releases_only_the_token_it_acquired(
    monkeypatch, module_name, name, body_name, outcome
):
    module = importlib.import_module(module_name)
    token = "synthetic-acquisition-token"
    acquired = MagicMock(return_value=None if outcome == "busy" else token)
    released = MagicMock()
    for target in [locks, module]:
        if hasattr(target, "acquire_solo_lock"):
            monkeypatch.setattr(target, "acquire_solo_lock", acquired)
        if hasattr(target, "release_solo_lock"):
            monkeypatch.setattr(target, "release_solo_lock", released)
    error = RuntimeError("synthetic body failure")
    body = AsyncMock(
        return_value={"synthetic": True}, side_effect=error if outcome == "failure" else None
    )
    if body_name:
        monkeypatch.setattr(module, body_name, body)
    if module_name == "app.tasks.metrics":
        session = MagicMock()
        session.execute = AsyncMock(
            return_value=SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: []))
        )
        context = MagicMock()
        context.__aenter__ = AsyncMock(
            return_value=session, side_effect=error if outcome == "failure" else None
        )
        context.__aexit__ = AsyncMock(return_value=False)
        monkeypatch.setattr(module, "AsyncSessionLocal", lambda: context)
        body = context.__aenter__
    if module_name == "app.api.v1.endpoints.events":
        body.return_value = 0
        monkeypatch.setattr(
            module, "EventService", lambda _session: SimpleNamespace(replay_and_publish=body)
        )

    def invoke():
        function = getattr(module, name)
        if name == "_discover_devices_for_controller":
            return asyncio.run(function("synthetic-controller"))
        if name == "replay_events":
            now = datetime.now(UTC)
            request = module.ReplayRequest(start_time=now - timedelta(minutes=1), end_time=now)
            return asyncio.run(
                function(
                    request,
                    session=object(),
                    current_user=SimpleNamespace(organization_id="owned-org"),
                )
            )
        if name == "sync_all_device_statuses":
            return function.run(organization_id="owned-org", site_id="owned-site")
        return function.run()

    if outcome == "failure" and name != "sync_all_gateways":
        with pytest.raises(RuntimeError, match="synthetic body failure"):
            invoke()
    elif outcome == "busy" and name == "replay_events":
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            invoke()
        assert exc.value.status_code == 409
    else:
        result = invoke()
        if outcome == "busy":
            assert result["skipped"] is True
        if outcome == "failure":
            assert result["success"] is False
    acquired.assert_called_once()
    if outcome == "busy":
        body.assert_not_awaited()
        released.assert_not_called()
    else:
        body.assert_awaited_once()
        released.assert_called_once_with(acquired.call_args.args[0], token)
