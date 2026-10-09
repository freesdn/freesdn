# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Discovery refuses unconfirmed leases and cannot delete a successor's lease."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core import redis_client
from app.tasks import discovery


class LeaseStore:
    def __init__(self):
        self.rows = {}
        self.set_calls = []
        self.closed = 0

    def set(self, key, token, *, nx, ex):
        assert nx is True
        self.set_calls.append((key, token, ex))
        if key in self.rows:
            return None
        self.rows[key] = token
        return True

    def eval(self, _script, count, key, token):
        assert count == 1
        if self.rows.get(key) == token:
            del self.rows[key]
            return 1
        return 0

    def delete(self, key):
        return self.rows.pop(key, None) is not None

    def close(self):
        self.closed += 1


@pytest.fixture
def store(monkeypatch):
    value = LeaseStore()
    monkeypatch.setattr(redis_client, "get_sync_redis", MagicMock(return_value=value))
    return value


def test_acquired_lease_returns_persisted_unique_token(store):
    token = discovery._acquire_discovery_lock()
    assert isinstance(token, str) and len(token) == 32
    assert store.rows[discovery._DISCOVERY_LOCK_KEY] == token
    assert store.set_calls == [(discovery._DISCOVERY_LOCK_KEY, token, 900)]


def test_contention_returns_no_owner_token(store):
    token = discovery._acquire_discovery_lock()
    assert discovery._acquire_discovery_lock() is None
    assert store.rows[discovery._DISCOVERY_LOCK_KEY] == token


def test_different_keys_have_different_acquisition_tokens(store):
    assert discovery._acquire_discovery_lock("left") != discovery._acquire_discovery_lock("right")


def test_expired_owner_cannot_delete_successor(store):
    first = discovery._acquire_discovery_lock("same")
    store.rows.pop("same")  # Simulate expiry, not application release.
    second = discovery._acquire_discovery_lock("same")
    discovery._release_discovery_lock("same", first)
    assert store.rows["same"] == second
    discovery._release_discovery_lock("same", second)
    assert "same" not in store.rows


def test_three_expired_generations_preserve_current_owner(store):
    tokens = []
    for _ in range(3):
        store.rows.pop("same", None)
        tokens.append(discovery._acquire_discovery_lock("same"))
    for token in reversed(tokens[:-1]):
        discovery._release_discovery_lock("same", token)
        assert store.rows["same"] == tokens[-1]


def test_token_cannot_release_another_key(store):
    first = discovery._acquire_discovery_lock("left")
    second = discovery._acquire_discovery_lock("right")
    discovery._release_discovery_lock("right", first)
    assert store.rows["right"] == second


def test_duplicate_release_cannot_delete_reacquired_lock(store):
    first = discovery._acquire_discovery_lock("same")
    discovery._release_discovery_lock("same", first)
    second = discovery._acquire_discovery_lock("same")
    discovery._release_discovery_lock("same", first)
    assert store.rows["same"] == second


@pytest.mark.parametrize("token", [None, True, 1, ""])
def test_missing_token_refused_without_connecting(store, token):
    redis_client.get_sync_redis.reset_mock()
    with pytest.raises(ValueError, match="token"):
        discovery._release_discovery_lock("same", token)
    redis_client.get_sync_redis.assert_not_called()


@pytest.mark.parametrize("stage", ["client", "set"])
def test_unavailable_acquisition_raises_only_safe_error(store, caplog, stage):
    marker = "synthetic-private-store-diagnostic"
    if stage == "client":
        redis_client.get_sync_redis.side_effect = RuntimeError(marker)
    else:
        store.set = MagicMock(side_effect=RuntimeError(marker))
    with pytest.raises(RuntimeError, match="^Discovery lease store unavailable$") as caught:
        discovery._acquire_discovery_lock("same")
    assert marker not in str(caught.value) + caplog.text
    assert caught.value.__suppress_context__
    assert store.closed == (1 if stage == "set" else 0)


def test_accepted_set_then_lost_ack_does_not_grant_permission(store):
    original = store.set

    def accepted_then_lost(*args, **kwargs):
        original(*args, **kwargs)
        raise TimeoutError("synthetic lost acknowledgment")

    store.set = accepted_then_lost
    with pytest.raises(RuntimeError, match="Discovery lease store unavailable"):
        discovery._acquire_discovery_lock("same")
    assert isinstance(store.rows["same"], str)
    assert store.closed == 1


def test_client_close_failure_does_not_change_acquired_identity(store):
    store.close = MagicMock(side_effect=RuntimeError("synthetic close failure"))
    token = discovery._acquire_discovery_lock("same")
    assert isinstance(token, str) and store.rows["same"] == token


def test_acquisition_uses_bounded_sentinel_aware_client(store):
    discovery._acquire_discovery_lock("same")
    redis_client.get_sync_redis.assert_called_once_with(socket_timeout=2, socket_connect_timeout=2)


@pytest.mark.parametrize("contended", [False, True])
def test_acquisition_always_closes_client(store, contended):
    if contended:
        store.rows["same"] = "someone-else"
    discovery._acquire_discovery_lock("same")
    assert store.closed == 1


@pytest.mark.parametrize("stage", ["client", "eval"])
def test_release_unavailable_does_not_raise_or_log_raw_diagnostic(store, caplog, stage):
    token = discovery._acquire_discovery_lock("same")
    marker = "synthetic-private-release-diagnostic"
    if stage == "client":
        redis_client.get_sync_redis.side_effect = RuntimeError(marker)
    else:
        store.eval = MagicMock(side_effect=RuntimeError(marker))
    discovery._release_discovery_lock("same", token)
    assert store.rows["same"] == token
    assert marker not in caplog.text
    assert "Discovery lease release unavailable" in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
    assert store.closed == (2 if stage == "eval" else 1)


def test_release_uses_bounded_client_and_closes_it(store):
    token = discovery._acquire_discovery_lock("same")
    redis_client.get_sync_redis.reset_mock()
    discovery._release_discovery_lock("same", token)
    redis_client.get_sync_redis.assert_called_once_with(socket_timeout=2, socket_connect_timeout=2)
    assert store.closed == 2


def test_release_close_failure_preserves_success(store):
    token = discovery._acquire_discovery_lock("same")
    store.close = MagicMock(side_effect=RuntimeError("synthetic close error"))
    discovery._release_discovery_lock("same", token)
    assert "same" not in store.rows


@pytest.mark.parametrize("organization", [None, "owned-org"])
def test_wrapper_retains_scope_and_return_value(store, monkeypatch, organization):
    async def body(org, site):
        assert (org, site) == (organization, "owned-site")
        key = "freesdn:discovery:running" + (":" + organization if organization else "")
        assert set(store.rows) == {key}
        return {"success": True, "total_devices_discovered": 3}

    effect = AsyncMock(side_effect=body)
    monkeypatch.setattr(discovery, "_discover_all_devices", effect)
    assert discovery.discover_all_devices.run(organization, "owned-site") == {
        "success": True,
        "total_devices_discovered": 3,
    }
    assert not store.rows
    effect.assert_awaited_once_with(organization, "owned-site")


@pytest.mark.parametrize("organization", [None, "owned-org"])
def test_contended_wrapper_skips_without_running_effect(store, monkeypatch, organization):
    key = "freesdn:discovery:running" + (":" + organization if organization else "")
    store.rows[key] = "other-owner"
    effect = AsyncMock()
    monkeypatch.setattr(discovery, "_discover_all_devices", effect)
    assert discovery.discover_all_devices.run(organization) == {
        "success": True,
        "skipped": True,
        "reason": "already_running",
    }
    effect.assert_not_called()
    assert store.rows[key] == "other-owner"


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_body_error_is_not_masked_and_does_not_retry(store, monkeypatch, cleanup_fails):
    effect = AsyncMock(side_effect=LookupError("synthetic body error"))
    monkeypatch.setattr(discovery, "_discover_all_devices", effect)
    if cleanup_fails:
        store.eval = MagicMock(side_effect=RuntimeError("synthetic cleanup error"))
    with pytest.raises(LookupError, match="synthetic body error"):
        discovery.discover_all_devices.run("owned-org")
    effect.assert_awaited_once()
    assert bool(store.rows) is cleanup_fails


@pytest.mark.parametrize("stage", ["client", "set"])
def test_wrapper_never_runs_effect_on_unconfirmed_lease(store, monkeypatch, stage):
    effect = AsyncMock(return_value={"success": True})
    monkeypatch.setattr(discovery, "_discover_all_devices", effect)
    if stage == "client":
        redis_client.get_sync_redis.side_effect = RuntimeError("synthetic connection outage")
    else:
        store.set = MagicMock(side_effect=TimeoutError("synthetic timeout"))
    with pytest.raises(RuntimeError, match="Discovery lease store unavailable"):
        discovery.discover_all_devices.run("owned-org")
    effect.assert_not_called()


def test_completed_effect_survives_release_outage_without_retry(store, monkeypatch):
    effect = AsyncMock(return_value={"success": True})
    monkeypatch.setattr(discovery, "_discover_all_devices", effect)
    store.eval = MagicMock(side_effect=TimeoutError("synthetic release timeout"))
    assert discovery.discover_all_devices.run("owned-org") == {"success": True}
    effect.assert_awaited_once()
    assert "freesdn:discovery:running:owned-org" in store.rows


@pytest.mark.parametrize("body_fails", [False, True])
def test_expiring_wrapper_cannot_remove_successor_even_on_exception(store, monkeypatch, body_fails):
    key = "freesdn:discovery:running:owned-org"
    successor = []

    async def body(*_args):
        store.rows.pop(key)
        successor.append(discovery._acquire_discovery_lock(key))
        if body_fails:
            raise LookupError("synthetic effect error")
        return {"success": True}

    monkeypatch.setattr(discovery, "_discover_all_devices", body)
    if body_fails:
        with pytest.raises(LookupError, match="synthetic effect error"):
            discovery.discover_all_devices.run("owned-org")
    else:
        assert discovery.discover_all_devices.run("owned-org") == {"success": True}
    assert store.rows.get(key) == successor[0]
