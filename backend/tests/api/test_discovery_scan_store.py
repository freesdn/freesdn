# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Regression tests for the cross-worker discovery scan store.

``_active_scans`` is a module-level dict, so it lives in ONE gunicorn worker.
The shipped deployment pre-forks two (``WEB_CONCURRENCY:-2`` in
docker-compose.yml and in docker-entrypoint.sh) behind a single Caddy upstream
pool, so every follow-up request -- progress, results, latest, history, cancel,
delete -- landed on the originating worker only about half the time and 404'd
in the other. The frontend poller swallows a 404, so the visible symptom was a
scan that quietly produced nothing and no error.

Each test drives the endpoint functions directly (the permission dependency and
the HTTP layer are unchanged by the fix and would only add setup), and models
"the other worker" the only way that is honest in one process: clear
``_active_scans`` and read again. Everything that survives that clear is
something the second worker can serve.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio

import app.api.v1.endpoints.discovery as disc
from app.services.scanner import DiscoveredHost, ScanProgress, ScanStatus

# ---------------------------------------------------------------------------
# A minimal async Redis that implements exactly the commands the store uses.
# Anything the store starts calling that is not here fails loudly rather than
# being silently absorbed.
# ---------------------------------------------------------------------------


class _FakeAsyncRedis:
    def __init__(self) -> None:
        self.strings: dict[str, str] = {}
        self.zsets: dict[str, dict[str, float]] = {}
        self.set_calls = 0

    async def set(self, key: str, value: str, ex: int | None = None) -> bool:
        self.set_calls += 1
        self.strings[key] = value
        return True

    async def get(self, key: str) -> str | None:
        return self.strings.get(key)

    async def delete(self, *keys: str) -> int:
        return sum(1 for k in keys if self.strings.pop(k, None) is not None)

    async def zadd(self, key: str, mapping: dict[str, float]) -> int:
        self.zsets.setdefault(key, {}).update(mapping)
        return len(mapping)

    async def zrevrange(self, key: str, start: int, stop: int) -> list[str]:
        members = sorted(self.zsets.get(key, {}).items(), key=lambda kv: kv[1], reverse=True)
        end = None if stop < 0 else stop + 1
        return [m for m, _ in members[start:end]]

    async def zrem(self, key: str, *members: str) -> int:
        z = self.zsets.get(key, {})
        return sum(1 for m in members if z.pop(m, None) is not None)

    async def expire(self, key: str, ttl: int) -> bool:
        return True


class _User:
    def __init__(self, org_id: str | None, superuser: bool = False) -> None:
        self.id = uuid4()
        self.organization_id = org_id
        self.is_superuser = superuser


class _StubScanner:
    """Stands in for NetworkScanner: records cancel(), carries a config."""

    def __init__(self, targets: list[str]) -> None:
        self.config = type("_Cfg", (), {"targets": targets})()
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> _FakeAsyncRedis:
    """Isolate the module's process-global state and hand it a fake Redis."""
    fake = _FakeAsyncRedis()
    monkeypatch.setattr(disc, "_active_scans", {})
    # The deletion tombstones are process-global too, and _ScriptedScanner reuses
    # one scan_id, so a delete in one test would otherwise mute the mirror in the
    # next one.
    monkeypatch.setattr(disc, "_deleted_scans", {})
    monkeypatch.setattr(disc, "_scan_store", lambda: _resolved(fake))
    return fake


def _resolved(value: Any) -> Any:
    fut: asyncio.Future[Any] = asyncio.get_event_loop().create_future()
    fut.set_result(value)
    return fut


def _entry(
    scan_id: str,
    org_id: str | None,
    *,
    status: ScanStatus = ScanStatus.RUNNING,
    hosts: int = 1,
    started: datetime | None = None,
    targets: list[str] | None = None,
) -> dict[str, Any]:
    progress = ScanProgress(
        scan_id=scan_id,
        started_at=started or datetime.now(UTC),
        total_hosts=8,
        status=status,
    )
    progress.scanned_hosts = 8
    progress.discovered_hosts = hosts
    results = [
        DiscoveredHost(ip_address=f"10.9.0.{i + 10}", likely_device_types=["switch"])
        for i in range(hosts)
    ]
    return {
        "scanner": _StubScanner(targets or ["10.9.0.0/29"]),
        "progress": progress,
        "results": results,
        "task": None,
        "organization_id": org_id,
        "owner_user_id": str(uuid4()),
    }


async def _seed_on_other_worker(entry: dict[str, Any], scan_id: str) -> None:
    """Publish a scan, then wipe local state -- i.e. hand it to worker B."""
    disc._active_scans[scan_id] = entry
    await disc._mirror_scan(scan_id, entry, force=True)
    disc._active_scans.clear()


ORG_A = "11111111-1111-1111-1111-111111111111"
ORG_B = "22222222-2222-2222-2222-222222222222"


# ---------------------------------------------------------------------------
# Reads must survive landing on the other worker
# ---------------------------------------------------------------------------


async def test_progress_is_served_by_the_worker_that_did_not_start_the_scan(
    store: _FakeAsyncRedis,
) -> None:
    """Mutation this catches: dropping the mirror fallback from _resolve_scan
    (back to ``_active_scans.get(scan_id)`` only), which 404s here."""
    scan_id = "scan-progress"
    await _seed_on_other_worker(_entry(scan_id, ORG_A), scan_id)

    prog = await disc.get_scan_progress(scan_id, _User(ORG_A))

    assert prog.scan_id == scan_id
    assert prog.total_hosts == 8
    assert prog.status == "running"


async def test_results_are_served_by_the_other_worker(store: _FakeAsyncRedis) -> None:
    """The poller's separate GET after ``status == completed`` is the request
    that actually broke.

    Mutation this catches: mirroring progress but not the hosts -- the operator
    would see a completed scan with zero devices and nothing to adopt.
    """
    scan_id = "scan-results"
    await _seed_on_other_worker(
        _entry(scan_id, ORG_A, status=ScanStatus.COMPLETED, hosts=3), scan_id
    )

    res = await disc.get_scan_results(scan_id, _User(ORG_A))

    assert res.status == "completed"
    assert res.total_discovered == 3
    assert [d.ip_address for d in res.devices] == ["10.9.0.10", "10.9.0.11", "10.9.0.12"]
    assert res.total_manageable == 3


async def test_unknown_scan_still_404s(store: _FakeAsyncRedis) -> None:
    """Control: the fallback must not invent an empty scan.

    Mutation this catches: ``_resolve_scan`` returning ``{}`` instead of None,
    which would turn every bogus id into a 200 with no devices.
    """
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        await disc.get_scan_progress("no-such-scan", _User(ORG_A))
    assert exc.value.status_code == 404


async def test_mirror_does_not_leak_another_orgs_scan(store: _FakeAsyncRedis) -> None:
    """Tenant isolation has to hold on the mirrored path too.

    Mutation this catches: skipping ``_scan_visible_to`` when the snapshot came
    from Redis -- the new store would become an IDOR the local dict never was.
    """
    from fastapi import HTTPException

    scan_id = "scan-org-a"
    await _seed_on_other_worker(_entry(scan_id, ORG_A), scan_id)

    with pytest.raises(HTTPException) as exc:
        await disc.get_scan_results(scan_id, _User(ORG_B))
    assert exc.value.status_code == 404

    # ...and the owner still sees it, so the assertion above is about the org
    # and not about the scan being unreadable.
    assert (await disc.get_scan_results(scan_id, _User(ORG_A))).scan_id == scan_id


# ---------------------------------------------------------------------------
# Aggregate views must cover both workers
# ---------------------------------------------------------------------------


async def test_history_merges_local_and_mirrored_scans(store: _FakeAsyncRedis) -> None:
    """History alternated between two different lists on refresh.

    Mutation this catches: reverting ``list_scan_history`` to iterate
    ``_active_scans`` only.
    """
    remote_id, local_id = "scan-remote", "scan-local"
    await _seed_on_other_worker(_entry(remote_id, ORG_A, targets=["10.9.0.0/29"]), remote_id)

    local = _entry(local_id, ORG_A, targets=["10.9.1.0/29"])
    disc._active_scans[local_id] = local

    history = await disc.list_scan_history(_User(ORG_A), limit=20)

    assert {row["scan_id"] for row in history} == {remote_id, local_id}
    assert all(row["started_at"] for row in history)
    assert {tuple(row["targets"]) for row in history} == {
        ("10.9.0.0/29",),
        ("10.9.1.0/29",),
    }


async def test_history_hides_other_orgs(store: _FakeAsyncRedis) -> None:
    """Mutation this catches: filtering visibility after the limit slice, or
    not at all, on the merged list."""
    await _seed_on_other_worker(_entry("a-scan", ORG_A), "a-scan")
    await _seed_on_other_worker(_entry("b-scan", ORG_B), "b-scan")

    history = await disc.list_scan_history(_User(ORG_B), limit=20)

    assert [row["scan_id"] for row in history] == ["b-scan"]


async def test_latest_results_picks_the_newest_across_workers(store: _FakeAsyncRedis) -> None:
    """ "Latest" used to mean "latest in whichever worker answered".

    Mutation this catches: reverting ``get_latest_scan_results`` to scan the
    local dict -- it would return the older, local scan.
    """
    old = datetime.now(UTC) - timedelta(hours=2)
    new = datetime.now(UTC)

    await _seed_on_other_worker(
        _entry("newer-remote", ORG_A, status=ScanStatus.COMPLETED, hosts=2, started=new),
        "newer-remote",
    )
    disc._active_scans["older-local"] = _entry(
        "older-local", ORG_A, status=ScanStatus.COMPLETED, hosts=1, started=old
    )

    res = await disc.get_latest_scan_results(_User(ORG_A))

    assert res.scan_id == "newer-remote"
    assert res.total_discovered == 2


# ---------------------------------------------------------------------------
# Cancel and delete must reach the owning worker
# ---------------------------------------------------------------------------


async def test_cancel_on_the_wrong_worker_raises_the_flag(store: _FakeAsyncRedis) -> None:
    """Mutation this catches: reverting cancel_scan to 404 when the scan is not
    local -- a running scan could then never be stopped from the other worker."""
    scan_id = "scan-cancel"
    await _seed_on_other_worker(_entry(scan_id, ORG_A), scan_id)

    msg = await disc.cancel_scan(scan_id, _User(ORG_A))

    assert "cancel" in msg.message.lower()
    assert store.strings.get(disc._SCAN_CANCEL_KEY.format(scan_id)) == "1"


async def test_cancel_flag_is_not_settable_by_another_org(store: _FakeAsyncRedis) -> None:
    """Mutation this catches: raising the flag before the visibility check,
    which would let any discovery:run user kill another tenant's scan."""
    from fastapi import HTTPException

    scan_id = "scan-cancel-org"
    await _seed_on_other_worker(_entry(scan_id, ORG_A), scan_id)

    with pytest.raises(HTTPException):
        await disc.cancel_scan(scan_id, _User(ORG_B))
    assert disc._SCAN_CANCEL_KEY.format(scan_id) not in store.strings


async def test_owning_worker_acts_on_the_remote_cancel_flag(
    store: _FakeAsyncRedis, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The flag is inert unless somebody reads it.

    Mutation this catches: deleting ``_watch_for_remote_cancel`` (or its
    ``_spawn_bg`` call in start_scan) -- cancel_scan would report success while
    the scan ran to completion.
    """
    monkeypatch.setattr(disc, "_CANCEL_POLL_INTERVAL_S", 0.01)
    scan_id = "scan-watch"
    scanner = _StubScanner(["10.9.0.0/29"])
    running: asyncio.Future[None] = asyncio.get_event_loop().create_future()
    task = asyncio.ensure_future(running)

    watcher = asyncio.ensure_future(disc._watch_for_remote_cancel(scan_id, scanner, task))
    await asyncio.sleep(0.03)
    assert not scanner.cancelled, "cancelled without anyone asking"

    await disc._request_remote_cancel(scan_id)
    await asyncio.wait_for(watcher, timeout=2)

    assert scanner.cancelled
    assert task.cancelled()


async def test_remote_delete_still_stops_the_running_scan(store: _FakeAsyncRedis) -> None:
    """Deleting a scan owned by the other worker must also stop it.

    _forget_mirrored_scan clears the cancel key as well as the snapshot, so the
    two calls only work in one order.

    Mutation this catches: raising the cancel flag BEFORE forgetting the mirror
    -- the delete then wipes the flag it just set, the owning worker never sees
    it, and the scan keeps running (and keeps republishing itself into history).
    """
    scan_id = "scan-remote-delete"
    await _seed_on_other_worker(_entry(scan_id, ORG_A), scan_id)

    await disc.delete_scan(scan_id, _User(ORG_A))

    assert disc._SCAN_KEY.format(scan_id) not in store.strings
    assert store.strings.get(disc._SCAN_CANCEL_KEY.format(scan_id)) == "1"


async def test_delete_removes_the_mirror(store: _FakeAsyncRedis) -> None:
    """Mutation this catches: dropping ``_forget_mirrored_scan`` -- the deleted
    scan would still be listed by history from the mirror."""
    scan_id = "scan-delete"
    await _seed_on_other_worker(_entry(scan_id, ORG_A), scan_id)

    await disc.delete_scan(scan_id, _User(ORG_A))

    assert disc._SCAN_KEY.format(scan_id) not in store.strings
    assert await disc.list_scan_history(_User(ORG_A), limit=20) == []


# ---------------------------------------------------------------------------
# Publishing rules
# ---------------------------------------------------------------------------


async def test_terminal_snapshot_is_never_throttled(store: _FakeAsyncRedis) -> None:
    """The final write is the one the whole feature exists for.

    Mutation this catches: applying ``_MIRROR_MIN_INTERVAL_S`` to terminal
    states too, which would drop the completed snapshot whenever the scan
    finished within the throttle window of the previous tick -- exactly the
    short scans an operator runs.
    """
    scan_id = "scan-terminal"
    entry = _entry(scan_id, ORG_A, hosts=1)
    disc._active_scans[scan_id] = entry

    await disc._mirror_scan(scan_id, entry)  # first tick, publishes
    first = store.set_calls

    await disc._mirror_scan(scan_id, entry)  # immediately after: throttled
    assert store.set_calls == first

    entry["progress"].status = ScanStatus.COMPLETED
    await disc._mirror_scan(scan_id, entry)  # terminal: must publish anyway
    assert store.set_calls == first + 1

    disc._active_scans.clear()
    assert (await disc.get_scan_results(scan_id, _User(ORG_A))).status == "completed"


async def test_truncated_results_are_declared_not_silent(
    store: _FakeAsyncRedis, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A shortened device list must say it is shortened.

    Mutation this catches: capping the mirrored hosts without surfacing it --
    the operator would adopt from a list they believed was complete.
    """
    monkeypatch.setattr(disc, "_MIRROR_MAX_HOSTS", 2)
    scan_id = "scan-truncated"
    await _seed_on_other_worker(
        _entry(scan_id, ORG_A, status=ScanStatus.COMPLETED, hosts=5), scan_id
    )

    res = await disc.get_scan_results(scan_id, _User(ORG_A))

    assert len(res.devices) == 2
    assert res.total_discovered == 5
    assert any("first 2 of 5" in e for e in res.errors)


async def test_local_reads_are_never_truncated(
    store: _FakeAsyncRedis, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The owning worker holds every host, so it must return every host.

    Mutation this catches: passing ``cap=_MIRROR_MAX_HOSTS`` on the local path
    in ``_resolve_scan``, which would shorten the answer for no reason.
    """
    monkeypatch.setattr(disc, "_MIRROR_MAX_HOSTS", 2)
    scan_id = "scan-local-full"
    disc._active_scans[scan_id] = _entry(scan_id, ORG_A, status=ScanStatus.COMPLETED, hosts=5)

    res = await disc.get_scan_results(scan_id, _User(ORG_A))

    assert len(res.devices) == 5
    assert res.errors == []


async def test_redis_down_degrades_to_local_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """No endpoint may start failing because the mirror is unavailable.

    Mutation this catches: dropping the ``if client is None`` guards, which
    would turn a Redis outage into a 500 on every discovery endpoint.
    """
    from fastapi import HTTPException

    monkeypatch.setattr(disc, "_active_scans", {})
    monkeypatch.setattr(disc, "_scan_store", lambda: _resolved(None))

    scan_id = "scan-no-redis"
    entry = _entry(scan_id, ORG_A, status=ScanStatus.COMPLETED, hosts=2)
    disc._active_scans[scan_id] = entry
    await disc._mirror_scan(scan_id, entry, force=True)  # no-op, must not raise

    assert (await disc.get_scan_results(scan_id, _User(ORG_A))).total_discovered == 2
    assert len(await disc.list_scan_history(_User(ORG_A), limit=20)) == 1

    disc._active_scans.clear()
    with pytest.raises(HTTPException) as exc:
        await disc.get_scan_results(scan_id, _User(ORG_A))
    assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# The same round trip against a real server
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def real_store(monkeypatch: pytest.MonkeyPatch) -> AsyncGenerator[Any]:
    """Point the store at a real Redis/Valkey, under test-only key names.

    The fake above is faithful to the commands the store issues today, but it
    cannot catch a value Redis would reject or a zset call whose real semantics
    differ. This runs the identical publish/read round trip against the server
    (CI provides one at localhost:6379) and skips when there is none, so the
    fake is never the only evidence.
    """
    from app.core.redis_client import get_async_redis

    client = get_async_redis(decode_responses=True, socket_timeout=2, socket_connect_timeout=2)
    try:
        await client.ping()
    except Exception as exc:  # noqa: BLE001 - any connection failure means "no server"
        await client.aclose()
        pytest.skip(f"no Redis/Valkey reachable for the mirror round trip: {exc}")

    # Namespaced so the run never touches a real deployment's scan keys.
    prefix = f"freesdn:test:{uuid4().hex}:"
    monkeypatch.setattr(disc, "_SCAN_KEY", prefix + "scan:{}")
    monkeypatch.setattr(disc, "_SCAN_CANCEL_KEY", prefix + "scan:{}:cancel")
    monkeypatch.setattr(disc, "_SCAN_INDEX_KEY", prefix + "scans")
    monkeypatch.setattr(disc, "_SCAN_TOMBSTONE_KEY", prefix + "scan:{}:deleted")
    monkeypatch.setattr(disc, "_active_scans", {})
    monkeypatch.setattr(disc, "_deleted_scans", {})
    monkeypatch.setattr(disc, "_scan_store", lambda: _resolved(client))
    try:
        yield client
    finally:
        keys = [k async for k in client.scan_iter(match=prefix + "*")]
        if keys:
            await client.delete(*keys)
        await client.aclose()


async def test_mirror_round_trips_through_a_real_redis(real_store: Any) -> None:
    """Publish on one worker, read on the other, for real.

    Mutation this catches: a snapshot that is not actually JSON-serialisable
    (a raw datetime or a DiscoveredHost would raise here but not in the fake),
    and any zadd/zrevrange misuse the in-memory stand-in papers over.
    """
    scan_id = f"scan-{uuid4().hex[:8]}"
    await _seed_on_other_worker(
        _entry(scan_id, ORG_A, status=ScanStatus.COMPLETED, hosts=2), scan_id
    )

    res = await disc.get_scan_results(scan_id, _User(ORG_A))
    assert res.status == "completed"
    assert [d.ip_address for d in res.devices] == ["10.9.0.10", "10.9.0.11"]

    history = await disc.list_scan_history(_User(ORG_A), limit=20)
    assert [row["scan_id"] for row in history] == [scan_id]

    await disc.cancel_scan(scan_id, _User(ORG_A))
    assert await real_store.get(disc._SCAN_CANCEL_KEY.format(scan_id)) == "1"

    await disc.delete_scan(scan_id, _User(ORG_A))
    assert await disc.list_scan_history(_User(ORG_A), limit=20) == []


async def test_a_deleted_scan_is_not_republished_through_a_real_redis(
    real_store: Any,
) -> None:
    """The deletion tombstone against a real server, not the in-memory stand-in.

    ``_SCAN_TOMBSTONE_KEY`` shares a prefix with ``_SCAN_KEY``, which the fake's
    plain dict cannot get wrong and a pattern-matched delete can. This drives
    the whole sequence -- delete on the non-owning worker, then the terminal
    publish the owning worker's cancelled task performs -- against real GET/SET/
    DEL/ZREM semantics and TTLs.

    Mutation this catches: the tombstone guard in ``_mirror_scan`` (verified),
    and -- unlike the fake-backed tests -- a tombstone the real server would not
    store as written: a TTL it rejects, a key ``_forget_mirrored_scan``'s own
    DEL matches, or a reply ``_scan_is_deleted`` reads as falsey because it came
    back as bytes rather than str.
    """
    scan_id = f"scan-{uuid4().hex[:8]}"
    entry = _entry(scan_id, ORG_A, status=ScanStatus.COMPLETED, hosts=2)
    await _seed_on_other_worker(entry, scan_id)

    # Worker B: no local entry, so this takes the mirror-only delete branch.
    await disc.delete_scan(scan_id, _User(ORG_A))
    assert await real_store.get(disc._SCAN_TOMBSTONE_KEY.format(scan_id)) == "1"
    assert await real_store.ttl(disc._SCAN_TOMBSTONE_KEY.format(scan_id)) > 0

    # Worker A: the cancelled task's teardown forces one last publish.
    disc._active_scans[scan_id] = entry
    await disc._mirror_scan(scan_id, entry, force=True)
    disc._active_scans.clear()

    assert await real_store.get(disc._SCAN_KEY.format(scan_id)) is None
    assert await disc.list_scan_history(_User(ORG_A), limit=20) == []


# ---------------------------------------------------------------------------
# End to end through start_scan, which is where the mirror writes are wired
# ---------------------------------------------------------------------------


class _ScriptedScanner:
    """A NetworkScanner shaped enough for start_scan, with a controllable run."""

    instances: list[_ScriptedScanner] = []
    #: When True a new scanner blocks after yielding, so a test can cancel it
    #: mid-run. Set on the CLASS, because start_scan constructs the instance.
    hang_default = False

    def __init__(self, config: Any) -> None:
        self.config = config
        self.progress: ScanProgress | None = None
        self.cancelled = False
        self.hang = _ScriptedScanner.hang_default
        _ScriptedScanner.instances.append(self)

    async def scan(self, progress_callback: Any = None) -> Any:
        self.progress = ScanProgress(
            scan_id="e2e-scan", started_at=datetime.now(UTC), total_hosts=2
        )
        if progress_callback:
            progress_callback(self.progress)
        for i in range(2):
            if self.cancelled:
                break
            yield DiscoveredHost(ip_address=f"10.9.0.{20 + i}", likely_device_types=["camera"])
        while self.hang and not self.cancelled:
            await asyncio.sleep(0.01)
        self.progress.status = ScanStatus.CANCELLED if self.cancelled else ScanStatus.COMPLETED
        self.progress.discovered_hosts = 2
        if progress_callback:
            progress_callback(self.progress)

    def cancel(self) -> None:
        self.cancelled = True


@pytest.fixture
def scripted(monkeypatch: pytest.MonkeyPatch) -> type[_ScriptedScanner]:
    import app.services.scanner as scanner_mod

    _ScriptedScanner.instances = []
    monkeypatch.setattr(_ScriptedScanner, "hang_default", False)
    monkeypatch.setattr(disc, "NetworkScanner", _ScriptedScanner)
    monkeypatch.setattr(scanner_mod, "expand_targets", lambda targets, _excludes: set(targets))
    return _ScriptedScanner


async def _start(user: _User) -> Any:
    from fastapi import BackgroundTasks

    from app.schemas.discovery import ScanRequestSchema

    return await disc.start_scan(
        ScanRequestSchema(targets=["10.9.0.0/29"]), user, BackgroundTasks()
    )


async def test_completed_scan_is_readable_from_the_other_worker_end_to_end(
    store: _FakeAsyncRedis, scripted: type[_ScriptedScanner]
) -> None:
    """The whole reported failure, start to finish.

    Mutation this catches: removing either mirror write from start_scan -- the
    per-tick one in _on_progress or the terminal one in _run_scan's finally.
    Without them the scan completes and the other worker still 404s.
    """
    started = await _start(_User(ORG_A))
    entry = disc._active_scans[started.scan_id]
    await asyncio.wait_for(entry["task"], timeout=5)
    await asyncio.sleep(0.05)  # let the spawned terminal mirror land

    disc._active_scans.clear()  # now ask the OTHER worker

    prog = await disc.get_scan_progress(started.scan_id, _User(ORG_A))
    assert prog.status == "completed"

    res = await disc.get_scan_results(started.scan_id, _User(ORG_A))
    assert [d.ip_address for d in res.devices] == ["10.9.0.20", "10.9.0.21"]


async def test_cancelled_scan_still_publishes_a_final_snapshot(
    store: _FakeAsyncRedis, scripted: type[_ScriptedScanner]
) -> None:
    """A cancelled scan must not be left reading "running" on the other worker.

    On this path the scanner is torn down by task.cancel(), so the progress
    callback never fires again and the status only reaches CANCELLED inside
    _run_scan's own handler. The terminal publish in its finally is the only
    thing that gets that out of this process.

    Mutation this catches: removing that terminal _mirror_scan. The scan then
    sits at "running" forever for anyone not on the owning worker -- the same
    dead end the fix exists to remove. (The finally uses _spawn_bg rather than
    await so a second task.cancel() cannot interrupt the publish; that timing
    is NOT reproduced here, so treat it as reasoning, not as covered.)
    """
    scripted.hang_default = True  # block after the hosts, so cancel lands mid-run
    started = await _start(_User(ORG_A))
    entry = disc._active_scans[started.scan_id]
    assert scripted.instances[0].hang

    await disc.cancel_scan(started.scan_id, _User(ORG_A))
    with contextlib.suppress(asyncio.CancelledError):
        await entry["task"]
    await asyncio.sleep(0.05)  # let the spawned publish land

    disc._active_scans.clear()
    prog = await disc.get_scan_progress(started.scan_id, _User(ORG_A))
    assert prog.status == "cancelled"


# ---------------------------------------------------------------------------
# Delete and cancel INTERACTING, which is where they contradicted each other
# ---------------------------------------------------------------------------
# Two rules above are each individually right and, run together, cancelled each
# other out:
#
#   test_remote_delete_still_stops_the_running_scan  -- a DELETE that lands on
#       the worker which does not own the scan drops the mirror and then asks
#       the owner to cancel.
#   test_cancelled_scan_still_publishes_a_final_snapshot -- a cancelled scan
#       MUST publish a terminal snapshot, because that is the only way the
#       "cancelled" status ever leaves the owning process.
#
# So the delete removed the snapshot, the cancel it requested arrived, and the
# owning task's teardown published the scan straight back -- terminal snapshot,
# index entry and all. The deleted scan was in history again within a couple of
# seconds and stayed for the full hour TTL. Neither test above could see it:
# each exercises one half and stops.


async def _hand_to_the_other_worker(scan_id: str, coro_factory: Any) -> Any:
    """Run one endpoint call as if it had landed on the worker that does not own
    the scan, by hiding the local entry for the duration of the call."""
    owning = disc._active_scans.pop(scan_id)
    try:
        return await coro_factory()
    finally:
        disc._active_scans[scan_id] = owning


async def test_a_scan_deleted_on_the_other_worker_is_not_republished(
    store: _FakeAsyncRedis, scripted: type[_ScriptedScanner], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reported bug, end to end and in the order it actually happens.

    Worker B deletes -> the owning worker's cancel watcher fires -> the task
    teardown runs. Before the fix the last step re-``set`` the snapshot key and
    re-``zadd``ed the index entry, so this asserts on the store itself rather
    than only on the history endpoint.

    Mutation this catches: removing the tombstone check from ``_mirror_scan``
    (either the local short-circuit or the ``_scan_is_deleted`` read), or
    writing the tombstone after the snapshot is dropped instead of before.
    """
    monkeypatch.setattr(disc, "_CANCEL_POLL_INTERVAL_S", 0.01)
    scripted.hang_default = True
    started = await _start(_User(ORG_A))
    scan_id = started.scan_id
    entry = disc._active_scans[scan_id]

    await _hand_to_the_other_worker(scan_id, lambda: disc.delete_scan(scan_id, _User(ORG_A)))

    with contextlib.suppress(asyncio.CancelledError):
        await entry["task"]
    await asyncio.sleep(0.1)  # let the teardown's spawned publish run

    assert disc._SCAN_KEY.format(scan_id) not in store.strings
    assert store.zsets.get(disc._SCAN_INDEX_KEY, {}) == {}
    assert await disc.list_scan_history(_User(ORG_A), limit=20) == []


async def test_the_owning_worker_also_forgets_a_remotely_deleted_scan(
    store: _FakeAsyncRedis, scripted: type[_ScriptedScanner], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Clearing the mirror is only half of "deleted".

    ``_active_scans`` on the owning worker is the other half: history merges the
    local dict with the mirror, so a scan left behind there is still listed by
    whichever worker owns it -- about half of all requests -- and
    ``_evict_completed_scans`` does not run until somebody starts another scan.

    Mutation this catches: dropping the ``_active_scans.pop`` from
    ``_watch_for_remote_cancel``. Verified: the store assertions in the test
    above still pass under that mutation (the mirror is correctly not
    republished) -- it is this test's ``scan_id not in _active_scans``, and the
    history assertion both tests share, that fail.
    """
    monkeypatch.setattr(disc, "_CANCEL_POLL_INTERVAL_S", 0.01)
    scripted.hang_default = True
    started = await _start(_User(ORG_A))
    scan_id = started.scan_id
    entry = disc._active_scans[scan_id]

    await _hand_to_the_other_worker(scan_id, lambda: disc.delete_scan(scan_id, _User(ORG_A)))

    with contextlib.suppress(asyncio.CancelledError):
        await entry["task"]
    await asyncio.sleep(0.1)

    # No _active_scans.clear() here: this is the OWNING worker answering.
    assert scan_id not in disc._active_scans
    assert await disc.list_scan_history(_User(ORG_A), limit=20) == []

    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        await disc.get_scan_results(scan_id, _User(ORG_A))
    assert exc.value.status_code == 404


async def test_a_local_delete_is_not_undone_by_its_own_cancellation(
    store: _FakeAsyncRedis, scripted: type[_ScriptedScanner]
) -> None:
    """The same contradiction on ONE worker: delete_scan cancels its own task.

    ``delete_scan`` pops the entry, cancels the task and only then awaits
    ``_forget_mirrored_scan``. The cancelled task's ``finally`` gets to run at
    that await, so the terminal publish and the mirror teardown are interleaved
    by the event loop -- the delete used to win only by luck. The remote-delete
    tests above never reach this path, because on that branch there is no local
    task at all.

    Mutation this catches: removing the tombstone guard from ``_mirror_scan``
    (verified -- this test then fails on the same "the snapshot key is back"
    assertion as the remote case).
    """
    scripted.hang_default = True
    started = await _start(_User(ORG_A))
    scan_id = started.scan_id
    entry = disc._active_scans[scan_id]
    assert disc._SCAN_KEY.format(scan_id) in store.strings  # it was published

    await disc.delete_scan(scan_id, _User(ORG_A))

    with contextlib.suppress(asyncio.CancelledError):
        await entry["task"]
    await asyncio.sleep(0.1)

    assert disc._SCAN_KEY.format(scan_id) not in store.strings
    assert await disc.list_scan_history(_User(ORG_A), limit=20) == []


async def test_a_plain_cancel_still_publishes_its_terminal_snapshot(
    store: _FakeAsyncRedis, scripted: type[_ScriptedScanner], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control the tombstone must not break.

    Cancelling is not deleting: the operator still wants to see the scan, its
    partial results, and that it ended as "cancelled". A tombstone written on
    the cancel path -- or a ``_mirror_scan`` guard that keys off "is this scan
    still in _active_scans" instead of off the tombstone -- would silently
    reintroduce the dead end the mirror was built to remove.

    Mutation this catches: raising the tombstone in ``_request_remote_cancel``
    or in ``cancel_scan``.
    """
    monkeypatch.setattr(disc, "_CANCEL_POLL_INTERVAL_S", 0.01)
    scripted.hang_default = True
    started = await _start(_User(ORG_A))
    scan_id = started.scan_id
    entry = disc._active_scans[scan_id]

    await _hand_to_the_other_worker(scan_id, lambda: disc.cancel_scan(scan_id, _User(ORG_A)))

    with contextlib.suppress(asyncio.CancelledError):
        await entry["task"]
    await asyncio.sleep(0.1)

    disc._active_scans.clear()
    prog = await disc.get_scan_progress(scan_id, _User(ORG_A))
    assert prog.status == "cancelled"
    assert [row["scan_id"] for row in await disc.list_scan_history(_User(ORG_A), limit=20)] == [
        scan_id
    ]


async def test_the_owning_worker_refuses_to_republish_before_the_tombstone_lands(
    store: _FakeAsyncRedis, scripted: type[_ScriptedScanner]
) -> None:
    """Why the tombstone is also kept in-process, not only in Redis.

    On a real server writing the tombstone is a network round trip, and the
    cancelled task's teardown can reach ``_mirror_scan`` before it lands. The
    in-memory Redis here completes without ever yielding, so it cannot produce
    that interleaving; taking the Redis tombstone away after the delete models
    the same state ("this worker deleted the scan, the store does not know yet")
    without pretending to reproduce the timing.

    Mutation this catches: removing ``_remember_deleted(scan_id)`` from
    ``delete_scan`` -- with the Redis tombstone not yet visible there is then
    nothing left to consult, and the scan is published again.
    """
    scripted.hang_default = True
    started = await _start(_User(ORG_A))
    scan_id = started.scan_id
    entry = disc._active_scans[scan_id]

    await disc.delete_scan(scan_id, _User(ORG_A))
    store.strings.pop(disc._SCAN_TOMBSTONE_KEY.format(scan_id), None)

    await disc._mirror_scan(scan_id, entry, force=True)

    assert disc._SCAN_KEY.format(scan_id) not in store.strings
    assert await disc.list_scan_history(_User(ORG_A), limit=20) == []


async def test_delete_does_not_start_failing_when_redis_is_unreachable(
    scripted: type[_ScriptedScanner], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Adding the tombstone must not add a new way for a Redis outage to 500.

    Every other endpoint in this module degrades to local-only when the mirror
    is down; the delete path now touches two more keys and reads a third, and
    all three have to be skipped rather than raise.

    Mutation this catches: dropping the ``if store is None`` guard from
    ``_scan_is_deleted`` or ``_unpublish`` -- both would raise AttributeError on
    ``None`` here, on the path an operator uses to stop a runaway scan.
    """
    monkeypatch.setattr(disc, "_active_scans", {})
    monkeypatch.setattr(disc, "_deleted_scans", {})
    monkeypatch.setattr(disc, "_scan_store", lambda: _resolved(None))
    scripted.hang_default = True

    started = await _start(_User(ORG_A))
    scan_id = started.scan_id
    entry = disc._active_scans[scan_id]

    await disc.delete_scan(scan_id, _User(ORG_A))
    with contextlib.suppress(asyncio.CancelledError):
        await entry["task"]
    await asyncio.sleep(0.1)

    # delete_scan's local branch stops the scan by cancelling the task (unlike
    # cancel_scan it does not also flip the scanner's own flag; tearing the
    # async generator down is what actually ends the run).
    assert entry["task"].cancelled()
    assert scan_id not in disc._active_scans
    assert await disc.list_scan_history(_User(ORG_A), limit=20) == []


async def test_another_org_cannot_plant_a_deletion_tombstone(store: _FakeAsyncRedis) -> None:
    """The tombstone is a mute button, so it has to sit behind the tenant check.

    A tombstone written for a scan the caller cannot see would keep that scan
    out of the mirror for the whole TTL -- strictly worse than the IDOR the
    visibility check was added for, because the owner's own worker would then
    stop publishing it.

    Mutation this catches: moving ``_forget_mirrored_scan`` (or a bare
    ``_remember_deleted``) above the ``_scan_visible_to`` check in
    ``delete_scan``.
    """
    from fastapi import HTTPException

    scan_id = "scan-tombstone-org"
    await _seed_on_other_worker(_entry(scan_id, ORG_A), scan_id)

    with pytest.raises(HTTPException) as exc:
        await disc.delete_scan(scan_id, _User(ORG_B))
    assert exc.value.status_code == 404

    assert disc._SCAN_TOMBSTONE_KEY.format(scan_id) not in store.strings
    assert not disc._locally_deleted(scan_id)
    assert (await disc.get_scan_results(scan_id, _User(ORG_A))).scan_id == scan_id


async def test_a_tombstoned_scan_is_never_written_in_the_first_place(
    store: _FakeAsyncRedis,
) -> None:
    """Not published-then-retracted: not published.

    Retracting afterwards converges on the right answer but is not the same
    thing. Between the write and the retraction the deleted scan is readable
    again by anyone polling history on the other worker, and the value being
    written is the whole snapshot -- up to 2000 hosts -- for a scan that no
    longer exists. The owning worker keeps ticking for up to
    ``_CANCEL_POLL_INTERVAL_S`` before its watcher notices the delete, so this
    is not a single instant.

    Mutation this catches: removing the tombstone read that guards the writes
    in ``_mirror_scan`` and leaning on the post-write retraction alone. Every
    other assertion in this file still passes under that mutation; only the
    "no write was attempted" one here fails.
    """
    scan_id = "scan-no-write"
    entry = _entry(scan_id, ORG_A, status=ScanStatus.CANCELLED, hosts=1)
    disc._active_scans[scan_id] = entry

    # Deleted on the other worker: the tombstone is in the store, and this
    # process has no local record of it yet.
    await disc._forget_mirrored_scan(scan_id)
    assert not disc._locally_deleted(scan_id)
    writes_before = store.set_calls

    await disc._mirror_scan(scan_id, entry, force=True)

    assert store.set_calls == writes_before, "the snapshot was written and then retracted"
    assert disc._SCAN_KEY.format(scan_id) not in store.strings


async def test_a_delete_that_lands_mid_publish_still_wins(
    store: _FakeAsyncRedis, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other ordering: the DELETE arrives while a publish is already in flight.

    Checking the tombstone before writing leaves a window -- three round trips
    wide against a real server -- in which the delete can land after the check
    and before the snapshot goes back. Nothing serialises the two workers, so
    without a second look the outcome depends on which request finished last.

    Forcing that interleaving needs a hook: the delete is fired from inside the
    store's first ``get``, which is the tombstone read ``_mirror_scan`` performs
    just before it writes. The interleaving itself is real (two workers, no
    lock); only the trigger is synthetic, and it is the trigger because a single
    process cannot otherwise land a request in the middle of another one.

    Mutation this catches: removing the post-write re-read from ``_mirror_scan``
    -- the snapshot then stays published and history lists the deleted scan.
    (Removing the pre-write read instead is caught by the test above, not by
    this one: with no pre-write read the hook fires on the post-write read, so
    the delete lands after the writes and cleans them up itself.)
    """
    scan_id = "scan-mid-publish"
    entry = _entry(scan_id, ORG_A, status=ScanStatus.CANCELLED, hosts=1)
    disc._active_scans[scan_id] = entry

    original_get = store.get
    calls = {"n": 0}

    async def get_then_delete(key: str) -> str | None:
        value = await original_get(key)
        calls["n"] += 1
        if calls["n"] == 1:
            await disc._forget_mirrored_scan(scan_id)
        return value

    monkeypatch.setattr(store, "get", get_then_delete)

    await disc._mirror_scan(scan_id, entry, force=True)

    assert calls["n"] >= 1, "the hook never fired, so nothing was interleaved"
    assert disc._SCAN_KEY.format(scan_id) not in store.strings
    assert store.zsets.get(disc._SCAN_INDEX_KEY, {}) == {}

    disc._active_scans.clear()
    assert await disc.list_scan_history(_User(ORG_A), limit=20) == []


async def test_the_tombstone_does_not_grow_without_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A long-lived worker deletes many scans; the local record has to be capped.

    Mutation this catches: dropping the eviction loop from ``_remember_deleted``
    -- a process-global dict that only ever grows is exactly the leak
    ``_evict_completed_scans`` exists to prevent for ``_active_scans``.
    """
    monkeypatch.setattr(disc, "_deleted_scans", {})
    monkeypatch.setattr(disc, "_MAX_DELETED_TOMBSTONES", 8)

    for i in range(50):
        disc._remember_deleted(f"scan-{i}")

    assert len(disc._deleted_scans) <= 8
    # The most recent deletions are the ones that still matter.
    assert disc._locally_deleted("scan-49")
    assert not disc._locally_deleted("scan-0")


async def test_an_expired_tombstone_stops_muting_the_mirror(
    store: _FakeAsyncRedis, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The local record is time-bounded, not permanent.

    Mutation this catches: ``_locally_deleted`` ignoring the stored expiry (a
    plain ``scan_id in _deleted_scans``), which would make the guard outlive the
    Redis tombstone's TTL and mute a mirror for the life of the process.
    """
    monkeypatch.setattr(disc, "_deleted_scans", {})
    scan_id = "scan-expiring-tombstone"
    disc._remember_deleted(scan_id)
    assert disc._locally_deleted(scan_id)

    disc._deleted_scans[scan_id] = time.monotonic() - 1
    assert not disc._locally_deleted(scan_id)
    assert scan_id not in disc._deleted_scans  # and it prunes itself

    entry = _entry(scan_id, ORG_A, status=ScanStatus.COMPLETED, hosts=1)
    disc._active_scans[scan_id] = entry
    await disc._mirror_scan(scan_id, entry, force=True)
    assert disc._SCAN_KEY.format(scan_id) in store.strings
