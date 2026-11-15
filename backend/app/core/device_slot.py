# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - one in-flight request group per device, across every process
======================================================================

Discovery, the controller health check, device-status sync, the gateway full
sync and health poll, drift checks, config backups, the camera/NVR, phone,
hypervisor, storage and Omada monitors all run in different Celery workers and
processes, on their own schedules. Each used to talk to a device whenever its
own beat fired, so on the 2026-11 soak an OPNsense received a full sync, a
health poll and a drift read at the same moment, and every one of them held a
PHP worker on the box while the others waited.

A **slot** is a Valkey lease, keyed by the physical device, that a poller must
hold for its whole request group (connect, the reads, disconnect):

* **exclusive** (every background poller): granted only while nobody else holds
  the device. A poller that cannot get it SKIPS the cycle and records why
  ("device busy: gateway sync since 12:03:04 UTC"); it never queues up.
* **shared** (interactive UI reads): up to ``DEVICE_UI_READ_CONCURRENCY``
  readers at once, never alongside an exclusive holder. A page that opens a
  dozen panels does not get a dozen sessions on the box at once, and a reader
  waits briefly instead of piling onto a poll in progress.

Safety:

* every lease carries a random token and is released by compare-and-delete, so
  a late release never frees somebody else's lease;
* the lease's DEADLINE outlives the holder's Celery hard time limit
  (``default_ttl``), so a live holder never loses its lease; but Valkey only
  keeps it ``LEASE_HEARTBEAT_SECONDS`` ahead, renewed by a heartbeat thread in
  the holder's process. A SIGKILLed holder (OOM killer, container restart,
  the hard time limit itself) stops renewing and frees the device within that
  heartbeat, not at the end of its time limit (16 minutes for discovery). A
  live holder that never releases (a leak) still loses the lease at its
  deadline, because renewals stop there;
* leases are remembered per process and released at ``task_postrun`` and
  ``worker_process_shutdown`` even when the holder's own ``finally`` never ran;
* a Valkey outage fails OPEN (the poll proceeds, logged): with the broker down
  nothing is scheduled anyway, and a lost state store must not stop fleet
  management. The same rule the shared breaker follows.

Device keys: one physical box is one key, whichever table points at it. A
gateway and a controller row for the same OPNsense share ``host:<address>``;
every device reached through a controller (APs and switches behind Omada,
cameras behind an NVR) uses its controller's key. A cloud-hosted controller is
keyed by its row instead (``controller:<id>``), because many tenants share the
cloud hostname.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import socket
import threading
import time
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from fastapi import HTTPException

logger = logging.getLogger(__name__)

_PREFIX = "freesdn:devslot:"

EXCLUSIVE = "exclusive"
SHARED = "shared"

#: Lease length for a holder outside any Celery task (an API request). A UI
#: read is bounded by the adapter's own timeouts well inside this.
API_TTL_SECONDS = 180
#: Margin above the holder's hard time limit.
_TTL_MARGIN = 60
#: How far ahead Valkey keeps a lease while its holder's process is alive. The
#: heartbeat renews it every quarter of this, from a thread of its own, so a
#: busy event loop does not starve it; only a process frozen for longer than
#: this (SIGSTOP, a paused VM) could lose a lease it still uses.
LEASE_HEARTBEAT_SECONDS = 90.0

# KEYS: 1 exclusive holder (string), 2 shared holders (zset token->expiry ms),
#       3 shared holder metadata (hash token->value)
# ARGV: 1 mode, 2 token, 3 value, 4 ttl ms, 5 shared cap
# Server time keeps every expiry on one clock whichever host asks.
_ACQUIRE_LUA = """
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local expired = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', now)
if #expired > 0 then
  redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
  redis.call('HDEL', KEYS[3], unpack(expired))
end
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
local ttl = tonumber(ARGV[4])
if ARGV[1] == 'exclusive' then
  if redis.call('ZCARD', KEYS[2]) > 0 then return 0 end
  redis.call('SET', KEYS[1], ARGV[2] .. '|' .. ARGV[3], 'PX', ttl)
  return 1
end
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[5]) then return 0 end
redis.call('ZADD', KEYS[2], now + ttl, ARGV[2])
redis.call('HSET', KEYS[3], ARGV[2], ARGV[3])
if redis.call('PTTL', KEYS[2]) < ttl then
  redis.call('PEXPIRE', KEYS[2], ttl)
  redis.call('PEXPIRE', KEYS[3], ttl)
end
return 1
"""

# Compare-and-renew: extend only this acquisition's lease, never another's.
# KEYS as above; ARGV: 1 mode, 2 token, 3 ttl ms
_RENEW_LUA = """
local ttl = tonumber(ARGV[3])
if ARGV[1] == 'exclusive' then
  local v = redis.call('GET', KEYS[1])
  if v and string.sub(v, 1, string.len(ARGV[2]) + 1) == ARGV[2] .. '|' then
    return redis.call('PEXPIRE', KEYS[1], ttl)
  end
  return 0
end
if not redis.call('ZSCORE', KEYS[2], ARGV[2]) then return 0 end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
redis.call('ZADD', KEYS[2], 'XX', now + ttl, ARGV[2])
if redis.call('PTTL', KEYS[2]) < ttl then
  redis.call('PEXPIRE', KEYS[2], ttl)
  redis.call('PEXPIRE', KEYS[3], ttl)
end
return 1
"""

# Compare-and-delete: only this acquisition's token releases the lease.
_RELEASE_LUA = """
if ARGV[1] == 'exclusive' then
  local v = redis.call('GET', KEYS[1])
  if v and string.sub(v, 1, string.len(ARGV[2]) + 1) == ARGV[2] .. '|' then
    return redis.call('DEL', KEYS[1])
  end
  return 0
end
redis.call('HDEL', KEYS[3], ARGV[2])
return redis.call('ZREM', KEYS[2], ARGV[2])
"""


# ── device keys ─────────────────────────────────────────────────────────


def normalize_host(host: Any) -> str | None:
    """``https://192.168.1.1:770/api`` -> ``192.168.1.1``; ``[fe80::1]:443`` -> ``fe80::1``.

    The port is dropped on purpose: a gateway row saved with ``:770`` and a
    controller row saved without it are still one box with one PHP pool.
    """
    if host is None:
        return None
    value = str(host).strip().lower()
    if not value:
        return None
    if "://" in value:
        value = urlsplit(value).hostname or ""
    else:
        value = value.split("/", 1)[0]
        if "@" in value:
            value = value.rsplit("@", 1)[1]
        if value.startswith("["):
            value = value[1:].split("]", 1)[0]
        elif value.count(":") == 1:
            value = value.split(":", 1)[0]
    value = value.rstrip(".")
    return value or None


def host_slot_key(host: Any, *, fallback: str) -> str:
    """The slot key for a device reached at ``host`` (``fallback`` when it has none)."""
    normalized = normalize_host(host)
    return f"host:{normalized}" if normalized else fallback


def gateway_slot_key(gw: Any) -> str:
    """A firewall/gateway (``firewall.gateway_connections``) row."""
    return host_slot_key(getattr(gw, "host", None), fallback=f"gateway:{getattr(gw, 'id', '')}")


def controller_slot_key(ctrl: Any) -> str:
    """A controller row, and every device reached through it.

    A cloud-hosted controller (Omada cloud) shares its API hostname with every
    other tenant of that cloud, so it is keyed by its own row.
    """
    fallback = f"controller:{getattr(ctrl, 'id', '')}"
    if str(getattr(ctrl, "connection_mode", "") or "").lower() == "cloud":
        return fallback
    return host_slot_key(getattr(ctrl, "host", None), fallback=fallback)


def nvr_slot_key(nvr: Any) -> str:
    """An NVR, and every camera polled through it."""
    return host_slot_key(getattr(nvr, "ip_address", None), fallback=f"nvr:{getattr(nvr, 'id', '')}")


def phone_slot_key(phone: Any) -> str:
    return host_slot_key(
        getattr(phone, "ip_address", None), fallback=f"phone:{getattr(phone, 'id', '')}"
    )


#: The node-local overlay daemon (Tailscale / NetBird): one box like any other.
OVERLAY_SLOT_KEY = "overlay:daemon"


def pbx_slot_key(pbx: Any) -> str:
    """A PBX (``voip.pbx`` row): its AMI and REST APIs are one box."""
    return host_slot_key(getattr(pbx, "ip_address", None), fallback=f"pbx:{getattr(pbx, 'id', '')}")


# ── leases ──────────────────────────────────────────────────────────────


@dataclass
class SlotLease:
    key: str
    token: str
    mode: str
    holder: str
    #: False when Valkey was unavailable and the caller was let through unguarded.
    guarded: bool = True
    task_id: str | None = None
    acquired_at: float = field(default_factory=time.time)
    #: Wall-clock time after which the lease is no longer renewed.
    deadline: float = 0.0
    #: How far ahead Valkey keeps it while this process is alive.
    heartbeat: float = 0.0
    renewed_at: float = field(default_factory=time.time)
    #: The Valkey keys it lives under (the prefix in force when it was taken).
    redis_keys: tuple[str, ...] = ()
    owner: Any = field(default=None, repr=False, compare=False)


_held_lock = threading.Lock()
_held: dict[str, SlotLease] = {}

#: The devices whose EXCLUSIVE slot the current asyncio task (or the task that
#: started it) holds. A write made while its caller already holds the device's
#: slot (a scheduled PoE change, a sync that reconciles) must not wait for
#: itself: :func:`acquire_write_turn` goes straight through for these.
_exclusive_here: contextvars.ContextVar[frozenset[str]] = contextvars.ContextVar(
    "freesdn_device_slots_held_here", default=frozenset()
)


def holds_here(device: str) -> bool:
    """True when this task already holds ``device``'s exclusive slot."""
    return device in _exclusive_here.get()


def _remember(lease: SlotLease) -> None:
    if lease.guarded:
        with _held_lock:
            _held[lease.token] = lease
        if lease.deadline - lease.acquired_at > lease.heartbeat > 0:
            _heartbeat.ensure_running()


def _forget(lease: SlotLease) -> None:
    with _held_lock:
        _held.pop(lease.token, None)


def held_leases() -> list[SlotLease]:
    with _held_lock:
        return list(_held.values())


class _Heartbeat:
    """One daemon thread per process that renews the leases it holds."""

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._pid: int | None = None
        self._start_lock = threading.Lock()

    def ensure_running(self) -> None:
        with self._start_lock:
            if self._thread is not None and self._thread.is_alive() and self._pid == os.getpid():
                return
            self._pid = os.getpid()
            self._thread = threading.Thread(
                target=self._run, name="freesdn-device-slot-heartbeat", daemon=True
            )
            self._thread.start()

    def _run(self) -> None:
        while True:
            try:
                pause = self.renew_once()
            except Exception:  # noqa: BLE001 - never let one bad beat stop renewals
                logger.exception("device slot heartbeat failed; retrying")
                pause = 1.0
            time.sleep(pause)

    def renew_once(self) -> float:
        """Renew every lease that is due; return how long to sleep."""
        now = time.time()
        sleep = 1.0
        for lease in held_leases():
            if lease.heartbeat <= 0 or lease.owner is None:
                continue
            remaining = lease.deadline - now
            if remaining <= 0:
                # Past its deadline: Valkey lets it go; so does this process.
                _forget(lease)
                continue
            interval = max(0.05, lease.heartbeat / 4)
            if now - lease.renewed_at >= interval:
                renewed = lease.owner._renew(lease, min(lease.heartbeat, remaining))
                if renewed is False:
                    # Gone from Valkey (expired, or another holder has the
                    # device): renewing it again can only fail. Its release
                    # stays a harmless compare-and-delete.
                    _forget(lease)
                    continue
                lease.renewed_at = now
            sleep = min(sleep, interval)
        return sleep


_heartbeat = _Heartbeat()


def _reset_after_fork() -> None:
    """A forked child holds none of its parent's leases and has no heartbeat
    thread; a lock held at fork time would never be released in the child."""
    global _held_lock, _heartbeat
    _held_lock = threading.Lock()
    _held.clear()
    _heartbeat = _Heartbeat()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_after_fork)


def _current_task() -> Any:
    try:
        from celery import current_task

        task = current_task
        if task is not None and getattr(getattr(task, "request", None), "id", None):
            return task
    except Exception:  # noqa: BLE001 - outside a worker there is simply no task
        pass
    return None


def default_ttl() -> int:
    """A lease length that outlives the current holder.

    Inside a Celery task: the task's hard time limit (the per-message override
    first, then the task's, then the app default) plus a margin, so a holder
    that is still running can never lose its lease, and a holder the hard limit
    SIGKILLed frees the device shortly after. Outside a task (an API request):
    ``API_TTL_SECONDS``.
    """
    task = _current_task()
    if task is None:
        return API_TTL_SECONDS
    limit: Any = None
    timelimit = getattr(task.request, "timelimit", None)
    if isinstance(timelimit, list | tuple) and timelimit and timelimit[0]:
        limit = timelimit[0]
    if not limit:
        limit = getattr(task, "time_limit", None)
    if not limit:
        try:
            from app.core.celery_app import celery_app

            limit = celery_app.conf.task_time_limit
        except Exception:  # noqa: BLE001
            limit = None
    return int(float(limit or 600)) + _TTL_MARGIN


def _default_redis() -> Any:
    from app.core.celery_app import _get_solo_redis

    return _get_solo_redis()


def _shared_cap() -> int:
    try:
        from app.core.config import settings

        return max(1, int(settings.DEVICE_UI_READ_CONCURRENCY))
    except Exception:  # noqa: BLE001
        return 2


class DeviceSlots:
    """Cross-process device leases (see the module docstring)."""

    def __init__(
        self,
        *,
        redis_factory: Callable[[], Any] | None = None,
        shared_cap: Callable[[], int] | None = None,
        heartbeat: float | None = None,
    ) -> None:
        self._redis_factory = redis_factory or _default_redis
        self._shared_cap = shared_cap or _shared_cap
        self._heartbeat = float(heartbeat if heartbeat is not None else LEASE_HEARTBEAT_SECONDS)

    @staticmethod
    def _keys(device: str) -> tuple[str, str, str]:
        base = f"{_PREFIX}{device}"
        return base, base + ":shared", base + ":shared-meta"

    # ── sync primitives (fast Valkey round trips) ───────────────────────

    def try_acquire(
        self,
        device: str,
        holder: str,
        *,
        ttl: float | None = None,
        mode: str = EXCLUSIVE,
        task_id: str | None = None,
    ) -> SlotLease | None:
        """Take the device's slot now, or ``None`` while somebody else holds it.

        ``ttl`` is the lease's deadline; Valkey keeps it at most the heartbeat
        ahead, renewed while this process lives (see the module docstring).
        """
        ttl_s = float(ttl if ttl is not None else default_ttl())
        held_for = min(ttl_s, self._heartbeat) if self._heartbeat > 0 else ttl_s
        keys = self._keys(device)
        token = uuid.uuid4().hex
        if task_id is None:
            task = _current_task()
            task_id = str(task.request.id) if task is not None else None
        meta = json.dumps(
            {
                "holder": holder,
                "mode": mode,
                "since": time.time(),
                "host": socket.gethostname(),
                "pid": os.getpid(),
                "task_id": task_id,
            }
        )
        try:
            got = self._redis_factory().eval(
                _ACQUIRE_LUA,
                3,
                *keys,
                mode,
                token,
                meta,
                max(1, int(held_for * 1000)),
                self._shared_cap(),
            )
        except Exception:  # noqa: BLE001 - fail open, see the module docstring
            logger.warning("device slot store unavailable for %s; proceeding unguarded", device)
            return SlotLease(device, token, mode, holder, guarded=False, task_id=task_id)
        if not got:
            return None
        now = time.time()
        lease = SlotLease(
            device,
            token,
            mode,
            holder,
            task_id=task_id,
            acquired_at=now,
            deadline=now + ttl_s,
            heartbeat=held_for,
            renewed_at=now,
            redis_keys=keys,
            owner=self,
        )
        _remember(lease)
        return lease

    def _renew(self, lease: SlotLease, seconds: float) -> bool | None:
        """Keep ``lease`` for another ``seconds`` (compare-and-renew).

        True: renewed. False: the lease is no longer this holder's. None: Valkey
        did not answer; the next beat tries again.
        """
        try:
            renewed = self._redis_factory().eval(
                _RENEW_LUA,
                3,
                *(lease.redis_keys or self._keys(lease.key)),
                lease.mode,
                lease.token,
                max(1, int(seconds * 1000)),
            )
        except Exception:  # noqa: BLE001 - the next beat tries again
            logger.warning("device slot renewal unavailable for %s", lease.key)
            return None
        if not renewed:
            logger.warning(
                "device slot %s held by %s was lost before it was released", lease.key, lease.holder
            )
        return bool(renewed)

    def release(self, lease: SlotLease | None) -> None:
        if lease is None:
            return
        _forget(lease)
        if not lease.guarded:
            return
        try:
            self._redis_factory().eval(
                _RELEASE_LUA,
                3,
                *(lease.redis_keys or self._keys(lease.key)),
                lease.mode,
                lease.token,
            )
        except Exception:  # noqa: BLE001 - the TTL bounds an unreleased lease
            logger.warning("device slot release unavailable for %s", lease.key)

    def holders(self, device: str) -> list[dict[str, Any]]:
        """Who holds the device right now (diagnostics and skip messages)."""
        excl, _, meta_key = self._keys(device)
        try:
            r = self._redis_factory()
            out: list[dict[str, Any]] = []
            raw = r.get(excl)
            if raw:
                text = raw.decode() if isinstance(raw, bytes) else str(raw)
                out.append(_parse_meta(text.split("|", 1)[1] if "|" in text else "{}"))
            for value in (r.hgetall(meta_key) or {}).values():
                text = value.decode() if isinstance(value, bytes) else str(value)
                out.append(_parse_meta(text))
            return out
        except Exception:  # noqa: BLE001
            return []

    def busy_reason(self, device: str) -> str:
        """Operator-facing reason a poll of ``device`` was skipped."""
        current = self.holders(device)
        if not current:
            return "Device busy: another request to it was in progress"
        first = current[0]
        since = first.get("since")
        when = ""
        if isinstance(since, int | float):
            stamp = datetime.fromtimestamp(float(since), UTC).strftime("%H:%M:%S UTC")
            when = f" since {stamp} ({max(0, int(time.time() - float(since)))}s)"
        extra = f" and {len(current) - 1} more" if len(current) > 1 else ""
        return f"Device busy: {first.get('holder') or 'another request'}{when}{extra}"

    # ── async API (pollers run inside asyncio.run; the API is async) ────

    async def acquire(
        self,
        device: str,
        holder: str,
        *,
        ttl: float | None = None,
        mode: str = EXCLUSIVE,
        wait: float = 0.0,
        poll_interval: float = 0.1,
    ) -> SlotLease | None:
        """Take the slot, waiting up to ``wait`` seconds; ``None`` if it stayed busy."""
        # Read the task context HERE: to_thread runs the Valkey call on another
        # thread, where Celery's current_task is not set.
        ttl_s = float(ttl if ttl is not None else default_ttl())
        task = _current_task()
        task_id = str(task.request.id) if task is not None else None
        deadline = time.monotonic() + max(0.0, wait)
        while True:
            lease = await asyncio.to_thread(
                self.try_acquire, device, holder, ttl=ttl_s, mode=mode, task_id=task_id
            )
            if lease is not None and mode == EXCLUSIVE:
                # Set here, in the caller's context (not on the worker thread).
                _exclusive_here.set(_exclusive_here.get() | {device})
            if lease is not None or time.monotonic() >= deadline:
                return lease
            await asyncio.sleep(min(poll_interval, max(0.0, deadline - time.monotonic())))

    async def arelease(self, lease: SlotLease | None) -> None:
        if lease is not None:
            if lease.mode == EXCLUSIVE and lease.key in _exclusive_here.get():
                _exclusive_here.set(_exclusive_here.get() - {lease.key})
            await asyncio.to_thread(self.release, lease)

    async def abusy_reason(self, device: str) -> str:
        return await asyncio.to_thread(self.busy_reason, device)

    @asynccontextmanager
    async def hold(
        self,
        device: str,
        holder: str,
        *,
        ttl: float | None = None,
        mode: str = EXCLUSIVE,
        wait: float = 0.0,
    ) -> AsyncIterator[SlotLease | None]:
        """``async with slots.hold(key, "gateway sync") as lease:`` -- ``None`` means busy."""
        lease = await self.acquire(device, holder, ttl=ttl, mode=mode, wait=wait)
        try:
            yield lease
        finally:
            if lease is not None:
                await self.arelease(lease)


def _parse_meta(text: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


#: The process-wide instance every poller uses.
device_slots = DeviceSlots()


# ── writes ──────────────────────────────────────────────────────────────


class DeviceWriteBusyError(HTTPException):
    """503: the device stayed busy, so the write was not sent."""

    def __init__(self, reason: str) -> None:
        super().__init__(
            status_code=503,
            detail=f"{reason}. The change was not sent to it; try again in a few seconds.",
            headers={"Retry-After": "5"},
        )


def _write_wait() -> float:
    try:
        from app.core.config import settings

        return max(0.0, float(settings.DEVICE_WRITE_SLOT_WAIT_SECONDS))
    except Exception:  # noqa: BLE001
        return 5.0


@dataclass
class WriteTurn:
    """A write's hold on its device; release it once the device has answered."""

    lease: SlotLease | None = None

    async def release(self) -> None:
        lease, self.lease = self.lease, None
        if lease is not None:
            await device_slots.arelease(lease)


async def acquire_write_turn(
    device: str | None, holder: str, *, wait: float | None = None
) -> WriteTurn:
    """Wait briefly for ``device``'s exclusive slot before a write is sent.

    The one place a device write takes its turn: the staging chokepoint
    (``AdapterStagingService.apply_change``, which every staged, same-request
    and grouped configuration write goes through) and audited operational
    actions (``device_writes.audited_device_action``) call it just before the
    device is contacted. It waits up to ``DEVICE_WRITE_SLOT_WAIT_SECONDS`` for a
    poll or another write to finish, then raises :class:`DeviceWriteBusyError`
    and nothing is sent. A write whose caller already holds the slot goes
    straight through, and so does one with no device key. A Valkey outage fails
    open, as for every poller.
    """
    if not device or holds_here(device):
        return WriteTurn()
    lease = await device_slots.acquire(device, holder, wait=_write_wait() if wait is None else wait)
    if lease is None:
        raise DeviceWriteBusyError(await device_slots.abusy_reason(device))
    return WriteTurn(lease)


def release_task_leases(task_id: str | None) -> int:
    """Release every lease a finished task still holds (``task_postrun``)."""
    if not task_id:
        return 0
    stale = [lease for lease in held_leases() if lease.task_id == task_id]
    for lease in stale:
        logger.warning("Releasing device slot %s left held by task %s", lease.key, task_id)
        device_slots.release(lease)
    return len(stale)


def release_all_held() -> int:
    """Release every lease this process holds (``worker_process_shutdown``)."""
    stale = held_leases()
    for lease in stale:
        device_slots.release(lease)
    return len(stale)
