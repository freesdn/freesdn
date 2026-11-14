# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Runtime-toggleable platform flags (no restart required).

The write-safety switch has two sources, and the more restrictive one wins:

  * ``ADAPTER_READ_ONLY`` in the server environment, set at deploy time. The
    Settings switch can never turn it off; the API refuses and says why.
  * The Settings switch, stored durably in Postgres (``core.platform_settings``,
    key ``adapter_read_only``) and cached in Valkey, so every process (API
    workers, Celery workers, beat) sees a change within seconds.

    effective read-only = environment OR stored switch

Until 26.12 the switch lived only in a Valkey key. A flush, a lost volume or a
Valkey error turned an operator's "read-only" into the environment default,
which the shipped compose file sets to read-write. Postgres is now the record;
Valkey only carries it to every process quickly.

The Valkey cache is two keys: ``freesdn:config:adapter_read_only``
("true"/"false", the key the switch used to live in, so a process still running
the previous version reads the same value) and
``freesdn:config:adapter_read_only:version``, the row version. A refill only
replaces a cached value with a NEWER version (compared inside Valkey), so a
stale read can never overwrite a newer write.

Per process:
  * an in-process cache answers for ``_CACHE_TTL_S``;
  * a refresh reads Valkey, and reads Postgres every ``_DB_TTL_S`` and on every
    refresh while Valkey cannot be read or holds no value. The newer version
    wins, and Valkey is refilled when it is behind;
  * a process that can read neither keeps the last value it had and, before it
    has ever had one, refuses writes. The gate never fails OPEN, during a
    Postgres blip, a Valkey blip or both.

WHERE THIS RUNS. ``is_adapter_read_only()`` is a plain ``def`` invoked from
``AdapterStagingService.apply_change`` and from every vendor client's per-write
gate -- all coroutines on the API event loop. A blocking read there holds the
*whole worker* for the round trip, so:

  * one pooled Valkey client for the process, because ``get_sync_redis()``
    builds a fresh ``redis.Redis`` (and pool) per call;
  * once primed, the refresh runs on a worker thread, so a degraded-but-
    reachable Valkey or Postgres can no longer freeze every request on the
    worker for the socket timeout; and
  * Postgres is read on its own short-lived connection with tight timeouts,
    from a thread with its own event loop, never on the caller's loop.

The very first read per process still blocks, on Valkey alone when Valkey holds
the value. That is deliberate: serving the environment default before the
stored switch has ever been consulted would let a write through that the
operator had disabled from Settings.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Literal

if TYPE_CHECKING:  # pragma: no cover - typing only
    from redis import Redis
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

logger = logging.getLogger(__name__)

_REDIS_KEY = "freesdn:config:adapter_read_only"
_REDIS_VERSION_KEY = "freesdn:config:adapter_read_only:version"
_CACHE_TTL_S = (
    5.0  # bounds Valkey reads to ~once/5s per worker; a toggle propagates within this window
)
#: How often a process re-reads Postgres while Valkey answers normally. This is
#: what repairs a cache that missed a write (a PUT made while Valkey was down).
_DB_TTL_S = 30.0

# Bound the blocking window explicitly. redis-py falls back
# ``socket_connect_timeout = socket_connect_timeout or socket_timeout``, and
# get_sync_redis() only passes socket_timeout=5 -- so a half-open connection
# could hold a caller for ~5s. This gate is a cheap boolean.
_SOCKET_TIMEOUT_S = 1.0
#: Connect and statement timeout for the Postgres read, in seconds.
_DB_TIMEOUT_S = 2.0

#: Compare-and-set in Valkey: write the value only when its version is newer
#: than the cached one (or the value key is missing and the version is not
#: older). Two keys change together or not at all.
_CAS_SCRIPT = """
local cur = tonumber(redis.call('GET', KEYS[2]) or '-1')
local new = tonumber(ARGV[2])
if new > cur or (redis.call('EXISTS', KEYS[1]) == 0 and new >= cur) then
  redis.call('SET', KEYS[1], ARGV[1])
  redis.call('SET', KEYS[2], ARGV[2])
  return 1
end
return 0
"""

StoredSource = Literal["database", "cache", "legacy_cache", "default"]


@dataclass(frozen=True)
class StoredSwitch:
    """What the Settings switch says, and where that answer came from.

    ``version`` is the row version; 0 means there is no row behind the value
    (a value cached by a version older than 26.12, or "never set").
    """

    read_only: bool
    version: int
    source: StoredSource


class _NoRow:
    """Postgres answered: the switch has never been saved."""


_NO_ROW: Final = _NoRow()

# (stored switch, monotonic expiry). None means "not known": refuse writes.
_cache: tuple[StoredSwitch | None, float] = (None, 0.0)
# False until a refresh has run at least once in this process. Until then a
# caller must wait for a real answer rather than be served a guess.
_cache_primed = False

# The last successful Postgres read: a StoredSwitch, _NO_ROW, or None (never).
_db_state: StoredSwitch | _NoRow | None = None
_db_read_at: float | None = None

_state_lock = threading.Lock()
_refresh_in_flight = False

# One client per process, so a refresh is a pooled round trip rather than a
# fresh connect + AUTH. Sentinel-backed clients re-resolve the master per
# connection, so caching the object stays failover-correct.
_client: Redis | None = None
_db_engine: AsyncEngine | None = None


def _get_client() -> Redis:
    """Return the process-wide sync client, creating it on first use."""
    global _client
    client = _client
    if client is None:
        from app.core.redis_client import get_sync_redis

        client = get_sync_redis(
            decode_responses=True,
            socket_timeout=_SOCKET_TIMEOUT_S,
            socket_connect_timeout=_SOCKET_TIMEOUT_S,
        )
        _client = client
    return client


def _get_db_engine() -> AsyncEngine:
    """A NullPool engine with tight timeouts, usable from any event loop.

    NullPool opens and closes a connection per read, so the engine holds no
    connection bound to a loop that has since finished; each read runs under
    its own ``asyncio.run`` on a worker thread.
    """
    global _db_engine
    engine = _db_engine
    if engine is None:
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.pool import NullPool

        from app.core.config import settings

        engine = create_async_engine(
            str(settings.DATABASE_URL),
            hide_parameters=True,
            poolclass=NullPool,
            connect_args={
                "timeout": _DB_TIMEOUT_S,
                "command_timeout": _DB_TIMEOUT_S,
                "statement_cache_size": 0,
            },
        )
        _db_engine = engine
    return engine


def _env_default() -> bool:
    """``ADAPTER_READ_ONLY`` from the environment; True if config is unreadable."""
    try:
        from app.core.config import settings

        return bool(getattr(settings, "ADAPTER_READ_ONLY", True))
    except Exception:
        return True


class _Unreadable(Exception):
    """A source could not be asked; distinct from "no value is stored"."""


def _on_event_loop() -> bool:
    """True when the caller is running inside an asyncio event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


def _run_blocking[T](factory: Callable[[], Coroutine[Any, Any, T]], timeout: float) -> T:
    """Run a coroutine to completion from synchronous code, on its own loop.

    On a thread with no running loop that is ``asyncio.run``. On an event-loop
    thread (the cold first read) it runs on a helper thread and waits, bounded,
    because ``asyncio.run`` cannot nest inside a running loop.
    """
    if not _on_event_loop():
        return asyncio.run(factory())
    box: list[Any] = []
    errors: list[BaseException] = []

    def _target() -> None:
        try:
            box.append(asyncio.run(factory()))
        except BaseException as exc:  # noqa: BLE001 - re-raised on the caller's thread
            errors.append(exc)

    worker = threading.Thread(target=_target, name="adapter-read-only-db", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise TimeoutError("platform setting read timed out")
    if errors:
        raise errors[0]
    result: T = box[0]
    return result


def _parse_cached(value: Any, version: Any) -> StoredSwitch | None:
    if value is None:
        return None
    read_only = str(value).strip().lower() == "true"
    try:
        ver = int(version) if version is not None else 0
    except (TypeError, ValueError):
        ver = 0
    return StoredSwitch(read_only, ver, "cache" if ver > 0 else "legacy_cache")


def _read_cache() -> StoredSwitch | None:
    """The cached switch, or None when Valkey holds no value.

    Raises :class:`_Unreadable` when Valkey cannot be read. An outage used to
    be reported as "no value", which fell back to the environment default; on
    the shipped compose that default is read-WRITE.
    """
    try:
        raw: Any = _get_client().mget([_REDIS_KEY, _REDIS_VERSION_KEY])
        values: list[Any] = list(raw)
    except Exception as exc:
        raise _Unreadable from exc
    return _parse_cached(values[0], values[1] if len(values) > 1 else None)


def _write_cache(stored: StoredSwitch) -> bool:
    """Put a row's value in Valkey unless Valkey already holds a newer one.

    Returns True when the value was written. Raises on a Valkey error.
    """
    written = _get_client().eval(
        _CAS_SCRIPT,
        2,
        _REDIS_KEY,
        _REDIS_VERSION_KEY,
        "true" if stored.read_only else "false",
        str(stored.version),
    )
    return bool(written)


def _stored_from_row(value: Any, version: Any) -> StoredSwitch:
    read_only = value.get("read_only") if isinstance(value, dict) else None
    if not isinstance(read_only, bool):
        # A row nobody can interpret must not be read as read-write.
        logger.error("adapter_read_only setting row is malformed; treating it as read-only")
        read_only = True
    return StoredSwitch(read_only, int(version or 0), "database")


async def _read_db_async() -> StoredSwitch | _NoRow:
    from sqlalchemy import select

    from app.models.platform_settings import ADAPTER_READ_ONLY_KEY, PlatformSetting

    async with _get_db_engine().connect() as conn:
        row = (
            await conn.execute(
                select(PlatformSetting.value, PlatformSetting.version).where(
                    PlatformSetting.key == ADAPTER_READ_ONLY_KEY
                )
            )
        ).first()
    if row is None:
        return _NO_ROW
    return _stored_from_row(row[0], row[1])


def _read_db() -> StoredSwitch | _NoRow:
    """The stored switch from Postgres, or ``_NO_ROW``. Raises ``_Unreadable``."""
    try:
        return _run_blocking(_read_db_async, timeout=2 * _DB_TIMEOUT_S + 1.0)
    except Exception as exc:
        raise _Unreadable from exc


async def _promote_cached_async(cached: StoredSwitch) -> StoredSwitch | _NoRow:
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.models.platform_settings import ADAPTER_READ_ONLY_KEY, PlatformSetting

    async with _get_db_engine().begin() as conn:
        await conn.execute(
            pg_insert(PlatformSetting)
            .values(
                key=ADAPTER_READ_ONLY_KEY,
                value={"read_only": cached.read_only},
                # Never below what Valkey holds, so the row is not "older" than
                # the cache and later saves move past both.
                version=max(cached.version, 1),
            )
            .on_conflict_do_nothing(index_elements=[PlatformSetting.key])
        )
    return await _read_db_async()


def _promote_cached(cached: StoredSwitch) -> StoredSwitch | _NoRow:
    """Copy a value only Valkey holds into Postgres, unless a row appeared meanwhile.

    A switch saved before 26.12 lives only in Valkey when the upgrade could not
    read it. Left there, losing the key later would silently restore the
    environment default (read-write on the shipped compose). Raises
    ``_Unreadable`` when Postgres cannot be written; the next refresh retries.
    """
    try:
        result = _run_blocking(
            lambda: _promote_cached_async(cached), timeout=4 * _DB_TIMEOUT_S + 1.0
        )
    except Exception as exc:
        raise _Unreadable from exc
    logger.warning(
        "adapter_read_only: the switch saved in Valkey (read_only=%s) had no Postgres "
        "row; it is now stored in Postgres",
        cached.read_only,
    )
    return result


def _decide(
    cached: StoredSwitch | None,
    cache_unreadable: bool,
    db: StoredSwitch | _NoRow | None,
) -> StoredSwitch | None:
    """Combine what Valkey and Postgres said. None means "not known"."""
    if isinstance(db, StoredSwitch):
        if cached is not None and cached.version > db.version:
            # A write newer than our last Postgres read already reached Valkey.
            return cached
        if cached is not None and cached.version == db.version:
            # Same version, so the same write. Should agree; if not, restrict.
            return db if db.read_only or not cached.read_only else cached
        return db
    if isinstance(db, _NoRow):
        if cached is not None:
            # Saved by a version older than 26.12, before the switch moved into
            # Postgres, and not migrated (Valkey was down during the upgrade).
            return cached
        if cache_unreadable:
            return None
        return StoredSwitch(False, 0, "default")
    # Postgres has never answered in this process.
    return cached


def _refresh_cache(*, cold: bool = False, force_db: bool = False) -> None:
    """Re-read the switch and replace the in-process cache. Blocks; never raises.

    A failed read never moves the gate toward read-write: when no source can
    say what the switch is, the value last read is kept, and before the first
    successful read in this process writes are refused until a read succeeds.
    The cache is still marked primed, so later refreshes stay off the event
    loop during an outage.
    """
    global _cache, _cache_primed, _db_state, _db_read_at
    now = time.monotonic()
    cache_unreadable = False
    try:
        cached = _read_cache()
    except _Unreadable:
        cached = None
        cache_unreadable = True

    if cache_unreadable or cached is None or force_db:
        db_due = True
    elif _db_read_at is None:
        # A cold read on the event loop answers from Valkey alone and leaves the
        # Postgres check to the first background refresh.
        db_due = not cold
    else:
        db_due = now - _db_read_at >= _DB_TTL_S
    db_answered = False
    if db_due:
        try:
            _db_state = _read_db()
            _db_read_at = now
            db_answered = True
        except _Unreadable:
            logger.debug("adapter_read_only: Postgres read failed", exc_info=True)
    if db_answered and isinstance(_db_state, _NoRow) and cached is not None:
        try:
            _db_state = _promote_cached(cached)
            _db_read_at = now
        except _Unreadable:
            logger.debug("adapter_read_only: promoting the cached switch failed", exc_info=True)

    stored = _decide(cached, cache_unreadable, _db_state)
    if stored is None:
        last_known = _cache[0] if _cache_primed else None
        _cache = (last_known, time.monotonic() + _CACHE_TTL_S)
        _cache_primed = True
        return

    if (
        not cache_unreadable
        and isinstance(_db_state, StoredSwitch)
        and stored is _db_state
        and (cached is None or cached.version < _db_state.version)
    ):
        try:
            _write_cache(_db_state)
        except Exception:
            logger.debug("adapter_read_only: Valkey refill failed", exc_info=True)

    _cache = (stored, time.monotonic() + _CACHE_TTL_S)
    _cache_primed = True


def _refresh_in_background() -> None:
    """Kick off at most one off-loop refresh, then return immediately."""
    global _refresh_in_flight
    with _state_lock:
        if _refresh_in_flight:
            return
        _refresh_in_flight = True

    def _worker() -> None:
        global _refresh_in_flight
        try:
            _refresh_cache()
        finally:
            with _state_lock:
                _refresh_in_flight = False

    # A daemon thread rather than loop.run_in_executor: this module is also
    # imported by Celery workers, and the refresh must not depend on an event
    # loop existing or outliving it.
    threading.Thread(target=_worker, name="adapter-read-only-refresh", daemon=True).start()


def _effective(stored: StoredSwitch | None) -> bool:
    if _env_default():
        return True
    if stored is None:
        return True
    return stored.read_only


def is_adapter_read_only() -> bool:
    """Effective read-only state for the adapter write gates.

    True when ``ADAPTER_READ_ONLY`` is set in the environment, when the
    Settings switch is on, or when this process has never been able to read the
    switch. Cheap and non-blocking on the hot path: an in-process cache (TTL 5s)
    bounds reads, and once primed the refresh is handed to a worker thread. A
    stale value is served for the duration of that refresh -- the toggle
    already lags up to the TTL, so this widens an existing window rather than
    opening a new one.
    """
    stored, expiry = _cache
    if time.monotonic() < expiry:
        return _effective(stored)

    if _cache_primed and _on_event_loop():
        _refresh_in_background()
        return _effective(stored)

    _refresh_cache(cold=not _cache_primed and _on_event_loop())
    return _effective(_cache[0])


EnforcedBy = Literal["environment", "setting", "environment_and_setting", "unverified", "none"]


@dataclass(frozen=True)
class ReadOnlyStatus:
    """Both sources of the write-safety mode, and which one is in force."""

    read_only: bool
    env_read_only: bool
    setting_read_only: bool | None
    setting_version: int
    setting_source: StoredSource | None
    enforced_by: EnforcedBy


def _status_from(stored: StoredSwitch | None) -> ReadOnlyStatus:
    env = _env_default()
    setting = stored.read_only if stored is not None else None
    enforced_by: EnforcedBy
    if env and setting:
        enforced_by = "environment_and_setting"
    elif env:
        enforced_by = "environment"
    elif stored is None:
        enforced_by = "unverified"
    elif setting:
        enforced_by = "setting"
    else:
        enforced_by = "none"
    return ReadOnlyStatus(
        read_only=_effective(stored),
        env_read_only=env,
        setting_read_only=setting,
        setting_version=stored.version if stored is not None else 0,
        setting_source=stored.source if stored is not None else None,
        enforced_by=enforced_by,
    )


async def read_only_status() -> ReadOnlyStatus:
    """Re-read both stores now and report what this process enforces.

    For the Settings page: a fresh answer, read off the event loop, rather than
    whatever the five-second cache happens to hold.
    """
    await asyncio.to_thread(_refresh_cache, force_db=True)
    return _status_from(_cache[0])


class EnvironmentEnforcesReadOnly(Exception):
    """The Settings switch cannot turn off read-only mode set by the environment."""


@dataclass(frozen=True)
class StoredResult:
    status: ReadOnlyStatus
    #: False when Valkey could not be told. Every process still picks the change
    #: up from Postgres within ``_DB_TTL_S``.
    propagated: bool


async def store_adapter_read_only(
    db: AsyncSession, read_only: bool, *, actor_id: Any = None
) -> StoredResult:
    """Save the Settings switch in Postgres, then tell every process through Valkey.

    Raises :class:`EnvironmentEnforcesReadOnly` when asked to turn read-only
    mode off while ``ADAPTER_READ_ONLY`` is set in the environment: the switch
    cannot loosen what the deployment enforces, and saving "off" would only
    take effect, unannounced, the day someone changes the environment.

    The row commits first. If Valkey cannot be written the change is still
    durable, the other processes read it from Postgres within ``_DB_TTL_S``, and
    the result says so.
    """
    global _cache, _cache_primed, _db_state, _db_read_at
    if not read_only and _env_default():
        raise EnvironmentEnforcesReadOnly
    from sqlalchemy import func
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.models.platform_settings import ADAPTER_READ_ONLY_KEY, PlatformSetting

    insert = pg_insert(PlatformSetting).values(
        key=ADAPTER_READ_ONLY_KEY,
        value={"read_only": bool(read_only)},
        version=1,
        updated_by=actor_id,
    )
    stmt = insert.on_conflict_do_update(
        index_elements=[PlatformSetting.key],
        set_={
            "value": insert.excluded.value,
            "version": PlatformSetting.version + 1,
            "updated_by": insert.excluded.updated_by,
            "updated_at": func.now(),
        },
    ).returning(PlatformSetting.version)
    version = int((await db.execute(stmt)).scalar_one())
    await db.commit()

    stored = StoredSwitch(bool(read_only), version, "database")
    try:
        await asyncio.to_thread(_write_cache, stored)
        propagated = True
    except Exception:
        logger.warning(
            "adapter_read_only saved (version %s) but Valkey could not be updated; "
            "other processes pick it up from Postgres within %ss",
            version,
            int(_DB_TTL_S),
            exc_info=True,
        )
        propagated = False
    now = time.monotonic()
    _db_state = stored
    _db_read_at = now
    _cache = (stored, now + _CACHE_TTL_S)
    _cache_primed = True
    return StoredResult(status=_status_from(stored), propagated=propagated)
