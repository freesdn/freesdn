# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
One fetch, shared by everything in a plugin that needs it.

Modelled on Home Assistant's ``DataUpdateCoordinator``, and it is here for the
reason it is there. Without it every consumer polls independently, and in
FreeSDN that showed up as four shipped sync plugins each hand-rolling the same
retry loop, the same transient-versus-permanent classification and the same
"did the last fetch work" bookkeeping. Four chances to get it subtly different,
four places to fix anything wrong, and no shared answer to "is this data
current".

The properties below are the ones that make it worth having over a cached call.
Each is tested because each was a decision, not a default.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from app.plugins.sdk import PluginCoordinator
from app.plugins.supervision import PluginNotReady


class _Ctx:
    """The slice of PluginContext a coordinator touches."""

    logger = logging.getLogger("test.coordinator")


def _coordinator(update, *, interval: float = 300.0) -> PluginCoordinator:
    return PluginCoordinator(_Ctx(), "probe", update, update_interval=interval)


# ── the shared fetch ────────────────────────────────────────────


async def test_concurrent_callers_share_one_fetch():
    """
    A route call landing while a scheduled run is mid-fetch must wait for that
    fetch, not start a second one against a remote that is already busy. This
    is the property a plain cache does not give you.
    """
    calls = 0

    async def update():
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.05)
        return {"n": calls}

    coord = _coordinator(update)
    await asyncio.gather(*(coord.async_get() for _ in range(5)))

    assert calls == 1, f"{calls} concurrent fetches instead of one"


async def test_fresh_data_is_not_refetched():
    calls = 0

    async def update():
        nonlocal calls
        calls += 1
        return calls

    coord = _coordinator(update, interval=300)
    assert await coord.async_get() == 1
    assert await coord.async_get() == 1
    assert calls == 1


async def test_stale_data_is_refetched():
    calls = 0

    async def update():
        nonlocal calls
        calls += 1
        return calls

    coord = _coordinator(update, interval=0)  # everything is immediately stale
    await coord.async_get()
    await coord.async_get()
    assert calls == 2


# ── failure that does not erase ─────────────────────────────────


async def test_a_failed_refresh_keeps_the_last_good_data():
    """
    During an outage, a report showing the last known state marked stale is
    more use than an empty page. Throwing the data away would turn a remote
    being briefly down into "you have no devices".
    """
    state = {"fail": False}

    async def update():
        if state["fail"]:
            raise RuntimeError("remote exploded")
        return {"devices": 40}

    coord = _coordinator(update, interval=0)
    await coord.async_get()
    assert coord.data == {"devices": 40}

    state["fail"] = True
    ok = await coord.async_refresh(force=True)

    assert ok is False
    assert coord.data == {"devices": 40}, "the last good data was erased"
    assert coord.last_update_success is False, "a failed fetch reported success"


async def test_a_failed_refresh_does_not_raise():
    """
    A coordinator that threw would put a try block around every consumer, which
    is most of what it exists to remove.
    """

    async def update():
        raise RuntimeError("remote exploded")

    coord = _coordinator(update, interval=0)
    assert await coord.async_refresh(force=True) is False


async def test_not_ready_is_re_raised():
    """
    The one failure it must NOT swallow. The supervisor has to see it to back
    off correctly and to keep the plugin out of quarantine -- swallowing it here
    would convert "the remote is down" back into "this plugin is broken", which
    is the distinction the previous change exists to draw.
    """

    async def update():
        raise PluginNotReady("NetBox unreachable")

    coord = _coordinator(update, interval=0)
    with pytest.raises(PluginNotReady):
        await coord.async_refresh(force=True)

    assert coord.last_update_success is False


# ── backoff ─────────────────────────────────────────────────────


async def test_repeated_failure_stops_hammering_the_remote():
    """
    Without backoff, a coordinator on a 30-second schedule retries a dead
    remote every 30 seconds forever. The point of a cache during an outage is
    to reduce load on the thing that is already struggling.
    """
    calls = 0

    async def update():
        nonlocal calls
        calls += 1
        raise RuntimeError("down")

    coord = _coordinator(update, interval=0)
    await coord.async_refresh(force=True)
    assert calls == 1

    # Not forced: the backoff window should suppress these entirely.
    for _ in range(5):
        await coord.async_refresh()
    assert calls == 1, f"backoff ignored; the remote was hit {calls} times"


async def test_backoff_grows_and_is_capped():
    async def update():
        raise RuntimeError("down")

    coord = _coordinator(update, interval=0)
    waits = []
    import time as _time

    for _ in range(10):
        await coord.async_refresh(force=True)
        waits.append(coord._next_attempt - _time.monotonic())

    assert waits[0] < waits[3], "the backoff does not grow"
    assert max(waits) <= PluginCoordinator.BACKOFF_MAX_SECONDS + 1, "the backoff is unbounded"


async def test_success_clears_the_backoff():
    state = {"fail": True}

    async def update():
        if state["fail"]:
            raise RuntimeError("down")
        return "ok"

    coord = _coordinator(update, interval=0)
    await coord.async_refresh(force=True)
    assert coord.consecutive_failures == 1

    state["fail"] = False
    await coord.async_refresh(force=True)

    assert coord.consecutive_failures == 0
    assert coord._next_attempt == 0.0, "a recovered remote is still being backed off"


# ── what an operator sees ───────────────────────────────────────


async def test_the_snapshot_distinguishes_fresh_from_merely_present():
    """
    ``data`` alone cannot tell an operator whether they are looking at the
    current state or at whatever was there before the outage started.
    """

    async def update():
        return {"devices": 40}

    coord = _coordinator(update, interval=300)
    await coord.async_get()

    snap = coord.snapshot()
    assert snap["last_update_success"] is True
    assert snap["stale"] is False
    assert snap["age_seconds"] is not None
    assert snap["consecutive_failures"] == 0
    assert snap["last_error"] is None


async def test_the_snapshot_reports_the_error_after_a_failure():
    async def update():
        raise RuntimeError("connection refused")

    coord = _coordinator(update, interval=0)
    await coord.async_refresh(force=True)

    snap = coord.snapshot()
    assert snap["last_update_success"] is False
    assert "connection refused" in (snap["last_error"] or "")


async def test_a_never_fetched_coordinator_reads_as_stale():
    """
    ``age is None`` must not read as "fresh". A coordinator that has never
    succeeded is the staleest thing there is.
    """

    async def update():
        return None

    coord = _coordinator(update)
    assert coord.age is None
    assert coord.is_stale is True


# ── reachable by plugin authors ─────────────────────────────────


def test_plugins_can_import_it():
    from app.plugins.sdk_alias import install_freesdn_sdk_alias

    install_freesdn_sdk_alias()
    import freesdn_sdk

    assert freesdn_sdk.PluginCoordinator is PluginCoordinator
