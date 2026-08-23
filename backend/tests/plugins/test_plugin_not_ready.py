# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
"Broken" and "blocked" are different states. Supervision could only see one.

Borrowed from Home Assistant's ``ConfigEntryNotReady``, and the distinction it
draws is the one FreeSDN was missing. Supervision could tell that a plugin had
failed five times in a row. It could not tell whether the plugin was broken or
whether somebody had rebooted their NetBox for ten minutes -- both looked
identical, so both were punished identically.

That is a real cost, not a tidiness argument. Quarantine has exponential
backoff, so a working integration knocked out by a ten-minute outage sits out a
cooldown AFTER the outage ends, and the operator sees a plugin marked
QUARANTINED with a reason that names their own infrastructure. The obvious
reading is "this plugin is broken", and the obvious response is to go and read
code that is working correctly.

A plugin now says which it is::

    if not await self._reachable():
        raise PluginNotReady("NetBox at netbox.lan is not responding")

and gets patience instead of punishment. Anything else raising is still a fault,
which is the right default: a plugin that does not know why it failed should not
be able to claim it was somebody else's problem.
"""

from __future__ import annotations

import inspect

import pytest

from app.plugins.supervision import (
    PluginHealth,
    PluginNotReady,
    PluginState,
    PluginSupervisor,
)

# ── it is a distinct state, not a flavour of failure ────────────


def test_not_ready_is_its_own_state():
    assert PluginState.NOT_READY.value == "not_ready"


def test_blocked_outranks_degraded():
    """
    A plugin whose NetBox is down is not degraded CODE. Reporting it as
    degraded sends an operator to read a plugin that is working correctly.
    """
    health = PluginHealth("probe")
    health.op("schedule").consecutive_errors = 3
    health.not_ready_reason = "NetBox unreachable"
    assert health.state is PluginState.NOT_READY


def test_quarantine_still_outranks_blocked():
    """
    A quarantined plugin is refused entry regardless. If it were reported as
    merely blocked, the panel would show "waiting" for something the platform
    has actually stopped calling.
    """
    import time

    health = PluginHealth("probe")
    health.not_ready_reason = "NetBox unreachable"
    health.quarantined_until = time.monotonic() + 60
    assert health.state is PluginState.QUARANTINED


# ── the guard treats it as information, not fault ───────────────


async def test_raising_not_ready_never_counts_toward_quarantine():
    """
    The whole point. Five consecutive outages of somebody else's system must
    not quarantine a working plugin.
    """
    sup = PluginSupervisor()
    for _ in range(sup.FAILURE_THRESHOLD + 2):
        with pytest.raises(PluginNotReady):
            async with sup.guard("probe", "schedule"):
                raise PluginNotReady("NetBox unreachable")

    health = sup.health("probe")
    assert health.state is PluginState.NOT_READY
    assert health.quarantine_count == 0, "a blocked plugin was quarantined"
    assert health.op("schedule").consecutive_errors == 0, "counted as a failure"


async def test_an_ordinary_exception_still_quarantines():
    """
    The default has to stay strict. A plugin that does not know why it failed
    must not get the benefit of the doubt.
    """
    sup = PluginSupervisor()
    for _ in range(sup.FAILURE_THRESHOLD):
        with pytest.raises(ValueError):
            async with sup.guard("probe", "event"):
                raise ValueError("genuinely broken")

    assert sup.health("probe").state is PluginState.QUARANTINED


async def test_backoff_grows_and_is_capped():
    """
    Gentler than quarantine on purpose: nothing is wrong with the plugin, so
    the platform is being patient rather than defensive. Capped so a long
    outage does not push the next attempt hours away.
    """
    sup = PluginSupervisor()
    waits = []
    for _ in range(12):
        with pytest.raises(PluginNotReady):
            async with sup.guard("probe", "schedule"):
                raise PluginNotReady("still down")
        waits.append(sup.health("probe").retry_after)

    assert waits[0] < waits[3], "the backoff does not grow"
    assert max(waits) <= sup.NOT_READY_MAX_SECONDS, "the backoff is unbounded"
    assert sup.NOT_READY_MAX_SECONDS < sup.MAX_COOLDOWN_SECONDS, (
        "waiting on somebody else's outage backs off harder than being broken"
    )


async def test_a_plugin_can_ask_for_a_specific_retry_delay():
    """A 429 or a maintenance window often states when to come back."""
    sup = PluginSupervisor()
    with pytest.raises(PluginNotReady):
        async with sup.guard("probe", "schedule"):
            raise PluginNotReady("rate limited", retry_after=42.0)

    assert sup.health("probe").retry_after == 42.0


async def test_success_clears_the_blocked_state():
    """
    Without this a plugin reads as blocked forever after one transient outage,
    which is a worse lie than the one this replaced.
    """
    sup = PluginSupervisor()
    with pytest.raises(PluginNotReady):
        async with sup.guard("probe", "schedule"):
            raise PluginNotReady("NetBox unreachable")
    assert sup.health("probe").state is PluginState.NOT_READY

    async with sup.guard("probe", "schedule"):
        pass

    health = sup.health("probe")
    assert health.state is PluginState.HEALTHY
    assert health.not_ready_reason is None
    assert health.not_ready_attempts == 0


# ── an operator can see what it is waiting for ──────────────────


async def test_the_snapshot_names_what_it_is_waiting_for():
    """
    "not_ready" alone is not actionable. The operator needs the reason, how
    long, and when it will try again -- otherwise the only way to find out is to
    read the plugin's code.
    """
    sup = PluginSupervisor()
    with pytest.raises(PluginNotReady):
        async with sup.guard("probe", "schedule"):
            raise PluginNotReady("NetBox at netbox.lan is not responding")

    snap = sup.snapshot("probe")
    assert snap["not_ready_reason"] == "NetBox at netbox.lan is not responding"
    assert snap["not_ready_attempts"] == 1
    assert snap["retry_after_seconds"] is not None
    assert "not_ready_for_seconds" in snap


def test_the_metric_records_it_separately():
    """
    ``not_ready`` is its own outcome label. Bucketing it with ``error`` would
    make a dashboard show a plugin failing during an outage it correctly
    reported and survived.
    """
    src = inspect.getsource(PluginSupervisor.guard)
    assert 'outcome = "not_ready"' in src


# ── a plugin author can actually reach it ───────────────────────


def test_plugins_can_import_it_from_the_sdk():
    """
    A plugin cannot import from ``app.*``. If the exception is not on the SDK
    surface, the feature does not exist for the people it is for.
    """
    from app.plugins.sdk_alias import install_freesdn_sdk_alias

    install_freesdn_sdk_alias()
    import freesdn_sdk

    assert hasattr(freesdn_sdk, "PluginNotReady")
    assert freesdn_sdk.PluginNotReady is PluginNotReady


@pytest.mark.parametrize("name", ["SiteSDK", "MetricsSDK"])
def test_the_newer_sdks_are_reachable_too(name: str):
    """Both existed on the platform and neither was exported, so a plugin using
    them had no importable name for a type hint."""
    from app.plugins.sdk_alias import install_freesdn_sdk_alias

    install_freesdn_sdk_alias()
    import freesdn_sdk

    assert hasattr(freesdn_sdk, name)
