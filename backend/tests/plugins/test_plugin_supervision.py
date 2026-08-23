# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Nothing contained a misbehaving plugin, and nothing said which one it was.

Plugins run in-process. The loader is explicit that this is import hygiene and
not a sandbox, which is a defensible position -- but it only holds if a plugin
that misbehaves is contained and visible. Neither was true.

  * The event bus swallows handler exceptions and caps each at 10s, which keeps
    the BUS healthy. It logs ``Error in event handler for device.updated``, with
    no plugin in it. A plugin that raised on every event did so forever, and no
    log line named it.
  * ``freesdn_plugin_operations_total`` was declared in metrics.py and
    incremented from nowhere: scraped, always zero. There was no plugin
    observability of any kind.
  * Nothing ever stopped calling a plugin. One that timed out on every event
    burned the full 10s budget on every event, indefinitely.
  * Routes and AI tools had no time limit at all.

The supervisor closes all four: attribution, metrics, an error budget, and a
quarantine that half-opens so a plugin which recovers comes back on its own --
the same shape as the adapter circuit breaker this codebase already uses.

It is NOT a security boundary, and this file does not pretend otherwise: a
plugin determined to hang the process can still do it with a tight synchronous
loop, because an asyncio timeout only interrupts at an await. What it bounds is
accidental damage, which is the realistic failure for trusted-author code.
"""

from __future__ import annotations

import asyncio

import pytest

from app.plugins.supervision import (
    PluginQuarantined,
    PluginState,
    PluginSupervisor,
)


@pytest.fixture
def sup() -> PluginSupervisor:
    """A fresh supervisor per test; the real one is process-wide."""
    return PluginSupervisor()


# ── counting and attribution ────────────────────────────────────


async def test_a_successful_call_is_counted(sup: PluginSupervisor):
    async with sup.guard("p", "event"):
        pass
    health = sup.health("p").snapshot()
    assert health["operations"]["event"]["calls"] == 1
    assert health["operations"]["event"]["errors"] == 0
    assert health["state"] == "healthy"


async def test_a_failure_is_attributed_to_the_plugin(sup: PluginSupervisor):
    """The whole point. The bus logged the event type and never the plugin."""
    with pytest.raises(ValueError):
        async with sup.guard("noisy-plugin", "event"):
            raise ValueError("boom")

    health = sup.health("noisy-plugin").snapshot()
    assert health["plugin_id"] == "noisy-plugin"
    assert health["operations"]["event"]["errors"] == 1
    assert "boom" in health["operations"]["event"]["last_error"]
    assert health["state"] == "degraded"


async def test_the_exception_still_propagates(sup: PluginSupervisor):
    """
    Supervision observes; it does not swallow. The bus already decides what to
    do with a handler exception, and a guard that ate them would take that
    decision away from every caller.
    """
    with pytest.raises(KeyError):
        async with sup.guard("p", "route"):
            raise KeyError("still mine")


async def test_operations_are_tracked_separately(sup: PluginSupervisor):
    """A plugin with healthy routes and a broken event handler is not one number."""
    async with sup.guard("p", "route"):
        pass
    with pytest.raises(RuntimeError):
        async with sup.guard("p", "event"):
            raise RuntimeError("x")

    ops = sup.health("p").snapshot()["operations"]
    assert ops["route"]["errors"] == 0
    assert ops["event"]["errors"] == 1


# ── the budget ──────────────────────────────────────────────────


async def _fail(sup: PluginSupervisor, plugin_id: str, times: int) -> None:
    for _ in range(times):
        try:
            async with sup.guard(plugin_id, "event"):
                raise RuntimeError("always")
        except (RuntimeError, PluginQuarantined):
            pass


async def test_a_plugin_under_the_budget_keeps_running(sup: PluginSupervisor):
    """
    A transient upstream blip must not quarantine a plugin whose only fault was
    being downstream of it.
    """
    await _fail(sup, "p", PluginSupervisor.FAILURE_THRESHOLD - 1)
    assert sup.health("p").state is PluginState.DEGRADED
    async with sup.guard("p", "event"):
        pass  # still allowed through


async def test_a_plugin_that_trips_the_budget_is_quarantined(sup: PluginSupervisor):
    await _fail(sup, "p", PluginSupervisor.FAILURE_THRESHOLD)
    assert sup.health("p").state is PluginState.QUARANTINED
    assert "p" in sup.quarantined_plugins()


async def test_a_quarantined_plugin_is_refused_without_being_called(sup: PluginSupervisor):
    """
    The saving. Before this, a plugin that timed out on every event was still
    invoked on every event and still cost the full timeout.
    """
    await _fail(sup, "p", PluginSupervisor.FAILURE_THRESHOLD)

    ran = False
    with pytest.raises(PluginQuarantined):
        async with sup.guard("p", "event"):
            ran = True
    assert ran is False, "a quarantined plugin's code was executed anyway"


async def test_success_resets_the_streak_but_not_the_history(sup: PluginSupervisor):
    """
    An intermittent plugin must not accumulate its way to a quarantine over a
    week, but its error RATE has to stay visible.
    """
    await _fail(sup, "p", PluginSupervisor.FAILURE_THRESHOLD - 1)
    async with sup.guard("p", "event"):
        pass

    op = sup.health("p").snapshot()["operations"]["event"]
    assert op["consecutive_errors"] == 0
    assert op["errors"] == PluginSupervisor.FAILURE_THRESHOLD - 1
    assert op["error_rate"] > 0
    assert sup.health("p").state is PluginState.HEALTHY


async def test_repeat_quarantines_back_off(sup: PluginSupervisor):
    """
    A plugin that is simply broken should stop consuming resources at a growing
    interval, rather than retrying every two minutes forever.
    """
    health = sup.health("p")
    await _fail(sup, "p", PluginSupervisor.FAILURE_THRESHOLD)
    first = health.quarantined_until

    health.quarantined_until = 0.0  # simulate the cooldown elapsing
    await _fail(sup, "p", PluginSupervisor.FAILURE_THRESHOLD)
    second = health.quarantined_until

    assert health.quarantine_count == 2
    assert second - first > 0, "the second cooldown is not longer than the first"


async def test_an_operator_can_lift_a_quarantine(sup: PluginSupervisor):
    """
    For someone who has fixed the cause and does not want to wait out a cooldown
    that doubles each time. The alternatives were waiting or restarting the API.
    """
    await _fail(sup, "p", PluginSupervisor.FAILURE_THRESHOLD)
    assert sup.health("p").state is PluginState.QUARANTINED

    sup.reset("p")
    assert sup.health("p").state is PluginState.HEALTHY
    async with sup.guard("p", "event"):
        pass


# ── timeouts ────────────────────────────────────────────────────


async def test_a_slow_call_is_cut_off_and_counted(sup: PluginSupervisor):
    """Routes, lifecycle hooks and AI tools had no time limit at all."""
    with pytest.raises(TimeoutError):
        async with sup.guard("p", "route", timeout=0.05):
            await asyncio.sleep(5)

    op = sup.health("p").snapshot()["operations"]["route"]
    assert op["timeouts"] == 1
    assert op["errors"] == 1
    assert "timed out" in op["last_error"]


async def test_repeated_timeouts_quarantine_too(sup: PluginSupervisor):
    for _ in range(PluginSupervisor.FAILURE_THRESHOLD):
        with pytest.raises(TimeoutError):
            async with sup.guard("p", "event", timeout=0.01):
                await asyncio.sleep(1)
    assert sup.health("p").state is PluginState.QUARANTINED


# ── record_only ─────────────────────────────────────────────────


async def test_lifecycle_hooks_are_recorded_but_never_refused(sup: PluginSupervisor):
    """
    A broken plugin must stay uninstallable-proof: refusing to run
    ``on_uninstall`` because ``on_install`` failed would trap it in place with
    no way out but a database edit.
    """
    await _fail(sup, "p", PluginSupervisor.FAILURE_THRESHOLD)
    assert sup.health("p").state is PluginState.QUARANTINED

    ran = False
    async with sup.guard("p", "lifecycle", record_only=True):
        ran = True
    assert ran is True, "a lifecycle hook was refused on a quarantined plugin"


async def test_record_only_failures_never_quarantine(sup: PluginSupervisor):
    for _ in range(PluginSupervisor.FAILURE_THRESHOLD * 2):
        with pytest.raises(RuntimeError):
            async with sup.guard("p", "lifecycle", record_only=True):
                raise RuntimeError("install blew up")
    assert sup.health("p").state is not PluginState.QUARANTINED
    assert sup.health("p").snapshot()["operations"]["lifecycle"]["errors"] > 0


# ── wiring ──────────────────────────────────────────────────────


def test_every_entry_into_plugin_code_is_guarded():
    """
    A guard that covers three of four entry points leaves the fourth as the one
    that takes the platform down.
    """
    import inspect

    from app.plugins import bridges, loader, sdk

    assert "supervisor.guard" in inspect.getsource(sdk), "event dispatch is unguarded"
    assert "supervisor.guard" in inspect.getsource(bridges), "AI tool handlers are unguarded"

    loader_src = inspect.getsource(loader)
    assert "_supervise_router" in loader_src, "plugin routes are unguarded"
    assert "supervisor.guard(" in loader_src, "lifecycle hooks are unguarded"


def test_the_route_wrapper_preserves_the_endpoint_signature():
    """
    FastAPI builds a route's dependant by inspecting the endpoint signature.
    A wrapper that loses it produces a route with no parameters, which fails at
    request time rather than at registration -- so it would ship.
    """
    import inspect

    from app.plugins.loader import _supervise_router

    class _Route:
        def __init__(self, endpoint):
            self.endpoint = endpoint

    class _Router:
        def __init__(self, routes):
            self.routes = routes

    async def endpoint(device_id: str, limit: int = 10) -> dict:
        return {"device_id": device_id, "limit": limit}

    original = inspect.signature(endpoint)
    route = _Route(endpoint)
    _supervise_router(_Router([route]), "p")

    assert route.endpoint is not endpoint, "the endpoint was not wrapped"
    assert inspect.signature(route.endpoint) == original, (
        "the wrapper lost the signature; FastAPI would build an empty dependant"
    )


def test_wrapping_is_idempotent():
    """register_plugin_routes can be reached more than once; double-wrapping
    would double-count every call and halve the effective timeout."""
    from app.plugins.loader import _supervise_router

    class _Route:
        def __init__(self, endpoint):
            self.endpoint = endpoint

    class _Router:
        def __init__(self, routes):
            self.routes = routes

    async def endpoint() -> dict:
        return {}

    route = _Route(endpoint)
    router = _Router([route])
    _supervise_router(router, "p")
    first = route.endpoint
    _supervise_router(router, "p")
    assert route.endpoint is first, "the endpoint was wrapped twice"
