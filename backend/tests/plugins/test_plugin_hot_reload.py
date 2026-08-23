# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Upgrading a plugin used to change everything except what it ran.

Reinstalling or upgrading replaced the files and rebuilt the per-organization
runtimes, but the REST handlers stayed bound to the PREVIOUS template object:
new code on disk, new version in the UI, old behaviour on every endpoint. The
only advertised remedy was "restart the API", which on an appliance means
dropping every other plugin, every websocket and every in-flight request to pick
up a one-line fix.

I hit this myself. A settings method was returning 14 where the database said 0,
and it took a restart to see the fix I had just uploaded.

WHAT RELOADS, MEASURED RATHER THAN ASSUMED
    Method bodies do. Rebinding ``__class__`` on the existing template redirects
    method lookup while preserving the identity every mounted closure captured.
    Verified live: a settings method changed to return 777 and then 888 was
    picked up on the next request each time, no restart.

    Route handler bodies do not. ``get_router`` produces its handlers as
    closures once, at mount time, and no amount of class rebinding rewrites a
    function object that already exists.

WHY NOT UNMOUNT THE ROUTES
    Because fastapi wraps every ``include_router`` in an opaque
    ``_IncludedRouter`` whose children are not reachable as ``.routes`` -- a
    top-level scan for the plugin's own prefix finds zero. This codebase has
    already been bitten once by a route tree-walk breaking across a fastapi
    version, and the middleware carries the scar. Reloading the code behind the
    existing routes needs no internals at all.
"""

from __future__ import annotations

import inspect

import pytest

from app.plugins import loader as loader_mod
from app.plugins.loader import _get_router_changed, _source_of, plugin_loader

# ── the swap itself ─────────────────────────────────────────────


def test_rebinding_class_makes_an_existing_closure_run_new_code():
    """
    The whole mechanism, in isolation. A route handler is a closure over the
    template; this is what lets it run the upgrade.
    """

    class V1:
        def label(self):
            return "OLD"

        def make_handler(self):
            def handler():
                return self.label()

            return handler

    class V2:
        def label(self):
            return "NEW"

    template = V1()
    handler = template.make_handler()
    assert handler() == "OLD"

    template.__class__ = V2

    assert handler() == "NEW", "the mounted closure did not pick up the new class"
    assert handler.__closure__[0].cell_contents is template, "identity was not preserved"


def test_adopt_new_code_keeps_the_running_objects_bindings():
    """
    ``ctx`` and the event-subscription ids belong to the RUNNING object's
    lifecycle. Replacing them with the fresh instance's would orphan live bus
    subscriptions -- the plugin would keep receiving events on handlers nothing
    can unsubscribe.
    """
    src = inspect.getsource(plugin_loader.__class__.adopt_new_code)
    assert "_ctx" in src and "_event_subscription_ids" in src
    assert "old._ctx = ctx" in src


def test_an_incompatible_layout_is_reported_not_crashed():
    """
    ``__class__`` assignment raises TypeError for incompatible layouts, e.g. a
    plugin using __slots__. Nothing is broken by that; the reload simply did not
    happen, and the caller needs to hear so.
    """
    src = inspect.getsource(plugin_loader.__class__.adopt_new_code)
    arm = src.split("except TypeError", 1)
    assert len(arm) == 2, "the incompatible-layout arm is gone"
    # The arm logs a warning and returns False. Reading a fixed slice was too
    # brittle -- the explanatory comment pushed the return past 300 chars.
    assert "return False" in arm[1], "the failure is swallowed instead of reported"
    assert "logger.warning" in arm[1], "an operator is never told the reload did not happen"


# ── knowing when a restart IS still needed ──────────────────────


def test_the_router_source_is_captured_at_mount_time():
    """
    The subtle half. An upgrade overwrites plugin.py AT THE SAME PATH, so
    reading the old class's source afterwards returns the NEW file and every
    comparison reports "unchanged" -- the exact under-report that would tell an
    operator no restart was needed while their endpoints served old handlers.

    Caught live: the verdict came back False for an upgrade that had genuinely
    changed get_router.
    """
    src = inspect.getsource(plugin_loader.__class__.register_plugin_routes)
    assert "_router_source[plugin_id]" in src, "the mounted source is not captured"


def test_source_reading_invalidates_the_line_cache():
    """
    ``linecache`` memoises by filename, and a plugin upgrade replaces the file
    at the same path. Without invalidating it, getsource returns the previous
    version's lines and the comparison is meaningless.
    """
    src = inspect.getsource(_source_of)
    assert "linecache" in src and "checkcache" in src


def test_unknown_source_counts_as_changed():
    """
    Over-reporting a restart is recoverable. Under-reporting it means an
    operator runs old code believing they upgraded, which is the failure this
    whole change exists to remove.
    """

    class Anything:
        def get_router(self):
            return None

    assert _get_router_changed(None, Anything) is True


class _Plugin:
    """Module level on purpose. A class defined INSIDE a test is not always
    readable by inspect -- under the containerised gate ``_source_of`` returned
    None for one, and the test failed on its own setup rather than on the
    behaviour it names."""

    def get_router(self):
        return None


def test_identical_router_source_needs_no_restart(monkeypatch):
    # Pin what the comparison sees, so this tests the decision and not whether
    # this file's source happens to be readable wherever pytest is running.
    monkeypatch.setattr(loader_mod, "_source_of", lambda _fn: "SAME")
    assert _get_router_changed("SAME", _Plugin) is False


def test_a_different_router_source_needs_a_restart(monkeypatch):
    monkeypatch.setattr(loader_mod, "_source_of", lambda _fn: "AFTER")
    assert _get_router_changed("BEFORE", _Plugin) is True


def test_source_of_reads_a_real_function():
    """Separate from the decision above: does the reader work at all here?

    Skipped rather than failed where source is unavailable -- that is a property
    of the environment, not of the code under test.
    """
    src = _source_of(_Plugin.get_router)
    if src is None:
        pytest.skip("source is not readable in this environment")
    assert "get_router" in src


def test_the_baseline_refreshes_only_when_nothing_changed():
    """
    If the handlers did change, what is mounted is still the OLD router, so the
    baseline must keep describing it. Refreshing regardless would report "no
    restart needed" on the NEXT upgrade while the stale handlers were still
    being served.
    """
    src = inspect.getsource(plugin_loader.__class__.adopt_new_code)
    refresh = src.split("if not changed_routes:", 1)
    assert len(refresh) == 2, "the baseline refresh is no longer conditional"
    assert "_router_source[plugin_id]" in refresh[1][:400]


# ── telling the operator ────────────────────────────────────────


def test_every_write_path_reports_the_verdict():
    """
    Previously only the marketplace path said anything about restarting, so the
    same situation was legible or silent depending on which button an operator
    pressed. Same shape as the install-failure gap fixed earlier.
    """
    from app.api.v1.endpoints import plugins as endpoints

    src = inspect.getsource(endpoints)
    for handler in ("install_plugin", "install_plugin_from_url", "upgrade_plugin"):
        block = src.split(f"async def {handler}(", 1)
        assert len(block) == 2, f"{handler} is gone"
        body = block[1].split("\n@router", 1)[0]
        assert "_with_reload_note(" in body, f"{handler} does not report restart_required"


@pytest.mark.parametrize("field", ["restart_required", "note"])
def test_the_response_model_carries_the_verdict(field: str):
    from app.api.v1.endpoints.plugins import PluginDetail

    assert field in PluginDetail.model_fields


def test_the_note_says_what_is_already_live():
    """
    "Restart required" alone would read as "your upgrade did not apply". Most of
    it did: the methods are running. The note has to say which half is which or
    an operator restarts a production appliance out of doubt.
    """
    from app.api.v1.endpoints.plugins import _reload_note

    src = inspect.getsource(_reload_note)
    assert "already" in src and "live" in src
