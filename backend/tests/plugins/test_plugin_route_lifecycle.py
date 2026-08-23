# SPDX-License-Identifier: MIT
# Copyright (C) 2024-2026 FreeSDN
"""
Reinstalling a plugin served its OLD code, and each cycle leaked routes.

FastAPI cannot unmount a route once it is mounted -- which the loader already
knew: ``unregister_plugin_routes`` is an explicit no-op stub saying so. But
``uninstall_plugin`` then did ``self._registered_routes.discard(plugin_id)``,
forgetting a plugin whose routes were still very much in the app.

So on the next install, ``register_plugin_routes`` saw an unregistered plugin
and called ``include_router`` again, mounting a SECOND copy of every route.
FastAPI serves the first match, and the first match is the ORIGINAL handler,
whose closure is bound to the previous plugin object. The result:

    files on disk        new version
    version in the UI    new version
    the endpoint         still running the old code

and the route table grew by a full set of routes on every uninstall/reinstall
cycle, permanently.

Found by driving it: config-drift-guard 1.0.1 added a ``notes`` key to its scan
response, the reinstalled plugin kept returning a response without it, and a
container restart was the only thing that fixed it.

Two changes, both guarded here:

  * uninstall no longer discards the entry, because the routes really are still
    mounted. Safe, because ``plugin_route_guard`` already answers 410 for a
    plugin that is not active for the caller's organization -- exactly what an
    uninstalled one is.
  * install reports ``restart_required`` so the operator is TOLD, rather than
    left to discover that new code is not running.
"""

from __future__ import annotations

import inspect

from app.plugins.loader import PluginLoader


def test_uninstall_does_not_forget_routes_it_cannot_unmount():
    """
    The regression itself. Discarding here is what let a reinstall double-mount.
    """
    src = inspect.getsource(PluginLoader.uninstall_plugin)
    assert "_registered_routes.discard" not in src, (
        "uninstall discards a plugin whose routes are still mounted; the next "
        "install will mount a second copy and FastAPI will serve the old one"
    )


def test_route_registration_is_still_idempotent():
    """The guard that makes the fix work at all."""
    src = inspect.getsource(PluginLoader.register_plugin_routes)
    assert "if plugin_id in self._registered_routes:" in src
    assert "return" in src.split("if plugin_id in self._registered_routes:", 1)[1][:80]


def test_unregister_is_still_honest_about_being_impossible():
    """
    If FastAPI ever gains route removal, this stub is where it lands -- and the
    uninstall fix above should be revisited at the same time.
    """
    src = inspect.getsource(PluginLoader.unregister_plugin_routes)
    assert "restart" in src.lower(), "the stub no longer explains why it does nothing"


def test_a_mounted_plugin_is_no_longer_assumed_stale():
    """
    ``routes_are_stale`` was "are this plugin's routes mounted?" and it is gone.

    That was the right question when nothing reloaded: a mounted plugin really
    did keep serving old handlers. Once method bodies started reloading in
    place it became true for essentially every install of an already-mounted
    plugin, so the marketplace demanded a restart nothing needed while the
    upload path -- same install, different button -- correctly said none was
    required. Reporting a restart nobody needs is how an operator learns to
    ignore the message that will one day matter.

    ``restart_required`` replaces it and answers the question that actually
    decides the outcome: did this version change its route TABLE?
    """
    loader = PluginLoader()
    assert not hasattr(loader, "routes_are_stale"), (
        "the mounted-means-stale predicate is back; it over-reports restarts"
    )

    assert loader.restart_required("anything") is False
    loader._registered_routes.add("already-mounted")
    assert loader.restart_required("already-mounted") is False, (
        "merely being mounted is being reported as needing a restart again"
    )
    loader._restart_required.add("changed-its-routes")
    assert loader.restart_required("changed-its-routes") is True


def test_install_tells_the_operator_when_a_restart_is_needed():
    """
    Silence here is the whole problem. An operator who is not told will conclude
    the new version is broken rather than that it is not running.

    Every install and upgrade path now answers this the same way, through
    ``_reload_note``. They previously disagreed, which is worse than either
    answer alone: the same situation was legible or alarming depending on which
    button was pressed.
    """
    from app.api.v1.endpoints.marketplace import install_from_marketplace

    src = inspect.getsource(install_from_marketplace)
    assert "_reload_note(" in src, "the marketplace no longer reports reload state"
    assert "routes_are_stale" not in src, "the over-reporting predicate is back"


def test_an_inactive_plugins_routes_are_refused_not_served():
    """
    Why leaving the entry registered is safe. If this guard ever stops
    answering 410 for an inactive plugin, an uninstalled plugin's still-mounted
    routes become reachable.
    """
    src = inspect.getsource(PluginLoader._build_route_guard)
    assert "HTTP_410_GONE" in src, "an inactive plugin's mounted routes are no longer refused"
    assert "get_active_for_org" in src, "the guard no longer checks per-organization activation"
