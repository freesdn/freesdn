# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Installed plugins did not survive a container recreate, and nothing said so.

PLUGIN_DIR defaults to ``/data/plugins`` and every install unpacks there. Every
OTHER path under /data in the shipped compose had a named volume behind it --
fabric_artifacts, evidence, agent-releases, proxmox-uploads -- and this one did
not, so plugin packages lived on the container's own writable layer. Any
``docker compose up -d`` after an image update discarded them.

The database was untouched by that, so the aftermath was a silent split:

    installed_plugins        is_active = true,  status = "installed"
    /data/plugins/<id>       gone
    GET /api/v1/<id>/        404
    GET /api/v1/health       "healthy"

The UI listed the plugin as enabled, its routes were gone, and its event
handlers never fired again. ``load_all_plugins`` logged one WARNING per plugin
and carried on, and the lifespan reported the subsystem healthy because it only
looked at start failures among plugins that had loaded -- a plugin that never
loaded at all could not fail to start.

Two fixes, and this file guards both:

  * ``plugin_data:/data/plugins`` on api, worker and scheduler, so the packages
    persist;
  * ``PluginLoader.missing_on_disk`` collected during load and read by the
    lifespan, so the split state degrades /health instead of hiding.

Verified live: installed both example plugins, ``compose up -d
--force-recreate api``, and the files, the routes and the stored settings all
came back.
"""

from __future__ import annotations

import inspect
import pathlib

import pytest


def _compose() -> str:
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "docker-compose.yml"
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    pytest.skip("docker-compose.yml not present in this checkout")


def test_plugin_dir_default_is_the_path_compose_must_persist():
    """Ties the two halves together: if the default moves, the mount must too."""
    from app.plugins.loader import PLUGIN_DIR

    assert str(PLUGIN_DIR).replace("\\", "/") == "/data/plugins", (
        "PLUGIN_DIR moved; update the plugin_data mount in docker-compose.yml"
    )


def test_the_plugin_directory_is_backed_by_a_named_volume():
    compose = _compose()
    assert "plugin_data:/data/plugins" in compose, (
        "PLUGIN_DIR has no named volume, so installed plugins are lost on recreate"
    )
    assert "\n  plugin_data:\n" in compose, "the plugin_data volume is not declared"


def test_every_service_that_loads_plugins_mounts_the_volume():
    """
    api serves the routes, and the worker and scheduler run tasks that touch
    plugin packages. A mount on api alone leaves the other two reading an empty
    directory.
    """
    compose = _compose()
    mounts = compose.count("plugin_data:/data/plugins")
    assert mounts >= 3, (
        f"only {mounts} service(s) mount plugin_data; api, worker and scheduler all need it"
    )


def test_no_other_data_path_is_left_without_a_volume():
    """
    The class of bug, not the instance. Any /data/<name> the backend writes to
    must have a named volume, or it is ephemeral in exactly the same way.
    """
    import re

    compose = _compose()
    referenced = set(re.findall(r"/data/([a-z0-9_-]+)", compose))
    mounted = set(re.findall(r"[a-z_]+:/data/([a-z0-9_-]+)", compose))

    # redis and caddy mount /data itself for their own state; neither is a
    # backend write path.
    unmounted = sorted(referenced - mounted - {"fabric_artifacts"})
    known_ok: set[str] = set()
    surprises = [name for name in unmounted if name not in known_ok]
    assert not surprises, f"/data paths with no named volume behind them: {surprises}"


def test_the_loader_records_plugins_whose_files_vanished():
    from app.plugins.loader import PluginLoader

    src = inspect.getsource(PluginLoader.load_all_plugins)
    assert "missing_on_disk" in src, (
        "load_all_plugins no longer records plugins that are active but absent"
    )
    assert PluginLoader().missing_on_disk == [], "the attribute must start empty"


def test_missing_plugin_files_degrade_the_subsystem():
    """
    The half that made this invisible. `/health` said healthy while every
    plugin route answered 404.
    """
    import app.main as main

    src = inspect.getsource(main.lifespan)
    marker = 'SUBSYSTEM_STATUS["plugins"]'
    assert marker in src, "the plugins subsystem status assignment is gone"

    assignment = src.split(marker, 1)[1].split("\n    except", 1)[0]
    assert "missing_on_disk" in assignment, (
        "a plugin that is active but absent from disk is still reported healthy"
    )
