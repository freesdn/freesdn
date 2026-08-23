# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Two things the marketplace install button did wrong, both found by pressing it.

ONE: installing from the marketplace never STARTED the plugin.

``POST /marketplace/plugins/{slug}/install`` wrote the files and the database
row and stopped. No per-organisation runtime was created and no routes were
mounted, so the plugin did nothing at all until the next API restart, while the
button reported success and the plugin list showed it installed. The upload path
had always called ``_start_plugin_everywhere``; the marketplace path, which is
the one actually in the UI, never did.

    POST /marketplace/plugins/hello-world/install  -> 201 {"restart_required": false}
    GET  /api/v1/hello-world/                      -> 410 not active
    (restart the API)
    GET  /api/v1/hello-world/                      -> 200 running

TWO: reinstalling anything that had ever served a request was a 500.

    KeyError: 'hello-world'
      loader.py, install_plugin:  plugin_instance = self._loaded[manifest.id]

Uninstall deliberately KEEPS ``_registered_routes`` (FastAPI cannot unmount a
route, and forgetting would mount a second copy of every one of them) while
deleting the ``_loaded`` entry. The reinstall path read ``_loaded`` directly on
the strength of the ``_registered_routes`` check, so the two disagreed exactly
when a plugin was reinstalled after being uninstalled.

Both fixed and verified live: install now answers 201 and the plugin's own route
answers 200 in the same breath, with no restart.
"""

from __future__ import annotations

import inspect

import pytest

# ── the plugin actually starts ──────────────────────────────────


def test_marketplace_install_starts_the_plugin():
    """
    The whole bug in one assertion. Without this call the endpoint installs a
    plugin that cannot run.
    """
    from app.api.v1.endpoints.marketplace import install_from_marketplace

    src = inspect.getsource(install_from_marketplace)
    body = "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))
    assert "_start_plugin_everywhere(" in body, "a marketplace install never starts the plugin"


def test_marketplace_install_takes_the_request_it_needs_to_start_it():
    """
    ``_start_plugin_everywhere`` mounts routes on the live app, which it can
    only reach through the request. The endpoint previously had no ``request``
    parameter at all -- the surest sign it was never starting anything.
    """
    from app.api.v1.endpoints.marketplace import install_from_marketplace

    params = inspect.signature(install_from_marketplace).parameters
    assert "request" in params, "no request, so no app, so nothing can be mounted"


def test_it_starts_before_it_reports_success():
    """
    Order matters: a start that fails must not be reported as an install that
    worked. ``_start_plugin_everywhere`` rolls back the organisations it already
    started and re-raises, and that has to happen inside the try.
    """
    from app.api.v1.endpoints.marketplace import install_from_marketplace

    src = inspect.getsource(install_from_marketplace)
    assert src.index("_start_plugin_everywhere(") < src.index('"status": "installed"')


# ── reinstall after uninstall ───────────────────────────────────


def _loader():
    from app.plugins.loader import PluginLoader

    return PluginLoader()


class _Template:
    """Stands in for the object mounted route handlers are closed over."""


def test_the_live_template_is_found_normally():
    loader = _loader()
    obj = _Template()
    loader._loaded["p"] = obj  # type: ignore[assignment]

    assert loader.mounted_template("p") is obj


def test_the_orphaned_template_survives_an_uninstall():
    """
    The fix. After an uninstall the handlers are still mounted and still bound
    to this object; a reinstall has to be able to reach it to update it.
    """
    loader = _loader()
    obj = _Template()
    loader._orphaned_template["p"] = obj  # type: ignore[assignment]

    assert loader.mounted_template("p") is obj, "the reinstall path cannot reach the mounted object"


def test_nothing_mounted_means_nothing_to_find():
    """
    None is a real answer, not an error: it means the routes are mounted and
    the object behind them is unreachable, which is the one case that genuinely
    needs a restart.
    """
    assert _loader().mounted_template("never-seen") is None


def test_the_live_template_wins_over_a_stale_orphan():
    """
    A plugin uninstalled and reinstalled twice would leave an old orphan behind.
    Adopting into it instead of the live object would update something nothing
    is pointing at any more.
    """
    loader = _loader()
    live, stale = _Template(), _Template()
    loader._loaded["p"] = live  # type: ignore[assignment]
    loader._orphaned_template["p"] = stale  # type: ignore[assignment]

    assert loader.mounted_template("p") is live


def test_uninstall_keeps_the_object_its_routes_still_use():
    from app.plugins.loader import PluginLoader

    src = inspect.getsource(PluginLoader.uninstall_plugin)
    assert "_orphaned_template[" in src, "uninstall drops the only reference to the mounted object"


def test_install_no_longer_subscripts_loaded_blindly():
    """
    The exact line that raised. A ``[...]`` here is the bug returning.
    """
    from app.plugins.loader import PluginLoader

    src = inspect.getsource(PluginLoader.install_plugin)
    body = "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))
    assert "self._loaded[manifest.id]" not in body.split("mounted_template", 1)[0], (
        "install still reads _loaded directly before resolving the mounted template"
    )
    assert "mounted_template(" in body


def test_an_unreachable_mounted_template_asks_for_a_restart():
    """
    Honesty over convenience: if the routes are mounted and we cannot reach what
    they point at, the operator is told to restart rather than shown a green
    install that silently kept old handlers.
    """
    from app.plugins.loader import PluginLoader

    src = inspect.getsource(PluginLoader.install_plugin)
    after = src.split("mounted_template(", 1)[1]
    assert "_restart_required.add" in after.split("else:", 1)[0]


# ── the example plugin's lifecycle hooks ────────────────────────


@pytest.mark.parametrize("hook", ["on_install", "on_uninstall", "on_upgrade"])
def test_the_example_plugin_does_not_use_ctx_where_there_is_none(hook: str):
    """
    ``self.ctx`` is per-organisation and these three hooks run once for the
    whole appliance, so it is None in all of them. hello-world called
    ``self.ctx.logger`` in on_install and on_uninstall and raised AttributeError
    on every install and every uninstall:

        Plugin hello-world failed during lifecycle (1 consecutive):
        AttributeError: 'NoneType' object has no attribute 'logger'

    Swallowed by the lifecycle guard, so it never surfaced -- while charging the
    plugin's error budget. It matters more than one plugin's log line, because
    this is the file every plugin author copies.
    """
    import pathlib
    import re

    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "registry" / "plugins" / "hello-world" / "plugin.py"
        if candidate.is_file():
            src = candidate.read_text(encoding="utf-8")
            break
    else:  # pragma: no cover - backend-only checkout
        pytest.skip("registry plugins are not present in this checkout")

    match = re.search(
        r"async def " + hook + r"\(.*?\n(.*?)(?=\n    async def |\n    def |\Z)", src, re.S
    )
    if match is None:
        pytest.skip(f"hello-world does not implement {hook}")

    # Strip the docstring: it is allowed -- and expected -- to NAME self.ctx in
    # order to say it is unavailable. An earlier version of this test matched
    # the explanation and failed on correct code.
    body = match.group(1)
    body = re.sub(r'""".*?"""', "", body, flags=re.S)
    assert "self.ctx" not in body, f"hello-world uses self.ctx in {hook}, where it is None"
