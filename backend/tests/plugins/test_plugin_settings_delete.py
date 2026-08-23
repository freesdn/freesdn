# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The settings SDK had no way to remove a key.

``get``, ``set``, ``get_secret``, ``set_secret`` -- and nothing else. So the only
way to retire a setting was ``set(key, "")``, which leaves the row behind for
ever. Fine for a handful of configuration fields; a slow leak for the pattern
the ticketing plugins use, where the key is per-ALERT:

    __jira_issue__<alert_id>  ->  NET-123

One row per alert that ever fired above the severity floor, accumulating in a
table shared by every plugin and every organisation, with nothing to prune it.
Found while reviewing my own plugins before the release rather than after it.

Verified against the real database:

    after set + set_secret : ['__probe_delete__', '__probe_delete__:encrypted']
    after set(key, '')     : ['__probe_delete__', '__probe_delete__:encrypted']
    delete() returned      : True
    after delete()         : []
    get_secret() now       : None
    delete() again         : False
"""

from __future__ import annotations

import inspect

import pytest


def _src() -> str:
    from app.plugins.sdk import PluginSettingsSDK

    return inspect.getsource(PluginSettingsSDK.delete)


def test_the_sdk_can_delete_a_setting():
    from app.plugins.sdk import PluginSettingsSDK

    assert hasattr(PluginSettingsSDK, "delete"), "the settings SDK still cannot remove a key"


def test_it_removes_the_encrypted_twin_too():
    """
    ``set_secret`` writes to ``<key>:encrypted``. Removing only the plaintext
    row would leave the credential readable to ``get_secret`` -- a delete that
    reports success and leaves the secret behind is worse than no delete.
    """
    src = _src()
    assert ":encrypted" in src
    assert ".in_(" in src, "only one of the two rows is targeted"


def test_it_is_scoped_to_the_plugin_and_organisation():
    """
    A settings delete that forgot either scope would reach into another
    plugin's or another tenant's rows.
    """
    src = _src()
    assert "self._plugin_id" in src
    assert "self._org_id" in src


def test_it_reports_whether_anything_was_there():
    """
    A bool return is what lets a caller tell "removed" from "already gone"
    without a second query.
    """
    from app.plugins.sdk import PluginSettingsSDK

    assert inspect.signature(PluginSettingsSDK.delete).return_annotation in (bool, "bool")
    assert "rowcount" in _src()


def test_it_persists():
    """The other SDK writers all end in _persist; a delete that only staged the
    statement would be undone by the session scope closing."""
    assert "_persist(" in _src()


# ── the plugins that needed it ──────────────────────────────────


@pytest.mark.parametrize(
    ("plugin_id", "prefix"),
    [("jira-tickets", "__jira_issue__"), ("servicenow-incidents", "__snow_incident__")],
)
def test_the_ticketing_plugins_delete_rather_than_blank(plugin_id: str, prefix: str):
    """
    These are the plugins that created the problem, and they are also the
    reference implementations other authors will copy. Leaving them blanking
    would teach the leak.
    """
    import pathlib

    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "registry" / "plugins" / plugin_id / "plugin.py"
        if candidate.is_file():
            src = candidate.read_text(encoding="utf-8")
            break
    else:  # pragma: no cover - backend-only checkout
        pytest.skip("registry plugins are not present in this checkout")

    assert "settings.delete(" in src, f"{plugin_id} still blanks its per-alert key"
    assert f'settings.set(f"{{{prefix}' not in src.replace(" ", ""), (
        f"{plugin_id} still writes an empty string to retire the mapping"
    )


def test_pagerduty_needs_no_such_cleanup():
    """
    Worth pinning: PagerDuty deduplicates server-side on ``dedup_key``, so it
    keeps no per-alert state and has nothing to delete. If it ever starts
    storing one, it inherits this problem.
    """
    import pathlib

    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "registry" / "plugins" / "pagerduty-incidents" / "plugin.py"
        if candidate.is_file():
            src = candidate.read_text(encoding="utf-8")
            break
    else:  # pragma: no cover
        pytest.skip("registry plugins are not present in this checkout")

    assert "settings.set(" not in src, "pagerduty has started keeping per-alert state"


def test_the_published_sdk_stub_advertises_it():
    """
    A plugin author works against the published stub, not this file. A method
    that exists only in the runtime is a method nobody discovers.
    """
    import pathlib

    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "freesdn-sdk" / "sdk" / "src" / "freesdn_sdk" / "context.py"
        if candidate.is_file():
            src = candidate.read_text(encoding="utf-8")
            break
    else:  # pragma: no cover
        pytest.skip("the SDK package is not present in this checkout")

    assert "async def delete" in src, "the published SDK does not offer delete"
