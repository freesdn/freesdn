# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Finding out at the form, not six hours later in an alert.

Home Assistant validates a connection in the config flow, before the entry is
created. FreeSDN had no equivalent: settings were validated for SHAPE by a JSON
Schema and never for whether they worked. An operator pasted a token, saw
"Saved", and learned the truth from the first scheduled sync -- or never, because
a schedule failing quietly into a log is the whole reason unattended work is
hard to trust.

Verified live against an unreachable host:

    PUT /plugins/zabbix-sync/settings  {"zabbix_url": "...", "zabbix_token": "..."}
    -> {"settings": {...}, "warning": "Zabbix did not accept the request:
        ValueError: Cannot resolve hostname: zabbix.invalid.example"}

ADVISORY, NOT BLOCKING, and that is the decision worth defending. The settings
are committed before the check runs, because an operator half-way through
configuring a plugin must not be blocked by a remote that happens to be down,
and a plugin whose validator is wrong must not be able to lock its own
configuration.
"""

from __future__ import annotations

import inspect

import pytest

# ── the hook exists and is optional ─────────────────────────────


async def test_the_base_class_provides_a_no_op_validator():
    """
    Optional by design. A plugin with nothing external to check should not have
    to write a method to say so.
    """
    from app.plugins.sdk import FreeSDNPlugin

    assert await FreeSDNPlugin.async_validate_config(object()) is None  # type: ignore[arg-type]


def test_the_docstring_shows_an_author_what_to_return():
    """
    The contract is "None or a sentence", which is unusual enough that an
    example is the difference between it being used and being ignored.
    """
    from app.plugins.sdk import FreeSDNPlugin

    doc = FreeSDNPlugin.async_validate_config.__doc__ or ""
    assert "return None" in doc.lower() or "Return None" in doc
    assert "async def async_validate_config" in doc, "no worked example"


# ── it runs when settings are saved ─────────────────────────────


def test_saving_settings_asks_the_plugin():
    from app.api.v1.endpoints import plugins as endpoints

    src = inspect.getsource(endpoints.update_plugin_settings)
    assert "_validate_plugin_config(" in src, "settings are saved without ever being checked"


def test_the_settings_are_committed_before_the_check():
    """
    Order matters and is the whole "advisory" argument. Validating first and
    refusing the save would let a remote being briefly down block an operator
    from finishing their configuration.
    """
    from app.api.v1.endpoints import plugins as endpoints

    src = inspect.getsource(endpoints.update_plugin_settings)
    assert src.index("await session.commit()") < src.index("_validate_plugin_config(")


def test_a_broken_validator_cannot_break_saving():
    """
    A plugin that raises in its own validator must not be able to make its
    settings unsaveable -- that would be a plugin holding its configuration
    hostage to its own bug.
    """
    from app.api.v1.endpoints.plugins import _validate_plugin_config

    src = inspect.getsource(_validate_plugin_config)
    assert "except Exception" in src
    assert "return None" in src.split("except Exception")[1][:200]


def test_a_hanging_validator_cannot_hang_the_form():
    from app.api.v1.endpoints.plugins import _validate_plugin_config

    src = inspect.getsource(_validate_plugin_config)
    assert "timeout=" in src, "the validator is unbounded"
    assert "TimeoutError" in src, "a timeout is not reported to the operator"


def test_the_validator_runs_supervised_and_scoped():
    """
    It is a call into plugin code like any other: counted against the error
    budget, and given its own database session so it cannot collide with a
    route or a scheduled run happening at the same moment.
    """
    from app.api.v1.endpoints.plugins import _validate_plugin_config

    src = inspect.getsource(_validate_plugin_config)
    assert "supervisor.guard(" in src
    assert "plugin_session_scope()" in src


def test_an_unreachable_remote_is_reported_as_such():
    """
    ``PluginNotReady`` here means the settings may be perfect and the remote
    merely down. Reporting that as a bad configuration would send an operator
    to re-check a token that is fine.
    """
    from app.api.v1.endpoints.plugins import _validate_plugin_config

    src = inspect.getsource(_validate_plugin_config)
    assert "PluginNotReady" in src
    assert "Could not check" in src


# ── the shipped plugins actually implement it ───────────────────


@pytest.mark.parametrize("plugin", ["netbox-sync", "librenms-sync", "zabbix-sync", "snipe-it-sync"])
def test_each_sync_plugin_validates_its_own_configuration(plugin: str):
    """
    A hook nothing implements is a hook that does not exist. Each of these
    already knew which fields it needed; what it lacked was a moment to say so
    that was not "after the first scheduled run".
    """
    import pathlib

    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "registry" / "plugins" / plugin / "plugin.py"
        if candidate.is_file():
            src = candidate.read_text(encoding="utf-8")
            break
    else:  # pragma: no cover - backend-only checkout
        pytest.skip("registry plugins are not present in this checkout")

    assert "async def async_validate_config" in src, f"{plugin} never checks its settings"
    # And it must actually reach the remote, not merely re-check the shape the
    # JSON Schema already checked.
    body = src.split("async def async_validate_config", 1)[1].split("\n    async def", 1)[0]
    assert "_config()" in body, f"{plugin} does not read its own configuration"
    assert any(marker in body for marker in ("_request(", "_rpc(", "_get(")), (
        f"{plugin} validates without contacting the remote"
    )


@pytest.mark.parametrize("plugin", ["zabbix-sync", "snipe-it-sync"])
def test_a_reachable_but_unusable_configuration_is_still_reported(plugin: str):
    """
    Both need numeric ids an operator has to go and find (a Zabbix host group, a
    Snipe-IT model and status). Connecting successfully while still being unable
    to sync is the failure mode most likely to waste somebody's afternoon.
    """
    import pathlib

    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "registry" / "plugins" / plugin / "plugin.py"
        if candidate.is_file():
            src = candidate.read_text(encoding="utf-8")
            break
    else:  # pragma: no cover
        pytest.skip("registry plugins are not present in this checkout")

    body = src.split("async def async_validate_config", 1)[1].split("\n    async def", 1)[0]
    assert "Connected" in body, f"{plugin} does not distinguish connected-but-incomplete"
