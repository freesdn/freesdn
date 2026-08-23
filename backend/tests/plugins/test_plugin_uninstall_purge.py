# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A credential outlived the plugin that used it, and the dialog was vague about it.

Uninstalling a plugin removed its files and left every stored setting behind,
including the encrypted API tokens. Verified against the running stack:

    select count(*) from plugin_settings where plugin_id='zabbix-sync'  -> 10
    DELETE /plugins/zabbix-sync                                         -> 204
    select count(*) ...                                                 -> 10

That is a defensible DEFAULT -- it is what makes uninstall-reinstall a safe
troubleshooting step -- but it was neither documented nor escapable. The
uninstall dialog said only that settings "may remain in the database": vague
about something that always happens, and silent about the part that matters,
which is the token.

So the fix is a choice rather than a new default. The two reasons to uninstall
want opposite behaviour:

    fixing a misbehaving plugin  -> keep the configuration, come back to it
    removing one you are done with -> take the credential with it

``?purge_settings=true`` does the second. Verified both ways afterwards:

    DELETE /plugins/zabbix-sync                        -> 204, rows: 10
    DELETE /plugins/zabbix-sync?purge_settings=true    -> 204, rows: 0
"""

from __future__ import annotations

import inspect


def _src() -> str:
    from app.api.v1.endpoints.plugins import uninstall_plugin

    return inspect.getsource(uninstall_plugin)


def _body() -> str:
    return "\n".join(ln for ln in _src().splitlines() if not ln.strip().startswith("#"))


# ── the option exists and is off ────────────────────────────────


def test_purge_is_offered():
    from app.api.v1.endpoints.plugins import uninstall_plugin

    assert "purge_settings" in inspect.signature(uninstall_plugin).parameters


def test_purge_is_off_by_default():
    """
    Making it the default would turn uninstall-reinstall -- the most ordinary
    troubleshooting step there is -- into silent credential loss.
    """
    from app.api.v1.endpoints.plugins import uninstall_plugin

    param = inspect.signature(uninstall_plugin).parameters["purge_settings"]
    assert param.default is False


def test_the_docstring_says_which_default_and_why():
    from app.api.v1.endpoints.plugins import uninstall_plugin

    doc = " ".join((uninstall_plugin.__doc__ or "").split())
    assert "KEPT by default" in doc
    assert "credential" in doc.lower()


# ── what it deletes ─────────────────────────────────────────────


def test_it_deletes_the_settings():
    body = _body()
    assert "delete(PluginSetting)" in body, "purge does not remove stored settings"


def test_it_deletes_the_per_org_state_too():
    """
    Leaving the enablement rows behind would have a reinstalled plugin come back
    disabled for an organization that disabled the previous one, with nothing
    on screen explaining why.
    """
    assert "delete(PluginOrganizationState)" in _body()


def test_it_purges_every_organization():
    """
    This is a PLATFORM uninstall -- the files are gone for everyone. Scoping the
    purge to the caller's own organization would leave other tenants'
    credentials for a plugin that no longer exists, which is the worst of both
    answers.
    """
    body = _body()
    delete_stmt = body.split("delete(PluginSetting)", 1)[1].split(")", 1)[0]
    assert "organization_id" not in delete_stmt, "the purge is scoped to one organization"


def test_nothing_is_deleted_when_purge_is_not_asked_for():
    body = _body()
    assert "if purge_settings:" in body
    guarded = body.split("if purge_settings:", 1)[1]
    assert "delete(PluginSetting)" in guarded, "the delete is outside the guard"
    assert "delete(PluginSetting)" not in body.split("if purge_settings:", 1)[0]


# ── it is recorded ──────────────────────────────────────────────


def test_the_purge_is_audited():
    """
    Deleting another tenant's stored credentials is exactly the kind of action
    that has to be answerable afterwards.
    """
    body = _body()
    assert "purged_settings" in body
    assert "AuditAction.UNINSTALL" in body


# ── the operator is told the truth ──────────────────────────────


def test_the_dialog_no_longer_says_settings_may_remain():
    """
    "May remain" was wrong twice over: they always remained, and it never said
    the credentials were among them.
    """
    import json
    import pathlib

    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "frontend" / "public" / "locales" / "en" / "settings.json"
        if candidate.is_file():
            data = json.loads(candidate.read_text(encoding="utf-8"))
            break
    else:  # pragma: no cover - backend-only checkout
        import pytest

        pytest.skip("frontend locales are not present in this checkout")

    dialog = data["PluginsPage"]["uninstallDialog"]
    assert "may remain" not in dialog["description"].lower()
    assert "credential" in dialog["description"].lower(), (
        "the dialog still does not say that credentials are kept"
    )
    assert "purgeLabel" in dialog, "there is no way to ask for the credentials to go"
