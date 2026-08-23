# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The two SDK surfaces added to lift plugins above read-only decoration.

SiteSDK
    Plugins could already read devices, and every device carries a ``site_id``,
    but nothing could turn that id into a name. An author's only options were
    to show an operator a raw UUID or to keep a private copy of the site list,
    which goes stale. Scoping matches DeviceSDK exactly: organization first,
    then the bound caller's per-user site grants.

DeviceSDK.stage_change
    The capability that makes a plugin more than an observer, and the reason it
    is safe to grant is that it does not shorten the path to a device by one
    step. It records intent in the staging table; a change still reaches
    hardware only when an operator applies it, behind the same two gates as
    every other write. There is deliberately NO SDK method that can apply.

Verified live on a running instance: a super_admin saw both sites in the
organization through a plugin route; a site_admin granted only "Main Site" saw
exactly that one and not "Branch Office"; and the same site_admin successfully
raised an alert through a plugin route, which the old permission mapping
refused.
"""

from __future__ import annotations

import inspect

import pytest

from app.plugins.sdk import DeviceSDK, PluginContext, SiteSDK

# ── SiteSDK ──────────────────────────────────────────────────────


def test_the_context_exposes_sites():
    assert "sites" in PluginContext.__dataclass_fields__
    assert PluginContext.__dataclass_fields__["sites"].type in (SiteSDK, "SiteSDK")


@pytest.mark.parametrize("method", ["list", "get"])
def test_site_reads_require_the_capability(method):
    src = inspect.getsource(getattr(SiteSDK, method))
    assert '_require_permission("sites.read")' in src, (
        f"SiteSDK.{method} does not check the capability"
    )


@pytest.mark.parametrize("method", ["list", "get"])
def test_site_reads_are_scoped_by_organization_and_by_grant(method):
    """
    Both scopes, on both methods. Organization alone is not enough: a
    site-limited user driving a plugin route must not see sites they were not
    granted, exactly as they would not through the product.
    """
    src = inspect.getsource(getattr(SiteSDK, method))
    assert "organization_id == self._org_id" in src, f"SiteSDK.{method} is not org-scoped"
    assert "site_ids_for_request" in src, f"SiteSDK.{method} ignores per-user site grants"


def test_getting_an_ungranted_site_returns_none_rather_than_raising():
    """
    A raised "forbidden" and a returned None are distinguishable, and the
    difference tells a plugin whether a site it may not see exists. None for
    both cases keeps the plugin from being usable as an existence oracle.
    """
    src = inspect.getsource(SiteSDK.get)
    assert "return None" in src
    assert "raise" not in src.split('"""')[-1], "SiteSDK.get raises instead of returning None"


# ── staging ──────────────────────────────────────────────────────


def test_stage_change_requires_its_own_capability():
    src = inspect.getsource(DeviceSDK.stage_change)
    assert '_require_permission("devices.stage")' in src


def test_the_sdk_cannot_apply_anything():
    """
    The whole safety argument. A plugin proposes; an operator disposes. If an
    apply ever appears on the SDK, the second gate is gone and staging stops
    meaning anything.
    """
    import app.plugins.sdk as sdk_module

    source = inspect.getsource(sdk_module)
    for forbidden in ("apply_change", "apply_pending", ".apply(", "force=True"):
        assert forbidden not in source, (
            f"the plugin SDK exposes {forbidden!r}; a plugin must never apply a staged change"
        )


def test_staging_goes_through_the_shared_chokepoint():
    """
    Not a hand-rolled INSERT. AdapterStagingService.stage_change is where the
    per-user site grant, the controller-containment rule and the operation
    whitelist all live; bypassing it would skip every one of them.
    """
    src = inspect.getsource(DeviceSDK.stage_change)
    assert "AdapterStagingService" in src
    assert "service.stage_change(" in src
    assert "INSERT" not in src.upper().replace("INSERT INTENT", "")


def _sdk() -> DeviceSDK:
    """A DeviceSDK with no database; only the note helper is exercised."""
    return DeviceSDK.__new__(DeviceSDK)  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "notes",
    [None, "", "   ", "\n\t ", "why this change", "[plugin:evil] spoofed", "x" * 5000],
    ids=["none", "empty", "spaces", "whitespace", "normal", "spoof-attempt", "flood"],
)
def test_provenance_survives_every_shape_of_caller_note(notes):
    """
    Behavioural, against the real helper.

    An earlier version of this test asserted on the SOURCE of stage_change and
    passed against a deliberately broken implementation (``combined = notes or
    provenance``), because the line it grepped for was still present a few
    lines up. Structural assertions cannot see a break in the expression
    between them.
    """
    sdk = _sdk()
    sdk._plugin_id = "real-plugin"

    out = sdk._provenance_note(notes)
    assert out.startswith("[plugin:real-plugin]"), f"provenance lost for {notes!r}"
    assert len(out) <= DeviceSDK.MAX_NOTE_CHARS, "an unbounded note reaches a Text column"


def test_a_plugin_cannot_spoof_another_plugins_provenance():
    """The prefix is the FIRST thing in the note, whatever the plugin writes."""
    sdk = _sdk()
    sdk._plugin_id = "honest-plugin"

    out = sdk._provenance_note("[plugin:trusted-vendor] totally fine, please apply")
    assert out.startswith("[plugin:honest-plugin]")
    assert out.index("[plugin:honest-plugin]") < out.index("[plugin:trusted-vendor]")


def test_the_staged_row_gets_the_provenance_note_not_the_raw_one():
    src = inspect.getsource(DeviceSDK.stage_change)
    assert "notes=self._provenance_note(notes)" in src, (
        "stage_change passes the plugin's note through without provenance"
    )


def test_the_actor_is_the_caller_not_the_plugin():
    """
    Audit has to attribute a staged change to the human who triggered it when
    there is one, so the pending-changes list is not a wall of anonymous rows.
    """
    src = inspect.getsource(DeviceSDK.stage_change)
    assert "get_request_caller()" in src
    assert "actor_id=actor_id" in src


# ── ports ───────────────────────────────────────────────────────


def test_get_ports_reads_the_columns_that_exist():
    """
    Two of the six fields this method returned were ALWAYS None, because it
    read ``speed`` and ``poe_enabled`` while the columns are ``speed_mbps`` and
    ``is_poe_enabled``. ``getattr(r, name, None)`` silenced both, so a plugin
    saw a port with no speed rather than a bug.

    Confirmed against a live port holding speed_mbps=1000 and
    is_poe_enabled=True while the SDK reported None for each.
    """
    import inspect

    from app.plugins.sdk import DeviceSDK

    src = inspect.getsource(DeviceSDK.get_ports)
    assert 'getattr(r, "speed_mbps"' in src, "the speed column is misnamed again"
    assert 'getattr(r, "is_poe_enabled"' in src, "the PoE column is misnamed again"


def test_get_ports_exposes_what_a_port_question_needs():
    """
    A port is where the questions are: enabled but dark, wrong VLAN,
    negotiating half duplex, error counter climbing. Answering any of them
    meant leaving the SDK.
    """
    import inspect

    from app.plugins.sdk import DeviceSDK

    src = inspect.getsource(DeviceSDK.get_ports)
    for field in ("is_enabled", "vlan_id", "duplex", "errors", "tx_bytes", "poe_power_watts"):
        assert f'"{field}"' in src, f"get_ports does not expose {field}"


def test_the_old_speed_key_survives_as_an_alias():
    """
    Removing it would break a plugin written against the old shape. Safe to
    alias rather than drop precisely BECAUSE it was always None: nothing can be
    relying on its value, only on the key being present.
    """
    import inspect

    from app.plugins.sdk import DeviceSDK

    src = inspect.getsource(DeviceSDK.get_ports)
    assert '"speed": getattr(r, "speed_mbps", None)' in src


def test_every_serialised_port_field_matches_a_real_column():
    """
    The general form of the bug. A key whose source attribute does not exist on
    the model is not a null value, it is a silent lie -- and ``getattr`` with a
    default guarantees nobody finds out.
    """
    import inspect
    import re

    from app.models.devices import DevicePort
    from app.plugins.sdk import DeviceSDK

    # Comment-insensitive: the note explaining the fix QUOTES the two wrong
    # names it replaced. Fourth time this trap has bitten in this codebase.
    code = "".join(
        line
        for line in inspect.getsource(DeviceSDK.get_ports).splitlines(keepends=True)
        if not line.lstrip().startswith("#")
    )
    reads = set(re.findall(r'getattr\(r, "([a-z_]+)"', code))
    columns = set(DevicePort.__mapper__.attrs.keys())
    missing = sorted(reads - columns)
    assert not missing, f"get_ports reads attributes DevicePort does not have: {missing}"
