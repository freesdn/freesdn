# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Deleted rows must not be visible to plugins.

They were, and the reason is worth writing down because the safeguard existed
and simply did not point here. ``tests/test_soft_delete_guard.py`` scans for
queries against soft-deletable models with no ``deleted_at`` filter, and its
``SCAN_DIRS`` was ``("api", "services", "tasks", "modules", "core")``. Not
``plugins``. So the one directory whose entire purpose is serving data to
third-party code was the one directory the check never looked at, and all six
query sites in the SDK returned deleted rows.

What that cost on a 40-device dev estate, measured rather than estimated:

  * ``DeviceSDK`` returned 40 devices where 16 were alive.
  * 48 of the 59 alerts raised in six hours were about devices the operator had
    already deleted.
  * ``config-drift-guard`` reported **2 site-parity findings that did not
    exist**. It counts populated sites to tell drift from deliberate design;
    deleted sites still had devices attached, so it believed there were enough
    sites to compare and found "drift" between a live site and a deleted one.
    After the fix it reports 0 findings and says why: "site parity needs at
    least 3 populated sites ... this organization has 1. The check did not run."

The last one is the reason this matters more than noise. Extra alerts are
irritating; a monitoring plugin inventing findings out of deleted data sends an
operator to investigate something that is not happening.

Scheduling turned all of this from an occasional annoyance into a standing one:
an unattended sweep every thirty minutes, forever.
"""

from __future__ import annotations

import inspect
import pathlib

import pytest


def _sdk_source() -> str:
    from app.plugins import sdk

    return inspect.getsource(sdk)


# ── the guard now covers this directory ─────────────────────────


def test_the_soft_delete_guard_scans_the_plugin_sdk():
    """
    The root cause. Without ``plugins`` in SCAN_DIRS every fix below can be
    undone by the next person without anything going red.
    """
    from tests.test_soft_delete_guard import SCAN_DIRS

    assert "plugins" in SCAN_DIRS, (
        "the soft-delete guard no longer scans app/plugins -- the SDK third-party "
        "code queries through is unchecked again"
    )


def test_the_plugin_sdk_is_not_grandfathered():
    """
    The baseline exists for debt that predates the guard. Adding the SDK to it
    would silence the check while leaving deleted devices visible to plugins,
    which is the same outcome as never scanning the directory.
    """
    baseline = (
        pathlib.Path(__file__).resolve().parents[1] / "soft_delete_guard_baseline.txt"
    ).read_text(encoding="utf-8")
    offenders = [ln for ln in baseline.splitlines() if "plugins/sdk.py" in ln]
    assert not offenders, f"plugin SDK queries were grandfathered instead of fixed: {offenders}"


# ── every query site ────────────────────────────────────────────


@pytest.mark.parametrize(
    ("cls_name", "method"),
    [
        ("DeviceSDK", "list"),
        ("DeviceSDK", "get"),
        ("SiteSDK", "list"),
        ("SiteSDK", "get"),
    ],
)
def test_reads_exclude_deleted_rows(cls_name: str, method: str):
    """
    All four were flagged by the guard the moment it was pointed at this
    directory. ``get`` matters as much as ``list``: a deleted device must read
    as absent, not as data.
    """
    import app.plugins.sdk as sdk_mod

    src = inspect.getsource(getattr(getattr(sdk_mod, cls_name), method))
    assert "alive()" in src, f"{cls_name}.{method} returns soft-deleted rows"


def test_an_alert_cannot_be_attached_to_a_deleted_device():
    """
    A deleted device is not a valid alert target. It is rejected the same way a
    cross-tenant id is, so the refusal does not become an existence oracle.
    """
    from app.plugins.sdk import AlertSDK

    src = inspect.getsource(AlertSDK.create)
    assert "Device.alive()" in src
    assert "Site.alive()" in src


def test_the_plugin_system_alert_rule_is_not_a_deleted_one():
    """
    Same defect as the automation engine's twin, fixed the same way: reusing a
    soft-deleted system rule hangs every plugin alert off a row the rest of the
    platform treats as gone.
    """
    from app.plugins.sdk import AlertSDK

    assert "AlertRule.alive()" in inspect.getsource(AlertSDK._get_or_create_plugin_rule)


def test_metrics_scoping_excludes_deleted_sites():
    """
    The newest SDK, written after this was understood. Included so the newest
    surface is not the next gap.
    """
    from app.plugins.sdk import MetricsSDK

    assert "Site.alive()" in inspect.getsource(MetricsSDK._visible_site_ids)


def test_no_read_path_in_the_sdk_is_left_unfiltered():
    """
    A sweep rather than a list, so a NEW query added tomorrow is covered even
    before someone thinks to add a case above. Every ``select(Device)`` or
    ``select(Site)`` in the SDK must sit in a function that filters.
    """
    import app.plugins.sdk as sdk_mod

    src = _sdk_source()
    unfiltered = []
    for name, obj in vars(sdk_mod).items():
        if not (isinstance(obj, type) and name.endswith("SDK")):
            continue
        for attr, fn in vars(obj).items():
            if not callable(fn) or attr.startswith("__"):
                continue
            try:
                body = inspect.getsource(fn)
            except (TypeError, OSError):  # pragma: no cover
                continue
            queries_model = "select(Device" in body or "select(Site" in body
            if queries_model and "alive()" not in body and "deleted_at" not in body:
                unfiltered.append(f"{name}.{attr}")
    assert not unfiltered, f"these SDK methods return soft-deleted rows: {unfiltered}"
    assert "select(Device" in src, "the sweep found nothing to check; it has gone vacuous"
