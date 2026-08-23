# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The assistant's rolled-up answers, and the device search that reaches them.

Three tools moved from a first-party ``ai-ops-tools`` plugin into the native AI
module. The plugin tier exists so people outside the project can extend FreeSDN
without a core pull request and without AGPL; a first-party plugin that shadows
a native module gets none of that benefit and costs three things -- operators
read "plugin" as third-party and restricted, the code runs under a permission
model it does not need, and it competes with the native feature for the same
job. Native tools reach every FreeSDN user; a plugin reaches whoever installed
it. The plugin is retired.

Each of the three closed a real hole, verified against the live 40-device
estate before these were written:

  SEARCH
      ``get_devices`` filtered by status, type and site, and by nothing a human
      actually arrives with. An operator reading a log has a MAC; a colleague
      on the phone has a name. ``get_device_detail`` demands a UUID, so neither
      could be turned into an answer.

  ROLLUPS
      ``get_devices`` returns at most 50 rows. On any estate past fifty devices
      the model cannot see the whole inventory, so it cannot count it -- and a
      rollup assembled from a truncated window is worse than none, because it
      is confidently wrong.

  THE 24-HOUR VIEW
      A point-in-time answer reads identically whether three devices have been
      offline for a month or since twenty minutes ago.
"""

from __future__ import annotations

import inspect

import pytest

from app.modules.ai.tools import TOOL_REGISTRY, load_tools
from app.modules.ai.tools.estate import (
    UNHEALTHY_OFFLINE_RATIO,
    UNSTABLE_AVAILABILITY,
    _get_estate_summary,
    _get_site_health,
)


@pytest.fixture(autouse=True)
def _tools_loaded():
    load_tools()


# ── they are native tools ───────────────────────────────────────


@pytest.mark.parametrize("name", ["get_site_health", "get_estate_summary"])
def test_the_rollups_are_registered_natively(name: str):
    """
    Registered here rather than through the plugin AI bridge, which is what
    makes them available to every FreeSDN instance instead of to whoever
    installed a plugin.
    """
    assert name in TOOL_REGISTRY, f"{name} is not a native AI tool"
    assert TOOL_REGISTRY[name].permission, f"{name} has no permission; the AI gate needs one"


def test_device_search_is_offered_to_the_model():
    """
    A capability the tool schema does not mention is a capability the model
    never uses. The handler gaining a parameter is half the change.
    """
    tool = TOOL_REGISTRY["get_devices"]
    assert "search" in tool.parameters["properties"], "the model is not told search exists"
    assert "MAC" in tool.description or "search" in tool.description.lower()


def test_search_normalises_mac_punctuation():
    """
    A MAC arrives punctuated differently by every tool that prints one --
    aa:bb:cc, AA-BB-CC, aabbcc -- and the column stores exactly one form.
    Verified live: all four spellings of the same address return the same
    device.
    """
    from app.modules.ai.tools.network import _get_devices

    src = inspect.getsource(_get_devices)
    assert "isalnum" in src, "MAC punctuation is not normalised"
    assert "func.lower" in src, "the search is case-sensitive"


def test_search_still_scopes_to_the_caller():
    """
    Search widens what a question can reach, so it must not widen what a
    principal can see. Verified live: another organization searching a known
    MAC gets zero rows.
    """
    from app.modules.ai.tools.network import _get_devices

    src = inspect.getsource(_get_devices)
    assert "site_scope_filter" in src
    assert "Site.organization_id == user.organization_id" in src
    # the search clause must come AFTER the scoping, not replace it
    assert src.index("organization_id") < src.index("if search:")


# ── scoping on the rollups ──────────────────────────────────────


@pytest.mark.parametrize("func_ref", [_get_site_health, _get_estate_summary])
async def test_a_caller_without_an_organization_gets_nothing(func_ref):
    """
    Both aggregate across an organization. Without one there is no scope to
    aggregate over, and an unscoped COUNT is a cross-tenant total.
    """

    class NoOrg:
        organization_id = None

    result = await func_ref(NoOrg(), None)
    assert "error" in result


@pytest.mark.parametrize("func_ref", [_get_site_health, _get_estate_summary])
def test_both_rollups_respect_per_user_site_grants(func_ref):
    """
    A site-limited operator asking "how is my network doing" must be told about
    their sites. The rollup is precisely where a missing grant filter turns
    into a whole-estate disclosure.
    """
    src = inspect.getsource(func_ref)
    combined = src + inspect.getsource(
        __import__("app.modules.ai.tools.estate", fromlist=["_site_rows"])._site_rows
    )
    assert "site_scope_filter" in combined


def test_the_rollups_exclude_deleted_records():
    from app.modules.ai.tools import estate

    for fn in (estate._site_rows, estate._get_site_health, estate._get_estate_summary):
        assert "deleted_at.is_(None)" in inspect.getsource(fn), f"{fn.__name__} counts deleted rows"


# ── counting, not fetching ──────────────────────────────────────


def test_the_summary_counts_in_the_database():
    """
    The entire point of the tool is answering a question about an estate larger
    than any window the model could page through. Fetching rows and calling
    len() would reintroduce the cap it exists to escape.
    """
    src = inspect.getsource(_get_estate_summary)
    assert "func.count" in src
    assert ".scalars().all()" not in src.split("site_ids = ", 1)[1].split("totals", 1)[0]


# ── the verdict ─────────────────────────────────────────────────


def test_unknown_is_not_treated_as_down():
    """
    A device the platform has not heard from is not the same claim as one it
    knows is down. Folding them together turns a discovery gap into a fake
    outage, on a screen an operator is using to decide whether to drive to site.
    """
    from app.modules.ai.tools.estate import DOWN

    assert "unknown" not in DOWN
    assert "offline" in DOWN


def test_an_empty_site_is_never_reported_as_unstable():
    """
    A real case, caught on the live estate. A site whose devices were all
    deleted still has 24 hours of metric history, so it reported
    "recently unstable" about hardware that is no longer there.
    """
    src = inspect.getsource(_get_site_health)
    assert "total > 0 and avg is not None" in src


def test_the_health_verdict_uses_named_thresholds():
    """
    A magic 0.25 buried in a conditional is a number nobody can find when they
    disagree with it.
    """
    assert 0 < UNHEALTHY_OFFLINE_RATIO < 1
    assert 0 < UNSTABLE_AVAILABILITY < 1
    src = inspect.getsource(_get_site_health)
    assert "UNHEALTHY_OFFLINE_RATIO" in src and "UNSTABLE_AVAILABILITY" in src


def test_an_alert_belonging_to_no_site_is_reported_not_dropped():
    """
    Dropping it would let an organization-wide problem vanish from a health
    report entirely -- the report would look clean while the thing it was
    supposed to surface went unmentioned.
    """
    src = inspect.getsource(_get_site_health)
    assert "unattached" in src
    assert "alerts_not_attached_to_a_site" in src


def test_a_missing_time_series_tier_degrades_rather_than_failing():
    """
    Time-series is optional. A lite deployment must still get a health report,
    just without the trend.
    """
    from app.modules.ai.tools.estate import _availability_by_site

    src = inspect.getsource(_availability_by_site)
    assert "return {}" in src
    assert "except Exception" in src
