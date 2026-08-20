# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Four VPN defects, each of which made the product report something untrue.

1. THE SYNC TASK THREW AWAY ITS OWN WORK
   ``PersistentVPNService.sync_live_connections`` returns an INT. The Celery task
   did ``len(connections) if connections else 0`` -- ``len()`` on an int raises
   TypeError, which the surrounding except caught and rolled back. So the sync
   only ever "succeeded" when the count was 0 and the falsy branch
   short-circuited; any run that actually had rows to sync discarded them. Live
   VPN telemetry never reached the database.

2. A SECOND VPN CONFIG 500'd THE SITE PANEL
   ``get_site_config`` used ``scalar_one_or_none()`` filtered only on
   ``site_id``. The UI offers "Add VPN configuration" and the model carries
   ``is_primary`` precisely because a site may have several -- so the multi-VPN
   feature broke the panel that displays it, with MultipleResultsFound.

3. CONFIGS INVISIBLE TO EVERY ORG-SCOPED READ
   Three of the five ``SiteVPNConfiguration(...)`` construction sites never set
   ``organization_id``, while EVERY read filters on it (endpoints/vpn.py in
   three places, vpn_cert_lifecycle.py in two). A config created through those
   paths existed in the table and was invisible to the queries meant to find it
   -- including certificate renewal, so its certs would silently never be
   renewed.

4. TUNNELS MARKED ACTIVE THAT WERE NEVER PUSHED
   ``BaseAdapter.push_vpn_config`` is a stub returning
   ``AdapterResult.fail(NOT_SUPPORTED)``, so ``hasattr(adapter,
   "push_vpn_config")`` was ALWAYS true and the honest "does not support VPN
   push" branch was unreachable dead code. Only OPNsense implements it. The
   result was discarded and a failed AdapterResult does not raise, so for every
   other adapter the tunnel was marked provisioned while nothing reached either
   gateway.
"""

from __future__ import annotations

import inspect

from app.adapters.base import AdapterResult, BaseAdapter
from app.services import brain_vpn, vpn_integration, vpn_orchestration
from app.tasks import vpn as vpn_task


def _code(obj) -> str:
    """Source with comments stripped -- the fixes quote the old code in comments."""
    src = inspect.getsource(obj)
    return "\n".join(line for line in src.splitlines() if not line.strip().startswith("#"))


# ── 1. the sync task ─────────────────────────────────────────────


def test_sync_live_connections_returns_an_int_not_a_sequence() -> None:
    """The premise of the bug. If this ever changes, the task must change with it."""
    sig = inspect.signature(vpn_integration.PersistentVPNService.sync_live_connections)
    assert sig.return_annotation in (int, "int")


def test_the_task_no_longer_calls_len_on_the_count() -> None:
    src = _code(vpn_task)
    assert "len(connections)" not in src, (
        "len() on an int raises TypeError, which rolls the whole sync back"
    )


# ── 2. multiple configs per site ─────────────────────────────────


def test_get_site_config_cannot_raise_on_a_second_row() -> None:
    src = _code(vpn_integration.PersistentVPNService.get_site_config)
    assert "scalar_one_or_none" not in src, (
        "scalar_one_or_none raises MultipleResultsFound the moment a site has "
        "two VPN configs, which the UI lets an operator create"
    )
    assert "is_primary" in src, "the choice between configs must be deterministic"


def test_upsert_site_config_cannot_raise_on_a_second_row() -> None:
    """
    Scoped to the SiteVPNConfiguration lookup specifically. The method also does
    a Site primary-key lookup where scalar_one_or_none is exactly right, so a
    blanket ban on the call would be wrong.
    """
    src = _code(vpn_integration.PersistentVPNService.upsert_site_config)
    cfg_query = src[src.index("select(SiteVPNConfiguration)") :]
    cfg_query = cfg_query[: cfg_query.index("if config:")]
    assert "scalar_one_or_none" not in cfg_query, (
        "the SiteVPNConfiguration lookup raises MultipleResultsFound again"
    )
    assert ".first()" in cfg_query
    assert "order_by" in cfg_query, "the choice between configs must be deterministic"


def test_the_read_is_ordered_so_repeated_calls_agree() -> None:
    """
    `.first()` without an ORDER BY would swap the 500 for a different bug: two
    reads returning different configs.
    """
    src = _code(vpn_integration.PersistentVPNService.get_site_config)
    assert "order_by" in src


# ── 3. organization_id on every construction site ────────────────


def test_every_site_vpn_config_construction_sets_organization_id() -> None:
    """
    Guard the class, not the three instances. A new construction site that
    forgets organization_id produces a row invisible to every org-scoped read --
    a failure with no error attached to it.
    """
    import pathlib
    import re

    root = pathlib.Path(vpn_integration.__file__).parents[1]
    offenders: list[str] = []
    for path in root.rglob("*.py"):
        if "__pycache__" in str(path):
            continue
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"(?<!class )SiteVPNConfiguration\(", text):
            # The call itself, plus the lines just above it: the org may be
            # injected into a kwargs dict rather than passed as a literal.
            before = text[max(0, match.start() - 800) : match.start()]
            window = text[match.start() : match.start() + 700]
            depth, end = 0, len(window)
            for i, ch in enumerate(window):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            call = window[:end]
            if "organization_id" in call:
                continue
            # `**data` where organization_id was just put into `data`
            if "**" in call and "organization_id" in before:
                continue
            line = text[: match.start()].count(chr(10)) + 1
            offenders.append(f"{path.name}:{line}")

    assert not offenders, (
        "SiteVPNConfiguration built without organization_id at "
        f"{offenders} -- every read of this table filters on it, so these rows "
        "are invisible to the queries meant to find them"
    )


def test_brain_vpn_resolves_the_org_from_the_site() -> None:
    src = _code(brain_vpn)
    assert src.count("organization_id=_site") == 2


# ── 4. the discarded push result ─────────────────────────────────


def test_base_adapter_push_vpn_config_is_a_failing_stub() -> None:
    """
    The premise: because BaseAdapter DEFINES it, hasattr() is always true for
    every adapter, and the result is a failure rather than an exception.
    """
    assert hasattr(BaseAdapter, "push_vpn_config")
    src = inspect.getsource(BaseAdapter.push_vpn_config)
    assert "AdapterResult.fail" in src


def test_provisioning_reads_the_push_result() -> None:
    src = _code(vpn_orchestration)
    assert "push_result" in src, "the adapter's AdapterResult is discarded again"
    assert 'getattr(push_result, "success", True) is False' in src


def test_a_failed_push_marks_the_tunnel_unprovisioned() -> None:
    """
    The whole point: a refused push must not leave the operator looking at an
    'active' tunnel that does not exist.
    """
    src = _code(vpn_orchestration)
    start = src.index("push_result")
    block = src[start : start + 900]
    assert "provisioned = False" in block
    assert "tunnel.error_message" in block


def test_the_stub_result_shape_is_what_the_check_expects() -> None:
    """Pin the contract the guard relies on, so a change to AdapterResult is caught."""
    failed = AdapterResult.fail("nope", error_code="NOT_SUPPORTED")
    assert failed.success is False
    assert getattr(failed, "success", True) is False
    ok = AdapterResult.ok({})
    assert getattr(ok, "success", True) is not False
