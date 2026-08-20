# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Controller limbs: the cross-vendor case, which failed 100% of the time.

Background
----------
``SiteRoleAssignment`` is polymorphic -- exactly one of ``gateway_id`` or
``controller_id`` is set, and the ``device_id`` property returns whichever it
is. ``GatewayConnection.vendor`` is restricted to opnsense/pfsense/mikrotik/
openwrt, so a UniFi or Omada device can ONLY appear in a role map as a
CONTROLLER assignment. Controller limbs are therefore not an edge case: they
are the entire cross-vendor push story, which is the feature the gateway module
exists for.

Two independent defects made that story impossible.

1. ``ReconciliationService._push_vlan_to_controller`` called
   ``await get_adapter(ctrl, self.db)``. ``get_adapter`` is SYNCHRONOUS and
   takes ``(controller_type, host, username, password)``, so this raised
   TypeError before a single packet reached the device. The caller records the
   limb as failed, so the operator saw "failed" rather than a lie -- but no
   controller ever received a VLAN, for any site, ever.

2. ``DistributionService`` plan builders read ``limb.gateway_id`` directly. For
   a controller limb that is None, so the plan carried the literal string
   ``"None"`` as a device_id, and the executor's ``UUID(device_id)`` raised
   ValueError. ``_execute_plan`` catches only DistributionError, so it escaped
   as an unhandled 500 -- and since the session rolls back on exception, the
   DistributionRecord was never committed. The operator got a red toast, an
   empty Distribution Log, and nothing to retry.

The distribution executor is gateway-shaped end to end (it resolves every step
through the GatewayConnection cache and calls ``build_adapter(gw)``), so
supporting controller limbs there is a capability it does not have. It now says
so clearly and points at the reconciliation path, which does.
"""

from __future__ import annotations

import inspect
import re
import uuid
from types import SimpleNamespace

import pytest

from app.modules.gateway.services.distribution_service import (
    DistributionError,
    DistributionService,
)


def _limb(*, controller: bool):
    """A role assignment shaped like SiteRoleAssignment's polymorphic contract."""
    gateway_id = None if controller else uuid.uuid4()
    controller_id = uuid.uuid4() if controller else None
    return SimpleNamespace(
        device_type="controller" if controller else "gateway",
        gateway_id=gateway_id,
        controller_id=controller_id,
        device_id=gateway_id or controller_id,
        role="limb",
    )


# ── Distribution: fail honestly instead of 500-ing ───────────────


def test_controller_limb_is_rejected_with_an_actionable_error() -> None:
    """
    The regression: this used to reach UUID("None") and escape as a 500 with no
    DistributionRecord. A DistributionError is caught upstream and becomes a
    real, recorded failure the operator can read.
    """
    with pytest.raises(DistributionError) as exc:
        DistributionService._reject_unsupported_limbs([_limb(controller=True)])

    message = str(exc.value)
    assert "controller" in message.lower()
    assert "Reconciliation" in message, "the error must name the path that DOES work"


def test_error_names_the_offending_controller_ids() -> None:
    """An operator needs to know WHICH device to reassign."""
    limbs = [_limb(controller=True), _limb(controller=True)]
    with pytest.raises(DistributionError) as exc:
        DistributionService._reject_unsupported_limbs(limbs)

    for limb in limbs:
        assert str(limb.controller_id) in str(exc.value)


def test_gateway_only_role_map_is_untouched() -> None:
    """The supported case must not have become an error."""
    DistributionService._reject_unsupported_limbs([_limb(controller=False)])
    DistributionService._reject_unsupported_limbs([])


def test_mixed_role_map_is_rejected_rather_than_partially_distributed() -> None:
    """
    Silently pushing to the gateway limbs while dropping the controller limb
    would leave the site inconsistent and report success -- a worse failure than
    refusing, because nothing would tell the operator the site is half-done.
    """
    with pytest.raises(DistributionError):
        DistributionService._reject_unsupported_limbs(
            [_limb(controller=False), _limb(controller=True)]
        )


def test_plan_builders_no_longer_read_gateway_id_directly() -> None:
    """
    ``str(limb.gateway_id)`` yields the literal "None" for a controller limb,
    which is what produced UUID("None"). The polymorphic ``device_id`` property
    exists precisely to avoid that, so pin its use.
    """
    src = inspect.getsource(DistributionService)
    assert "str(limb.gateway_id)" not in src, (
        "a plan builder is reading gateway_id directly again; use device_id"
    )
    assert "str(brain.gateway_id)" not in src
    assert "str(limb.device_id)" in src


def test_both_entry_points_validate_before_building_a_plan() -> None:
    """
    The guard must run in distribute AND retract. Rollback hit the identical
    crash, which is the worst moment to discover it.
    """
    for fn in (DistributionService.distribute_vlan, DistributionService.retract_vlan):
        src = inspect.getsource(fn)
        assert "_reject_unsupported_limbs" in src, f"{fn.__name__} does not validate limbs"


# ── Reconciliation: the adapter call that always raised ──────────


def test_reconciliation_builds_the_adapter_from_the_controller_row() -> None:
    """
    ``await get_adapter(ctrl, self.db)`` was wrong three ways at once: get_adapter
    is not a coroutine, its first parameter is a controller_type STRING not a
    Controller row, and two required arguments were missing. It could only ever
    raise TypeError.
    """
    from app.modules.gateway.services import reconciliation_service

    src = inspect.getsource(reconciliation_service.ReconciliationService)
    # Strip comments first: the fix deliberately quotes the old broken call in a
    # comment explaining what it was, and a naive substring check trips on that.
    code = re.sub(r"#.*", "", src)
    assert "await get_adapter(ctrl" not in code, "the broken call signature is back"
    assert "build_adapter_for_controller(ctrl)" in code


def test_get_adapter_really_is_synchronous_and_needs_four_arguments() -> None:
    """
    Pin the shape that made the original call impossible, so this test explains
    itself if someone later makes get_adapter async and wonders why the wrapper
    exists.
    """
    from app.services.adapter_factory import get_adapter

    assert not inspect.iscoroutinefunction(get_adapter)
    params = list(inspect.signature(get_adapter).parameters)
    assert params[:4] == ["controller_type", "host", "username", "password"]


def test_the_safe_wrapper_takes_a_row_and_is_not_a_coroutine() -> None:
    from app.services.adapter_factory import build_adapter_for_controller

    assert not inspect.iscoroutinefunction(build_adapter_for_controller)
    assert list(inspect.signature(build_adapter_for_controller).parameters) == ["controller"]


def test_wrapper_passes_cloud_credentials_for_a_cloud_controller(monkeypatch) -> None:
    """
    Cloud-mode Omada authenticates by OAuth2 client credentials, not username /
    password. Dropping them yields an adapter that cannot log in -- the same
    class of silent breakage, one layer down.
    """
    from app.services import adapter_factory

    captured: dict = {}

    def _fake_get_adapter(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(adapter_factory, "get_adapter", _fake_get_adapter)

    ctrl = SimpleNamespace(
        controller_type="omada",
        host="10.0.0.5",
        username="u",
        password="p",
        port=8043,
        use_ssl=True,
        verify_ssl=False,
        connection_mode="cloud",
        client_id="cid",
        client_secret="csecret",
        omada_id="oid",
        cloud_region="eu",
    )
    adapter_factory.build_adapter_for_controller(ctrl)

    assert captured["client_id"] == "cid"
    assert captured["omada_id"] == "oid"
    assert captured["cloud_region"] == "eu"
    assert captured["mode"] == "cloud"


def test_wrapper_omits_cloud_fields_for_a_local_controller(monkeypatch) -> None:
    from app.services import adapter_factory

    captured: dict = {}
    monkeypatch.setattr(
        adapter_factory, "get_adapter", lambda **kw: captured.update(kw) or object()
    )

    ctrl = SimpleNamespace(
        controller_type="unifi",
        host="10.0.0.6",
        username="u",
        password="p",
        port=443,
        use_ssl=True,
        verify_ssl=False,
        connection_mode="local",
    )
    adapter_factory.build_adapter_for_controller(ctrl)

    assert "client_id" not in captured
    assert captured["mode"] == "local"
