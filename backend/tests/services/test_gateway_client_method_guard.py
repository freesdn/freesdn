# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A vendor-specific endpoint must refuse a controller of another vendor.

Found by sweeping every GET endpoint against the owner's real fleet. Handing an
Omada-only endpoint a Proxmox controller id crashed the API:

    GET /api/v1/gateway-insights/{proxmox_id}/sites/{site}/top-talkers  -> 500
    "'ProxmoxClient' object has no attribute 'get_top_talkers'"

The vendor services dispatch by name -- ``getattr(client, method_name)`` -- on
whatever client the resolved controller's vendor produces. A controller id is
just a uuid, so nothing upstream rejects one belonging to a different vendor,
and the AttributeError surfaced as a bare 500 instead of telling the caller
they addressed the wrong controller.

``GatewayServiceBase._client_method`` is the guard. It has to do BOTH halves,
which is what these tests pin:

  * refuse a method the vendor does not implement, with 501 and a message
    naming the controller type and the operation;
  * NOT get in the way of the vendor it is for -- a guard that blocked the
    happy path would be worse than the 500.

501 matches what controllers.py already returns for an operation a controller
type does not support (controllers.py:389, :2172, :2220, :2268).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase


def _svc() -> GatewayServiceBase:
    # The guard is pure: it needs no database, only the controller and client.
    return GatewayServiceBase(db=MagicMock())


def _ctrl(controller_type: str) -> MagicMock:
    c = MagicMock()
    c.controller_type = controller_type
    return c


def test_wrong_vendor_client_is_refused_with_501():
    """The live 500: a Proxmox client reached an Omada-only method."""

    class ProxmoxClient:
        async def get_nodes(self):  # pragma: no cover - never called
            return []

    with pytest.raises(HTTPException) as ei:
        _svc()._client_method(_ctrl("proxmox"), ProxmoxClient(), "get_top_talkers")

    assert ei.value.status_code == 501
    # The operator has to be able to act on this: which controller type, and
    # which operation. A bare "not supported" would not be actionable.
    assert "proxmox" in str(ei.value.detail)
    assert "get_top_talkers" in str(ei.value.detail)


def test_right_vendor_client_is_returned_unchanged():
    """The guard must not break the vendor it exists for."""
    sentinel = object()

    class OmadaClient:
        def get_top_talkers(self):
            return sentinel

    client = OmadaClient()
    method = _svc()._client_method(_ctrl("omada"), client, "get_top_talkers")

    assert method() is sentinel
    assert method.__self__ is client, "must return the BOUND method, not a copy"


def test_a_non_callable_attribute_does_not_pass_as_a_method():
    """`hasattr` alone is not enough.

    A client carrying a same-named data attribute would satisfy a plain
    `getattr` check and then blow up on the call instead -- the same 500, one
    line later.
    """

    class OddClient:
        get_top_talkers = "not callable"

    with pytest.raises(HTTPException) as ei:
        _svc()._client_method(_ctrl("omada"), OddClient(), "get_top_talkers")
    assert ei.value.status_code == 501


def test_a_method_valued_none_is_refused():
    """An unimplemented hook left as None must not be called."""

    class StubClient:
        get_top_talkers = None

    with pytest.raises(HTTPException) as ei:
        _svc()._client_method(_ctrl("omada"), StubClient(), "get_top_talkers")
    assert ei.value.status_code == 501


def test_no_module_dispatches_by_name_without_the_guard():
    """Ratchet over the WHOLE dispatch surface, not just the proven two.

    22 sites across 12 modules resolve a controller and then call
    `getattr(client, method_name)`. Every one of them is a 500 waiting for a
    controller id of the wrong vendor; fixing only the ones that happened to
    be probed would leave the class alive, and nothing else in the suite
    would notice a regression.

    Scanned as source rather than by import so a new file is covered the
    moment it is added.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2] / "app"
    assert root.is_dir(), f"expected the app package at {root}"

    offenders = []
    for path in sorted(root.rglob("*.py")):
        if path.name == "adapter_base.py":
            continue  # declares the guard; names the old pattern in its docstring
        text = path.read_text(encoding="utf-8", errors="replace")
        for num, line in enumerate(text.splitlines(), 1):
            if "getattr(client, method_name)" in line and "_client_method" not in line:
                offenders.append(f"{path.relative_to(root).as_posix()}:{num}")

    joined = chr(10).join("  " + o for o in offenders)
    assert not offenders, (
        "these dispatch by name without the vendor guard, so a controller of "
        "another vendor returns 500 instead of 501:" + chr(10) + joined
    )


def test_the_proven_dispatchers_still_use_the_guard():
    """The two endpoint dispatchers reproduced live must not regress."""
    import inspect

    from app.api.v1.endpoints import adapter_omada_diagnostics, adapter_omada_insights

    for mod in (adapter_omada_insights, adapter_omada_diagnostics):
        src = inspect.getsource(mod)
        assert "_client_method(ctrl, client, method_name)" in src, (
            f"{mod.__name__} must dispatch through _client_method so a "
            "controller of another vendor gets 501, not a 500"
        )


# ── the canonical guard: SUPPORTED_CONTROLLER_TYPE ──────────────────────────
#
# GatewayServiceBase._get_client already refuses a controller of the wrong
# vendor with a 400 naming both types, whenever the subclass declares which
# vendor it serves (adapter_base.py:546). 69 of 74 subclasses did. The three
# that did not are exactly the ones whose endpoints answered 500 on a live
# sweep, because a Proxmox client reached their name-based dispatch.
#
# Allow-listed rather than silently skipped, so a new vendor service cannot
# merge unclassified -- the same discipline as TENANT_EXEMPT in core/tenancy.py.

CONTROLLER_TYPE_EXEMPT = {
    # Applies staged ``overlay.*`` daemon VPN writes. Its docstring says "no
    # controller": it is deliberately controller-less, so pinning it to a
    # vendor would be wrong.
    "OverlayVPNApplierService",
}


def test_every_gateway_service_declares_the_vendor_it_serves():
    """Ratchet: no GatewayServiceBase subclass may be vendor-unclassified.

    Without SUPPORTED_CONTROLLER_TYPE a controller id of any vendor resolves,
    and whatever the service does next with that client is undefined -- in the
    observed cases, AttributeError as a bare 500.
    """
    import pathlib
    import re

    app = pathlib.Path(__file__).resolve().parents[2] / "app"
    assert app.is_dir(), f"expected the app package at {app}"

    missing = []
    for path in sorted(app.rglob("*.py")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"^class (\w+)\(([^)]*GatewayServiceBase[^)]*)\)", text, re.M):
            cls = m.group(1)
            if cls in CONTROLLER_TYPE_EXEMPT:
                continue
            nxt = text.find(chr(10) + "class ", m.end())
            body = text[m.end() : nxt if nxt > 0 else len(text)]
            if "SUPPORTED_CONTROLLER_TYPE" not in body:
                missing.append(f"{path.relative_to(app).as_posix()}::{cls}")

    joined = chr(10).join("  " + x for x in missing)
    assert not missing, (
        "these gateway services accept a controller of ANY vendor, so a "
        "mismatched id reaches the client and faults as a 500. Set "
        "SUPPORTED_CONTROLLER_TYPE, or add the class to CONTROLLER_TYPE_EXEMPT "
        "with a reason:" + chr(10) + joined
    )


def test_the_exempt_list_is_not_a_dumping_ground():
    """An exemption must name a class that still exists.

    A stale entry would silently exempt nothing while implying coverage.
    """
    import pathlib
    import re

    app = pathlib.Path(__file__).resolve().parents[2] / "app"
    declared = set()
    for path in app.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="replace")
        declared.update(re.findall(r"^class (\w+)\([^)]*GatewayServiceBase", text, re.M))

    stale = CONTROLLER_TYPE_EXEMPT - declared
    assert not stale, f"CONTROLLER_TYPE_EXEMPT names classes that no longer exist: {sorted(stale)}"
