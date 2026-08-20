# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A firewall rule the device refused must not come back as HTTP 200.

Background
----------
``GatewayService._write_result`` exists specifically to stop this. Its own
docstring says so::

    A failed write raises (via the central mapper) so it surfaces the right
    HTTP status (read-only->403, not-found->404, timeout->504, generic->502)
    instead of HTTP 200 with success:false ... Single chokepoint for every
    gateway write endpoint.

It is used at 58 call sites. Two writes bypassed it -- ``push_firewall_rule``
and ``delete_vendor_rule`` -- and returned exactly the shape the chokepoint was
built to eliminate: HTTP 200 carrying ``{"success": false}``.

Those two are not an obscure corner. They are the live firewall rule push and
delete on the Gateway page, i.e. the highest-consequence write the firewall
module performs. A rule OPNsense/pfSense/MikroTik rejected -- or refused because
ADAPTER_READ_ONLY is engaged, which the dev compose sets by default -- resolved
as a successful mutation, so the caller had to inspect the body to notice, and
the operator believed a rule was in place that was not.

Both now call ``raise_for_adapter_result`` before building their response. The
response SHAPE is unchanged, because GatewayRulePushResponse needs
``vendor_rule_id`` / ``applied``, which ``_write_result`` does not produce.
"""

from __future__ import annotations

import inspect
import uuid
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from app.adapters.base import AdapterResult
from app.adapters.exceptions import AdapterError
from app.modules.firewall.gateway_service import GatewayService


def _service(result: AdapterResult) -> GatewayService:
    """A GatewayService whose adapter returns the given result for both writes."""
    svc = GatewayService.__new__(GatewayService)

    adapter = SimpleNamespace(
        create_firewall_rule=lambda _payload: _async(result),
        delete_firewall_rule=lambda _vendor_id: _async(result),
    )
    gateway = SimpleNamespace(id=uuid.uuid4(), vendor="opnsense")

    @asynccontextmanager
    async def _ctx(*_a, **_kw):
        yield (gateway, adapter)

    async def _adapter_for(*_a, **_kw):
        return _ctx()

    svc._adapter_for = _adapter_for  # type: ignore[method-assign]
    svc._translate_rule_to_vendor = lambda _vendor, rule: rule  # type: ignore[method-assign]
    svc._extract_vendor_rule_id = lambda _vendor, _result: "vendor-1"  # type: ignore[method-assign]
    return svc


async def _async(value):
    return value


# ── The regression ───────────────────────────────────────────────


async def test_refused_push_raises_instead_of_returning_success_false() -> None:
    """
    raise_for_adapter_result maps an uncoded device failure to AdapterError,
    which the app's exception handler turns into HTTP 502. What matters here is
    that it RAISES rather than returning a 200 body with success:false.
    """
    svc = _service(AdapterResult.fail("the firewall rejected the rule"))

    with pytest.raises(AdapterError):
        await svc.push_firewall_rule(uuid.uuid4(), uuid.uuid4(), {"action": "pass"})


async def test_refused_delete_raises_instead_of_returning_success_false() -> None:
    svc = _service(AdapterResult.fail("no such rule on the device"))

    with pytest.raises(AdapterError):
        await svc.delete_vendor_rule(uuid.uuid4(), uuid.uuid4(), "vendor-1")


async def test_read_only_refusal_is_not_reported_as_a_successful_push() -> None:
    """
    The dev compose sets ADAPTER_READ_ONLY, so this is the refusal an operator
    is most likely to hit -- and the one most likely to be mistaken for success.
    """
    svc = _service(AdapterResult.fail("ADAPTER_READ_ONLY is set", error_code="READ_ONLY"))
    with pytest.raises(Exception) as exc:
        await svc.push_firewall_rule(uuid.uuid4(), uuid.uuid4(), {"action": "pass"})
    assert "READ_ONLY" in str(exc.value) or "read" in str(exc.value).lower()


# ── The success path, and its response shape ─────────────────────


async def test_successful_push_keeps_its_response_shape() -> None:
    """
    GatewayRulePushResponse needs vendor_rule_id and applied, which is why these
    methods build their body by hand instead of delegating to _write_result.
    Changing that shape would break the endpoint's response model.
    """
    svc = _service(AdapterResult.ok({"uuid": "abc"}, message="Rule pushed"))

    out = await svc.push_firewall_rule(uuid.uuid4(), uuid.uuid4(), {"action": "pass"})

    assert out["success"] is True
    assert out["applied"] is True
    assert out["vendor_rule_id"] == "vendor-1"
    assert "message" in out


async def test_successful_delete_keeps_its_response_shape() -> None:
    svc = _service(AdapterResult.ok(None, message="Rule deleted"))

    out = await svc.delete_vendor_rule(uuid.uuid4(), uuid.uuid4(), "vendor-1")

    assert out["success"] is True
    assert out["message"] == "Rule deleted"


# ── Nothing may bypass the chokepoint again ──────────────────────


def test_no_gateway_write_returns_success_false_at_http_200() -> None:
    """
    Guard the class, not just these two. Any method that builds a response dict
    from ``result.success`` must first have raised on failure -- otherwise it is
    another HTTP-200-with-success-false in waiting.
    """
    src = inspect.getsource(GatewayService)
    builders = src.count('"success": result.success')
    raisers = src.count("raise_for_adapter_result(result)")
    assert raisers >= builders, (
        f"{builders} response(s) built from result.success but only {raisers} "
        "raise_for_adapter_result call(s); a gateway write is reporting a "
        "refused device write as HTTP 200 again"
    )
