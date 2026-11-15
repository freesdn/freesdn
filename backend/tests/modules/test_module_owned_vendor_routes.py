# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Disabling a module closes the vendor routes it owns, with a typed refusal.

``app/modules/enablement.py`` gated ``/api/v1/{module_id}/...``, but Proxmox,
FreePBX, TrueNAS, OPNsense and pfSense also have routers on the core API router
(``/api/v1/gateway-proxmox-vm/...`` and 41 more). Those carried no gate, so with
the hypervisor module disabled every Proxmox route still read and staged; the
same for VoIP and FreePBX, storage and TrueNAS, firewall and OPNsense/pfSense.

These tests drive real requests through the real ``api_router`` with only the
caller and the enablement row faked:

* every router whose prefix ``MODULE_OWNED_ROUTER_PREFIXES`` assigns to a
  module answers 403 with ``type: "module_disabled"`` and the module id, and is
  found by scanning the endpoint package, so a router added later is covered;
* a vendor router with no single owner (Omada, UniFi, MikroTik, OpenWrt) is not
  refused by the module gate;
* the ``/modules/`` router the UI uses to show a module as disabled, and to turn
  it back on, stays reachable.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
import uuid
from collections.abc import AsyncIterator
from types import SimpleNamespace

import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient

from app.core.dependencies import get_current_user_optional
from app.core.middleware import setup_exception_handlers
from app.db.session import get_session
from app.modules.enablement import (
    MODULE_OWNED_ROUTER_PREFIXES,
    module_enabled_dependency,
    module_owner_for_router_prefix,
)

ORG = uuid.uuid4()


class _Result:
    def __init__(self, value: bool | None) -> None:
        self._value = value

    def scalar_one_or_none(self) -> bool | None:
        return self._value


class _DisabledEverywhere:
    """A session whose enablement row says ``is_enabled=False`` for any module."""

    def __init__(self) -> None:
        self.queries = 0

    async def execute(self, _stmt: object) -> _Result:
        self.queries += 1
        return _Result(False)


def _app_with(router: APIRouter, session: _DisabledEverywhere, prefix: str = "") -> FastAPI:
    app = FastAPI()
    setup_exception_handlers(app)
    app.include_router(router, prefix=prefix)

    async def _session() -> AsyncIterator[_DisabledEverywhere]:
        yield session

    app.dependency_overrides[get_current_user_optional] = lambda: SimpleNamespace(
        organization_id=ORG
    )
    app.dependency_overrides[get_session] = _session
    return app


def _concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", str(uuid.uuid4()), path)


def _vendor_routers() -> dict[str, APIRouter]:
    """Every ``router`` defined in ``app.api.v1.endpoints``, by router prefix."""
    import app.api.v1.endpoints as pkg

    found: dict[str, APIRouter] = {}
    for info in pkgutil.iter_modules(pkg.__path__, pkg.__name__ + "."):
        module = importlib.import_module(info.name)
        router = getattr(module, "router", None)
        if isinstance(router, APIRouter) and router.prefix:
            found[router.prefix] = router
    return found


def _first_route(router: APIRouter) -> tuple[str, str]:
    for route in router.routes:
        if isinstance(route, APIRoute) and route.methods:
            return sorted(route.methods)[0], route.path
    raise AssertionError(f"router {router.prefix} has no routes")


def test_the_ownership_map_matches_whole_router_families() -> None:
    assert module_owner_for_router_prefix("/gateway-proxmox-vm") == "hypervisor"
    assert module_owner_for_router_prefix("/gateway-freepbx-extensions") == "voip"
    assert module_owner_for_router_prefix("/gateway-storage") == "storage"
    assert module_owner_for_router_prefix("/gateway-opnsense-firewall") == "firewall"
    assert module_owner_for_router_prefix("/gateway-pfsense-nat") == "firewall"
    # A shared prefix that is not followed by "-" is a different family.
    assert module_owner_for_router_prefix("/gateway-storagebox") is None
    for unowned in ("/gateway-vpn", "/gateway-unifi-devices", "/gateway-mikrotik-ip", None):
        assert module_owner_for_router_prefix(unowned) is None


async def test_every_module_owned_vendor_router_refuses_when_its_module_is_disabled() -> None:
    from app.api.v1 import api_router

    owned = {
        prefix: module_owner_for_router_prefix(prefix)
        for prefix in _vendor_routers()
        if module_owner_for_router_prefix(prefix)
    }
    by_module: dict[str, int] = {}
    for module_id in owned.values():
        by_module[module_id] = by_module.get(module_id, 0) + 1
    # Proxmox 12, FreePBX 6, TrueNAS 1, OPNsense 13 + pfSense 10 when written.
    # The floor keeps the scan from passing by finding nothing.
    assert set(by_module) == set(MODULE_OWNED_ROUTER_PREFIXES.values())
    assert sum(by_module.values()) >= 42, by_module

    session = _DisabledEverywhere()
    app = _app_with(api_router, session)
    routers = _vendor_routers()
    open_routes: list[str] = []
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        for prefix, module_id in sorted(owned.items()):
            method, path = _first_route(routers[prefix])
            resp = await client.request(method, _concrete(path), json={})
            error = resp.json().get("error") or {}
            if not (
                resp.status_code == 403
                and error.get("type") == "module_disabled"
                and error.get("module_id") == module_id
            ):
                open_routes.append(f"{method} {path} -> {resp.status_code} {error}")

    assert not open_routes, (
        "these vendor routes still answer while the module that owns them is disabled:\n"
        + "\n".join(open_routes)
    )
    assert session.queries >= len(owned)


async def test_vendor_routers_with_no_single_owner_are_not_refused_by_the_module_gate() -> None:
    from app.api.v1 import api_router

    routers = _vendor_routers()
    app = _app_with(api_router, _DisabledEverywhere())
    # The fake caller is only good enough for the module gate, so past it these
    # routes fail on their own auth dependency; all that matters is that the
    # module gate did not answer.
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        for prefix in ("/gateway-vpn", "/gateway-unifi-devices", "/gateway-mikrotik-ip"):
            method, path = _first_route(routers[prefix])
            resp = await client.request(method, _concrete(path), json={})
            assert "module_disabled" not in resp.text, (prefix, resp.status_code, resp.text)


async def test_the_refusal_names_the_module_in_a_typed_envelope() -> None:
    router = APIRouter()

    @router.get("/thing", dependencies=[Depends(module_enabled_dependency("cameras"))])
    async def _thing() -> dict[str, str]:
        return {"ok": "yes"}

    app = _app_with(router, _DisabledEverywhere())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get("/thing")

    assert resp.status_code == 403
    error = resp.json()["error"]
    assert error["type"] == "module_disabled"
    assert error["module_id"] == "cameras"
    assert "Settings > Modules" in error["message"]


async def test_the_module_status_router_stays_reachable_while_a_module_is_disabled() -> None:
    """The UI reads ``/modules/...`` to show "disabled" and to re-enable a module."""
    from app.modules.api import router as modules_router

    app = _app_with(modules_router, _DisabledEverywhere(), prefix="/api/v1")
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        for path in ("/api/v1/modules/states", "/api/v1/modules/cameras/health"):
            resp = await client.get(path)
            assert "module_disabled" not in resp.text, (path, resp.status_code, resp.text)


@pytest.mark.parametrize("module_id", sorted(set(MODULE_OWNED_ROUTER_PREFIXES.values())))
def test_every_owner_is_a_real_module(module_id: str) -> None:
    """A typo in the map would gate on a module id no row can ever disable."""
    from pathlib import Path

    import app.modules
    from app.modules.loader import EXCLUDED_MODULES

    # discover_modules() looks for exactly this file; checking it here avoids
    # re-executing every module.py a second time in the same process.
    assert (Path(app.modules.__file__).parent / module_id / "module.py").is_file()
    assert module_id not in EXCLUDED_MODULES
