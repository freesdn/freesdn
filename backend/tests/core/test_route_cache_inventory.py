# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Slash aliases must work without compiling every response schema on first use."""

from unittest.mock import Mock

import httpx
import pytest
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Request

from app.core import middleware
from app.core.middleware import TrailingSlashNormalizeMiddleware


@pytest.fixture
async def routed(monkeypatch):
    monkeypatch.setattr(middleware, "_ROUTE_EPOCH", middleware._ROUTE_EPOCH)
    app = FastAPI(redirect_slashes=False)
    app.add_middleware(TrailingSlashNormalizeMiddleware)
    inner = APIRouter(prefix="/inner")

    async def authorized(x_fixture_token: str | None = Header(default=None)):
        if x_fixture_token != "owned-fixture":
            raise HTTPException(status_code=401)

    @inner.get("/items/", dependencies=[Depends(authorized)])
    async def items(request: Request, value: str = ""):
        return {"path": request.scope["path"], "value": value}

    @inner.post("/items/", dependencies=[Depends(authorized)])
    async def create(request: Request, payload: dict):
        return {
            "path": request.scope["path"],
            "raw_path": request.scope["raw_path"].decode(),
            "payload": payload,
        }

    @inner.get("/status")
    async def status():
        return {"status": "ok"}

    @inner.get("/hidden/", include_in_schema=False)
    async def hidden():
        return {"hidden": True}

    @inner.get("/item/{item_id}")
    async def item(item_id: str):
        return {"id": item_id}

    middle = APIRouter(prefix="/middle")
    middle.include_router(inner, prefix="/nested")
    app.include_router(middle, prefix="/api/v1")
    app.include_router(inner, prefix="/second")
    app.include_router(inner, prefix="/undocumented", include_in_schema=False)
    # Real HTTP behavior must not depend on generating documentation.
    schema = Mock(side_effect=AssertionError("OpenAPI must stay off the request path"))
    app.openapi = schema
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="http://test", follow_redirects=False
    ) as client:
        yield app, client, schema


@pytest.mark.parametrize("prefix", ["/api/v1/middle/nested/inner", "/second/inner"])
async def test_nested_static_alias_does_not_generate_openapi(routed, prefix):
    _, client, schema = routed
    response = await client.get(
        prefix + "/items?value=a%2Fb", headers={"X-Fixture-Token": "owned-fixture"}
    )
    assert response.status_code == 200
    assert response.json() == {"path": prefix + "/items/", "value": "a/b"}
    assert "location" not in response.headers
    schema.assert_not_called()


async def test_canonical_and_slash_added_requests_keep_schema_lazy(routed):
    _, client, schema = routed
    for path in ["/second/inner/status", "/second/inner/status/"]:
        response = await client.get(path)
        assert response.status_code == 200 and response.json() == {"status": "ok"}
    schema.assert_not_called()


async def test_post_alias_preserves_body_raw_path_and_authorization(routed):
    _, client, schema = routed
    path = "/second/inner/items"
    denied = await client.post(path, json={"value": "owned"})
    assert denied.status_code == 401
    response = await client.post(
        path, json={"value": "owned"}, headers={"X-Fixture-Token": "owned-fixture"}
    )
    assert response.status_code == 200
    assert response.json() == {
        "path": path + "/",
        "raw_path": path + "/",
        "payload": {"value": "owned"},
    }
    assert (await client.delete(path)).status_code == 405
    schema.assert_not_called()


async def test_plugin_registration_refreshes_aliases_without_building_schema(routed):
    app, client, schema = routed
    assert (await client.get("/second/inner/status")).status_code == 200
    app.openapi_schema = {"paths": {"/stale": {}}}
    plugin = APIRouter()

    @plugin.get("/")
    async def plugin_root():
        return {"plugin": "owned"}

    app.include_router(plugin, prefix="/api/v1/plugins/owned")
    middleware.invalidate_route_cache()
    response = await client.get("/api/v1/plugins/owned")
    assert response.status_code == 200 and response.json() == {"plugin": "owned"}
    assert app.openapi_schema is None
    schema.assert_not_called()


@pytest.mark.parametrize("path", ["/second/inner/hidden", "/undocumented/inner/items"])
async def test_schema_hidden_routes_keep_the_existing_no_alias_boundary(routed, path):
    _, client, schema = routed
    assert (await client.get(path)).status_code == 404
    assert (
        await client.get(path + "/", headers={"X-Fixture-Token": "owned-fixture"})
    ).status_code == 200
    schema.assert_not_called()


async def test_dynamic_routes_and_unknown_paths_are_not_invented(routed):
    _, client, schema = routed
    assert (await client.get("/second/inner/item/owned")).json() == {"id": "owned"}
    assert (await client.get("/second/inner/item/owned/")).status_code == 404
    assert (await client.get("/second/inner/missing")).status_code == 404
    schema.assert_not_called()


def test_complete_application_static_inventory_matches_openapi():
    # A FastAPI upgrade changing included-router representation must fail this
    # contract instead of silently hiding every application's slash aliases.
    from app.main import app

    previous = app.openapi_schema
    try:
        app.openapi_schema = None
        expected = {path for path in app.openapi()["paths"] if "{" not in path}
        actual = set(TrailingSlashNormalizeMiddleware._static_route_paths(app.routes))
        assert expected and actual == expected
    finally:
        app.openapi_schema = previous
