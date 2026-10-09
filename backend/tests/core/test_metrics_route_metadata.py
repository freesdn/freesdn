# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Cold label resolution and real ASGI metrics; no dispatch/auth substitution."""

from unittest.mock import patch

import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.routing import _IncludedRouter
from httpx import ASGITransport, AsyncClient
from prometheus_client import CollectorRegistry
from prometheus_fastapi_instrumentator import Instrumentator as UpstreamInstrumentator
from prometheus_fastapi_instrumentator.middleware import PrometheusInstrumentatorMiddleware
from prometheus_fastapi_instrumentator.routing import get_route_name
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from app.core import metrics as metrics_module


async def endpoint():
    return {"ok": True}


async def opaque_app(scope, receive, send):
    await Response("opaque")(scope, receive, send)


def request(app, path, method="GET", root_path=""):
    return Request({
        "type": "http", "app": app, "path": path, "raw_path": path.encode(),
        "method": method, "root_path": root_path, "scheme": "http",
        "query_string": b"", "headers": [], "server": ("test", 80),
    })


def instrumentation(app, *, build_handler=True, **options):
    registry = CollectorRegistry()
    instrumentator = metrics_module.Instrumentator(registry=registry, **options)
    instrumentator.instrument(app)
    configured = app.user_middleware[0]
    assert issubclass(configured.cls, PrometheusInstrumentatorMiddleware)
    return (configured.cls(opaque_app, *configured.args, **configured.kwargs)
            if build_handler else None), registry


def routed_app():
    app = FastAPI()
    leaf = APIRouter(prefix="/leaf")
    leaf.add_api_route("/items/{item_id:int}", endpoint, methods=["GET"])
    leaf.add_api_route("/items/{item_id:int}", endpoint, methods=["POST"])
    leaf.add_api_route("/files/{tail:path}", endpoint, methods=["GET"])
    leaf.add_api_route("/hidden", endpoint, include_in_schema=False)
    parent = APIRouter(prefix="/parent")
    parent.include_router(leaf, prefix="/nested")
    app.include_router(parent, prefix="/api")
    child = FastAPI()
    child.add_api_route("/objects/{object_id}", endpoint)
    app.mount("/mounted", child)
    app.mount("/opaque", opaque_app)
    app.router.routes.append(Route("/star/{item_id:int}", endpoint, methods=["GET"]))
    app.add_api_websocket_route("/ws", endpoint)
    return app


@pytest.mark.parametrize(("path", "method", "expected"), [
    ("/api/parent/nested/leaf/items/3", "GET", "/api/parent/nested/leaf/items/{item_id:int}"),
    ("/api/parent/nested/leaf/items/3", "POST", "/api/parent/nested/leaf/items/{item_id:int}"),
    ("/api/parent/nested/leaf/items/3", "DELETE", "/api/parent/nested/leaf/items/{item_id:int}"),
    ("/api/parent/nested/leaf/items/3", "HEAD", "/api/parent/nested/leaf/items/{item_id:int}"),
    ("/api/parent/nested/leaf/items/3", "OPTIONS", "/api/parent/nested/leaf/items/{item_id:int}"),
    ("/api/parent/nested/leaf/items/no", "GET", None),
    ("/api/parent/nested/leaf/files/a/b", "GET", "/api/parent/nested/leaf/files/{tail:path}"),
    ("/api/parent/nested/leaf/hidden", "GET", "/api/parent/nested/leaf/hidden"),
    ("/mounted/objects/secret", "GET", "/mounted/objects/{object_id}"),
    ("/mounted/missing", "GET", None),
    ("/opaque/secret/child", "GET", "/opaque"),
    ("/star/2", "GET", "/star/{item_id:int}"),
    ("/star/2", "HEAD", "/star/{item_id:int}"),
    ("/ws", "GET", None),
    ("/missing-secret", "GET", None),
])
def test_registered_templates_keep_upstream_semantics(path, method, expected):
    app = routed_app()
    middleware, _ = instrumentation(app)
    req = request(app, path, method)
    actual = middleware._get_handler(req)
    assert actual == (expected or path, expected is not None)
    assert get_route_name(req, False) == expected


@pytest.mark.parametrize(("app_root", "scope_root", "include_root", "expected"), [
    ("/proxy", "/proxy", False, "/items/{item_id}"),
    ("/proxy", "/proxy", True, "/proxy/items/{item_id}"),
    ("", "/parent-mount", False, "/items/{item_id}"),
    ("", "/parent-mount", True, "/items/{item_id}"),
])
def test_configured_root_and_parent_mount_root(app_root, scope_root, include_root, expected):
    app = FastAPI(root_path=app_root)
    app.add_api_route("/items/{item_id}", endpoint)
    middleware, _ = instrumentation(app, should_include_root_path=include_root)
    req = request(app, scope_root + "/items/tenant-id", root_path=scope_root)
    assert middleware._get_handler(req) == (expected, True)
    assert get_route_name(req, include_root) == expected


@pytest.mark.parametrize(("registered", "path", "root", "expected"), [
    ("/items/{item_id}/", "/items/private-id", "", "/items/{item_id}/"),
    ("/items/{item_id}", "/items/private-id/", "", "/items/{item_id}"),
    ("/items/{item_id}/", "/proxy/items/private-id", "/proxy", "/proxy/items/{item_id}/"),
    ("/items/{item_id}", "/proxy/items/private-id/", "/proxy", "/proxy/items/{item_id}"),
])
def test_redirect_labels_use_registered_template_not_private_url(registered, path, root, expected):
    app = FastAPI(root_path=root)
    app.add_api_route(registered, endpoint)
    middleware, _ = instrumentation(app, should_include_root_path=True)
    assert middleware._get_handler(request(app, path, root_path=root)) == (expected, True)
    assert "private-id" not in expected


def test_disabled_slash_redirect_does_not_invent_a_template():
    app = FastAPI(redirect_slashes=False)
    app.add_api_route("/items/{item_id}/", endpoint)
    middleware, _ = instrumentation(app)
    assert middleware._get_handler(request(app, "/items/private-id")) == ("/items/private-id", False)


def test_later_full_match_wins_over_earlier_method_partial():
    app = FastAPI()
    first = APIRouter()
    first.add_api_route("/thing/{value}", endpoint, methods=["POST"])
    app.include_router(first)
    app.add_api_route("/thing/specific", endpoint, methods=["GET"])
    middleware, _ = instrumentation(app)
    req = request(app, "/thing/specific")
    assert middleware._get_handler(req) == ("/thing/specific", True)
    assert get_route_name(req, False) == "/thing/specific"


def test_included_mount_prefix_and_nested_parameter_are_preserved():
    app = FastAPI()
    nested = FastAPI()
    nested.add_api_route("/items/{item_id}", endpoint)
    router = APIRouter(prefix="/original")
    router.routes.append(Mount(router.prefix + "/tenant/{tenant_id}", app=nested))
    app.include_router(router, prefix="/api")
    middleware, _ = instrumentation(app)
    req = request(app, "/api/original/tenant/secret/items/private")
    expected = "/api/original/tenant/{tenant_id}/items/{item_id}"
    assert middleware._get_handler(req) == (expected, True)
    assert get_route_name(req, False) == expected


def test_live_registration_removal_and_template_replacement_need_no_request_cache():
    app = FastAPI()
    router = APIRouter()
    app.include_router(router, prefix="/plugin")
    middleware, _ = instrumentation(app)
    req = request(app, "/plugin/private")
    assert middleware._get_handler(req) == ("/plugin/private", False)
    router.add_api_route("/{first}", endpoint)
    assert middleware._get_handler(req) == ("/plugin/{first}", True)
    router.routes.clear()
    router._mark_routes_changed()
    assert middleware._get_handler(req) == ("/plugin/private", False)
    router.add_api_route("/{second}", endpoint)
    assert middleware._get_handler(req) == ("/plugin/{second}", True)


def test_cold_lookup_builds_no_effective_dependencies_for_unrelated_routes(record_property):
    app = FastAPI()
    for group in range(12):
        router = APIRouter()
        for item in range(12):
            router.add_api_route(f"/route-{item}/{{value}}", endpoint)
        app.include_router(router, prefix=f"/group-{group}")
    middleware, _ = instrumentation(app)
    with patch.object(_IncludedRouter, "_build_effective_context", autospec=True,
                      side_effect=_IncludedRouter._build_effective_context) as spy:
        observed = middleware._get_handler(request(app, "/group-0/route-0/private"))
    record_property("effective_context_constructions", spy.call_count)
    assert observed == ("/group-0/route-0/{value}", True)
    assert spy.call_count == 0


def test_complete_application_cold_label_lookup_does_not_expand_dependencies(record_property):
    from app.main import create_application

    with patch.object(metrics_module.settings, "ENABLE_METRICS", True):
        app = create_application()
        # create_application normally configures this already. Reuse the actual
        # registered configuration; no warm request or OpenAPI generation.
        configured = next(c for c in app.user_middleware
                          if issubclass(c.cls, PrometheusInstrumentatorMiddleware))
    middleware = configured.cls(opaque_app, *configured.args, **configured.kwargs)
    with patch.object(_IncludedRouter, "_build_effective_context", autospec=True,
                      side_effect=_IncludedRouter._build_effective_context) as spy:
        observed = middleware._get_handler(request(app, "/api/v1/agents/releases"))
    record_property("complete_application_effective_context_constructions", spy.call_count)
    assert observed == ("/api/v1/agents/releases", True)
    assert spy.call_count == 0


@pytest.mark.asyncio
async def test_actual_http_dependencies_counters_status_and_exclusions():
    app = FastAPI()
    calls = []

    async def authenticate():
        calls.append("dependency")
        return "real-dependency"

    async def protected(item_id: int, principal=Depends(authenticate)):
        assert principal == "real-dependency"
        return JSONResponse({"id": item_id}, status_code=201)

    router = APIRouter()
    router.add_api_route("/items/{item_id}", protected)
    app.include_router(router, prefix="/api")
    app.add_api_route("/health", endpoint)
    _, registry = instrumentation(app, build_handler=False, should_ignore_untemplated=True,
                                  should_group_status_codes=True, excluded_handlers=["/health"])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get("/api/items/3")).status_code == 201
        assert (await client.post("/api/items/3")).status_code == 405
        assert (await client.get("/health")).status_code == 200
        assert (await client.get("/unknown-sensitive-id")).status_code == 404
    assert calls == ["dependency"]
    samples = [s for metric in registry.collect() for s in metric.samples
               if s.name == "http_requests_total"]
    assert {(s.labels["handler"], s.labels["method"], s.labels["status"], s.value)
            for s in samples} == {("/api/items/{item_id}", "GET", "2xx", 1),
                                  ("/api/items/{item_id}", "POST", "4xx", 1)}


def test_upstream_middleware_configuration_is_preserved_without_global_patch():
    left, right = FastAPI(), FastAPI()
    options = {"should_group_status_codes": False, "should_ignore_untemplated": True,
               "should_include_root_path": True, "should_round_latency_decimals": True,
               "round_latency_decimals": 3, "excluded_handlers": ["/health"], "body_handlers": ["/safe"],
               "inprogress_name": "configured_progress", "inprogress_labels": True}
    registry = CollectorRegistry()
    metrics_module.Instrumentator(registry=registry, **options).instrument(
        left, metric_namespace="freesdn", metric_subsystem="requests")
    UpstreamInstrumentator(registry=registry, **options).instrument(
        right, metric_namespace="freesdn", metric_subsystem="requests")
    assert left.user_middleware[0].kwargs == right.user_middleware[0].kwargs
    assert right.user_middleware[0].cls is PrometheusInstrumentatorMiddleware


def test_environment_disabled_instrumentation_registers_nothing(monkeypatch):
    monkeypatch.setenv("FREESDN_METRICS_TEST_ENABLE", "false")
    app = FastAPI()
    metrics_module.Instrumentator(should_respect_env_var=True,
                                 env_var_name="FREESDN_METRICS_TEST_ENABLE").instrument(app)
    assert app.user_middleware == []
