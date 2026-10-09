# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Resolve metric labels without building FastAPI dependency/response models.

The pinned FastAPI stores included routers lazily. Expanding their effective
contexts just to name a request builds dependencies for unrelated endpoints on
the event loop. Read original route metadata instead; dispatch and dependency
validation remain entirely FastAPI's responsibility.
"""

from __future__ import annotations

import copy
from collections.abc import Iterator, Sequence
from functools import lru_cache
from re import Pattern
from typing import Any, Protocol, cast

from prometheus_fastapi_instrumentator import Instrumentator as BaseInstrumentator
from prometheus_fastapi_instrumentator.middleware import PrometheusInstrumentatorMiddleware
from starlette.applications import Starlette
from starlette.convertors import Convertor
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.routing import BaseRoute, Match, Mount, compile_path
from starlette.types import Scope


class _RouteMetadata(Protocol):
    path: str
    path_regex: Pattern[str]
    path_format: str
    param_convertors: dict[str, Convertor[Any]]


@lru_cache(maxsize=4096)
def _compiled_template(path: str) -> Any:
    # Only registered templates are cached, never request paths or identities.
    return compile_path(path)


def _metadata_routes(routes: Sequence[BaseRoute], prefix: str = "") -> Iterator[BaseRoute]:
    for route in routes:
        router = getattr(route, "original_router", None)
        context = getattr(route, "include_context", None)
        if router is not None and context is not None:
            yield from _metadata_routes(router.routes, prefix + context.prefix)
            continue
        path = getattr(route, "path", None)
        if prefix and isinstance(path, str):
            # A shallow metadata copy keeps Starlette's matching/converters and
            # the original method set (including FastAPI's HEAD behavior). It
            # constructs no APIRoute, dependency or response field.
            route = copy.copy(route)
            metadata = cast(_RouteMetadata, route)
            metadata.path = prefix + path
            pattern = metadata.path
            if isinstance(route, Mount):
                metadata.path = metadata.path.rstrip("/")
                pattern = metadata.path + "/{path:path}"
            metadata.path_regex, metadata.path_format, metadata.param_convertors = (
                _compiled_template(pattern)
            )
        yield route


def _route_name(scope: Scope, routes: Sequence[BaseRoute]) -> str | None:
    partial: str | None = None
    name: str | None
    for route in _metadata_routes(routes):
        match, child_scope = route.matches(scope)
        if match == Match.NONE:
            continue
        if isinstance(route, Mount):
            if route.routes:
                child = _route_name({**scope, **child_scope}, route.routes)
                if child is None:
                    continue
                name = route.path + child
            else:
                name = route.path
        else:
            name = getattr(route, "path", None)
            if not isinstance(name, str):
                continue
        if match == Match.FULL:
            return name
        if partial is None:
            partial = name
    return partial


def metric_route_name(request: Request, include_root_path: bool = False) -> str | None:
    """Read live route definitions, including dynamic registration/removal.

    No route-table cache requires plugin invalidation. Only compiled registered
    templates use a bounded cache. Unlike the upstream redirect fallback, slash
    redirects use the destination template, not a raw URL containing IDs. This
    deliberately keeps redirect labels bounded and free of tenant identifiers.
    """
    app = request.scope.get("app")
    routes = getattr(app, "routes", None)
    if not routes:
        return None
    name = _route_name(request.scope, routes)
    if name is None and getattr(getattr(app, "router", None), "redirect_slashes", False):
        path = request.scope.get("path", "")
        toggled = path[:-1] if path.endswith("/") else path + "/"
        if toggled and toggled != path:
            name = _route_name({**request.scope, "path": toggled}, routes)
    if name is None or not include_root_path:
        return name
    # A parent mount's scope root is intentionally not added for a separately
    # instrumented child app; only that application's configured root applies.
    root = getattr(app, "root_path", "") or ""
    return root.rstrip("/") + name if root else name


class MetadataMetricsMiddleware(PrometheusInstrumentatorMiddleware):
    def _get_handler(self, request: Request) -> tuple[str, bool]:
        name = metric_route_name(request, self.should_include_root_path)
        return (name, True) if name else (request.url.path, False)


class MetadataInstrumentator(BaseInstrumentator):
    """Keep upstream metric configuration, replacing only label resolution.

    Instrumentation is registered before the ASGI stack starts. Preserve every
    upstream middleware option and change only the newly registered class. No
    global patch or installed dependency change affects other applications.
    """

    def instrument(self, app: Starlette, *args: Any, **kwargs: Any) -> MetadataInstrumentator:
        previous = tuple(app.user_middleware)
        super().instrument(app, *args, **kwargs)
        for index, configured in enumerate(app.user_middleware):
            if cast(object, configured.cls) is PrometheusInstrumentatorMiddleware and not any(
                configured is old for old in previous
            ):
                app.user_middleware[index] = Middleware(
                    MetadataMetricsMiddleware,
                    *cast(tuple[Any, ...], configured.args),
                    **cast(dict[str, Any], configured.kwargs),
                )
        return self
