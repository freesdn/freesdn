# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
BodySizeLimitMiddleware: the global cap must not swallow the upload routes.

Background
----------
The middleware caps every request body at 1 MB, and its Content-Length
pre-check returns 413 before any handler runs. It had no path allow-list, so it
silently won over every upload route in the product:

    1 MB    global middleware          <- won
   50 MB    /backups/import
   64 MB    /setup/restore
    4 GB    Proxmox ISO upload

The worst consequence was `/setup/restore`, the first-install .fsdnvault
rebuild: it 413'd on any vault over 1 MB, at exactly the moment an operator has
lost their instance. The middleware docstring explains how it happened -- "1 MB
is generous for any single Omada config op" -- it was sized for JSON control
writes, and the upload routes were added behind it later.

These tests pin both halves: the cap still protects the control plane, and the
upload routes are allowed through to enforce their own precise limits.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.core.middleware import (
    _LARGE_BODY_MAX_BYTES,
    _LARGE_BODY_PATH_PREFIXES,
    BodySizeLimitMiddleware,
)

_CAP = 1_048_576


@pytest.fixture
def client() -> TestClient:
    """An app carrying only the middleware under test, echoing the byte count."""
    app = FastAPI()
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=_CAP)

    @app.post("/{full_path:path}")
    async def _echo(full_path: str, request: Request) -> dict:
        body = await request.body()
        return {"received": len(body)}

    return TestClient(app)


def _body(n: int) -> bytes:
    return b"x" * n


def test_control_plane_route_still_capped(client: TestClient) -> None:
    """The DoS backstop must survive: an oversize stage payload is still 413."""
    resp = client.post("/api/v1/changes/omada", content=_body(_CAP + 1))
    assert resp.status_code == 413, "the global cap must still protect control-plane writes"


def test_control_plane_route_accepts_under_cap(client: TestClient) -> None:
    resp = client.post("/api/v1/changes/omada", content=_body(2048))
    assert resp.status_code == 200
    assert resp.json()["received"] == 2048


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/setup/restore",
        "/api/v1/backups/import",
        "/api/v1/firmware/upload",
        "/api/v1/plugins/install",
        "/api/v1/plugins/acme-plugin/upgrade",
        "/api/v1/agents/releases",
        "/api/v1/data/imports",
        "/api/v1/hypervisor/storage/local/upload",
        "/api/v1/cameras/abc/recordings/export",
    ],
)
def test_upload_routes_accept_bodies_over_the_global_cap(client: TestClient, path: str) -> None:
    """
    Each upload route must get past the 1 MB global cap.

    This is the regression that mattered: before the allow-list every one of
    these returned 413 at 1 MB + 1 byte, regardless of the handler's own limit.
    """
    size = _CAP + 4096
    resp = client.post(path, content=_body(size))
    assert resp.status_code == 200, f"{path} was rejected by the global cap"
    assert resp.json()["received"] == size


def test_upload_routes_are_still_bounded(client: TestClient) -> None:
    """Raised ceiling, not removed: a body past the large cap is still refused."""
    resp = client.post(
        "/api/v1/setup/restore",
        headers={"content-length": str(_LARGE_BODY_MAX_BYTES + 1)},
        content=b"",
    )
    assert resp.status_code == 413


def test_allow_list_prefixes_are_absolute_api_paths() -> None:
    """
    A relative prefix would never match `request.url.path` and would fail open
    into the 1 MB cap again, silently.
    """
    for prefix in _LARGE_BODY_PATH_PREFIXES:
        assert prefix.startswith("/api/v1/"), f"{prefix!r} is not an absolute API path"
