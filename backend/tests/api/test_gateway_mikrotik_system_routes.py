# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the MikroTik system routes + cache + role gates.

Focus: the route surface exists and is gated correctly. Live RouterOS
calls are mocked at the service layer so these tests run without a
real controller.
"""

from __future__ import annotations

import time
from uuid import uuid4

import pytest

# ─── Route surface — every GET is registered ─────────────────


@pytest.mark.parametrize(
    "path_template",
    [
        "/api/v1/gateway-mikrotik-system/{cid}/firmware/status",
        "/api/v1/gateway-mikrotik-system/{cid}/packages",
        "/api/v1/gateway-mikrotik-system/{cid}/backup/list",
        "/api/v1/gateway-mikrotik-system/{cid}/backup/metadata/{name}",
        "/api/v1/gateway-mikrotik-system/{cid}/backup/download/{name}",
        "/api/v1/gateway-mikrotik-system/{cid}/neighbors",
        "/api/v1/gateway-mikrotik-system/{cid}/neighbors/settings",
        "/api/v1/gateway-mikrotik-system/{cid}/lldp",
        "/api/v1/gateway-mikrotik-system/{cid}/topology",
    ],
)
def test_route_exists(path_template: str) -> None:
    from app.main import app

    # fastapi 0.137+ wraps each included router in an opaque _IncludedRouter
    # (its .routes is empty), so iterating app.routes no longer surfaces API
    # paths — the OpenAPI schema is fastapi's canonical full-path inventory.
    paths = set(app.openapi().get("paths", {}))
    cid = "{controller_id}"
    name = "{name}"
    expected = path_template.format(cid=cid, name=name)
    # FastAPI stores paths with the underlying parameter name; the
    # template-substitute above mirrors the same shape.
    assert expected in paths, (
        f"expected {expected!r} to be a registered route; got "
        f"{[p for p in paths if 'mikrotik-system' in (p or '')][:5]}"
    )


# ─── Cache behaviour (PERF-CRIT-4) ──────────────────────────────────


@pytest.mark.asyncio
async def test_paginate_caches_full_list_30s(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Second call within the TTL window must NOT re-invoke fetch."""
    from app.api.v1.endpoints import adapter_mikrotik_system as ep

    # Clear any state from earlier tests.
    ep._paginate_cache.clear()

    org_id = uuid4()
    ctrl_id = uuid4()
    call_count = {"n": 0}

    async def _fetch() -> dict:
        call_count["n"] += 1
        return {"items": list(range(100)), "controller_id": str(ctrl_id)}

    first = await ep._paginate_cached(
        organization_id=org_id,
        controller_id=ctrl_id,
        endpoint_key="logs",
        query_hash="",
        fetch=_fetch,
        limit=10,
        offset=0,
    )
    second = await ep._paginate_cached(
        organization_id=org_id,
        controller_id=ctrl_id,
        endpoint_key="logs",
        query_hash="",
        fetch=_fetch,
        limit=10,
        offset=10,
    )
    assert call_count["n"] == 1, "second call should hit cache, not refetch"
    assert first["items"] == list(range(10))
    assert second["items"] == list(range(10, 20))
    # Same total — cache holds the full upstream response.
    assert first["total"] == second["total"] == 100


@pytest.mark.asyncio
async def test_paginate_invalidates_after_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After TTL expiry the next request refetches transparently."""
    from app.api.v1.endpoints import adapter_mikrotik_system as ep

    ep._paginate_cache.clear()
    org_id = uuid4()
    ctrl_id = uuid4()
    call_count = {"n": 0}

    async def _fetch() -> dict:
        call_count["n"] += 1
        return {"items": [call_count["n"]], "controller_id": str(ctrl_id)}

    # Force a very short TTL for the test — patch the constant in place
    # and reset after.
    monkeypatch.setattr(ep, "_PAGINATE_CACHE_TTL", 0.0)
    await ep._paginate_cached(
        organization_id=org_id,
        controller_id=ctrl_id,
        endpoint_key="logs",
        query_hash="",
        fetch=_fetch,
        limit=10,
        offset=0,
    )
    # Sleep a tick so monotonic time advances past the 0-TTL window.
    time.sleep(0.01)
    await ep._paginate_cached(
        organization_id=org_id,
        controller_id=ctrl_id,
        endpoint_key="logs",
        query_hash="",
        fetch=_fetch,
        limit=10,
        offset=0,
    )
    assert call_count["n"] == 2, "post-TTL miss should refetch"


@pytest.mark.asyncio
async def test_paginate_invalidate_drops_controller_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.api.v1.endpoints import adapter_mikrotik_system as ep

    ep._paginate_cache.clear()
    org_id = uuid4()
    ctrl_a = uuid4()
    ctrl_b = uuid4()

    async def _fetch() -> dict:
        return {"items": [1, 2, 3]}

    # Populate cache for two controllers.
    await ep._paginate_cached(
        organization_id=org_id, controller_id=ctrl_a,
        endpoint_key="logs", query_hash="",
        fetch=_fetch, limit=10, offset=0,
    )
    await ep._paginate_cached(
        organization_id=org_id, controller_id=ctrl_b,
        endpoint_key="logs", query_hash="",
        fetch=_fetch, limit=10, offset=0,
    )
    assert len(ep._paginate_cache) == 2

    # Invalidate ctrl_a only.
    ep._invalidate_paginate_cache(org_id, ctrl_a)
    remaining = list(ep._paginate_cache.keys())
    assert len(remaining) == 1
    assert remaining[0][1] == str(ctrl_b), (
        "controller B's cache should survive invalidation of A"
    )


@pytest.mark.asyncio
async def test_paginate_cache_evicts_oldest_when_full(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the bounded cache reaches max size, oldest entries get
    evicted to make room. No unbounded growth."""
    from app.api.v1.endpoints import adapter_mikrotik_system as ep

    ep._paginate_cache.clear()
    monkeypatch.setattr(ep, "_PAGINATE_CACHE_MAX", 8)
    org_id = uuid4()

    async def _fetch() -> dict:
        return {"items": [1]}

    # Fill cache past the cap.
    for i in range(12):
        await ep._paginate_cached(
            organization_id=org_id,
            controller_id=uuid4(),
            endpoint_key="logs",
            query_hash=str(i),
            fetch=_fetch,
            limit=10,
            offset=0,
        )

    # Cache size must remain ≤ cap (with 25% headroom from the eviction).
    assert len(ep._paginate_cache) <= ep._PAGINATE_CACHE_MAX


# ─── Stage-gate role checks ────────────────


def test_catastrophic_system_features_listed() -> None:
    """The catastrophic frozenset must include the additions
    so they get the site_admin role gate at stage time."""
    from app.api.v1.endpoints.adapter_mikrotik_system import (
        _CATASTROPHIC_SYSTEM_FEATURES,
    )

    expected = {
        "mikrotik.system.reboot",
        "mikrotik.system.shutdown",
        "mikrotik.system.backup_load",
        "mikrotik.system.tool_fetch",
        "mikrotik.system.export_config",
        "mikrotik.system.firmware.install",
        "mikrotik.system.package.uninstall",
        "mikrotik.system.backup.restore",
    }
    assert expected.issubset(_CATASTROPHIC_SYSTEM_FEATURES)


def test_controller_tier_system_features_listed() -> None:
    """The controller-tier frozenset must include additions so
    stage requires controller:write, not just network:write."""
    from app.api.v1.endpoints.adapter_mikrotik_system import (
        _CONTROLLER_TIER_SYSTEM_FEATURES,
    )

    expected = {
        "mikrotik.system.firmware.install",
        "mikrotik.system.package.uninstall",
        "mikrotik.system.backup.restore",
    }
    assert expected.issubset(_CONTROLLER_TIER_SYSTEM_FEATURES)


# ─── Apply dispatch table covers features ────────────────────


def test_apply_table_covers_round3_features() -> None:
    """Every new feature must have an entry in the
    GatewayMikrotikSystemService _APPLY table or the dispatcher will
    reject it with a 400 at apply time."""
    from app.services.adapter_mikrotik_system import _APPLY

    required = [
        ("mikrotik.system.firmware.check", "create"),
        ("mikrotik.system.firmware.channel", "update"),
        ("mikrotik.system.firmware.download", "create"),
        ("mikrotik.system.firmware.install", "create"),
        ("mikrotik.system.firmware.cancel", "create"),
        ("mikrotik.system.package.enable", "update"),
        ("mikrotik.system.package.disable", "update"),
        ("mikrotik.system.package.uninstall", "delete"),
        ("mikrotik.system.backup.create_binary", "create"),
        ("mikrotik.system.backup.export_text", "create"),
        ("mikrotik.system.backup.upload", "create"),
        ("mikrotik.system.backup.delete", "delete"),
        ("mikrotik.system.backup.restore", "create"),
        ("mikrotik.system.neighbor.settings", "update"),
    ]
    for key in required:
        assert key in _APPLY, f"applier table missing entry for {key!r}"
