# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Read-path boundaries and real service result contracts for Fabric operations."""

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.dialects import postgresql

from app.core.fabric.execution import OperationContext
from app.core.fabric.executor import OperationExecutor
from app.core.fabric.operations import Operation, OperationTier
from app.modules.firewall.module import _fabric_search_alerts_handler
from app.modules.network.module import _fabric_client_list_handler
from app.modules.network.service import NetworkClientService
from app.modules.storage.module import _fabric_storage_health_handler


def sql(statement):
    return str(statement.compile(dialect=postgresql.dialect()))


def context(grants=None):
    return OperationContext(uuid4(), {}, db=MagicMock(), accessible_site_ids=grants)


@pytest.mark.parametrize("scope", ["unrestricted", "limited", "empty"])
async def test_network_handler_preserves_explicit_invocation_scope(monkeypatch, scope):
    grants = None if scope == "unrestricted" else {uuid4()} if scope == "limited" else set()
    ctx = context(grants)
    ctx.params = {"site_id": str(uuid4()), "limit": 4}
    listing = AsyncMock(return_value=([], 0))
    monkeypatch.setattr(NetworkClientService, "list", listing)
    result = await _fabric_client_list_handler(ctx)
    assert result.success and result.output == {"total": 0, "clients": []}
    assert listing.await_args.kwargs.get("site_ids") == grants
    assert str(listing.await_args.kwargs["site_id"]) == ctx.params["site_id"]


@pytest.mark.parametrize("method", ["list", "get_stats"])
@pytest.mark.parametrize("filters", ["none", "site", "grants", "both"])
async def test_client_page_and_total_always_intersect_tenant_and_optional_site_filters(
    filters,
    method,
):
    org, site = uuid4(), uuid4()
    grants = {uuid4()} if filters in ["grants", "both"] else None
    requested = site if filters in ["site", "both"] else None
    db = MagicMock()
    db.scalar = AsyncMock(return_value=0)
    db.execute = AsyncMock(
        return_value=SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: []))
    )
    service = NetworkClientService(db)
    result = await getattr(service, method)(org, site_id=requested, site_ids=grants)
    if method == "list":
        assert result == ([], 0)
        statements = [db.scalar.await_args.args[0], db.execute.await_args.args[0]]
    else:
        assert result["total_clients"] == 0
        statements = [call.args[0] for call in db.scalar.await_args_list]
        assert len(statements) == 4
    for statement in statements:
        compiled = statement.compile(dialect=postgresql.dialect())
        values = list(compiled.params.values())
        assert "sites.organization_id =" in str(compiled) and org in values
        assert "sites.deleted_at IS NULL" in str(compiled)
        if requested is not None:
            assert "devices.site_id =" in str(compiled) and requested in values
        if grants is not None:
            assert any(
                isinstance(value, (list, set, tuple)) and set(value) == grants for value in values
            )


@pytest.mark.parametrize("scope", ["unrestricted", "limited", "empty"])
async def test_firewall_handler_unpacks_rows_and_passes_scope(monkeypatch, scope):
    grants = None if scope == "unrestricted" else {uuid4()} if scope == "limited" else set()
    ctx = context(grants)
    alert = SimpleNamespace(
        id=uuid4(),
        severity="critical",
        signature_name="Owned IDS alert",
        device_id=uuid4(),
        source_ip="192.0.2.1",
        dest_ip="192.0.2.2",
        is_acknowledged=False,
        timestamp=datetime.now(UTC),
    )
    search = AsyncMock(return_value=([alert], 25))
    factory = MagicMock(return_value=SimpleNamespace(search_alerts=search))
    monkeypatch.setattr("app.modules.firewall.service.FirewallService", factory)
    result = await _fabric_search_alerts_handler(ctx)
    assert result.success and result.output["count"] == 1
    assert result.output["alerts"][0]["id"] == str(alert.id)
    assert result.output["alerts"][0]["signature"] == alert.signature_name
    assert factory.call_args.kwargs.get("accessible_site_ids") == grants


async def test_empty_firewall_page_is_empty_not_two_placeholder_rows(monkeypatch):
    factory = MagicMock(return_value=SimpleNamespace(search_alerts=AsyncMock(return_value=([], 0))))
    monkeypatch.setattr("app.modules.firewall.service.FirewallService", factory)
    result = await _fabric_search_alerts_handler(context())
    assert result.success and result.output == {"count": 0, "alerts": []}


@pytest.mark.parametrize("scope", ["unrestricted", "limited", "empty"])
async def test_storage_query_excludes_deleted_sites_and_preserves_invocation_scope(
    scope,
):
    grants = None if scope == "unrestricted" else {uuid4()} if scope == "limited" else set()
    ctx = context(grants)
    ctx.db.execute = AsyncMock(
        return_value=SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: []))
    )
    result = await _fabric_storage_health_handler(ctx)
    assert result.success and result.output["count"] == 0
    statement = ctx.db.execute.await_args.args[0]
    assert "sites.deleted_at IS NULL" in sql(statement)
    if grants is not None:
        assert "controllers.site_id IN" in sql(statement)
        assert any(
            isinstance(value, (list, tuple, set)) and set(value) == grants
            for value in statement.compile().params.values()
        )


@pytest.mark.parametrize(
    "handler",
    [
        _fabric_client_list_handler,
        _fabric_search_alerts_handler,
        _fabric_storage_health_handler,
    ],
)
async def test_database_read_error_does_not_leak_connection_details(handler, monkeypatch):
    ctx = context()
    failure = RuntimeError("PRIVATE_DATABASE_URL_AND_PASSWORD")
    ctx.db.execute = AsyncMock(side_effect=failure)
    if handler is _fabric_client_list_handler:
        monkeypatch.setattr(NetworkClientService, "list", AsyncMock(side_effect=failure))
    elif handler is _fabric_search_alerts_handler:
        factory = MagicMock(
            return_value=SimpleNamespace(search_alerts=AsyncMock(side_effect=failure))
        )
        monkeypatch.setattr("app.modules.firewall.service.FirewallService", factory)
    op = Operation(
        id="owned.read",
        title="Owned",
        provider_id="owned",
        tier=OperationTier.NATIVE,
        handler=handler,
    )
    result = await OperationExecutor().execute(op, ctx)
    assert not result.success and result.error_code == "READ_ERROR"
    assert "PRIVATE_DATABASE_URL_AND_PASSWORD" not in result.error
