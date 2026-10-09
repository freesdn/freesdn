"""Bulk hardware requests must never succeed as inventory-only edits."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints import switches


@pytest.mark.parametrize(
    "updates",
    [
        {"enabled": False},
        {"poe_config": {"enabled": False}},
        {"name": "new label", "speed": "100"},
        {"mtu": 9000},
    ],
)
async def test_hardware_fields_fail_before_any_database_change(monkeypatch, updates):
    port = SimpleNamespace(name="original", is_enabled=True, is_poe_enabled=True)
    result = MagicMock()
    result.scalars.return_value.all.return_value = [port]
    session = SimpleNamespace(execute=AsyncMock(return_value=result), commit=AsyncMock())
    monkeypatch.setattr(switches, "_get_switch", AsyncMock())
    monkeypatch.setattr(switches, "_org_id", lambda _user: uuid4())
    monkeypatch.setattr(switches, "_port_to_out", lambda _port: {})
    request = switches.BulkPortUpdateIn(port_ids=[str(uuid4())], updates=updates)
    with pytest.raises(HTTPException) as error:
        await switches.bulk_update_ports(str(uuid4()), request, session, object())
    assert error.value.status_code == 422
    assert port.name == "original" and port.is_enabled and port.is_poe_enabled
    session.execute.assert_not_called()
    session.commit.assert_not_called()
