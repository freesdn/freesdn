"""Real log REST routes and service, with synthetic user and adapter results."""

from contextlib import asynccontextmanager
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.adapters.base import AdapterResult
from app.core.dependencies import CurrentUser, get_current_active_user
from app.modules.firewall.gateway_api import get_gateway_service, router
from app.modules.firewall.gateway_service import GatewayService


async def request_logs(result, kind, limit=50):
    gateway = SimpleNamespace(id=uuid4(), vendor="opnsense")
    service = GatewayService(db=None)

    class Adapter:
        async def get_system_log(self, limit):
            return result

        async def get_firewall_log(self, limit):
            return result

    async def adapter_for(*args):
        @asynccontextmanager
        async def context():
            yield gateway, Adapter()

        return context()

    service._adapter_for = adapter_for
    app = FastAPI()
    app.include_router(router, prefix="/firewall")
    user = SimpleNamespace(
        id=uuid4(), organization_id=uuid4(), role="viewer", email="owned@example.test"
    )
    app.dependency_overrides[get_current_active_user] = lambda: CurrentUser(user, ["firewall.view"])
    app.dependency_overrides[get_gateway_service] = lambda: service
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://owned") as client:
        return await client.get(f"/firewall/gateways/{gateway.id}/logs/{kind}?limit={limit}")


@pytest.mark.parametrize("kind", ["system", "firewall"])
@pytest.mark.parametrize("shape", ["flat", "rows", "logs", "strings", "empty"])
async def test_gateway_log_routes_return_dashboard_arrays(kind, shape):
    rows = [{"message": "owned-log"}]
    data = {
        "flat": rows,
        "rows": {"rows": rows},
        "logs": {"logs": rows},
        "strings": ["owned-log"],
        "empty": [],
    }[shape]
    response = await request_logs(AdapterResult.ok(data), kind)
    assert response.status_code == 200
    assert response.json()["logs"] == ([] if shape == "empty" else rows)


@pytest.mark.parametrize("kind", ["system", "firewall"])
@pytest.mark.parametrize("failure", ["adapter", "object", "wrong-logs", "wrong-row", "none"])
async def test_gateway_log_failure_is_not_reported_as_empty_success(kind, failure):
    data = {
        "object": {"private-error": "owned-secret"},
        "wrong-logs": {"logs": "owned-secret"},
        "wrong-row": [7],
        "none": None,
    }
    result = (
        AdapterResult.fail("owned-secret")
        if failure == "adapter"
        else AdapterResult.ok(data[failure])
    )
    response = await request_logs(result, kind)
    assert response.status_code == 502
    assert response.json() == {"detail": "Gateway logs are unavailable"}
    assert "owned-secret" not in response.text


@pytest.mark.parametrize("kind", ["system", "firewall"])
async def test_gateway_log_limit_applies_to_the_result(kind):
    response = await request_logs(
        AdapterResult.ok([{"message": str(n)} for n in range(3)]), kind, limit=2
    )
    assert response.status_code == 200 and len(response.json()["logs"]) == 2
