"""Public hint contract and actual ASGI validation boundary; authority is controlled here."""
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.api.v1.endpoints.vault_export import (
    VaultConfirmationPolicy,
    create_vault_confirmation_router,
)
from app.core.dependencies import get_current_active_user
from app.services.vault_export_authority import VaultExportAuthority

PREFIX = "/owned/api/auth/vault-export"


@pytest.fixture
def contract_app(monkeypatch):
    app = FastAPI()
    router = create_vault_confirmation_router(VaultConfirmationPolicy())
    app.include_router(router, prefix=PREFIX)
    actor = SimpleNamespace(id="11111111-1111-4111-8111-111111111111",
                            organization_id="22222222-2222-4222-8222-222222222222")

    async def current_actor():
        return actor

    app.dependency_overrides[get_current_active_user] = current_actor
    authority = SimpleNamespace(confirmation_requirements=AsyncMock(return_value=("local", False)))
    capture = AsyncMock(return_value=authority)
    monkeypatch.setattr(VaultExportAuthority, "capture", capture)
    return app, router, capture


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["", "restore", "CREATE", "synthetic-invalid-private-input-" * 80])
async def test_invalid_action_is_redacted_client_error_before_snapshot(contract_app, action):
    app, _, capture = contract_app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://owned.invalid") as client:
        response = await client.get(PREFIX + "/requirements", params={"action": action})
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid vault confirmation request"}
    assert response.headers["cache-control"] == "private, no-store"
    assert response.headers["pragma"] == "no-cache"
    capture.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["create", "download"])
async def test_supported_actions_keep_typed_hint_and_no_store(contract_app, action):
    app, _, capture = contract_app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://owned.invalid") as client:
        response = await client.get(PREFIX + "/requirements", params={"action": action})
    assert response.status_code == 200
    assert response.json() == {"method": "local", "mfa_required": False, "oidc_redirect_uri": None}
    assert response.headers["cache-control"] == "private, no-store"
    assert response.headers["pragma"] == "no-cache"
    capture.assert_awaited_once()
    assert capture.await_args.kwargs["action"] == action


@pytest.mark.parametrize("name", ["X-FreeSDN-Vault-Actor", "X-FreeSDN-Vault-Organization"])
def test_hint_contract_documents_captured_context_without_granting_authority(contract_app, name):
    app, _, _ = contract_app
    operation = app.openapi()["paths"][PREFIX + "/requirements"]["get"]
    headers = {p["name"]: p for p in operation["parameters"] if p["in"] == "header"}
    assert name in headers
    item = headers[name]
    assert item["required"] is False
    assert item["schema"]["minLength"] == item["schema"]["maxLength"] == 36
    assert "both" in item["description"] and "no authority" in item["description"]


@pytest.mark.parametrize("status", ["200", "400", "401", "403", "409", "422", "429", "500", "503"])
def test_hint_contract_documents_status_and_cache_policy(contract_app, status):
    app, _, _ = contract_app
    responses = app.openapi()["paths"][PREFIX + "/requirements"]["get"]["responses"]
    assert status in responses
    assert responses[status]["headers"]["Cache-Control"]["schema"]["const"] == "private, no-store"
    assert responses[status]["headers"]["Pragma"]["schema"]["const"] == "no-cache"


def test_hint_contract_retains_query_response_and_no_body_dependencies(contract_app):
    app, router, _ = contract_app
    spec = app.openapi()
    operation = spec["paths"][PREFIX + "/requirements"]["get"]
    action = next(p for p in operation["parameters"] if p["name"] == "action")
    assert action["in"] == "query" and action["schema"]["enum"] == ["create", "download"]
    assert action["schema"]["default"] == "create" and action["required"] is False
    assert "requestBody" not in operation
    schema = spec["components"]["schemas"]["VaultFactorRequirements"]
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"]) == {"method", "mfa_required", "oidc_redirect_uri"}
    assert schema["properties"]["method"]["enum"] == ["local", "ldap", "oidc"]
    route = next(r for r in router.routes if r.path == "/requirements")
    assert route.body_field is None
    stack = [route.dependant]
    while stack:
        item = stack.pop()
        assert item.body_params == []
        stack.extend(item.dependencies)
