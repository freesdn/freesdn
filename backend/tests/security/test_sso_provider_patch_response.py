# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Independent unrun diagnostic for the first baseline's valid PATCH failures.

No held row, forced wait, pinned connection, fake provider or mocked response:
create and read the provider through real HTTP and inspect committed PostgreSQL.
"""

from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token
from app.main import app
from app.models.api_keys import APIKey, generate_api_key
from app.models.sso import SSOProvider
from tests.services.test_backup_vault_security_roundtrip import source_fixture
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db


@pytest.mark.parametrize("credential", ["jwt", "api_key"])
async def test_standard_provider_patch_returns_committed_response(
    vault_db, tmp_path, monkeypatch, request, credential,
):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    f.user.role = "org_admin"
    if credential == "jwt":
        headers = {"Authorization": "Bearer " + create_access_token(
            subject=str(f.user.id), token_version=f.user.token_version,
        )}
    else:
        raw, prefix, key_hash = generate_api_key()
        f.db.add(APIKey(
            id=uuid4(), user_id=f.user.id, name="Owned ordinary provider PATCH key",
            key_prefix=prefix, key_hash=key_hash, scopes=[], is_active=True,
        ))
        headers = {"X-API-Key": raw}
    await f.db.commit()
    peer = uuid4().int
    transport = httpx.ASGITransport(
        app=app, raise_app_exceptions=False,
        client=(f"198.19.{(peer >> 8) & 255}.{peer & 255}", 45126),
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://test", headers=headers) as client:
        creation = await client.post("/api/v1/auth/sso/providers", json={
            "name": "Owned provider before normal PATCH", "slug": uuid4().hex,
            "organization_id": str(f.org.id), "protocol": "oidc", "status": "active",
            "oidc_issuer": "https://owned-response.example.invalid", "oidc_client_id": "owned-client",
            "jit_provisioning": False, "default_role": "viewer",
        })
        assert creation.status_code == 201, creation.text
        provider_id = UUID(creation.json()["id"])
        patch = await client.patch(f"/api/v1/auth/sso/providers/{provider_id}", json={
            "name": "Owned provider after normal PATCH",
        })
        readback = await client.get(f"/api/v1/auth/sso/providers/{provider_id}")
    async with AsyncSession(f.db.bind) as observer:
        row = (await observer.execute(select(
            SSOProvider.name, SSOProvider.updated_by, SSOProvider.updated_at,
        ).where(SSOProvider.id == provider_id))).one()
    durable_update = row[0] == "Owned provider after normal PATCH" and row[1] == f.user.id
    request.node.user_properties.extend([
        ("real_HTTP_provider_creation_status", creation.status_code),
        ("normal_unpinned_request_sessions", True),
        ("artificial_lock_or_wait", False),
        ("PATCH_response_status", patch.status_code),
        ("GET_readback_status", readback.status_code),
        ("durable_requested_update_committed", durable_update),
        ("updated_at_materialized_in_fresh_connection", row[2] is not None),
    ])
    # Observe ordinary committed behavior before the response-contract assertion.
    assert readback.status_code == 200, readback.text
    assert readback.json()["name"] == "Owned provider after normal PATCH"
    assert durable_update and row[2] is not None
    assert patch.status_code == 200, patch.text
    assert patch.json()["name"] == row[0]
