# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Signed-catalog attack regressions through the real sync and PostgreSQL path."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException, Request
from sqlalchemy import select

from app.api.v1.endpoints import marketplace as mp
from app.core.dependencies import DEFAULT_ROLE_PERMISSIONS, CurrentUser
from app.core.security import create_access_token, decode_token, get_password_hash
from app.models.core import User, UserSession
from app.models.marketplace import MarketplacePlugin


async def _catalog_request_actor(session):
    """Supply real account/session rows for direct catalog component calls.

    This does not replace HTTP authentication coverage: the separate16 wait
    probes exercise that dependency with both JWT and API-key credentials.
    No authority checker is mocked and no caller transaction is committed here.
    """
    user_id = uuid4()
    name = "owned-catalog-" + user_id.hex
    user = User(id=user_id, username=name, email=name + "@example.com",
                full_name="Owned catalog actor", organization_id=None,
                hashed_password=get_password_hash("Owned catalog compatibility password"),
                role="super_admin", is_active=True, is_verified=True, token_version=17)
    session.add(user)
    await session.flush()
    token = create_access_token(str(user_id), token_version=17,
                                expires_delta=timedelta(minutes=5))
    claims = await decode_token(token)
    assert claims is not None
    session.add(UserSession(user_id=user_id, access_jti=claims["jti"],
                            created_at=datetime.now(UTC),
                            expires_at=datetime.fromtimestamp(claims["exp"], UTC)))
    await session.flush()
    return Request({"type": "http", "headers": []}), CurrentUser(
        user, list(DEFAULT_ROLE_PERMISSIONS["super_admin"]), token_claims=claims,
    )


async def _sync_with_catalog_actor(session):
    request, actor = await _catalog_request_actor(session)
    return await mp.sync_marketplace(request, actor, session)


def _catalog_setup(monkeypatch):
    key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(
        mp, "MARKETPLACE_PUBLISHER_PUBLIC_KEY", key.public_key().public_bytes_raw().hex()
    )
    monkeypatch.setattr(mp, "MARKETPLACE_ALLOW_UNSIGNED", False)
    monkeypatch.setattr(mp, "MARKETPLACE_MIN_SERIAL", "0", raising=False)
    monkeypatch.setattr(
        mp, "MARKETPLACE_REGISTRY_URL", "https://registry.example.invalid/plugins.json"
    )
    monkeypatch.setattr(mp, "is_unscoped_superuser", lambda _user: True)

    def make(serial, ids=("kept", "removed"), **fields):
        now = datetime.now(UTC)
        data = {
            "catalog_version": 1,
            "serial": serial,
            "generated_at": (now - timedelta(minutes=1)).isoformat(),
            "expires_at": (now + timedelta(days=1)).isoformat(),
            "plugins": [
                {
                    "plugin_id": i,
                    "slug": i,
                    "name": i,
                    "short_description": "Fixture",
                    "author_name": "Fixture author",
                    "category": "monitoring",
                    "latest_version": "1.0.0",
                    "min_core_version": "0.1.0",
                    "download_url": f"https://example.invalid/{i}.zip",
                    "checksum_sha256": "a" * 64,
                }
                for i in ids
            ],
            **fields,
        }
        data["signature"] = key.sign(mp._canonical_catalog_bytes(data)).hex()
        return data

    async def sync(session, data):
        monkeypatch.setattr(mp, "_fetch_registry_catalog", AsyncMock(return_value=data))
        return await _sync_with_catalog_actor(session)

    return make, sync


@pytest.fixture
def catalogs(monkeypatch):
    return _catalog_setup(monkeypatch)


async def test_signed_older_catalog_cannot_revive_withdrawal(db_session, catalogs):
    make, sync = catalogs
    old = make(1)
    await sync(db_session, old)
    await sync(db_session, make(2, ("kept",)))
    with pytest.raises(HTTPException, match="rollback") as error:
        await sync(db_session, old)
    assert error.value.status_code == 409
    row = (
        await db_session.execute(
            select(MarketplacePlugin).where(MarketplacePlugin.plugin_id == "removed")
        )
    ).scalar_one()
    assert row.status == "withdrawn"


async def test_expired_signed_catalog_cannot_revive_withdrawal(db_session, catalogs):
    make, sync = catalogs
    await sync(db_session, make(1))
    await sync(db_session, make(2, ("kept",)))
    with pytest.raises(HTTPException, match="expired"):
        await sync(
            db_session,
            make(
                3,
                generated_at=(datetime.now(UTC) - timedelta(days=2)).isoformat(),
                expires_at=(datetime.now(UTC) - timedelta(days=1)).isoformat(),
            ),
        )
    row = (
        await db_session.execute(
            select(MarketplacePlugin).where(MarketplacePlugin.plugin_id == "removed")
        )
    ).scalar_one()
    assert row.status == "withdrawn"


async def test_reusing_signed_serial_for_different_content_is_rejected(db_session, catalogs):
    make, sync = catalogs
    await sync(db_session, make(3, ("kept",)))
    with pytest.raises(HTTPException, match="reused"):
        await sync(db_session, make(3))
    assert (
        await db_session.execute(
            select(MarketplacePlugin).where(MarketplacePlugin.plugin_id == "removed")
        )
    ).scalar_one_or_none() is None


async def test_signed_empty_snapshot_withdraws_every_offer(db_session, catalogs):
    make, sync = catalogs
    await sync(db_session, make(1))
    result = await sync(db_session, make(2, ()))
    assert sorted(result["withdrawn"]) == ["kept", "removed"]
    assert (
        not (
            await db_session.execute(
                select(MarketplacePlugin).where(MarketplacePlugin.status == "published")
            )
        )
        .scalars()
        .all()
    )
