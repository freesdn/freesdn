"""Actual REST auth and audit-verdict serialization regression checks.

Disposable PostgreSQL rows, real JWT/API-key verification, independent request
transactions. No device/IdP exchange, reverse-proxy or deployment acceptance.
"""
import json
import os
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.security import create_access_token
from app.db.session import get_session
from app.main import app
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import Organization, User
from app.models.security_audit import AuditLogRecord
from app.services.audit import AuditService
from app.services.audit_chain import prune_prefix


@pytest_asyncio.fixture
async def owned_http_database(monkeypatch):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    org_ids = [uuid4(), uuid4()]
    user_id, key_id = uuid4(), uuid4()
    audit_ids = []

    async def independent_session():
        async with AsyncSession(engine, expire_on_commit=False) as session:
            try:
                yield session
                await session.commit()
            except BaseException:
                await session.rollback()
                raise

    monkeypatch.setitem(app.dependency_overrides, get_session, independent_session)
    try:
        async with AsyncSession(engine, expire_on_commit=False) as db:
            assert await db.scalar(select(func.count()).select_from(AuditLogRecord)) == 0
            db.add_all(Organization(id=identity, name="Owned audit HTTP", slug=uuid4().hex)
                       for identity in org_ids)
            await db.flush()
            user = User(id=user_id, organization_id=org_ids[0], username=uuid4().hex,
                        email=uuid4().hex + "@example.invalid", role="super_admin",
                        hashed_password="!DISABLED!", is_active=True, is_verified=True,
                        token_version=17)
            db.add(user)
            await db.commit()
            yield SimpleNamespace(db=db, user=user, user_id=user_id, org_ids=org_ids,
                                  key_id=key_id, audit_ids=audit_ids)
            await db.rollback()
    finally:
        async with engine.begin() as connection:
            await connection.execute(delete(AuditLogRecord).where(AuditLogRecord.id.in_(audit_ids)))
            await connection.execute(delete(APIKey).where(APIKey.id == key_id))
            await connection.execute(delete(User).where(User.id == user_id))
            await connection.execute(delete(Organization).where(Organization.id.in_(org_ids)))
        await engine.dispose()


def client(headers):
    identity = uuid4().int
    peer = f"198.19.{(identity >> 8) & 255}.{identity & 255}"
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False,
                                                        client=(peer, 45123)),
                             base_url="http://test", headers=headers)


AUTH_CASES = [
    ("anonymous", 401), ("jwt_super", 200), ("jwt_viewer", 403),
    ("jwt_org_admin", 403), ("jwt_admin", 403), ("jwt_disabled", 401),
    ("jwt_deleted", 401), ("jwt_revoked", 401), ("key_unscoped", 200),
    ("key_audit_scope", 403), ("key_wildcard_scope", 403),
    ("key_revoked", 401), ("key_expired", 401), ("key_owner_demoted", 403),
]


@pytest.mark.parametrize("credential,expected_status", AUTH_CASES)
async def test_actual_audit_endpoint_credential_scope(
    owned_http_database, credential, expected_status, record_property,
):
    f = owned_http_database
    headers = {}
    if credential.startswith("jwt_"):
        role = {"jwt_viewer": "viewer", "jwt_org_admin": "org_admin", "jwt_admin": "admin"}
        f.user.role = role.get(credential, "super_admin")
        if credential == "jwt_disabled":
            f.user.is_active = False
        if credential == "jwt_deleted":
            f.user.deleted_at = datetime.now(UTC)
        headers = {"Authorization": "Bearer " + create_access_token(
            subject=str(f.user_id), token_version=16 if credential == "jwt_revoked" else 17,
        )}
    elif credential.startswith("key_"):
        raw, prefix, hashed = generate_api_key()
        scopes = {"key_audit_scope": ["audit:read"], "key_wildcard_scope": ["*"]}
        f.db.add(APIKey(id=f.key_id, user_id=f.user_id, name="Owned audit HTTP key",
                        key_prefix=prefix, key_hash=hashed, scopes=scopes.get(credential, []),
                        is_active=credential != "key_revoked",
                        expires_at=datetime.now(UTC) - timedelta(days=1)
                        if credential == "key_expired" else None))
        if credential == "key_owner_demoted":
            f.user.role = "viewer"
        headers = {"X-API-Key": raw}
    await f.db.commit()
    async with client(headers) as http:
        response = await http.get("/api/v1/audit/validate")
    body = response.json()
    record_property("actual_http_auth", json.dumps({"credential": credential,
                    "status": response.status_code, "body": body}))
    assert response.status_code == expected_status
    if expected_status == 200:
        assert body["valid"] and body["complete"] and body["checked"] == 0
        assert not body["state_authenticated"] and not body["retained_history_authenticated"]
        assert not body["history_authenticated"] and not body["external_immutability_proven"]
    else:
        assert not {"checked", "valid", "unsigned_history_rows", "retention_applied"} & body.keys()


@pytest.mark.parametrize("window", ["full", "limit", "middle", "missing_start",
                                    "reverse", "tampered_body", "retained_prefix",
                                    "invalid_limit", "invalid_uuid"])
async def test_actual_audit_endpoint_preserves_verification_flags(
    owned_http_database, window, record_property,
):
    f = owned_http_database
    marker = "Owned audit " + uuid4().hex
    stamp = datetime.now(UTC) - timedelta(days=200)
    for number in range(2):
        identity = uuid4()
        f.audit_ids.append(identity)
        await AuditService(f.db).persist_record(AuditLogRecord(
            id=identity, timestamp=stamp + timedelta(seconds=number), action=marker,
            resource_type="owned_http", organization_id=f.org_ids[number],
        ))
    await f.db.commit()
    if window == "tampered_body":
        await f.db.execute(text("UPDATE audit.audit_logs SET action='owned_changed' WHERE id=:id"),
                           {"id": f.audit_ids[1]})
        await f.db.commit()
    elif window == "retained_prefix":
        assert await prune_prefix(f.db, datetime.now(UTC), batch_size=1) == 1
        await f.db.commit()
    params = {
        "limit": {"limit": 1},
        "middle": {"start_id": str(f.audit_ids[1]), "end_id": str(f.audit_ids[1])},
        "missing_start": {"start_id": str(uuid4())},
        "reverse": {"start_id": str(f.audit_ids[1]), "end_id": str(f.audit_ids[0])},
        "invalid_limit": {"limit": 100001}, "invalid_uuid": {"start_id": "not-a-uuid"},
    }.get(window, {})
    headers = {"Authorization": "Bearer " + create_access_token(subject=str(f.user_id), token_version=17)}
    async with client(headers) as http:
        response = await http.get("/api/v1/audit/validate", params=params)
    body = response.json()
    record_property("actual_http_verdict", json.dumps({"window": window,
                    "status": response.status_code, "body": body}))
    assert marker not in response.text
    if window in {"invalid_limit", "invalid_uuid"}:
        assert response.status_code == 422
        assert "checked" not in body
        return
    assert response.status_code == 200
    assert not body["history_authenticated"] and not body["external_immutability_proven"]
    if window in {"missing_start", "reverse", "tampered_body"}:
        assert not body["valid"] and not body["complete"]
        assert not body["retained_history_authenticated"]
        assert body["broken_reason"]
    elif window in {"limit", "middle"}:
        assert body["valid"] and not body["complete"] and body["checked"] == 1
        assert body["state_authenticated"] and body["boundary_verified"]
        assert not body["retained_history_authenticated"]
        if window == "limit":
            assert body["next_start_id"] == str(f.audit_ids[1])
    else:
        assert body["valid"] and body["complete"] and body["retained_history_authenticated"]
        assert body["state_authenticated"] and body["boundary_verified"]
        assert body["retention_applied"] == (window == "retained_prefix")
        assert body["checked"] == (1 if window == "retained_prefix" else 2)
        assert body["unsigned_history_rows"] == 0
