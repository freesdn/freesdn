# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Competing first-install requests must have exactly one committed winner."""

import asyncio
import gzip
import hashlib
import json
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
from fastapi import Depends
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_password_hash
from app.db.session import create_test_engine, get_session
from app.main import app
from app.models.core import Organization, Site, User
from app.services.backup import BackupEncryption
from app.services.backup_contributors import (
    BackupArchive,
    BackupContributorRegistry,
    BackupManifest,
    ContributorEntry,
    CoreBackupContributor,
)
from app.setup.api import get_setup_service, require_setup_incomplete
from app.setup.service import SetupService


def owned_vault(org_id, identity, passphrase, *, invalid=False):
    # This newly generated local account explicitly has no MFA/SSO history.
    # Declare its full current-format state; never infer defaults for legacy input.
    archive = BackupArchive(
        manifest=BackupManifest(
            backup_id=str(uuid4()), created_at=datetime.now(UTC), organization_id=str(org_id),
            contributors=[ContributorEntry(id="core", schema_version="2.0.0", counts={"sites": 1, "users": 1})],
        ),
        contributors={"core": {
            "account_security_format": "2.0.0", "sso_providers": [], "user_site_access": [],
            "sites": [{"id": str(uuid4()), "organization_id": str(org_id), "name": "Owned bootstrap site", "slug": uuid4().hex}],
            "users": [{"id": str(uuid4()), "organization_id": str(org_id), "username": identity,
                       "email": identity + "@example.com", "role": "super_admin", "is_active": True,
                       "is_verified": True, "hashed_password": get_password_hash("Owned bootstrap account password"),
                       "full_name": "Owned bootstrap account", "language": "en", "preferences": {},
                       "mfa_enabled": False, "mfa_secret": None, "mfa_backup_codes": None,
                       "mfa_pending_secret": None, "mfa_pending_backup_codes": None,
                       "mfa_last_totp_step": None, "token_version": 0, "failed_login_attempts": 0,
                       "locked_until": None, "last_login": None, "auth_provider": None,
                       "external_id": None, "sso_provider_id": None}],
        }},
    )
    if invalid:
        archive.contributors["core"]["users"].append(None)
    body, key_id = BackupEncryption(master_key=passphrase).encrypt(
        gzip.compress(archive.model_dump_json().encode())
    )
    header = json.dumps({"backup_id": archive.manifest.backup_id, "checksum": hashlib.sha256(body).hexdigest(),
                         "encrypted": True, "compressed": True, "secrets": True, "key_id": key_id, "version": "2.0"}).encode()
    return len(header).to_bytes(4, "big") + header + body


@pytest.mark.parametrize("kinds", [("admin", "admin"), ("vault", "vault"), ("admin", "vault"), ("vault", "admin"), ("invalid-vault", "admin")])
async def test_concurrent_bootstrap_has_one_committed_administrator(monkeypatch, kinds):
    import app.services.backup_contributors as contributors

    # Dispatcher unit tests deliberately reset the process singleton. Own the
    # registry for this integration fixture and use the real core restoration.
    registry = BackupContributorRegistry()
    registry.register(CoreBackupContributor())
    monkeypatch.setattr(contributors, "get_registry", lambda: registry)
    engine = create_test_engine()
    identities = ["owned_bootstrap_" + uuid4().hex for _ in kinds]
    org_ids = [uuid4() for _ in kinds]
    slugs = ["owned-bootstrap-" + uuid4().hex for _ in kinds]
    passphrase = "Owned concurrent bootstrap archive passphrase"
    payloads = [owned_vault(org, identity, passphrase, invalid=kind == "invalid-vault") if kind.endswith("vault") else None
                for org, identity, kind in zip(org_ids, identities, kinds, strict=True)]
    gate = asyncio.Barrier(2)
    real_gate_calls = []

    async def independent_session():
        async with AsyncSession(engine, expire_on_commit=False, autoflush=False) as session:
            try:
                yield session
                await session.commit()
            except BaseException:
                await session.rollback()
                raise

    async def synchronized_real_gate(service: SetupService = Depends(get_setup_service)):
        # Both requests genuinely pass the existing public authorization gate.
        # The barrier controls scheduling only; it does not grant permission.
        result = await require_setup_incomplete(service)
        real_gate_calls.append(id(service.db))
        await asyncio.wait_for(gate.wait(), timeout=10)
        return result

    monkeypatch.setitem(app.dependency_overrides, get_session, independent_session)
    monkeypatch.setitem(app.dependency_overrides, require_setup_incomplete, synchronized_real_gate)
    try:
        async with AsyncSession(engine) as check:
            assert await check.scalar(select(func.count()).select_from(User).where(User.role == "super_admin", User.deleted_at.is_(None))) == 0
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            async def submit(index):
                if kinds[index].endswith("vault"):
                    return await client.post("/api/v1/setup/restore", files={"file": ("owned.fsdnvault", payloads[index], "application/octet-stream")}, data={"passphrase": passphrase})
                return await client.post("/api/v1/setup/admin", json={
                    "email": identities[index] + "@example.com", "username": identities[index],
                    "password": "OwnedSetupPassword123!", "first_name": "Owned", "last_name": "Bootstrap",
                    "organization_name": "Owned bootstrap organization", "organization_slug": slugs[index],
                })
            responses = await asyncio.wait_for(asyncio.gather(submit(0), submit(1)), timeout=25)
        assert len(real_gate_calls) == len(set(real_gate_calls)) == 2
        async with AsyncSession(engine) as check:
            users = list((await check.scalars(select(User).where(User.username.in_(identities)))).all())
            orgs = list((await check.scalars(select(Organization).where((Organization.id.in_(org_ids)) | (Organization.slug.in_(slugs))))).all())
            state = (sum(r.status_code == 200 and r.json().get("success") is True for r in responses), len(users), len(orgs))
            assert state == (1, 1, 1), {"statuses": [r.status_code for r in responses], "committed_counts": state}
            assert sorted(r.status_code for r in responses)[1] in ({403, 409} if "invalid-vault" in kinds else {400, 403})
            assert users[0].role == "super_admin" and users[0].organization_id == orgs[0].id
            assert users[0].is_active and users[0].deleted_at is None
    finally:
        # These tests use independent commits, so remove only their owned rows.
        async with AsyncSession(engine) as cleanup:
            owned_orgs = list((await cleanup.scalars(select(Organization.id).where((Organization.id.in_(org_ids)) | (Organization.slug.in_(slugs))))).all())
            await cleanup.execute(delete(User).where(User.username.in_(identities)))
            await cleanup.execute(delete(Site).where(Site.organization_id.in_(owned_orgs)))
            await cleanup.execute(delete(Organization).where(Organization.id.in_(owned_orgs)))
            await cleanup.commit()
        await engine.dispose()
        # Override callables may remain classified after fixture cleanup.
        # All owned requests and database cleanup have finished.
        engine = None
