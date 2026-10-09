# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""First-install vault failures must leave a fresh, retryable database."""

import gzip
import hashlib
import json
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select

from app.core.security import get_password_hash, verify_password
from app.models.core import Organization, Site, User
from app.services.backup import BackupEncryption, BackupService
from app.services.backup_contributors import (
    BackupArchive,
    BackupContributorRegistry,
    BackupManifest,
    ContributorEntry,
    ContributorPayload,
    RestoreResult,
)
from app.services.backup_contributors.core import CoreBackupContributor


class OwnedExtraContributor:
    contributor_id = "z_owned_recovery"
    schema_version = "1.0.0"
    depends_on = ("core",)
    default_included = True

    def __init__(self, mode):
        self.mode = mode

    async def collect(self, session, organization_id, options):
        return ContributorPayload(schema_version=self.schema_version, data={})

    async def restore(self, session, organization_id, payload, *, dry_run, options):
        assert not dry_run and options["include_secrets"]
        site = await session.get(Site, UUID(payload.data["site_id"]))
        site.description = "Owned extra contributor applied"
        await session.flush()
        if self.mode == "raised-error":
            raise RuntimeError("Owned recovery refusal after a write")
        return RestoreResult(
            contributor_id=self.contributor_id,
            status="error" if self.mode == "reported-error" else "ok",
            updated={"sites": 1},
            errors=["Owned recovery refusal"] if self.mode == "reported-error" else [],
        )


def seal_vault(config, passphrase):
    """Real current encryption and wire format; no encryption mock or test KDF."""
    body, key_id = BackupEncryption(master_key=passphrase).encrypt(
        gzip.compress(json.dumps(config).encode())
    )
    header = json.dumps({
        "backup_id": str(uuid4()), "checksum": hashlib.sha256(body).hexdigest(),
        "encrypted": True, "compressed": True, "secrets": True,
        "key_id": key_id, "created_at": datetime.now(UTC).isoformat(), "version": "2.0",
    }).encode()
    return len(header).to_bytes(4, "big") + header + body


def archive_fixture(monkeypatch, mode):
    import app.services.backup_contributors as contributors

    org, site, user = uuid4(), uuid4(), uuid4()
    password = "Owned first install account password"
    passphrase = "Owned first install archive passphrase"
    identity = uuid4().hex
    # This newly generated local account explicitly has no MFA/SSO history.
    # Declare its full current-format state; never infer defaults for legacy input.
    data = {
        "core": {
            "account_security_format": "2.0.0", "sso_providers": [], "user_site_access": [],
            "sites": [{"id": str(site), "organization_id": str(org), "name": "Owned restored site",
                       "slug": uuid4().hex, "description": "Core restored configuration"}],
            "users": [{"id": str(user), "organization_id": str(org), "username": identity,
                       "email": identity + "@example.invalid", "role": "super_admin",
                       "hashed_password": get_password_hash(password), "is_active": True, "is_verified": True,
                       "full_name": "Owned first install account", "language": "en", "preferences": {},
                       "mfa_enabled": False, "mfa_secret": None, "mfa_backup_codes": None,
                       "mfa_pending_secret": None, "mfa_pending_backup_codes": None,
                       "mfa_last_totp_step": None, "token_version": 0, "failed_login_attempts": 0,
                       "locked_until": None, "last_login": None, "auth_provider": None,
                       "external_id": None, "sso_provider_id": None}],
        },
        "z_owned_recovery": {"site_id": str(site)},
    }
    if mode == "core-error":
        data["core"]["users"].append(None)
    elif mode == "no-admin":
        data["core"]["users"][0]["role"] = "org_admin"
    elif mode == "inactive-admin":
        data["core"]["users"][0]["is_active"] = False
    archive = BackupArchive(
        manifest=BackupManifest(
            backup_id=str(uuid4()), created_at=datetime.now(UTC), organization_id=str(org),
            contributors=[
                ContributorEntry(id="core", schema_version="2.0.0", counts={"sites": 1, "users": 1}),
                ContributorEntry(id="z_owned_recovery", schema_version="1.0.0", counts={"sites": 1}),
            ],
        ),
        contributors=data,
    )
    registry = BackupContributorRegistry()
    registry.register(CoreBackupContributor())
    extra = OwnedExtraContributor(mode)
    if mode != "missing":
        registry.register(extra)
    if mode == "schema-mismatch":
        extra.schema_version = "2.0.0"
    monkeypatch.setattr(contributors, "get_registry", lambda: registry)
    monkeypatch.setattr(BackupService, "_contributors_initialized", True)
    return org, site, user, password, passphrase, archive, registry, extra


async def row_counts(session):
    return [await session.scalar(select(func.count()).select_from(model)) for model in (Organization, Site, User)]


@pytest.mark.parametrize("mode", ["reported-error", "raised-error", "missing", "schema-mismatch", "core-error", "no-admin", "inactive-admin", "success"])
async def test_first_install_vault_failure_rolls_back_and_allows_recovery_retry(
    db_session, async_client, monkeypatch, mode
):
    org, site, user, password, passphrase, archive, registry, extra = archive_fixture(monkeypatch, mode)
    assert await row_counts(db_session) == [0, 0, 0]
    sealed = seal_vault(archive.model_dump(mode="json"), passphrase)
    assert password.encode() not in sealed and b"Core restored configuration" not in sealed

    async def restore(blob):
        return await async_client.post(
            "/api/v1/setup/restore", files={"file": ("owned.fsdnvault", blob, "application/octet-stream")},
            data={"passphrase": passphrase},
        )

    response = await restore(sealed)
    if mode != "success":
        # Capture status and live row state together before any failure stops
        # this test, so baseline evidence also shows partially committed setup.
        assert (response.status_code, await row_counts(db_session)) == (409, [0, 0, 0])
        assert response.json().get("success") is not True
        status = await async_client.get("/api/v1/setup/status")
        assert status.status_code == 200 and status.json()["is_complete"] is False
        extra.mode = "success"
        extra.schema_version = "1.0.0"
        if mode == "missing":
            registry.register(extra)
        if mode == "core-error":
            archive.contributors["core"]["users"].pop()
        elif mode in {"no-admin", "inactive-admin"}:
            archive.contributors["core"]["users"][0].update(role="super_admin", is_active=True)
        if mode in {"core-error", "no-admin", "inactive-admin"}:
            sealed = seal_vault(archive.model_dump(mode="json"), passphrase)
        response = await restore(sealed)

    assert response.status_code == 200 and response.json()["success"] is True
    assert response.json()["result"]["summary"]["contributors_failed"] == 0
    assert await row_counts(db_session) == [1, 1, 1]
    restored = await db_session.get(User, user)
    assert restored.organization_id == org and restored.role == "super_admin" and restored.is_active
    assert verify_password(password, restored.hashed_password)
    assert (await db_session.get(Site, site)).description == "Owned extra contributor applied"
    status = await async_client.get("/api/v1/setup/status")
    assert status.status_code == 200 and status.json()["is_complete"] is True
    assert (await restore(sealed)).status_code == 403


async def test_first_install_rejects_invalid_archive_without_echoing_decrypted_input(
    db_session, async_client, caplog
):
    sentinel = "owned-private-vault-content-do-not-echo"
    passphrase = "Owned malformed archive passphrase"
    config = {"manifest": {"created_at": sentinel}, "contributors": {}}
    sealed = seal_vault(config, passphrase)
    response = await async_client.post(
        "/api/v1/setup/restore", files={"file": ("owned.fsdnvault", sealed, "application/octet-stream")},
        data={"passphrase": passphrase},
    )
    assert response.status_code == 400
    assert sentinel not in response.text and sentinel not in caplog.text
    assert await row_counts(db_session) == [0, 0, 0]
