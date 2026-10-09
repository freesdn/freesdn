# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A sealed snapshot must not undo later destination security decisions.

Private planned cases; not yet frozen, collected or executed. The companion
31-case module owns real committed PostgreSQL rows and actual sealed archives.
No source/destination field-key rotation occurs for an existing installation.
"""

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pyotp
import pytest
from sqlalchemy import delete, select

from app.core.security import get_password_hash
from app.core.security_utils import decrypt_field, encrypt_field
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import Site, User, UserSession, UserSiteAccess
from app.services.backup import BackupService
from tests.services.test_backup_vault_security_roundtrip import export_vault, source_fixture
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db

CONFLICTS = [
    "role", "password", "mfa_seed", "mfa_mode", "external_subject",
    "provider_binding", "grant_reduced", "grant_newly_restricted",
]
PRESERVE = [
    "disabled", "unverified", "lockout", "failed_attempts", "consumed_totp",
    "remaining_codes",
]
CONTROLS = ["unchanged", "equivalent_grant_new_id", "empty_codes", "rolled_back_change"]


async def security_snapshot(db, user_id, site_id, key_id, session_id):
    """Fresh scalars include an earlier core resource and revoked credentials."""
    user = (await db.execute(select(*User.__table__.columns).where(User.id == user_id))).mappings().one()
    grants = (await db.execute(select(UserSiteAccess.site_id, UserSiteAccess.access_level)
                               .where(UserSiteAccess.user_id == user_id))).all()
    key = await db.scalar(select(APIKey.is_active).where(APIKey.id == key_id))
    session = (await db.execute(select(UserSession.is_revoked, UserSession.revoked_at)
                                 .where(UserSession.id == session_id))).one()
    site_name = await db.scalar(select(Site.name).where(Site.id == site_id))
    return dict(user), sorted(grants), key, tuple(session), site_name


@pytest.mark.parametrize("case", [*CONFLICTS, *PRESERVE, *CONTROLS])
async def test_existing_vault_preserves_newer_security_or_refuses_atomically(vault_db, tmp_path, monkeypatch, case):
    provider_case = case in {"external_subject", "provider_binding"}
    f = await source_fixture(vault_db, tmp_path, monkeypatch, protocol="oidc" if provider_case else None)
    site = Site(organization_id=f.org.id, name="Archived site name", slug=uuid4().hex)
    f.db.add(site)
    await f.db.flush()
    grant_case = case in {"grant_reduced", "grant_newly_restricted", "equivalent_grant_new_id"}
    if grant_case:
        # Actual CurrentUser rules apply site caps to this role; using a
        # super-admin here would not prove a change to effective access.
        f.user.role = "operator"
    if case in {"grant_reduced", "equivalent_grant_new_id"}:
        f.db.add(UserSiteAccess(user_id=f.user.id, site_id=site.id, access_level="write"))
    source_codes = json.loads(f.user.mfa_backup_codes)
    source_codes.append(get_password_hash("Owned second recovery code " + uuid4().hex))
    f.user.mfa_backup_codes = json.dumps(source_codes)
    archive = await export_vault(f)

    # A preceding core resource changes before user recovery; a conflict must
    # roll it back as well, proving actual dispatcher transaction boundaries.
    site.name = "Current destination site name"
    f.user.token_version = 1000
    _, key_prefix, key_hash = generate_api_key()
    key = APIKey(user_id=f.user.id, name="Owned destination key", key_prefix=key_prefix,
                 key_hash=key_hash, scopes=[], is_active=True)
    login = UserSession(user_id=f.user.id, created_at=datetime.now(UTC),
                        expires_at=datetime.now(UTC) + timedelta(minutes=30))
    f.db.add_all([key, login])
    if case == "role":
        f.user.role = "viewer"
    elif case == "password":
        f.user.hashed_password = get_password_hash("Owned replacement password " + uuid4().hex)
    elif case == "mfa_seed":
        f.user.mfa_secret = encrypt_field(pyotp.random_base32())
    elif case == "mfa_mode":
        f.user.mfa_enabled = False
        f.user.mfa_secret = None
        f.user.mfa_backup_codes = None
        f.user.mfa_last_totp_step = None
    elif case == "external_subject":
        f.user.external_id = "owned-new-external-subject"
    elif case == "provider_binding":
        f.user.auth_provider = "local"
        f.user.external_id = None
        f.user.sso_provider_id = None
    elif case in {"grant_reduced", "grant_newly_restricted", "equivalent_grant_new_id"}:
        await f.db.execute(delete(UserSiteAccess).where(UserSiteAccess.user_id == f.user.id))
        f.db.add(UserSiteAccess(user_id=f.user.id, site_id=site.id,
                               access_level="write" if case == "equivalent_grant_new_id" else "read"))
    elif case == "disabled":
        f.user.is_active = False
    elif case == "unverified":
        f.user.is_verified = False
    elif case == "lockout":
        f.user.locked_until = datetime(2099, 1, 1, tzinfo=UTC)
    elif case == "failed_attempts":
        f.user.failed_login_attempts = 19
    elif case == "consumed_totp":
        f.user.mfa_last_totp_step += 10
    elif case == "remaining_codes":
        f.user.mfa_backup_codes = json.dumps(source_codes[1:])
    elif case == "empty_codes":
        f.user.mfa_backup_codes = "[]"
    else:
        assert case in {"unchanged", "rolled_back_change"}
    await f.db.commit()
    if case == "rolled_back_change":
        savepoint = await f.db.begin_nested()
        f.user.role = "viewer"
        f.user.mfa_secret = encrypt_field(pyotp.random_base32())
        await f.db.flush()
        await savepoint.rollback()
        await f.db.refresh(f.user)
        await f.db.commit()
    # A refused contributor rolls back a real savepoint and may expire ORM
    # attributes. Keep immutable IDs before that boundary; post-restore probes
    # must not perform an implicit async lazy load through an expired object.
    user_id, org_id, site_id, key_id, session_id = f.user.id, f.org.id, site.id, key.id, login.id
    before = await security_snapshot(f.db, user_id, site_id, key_id, session_id)
    report = await BackupService(f.db)._dispatch_restore_via_contributors(
        archive, organization_id=org_id, dry_run=False,
        restore_options={"overwrite_existing": True, "restore_users": True,
                         "restore_devices": False, "include_secrets": True},
    )
    await f.db.commit()
    after = await security_snapshot(f.db, user_id, site_id, key_id, session_id)
    if case in CONFLICTS:
        assert report["summary"]["contributors_failed"] == 1, {"case": case, "summary": report["summary"]}
        assert after == before, "Conflict must leave account, grants, credentials and earlier resources intact"
    else:
        assert report["summary"]["contributors_failed"] == report["summary"]["total_errors"] == 0
        for field in ["mfa_enabled", "mfa_pending_backup_codes",
                      "mfa_last_totp_step", "is_active", "is_verified", "failed_login_attempts",
                      "locked_until", "auth_provider", "external_id", "sso_provider_id",
                      "hashed_password", "role"]:
            assert after[0][field] == before[0][field], (case, field)
        for field in ["mfa_secret", "mfa_pending_secret"]:
            # Encryption is randomized even under the same destination key;
            # preserve the seed's meaning without requiring equal ciphertext.
            before_seed = decrypt_field(before[0][field]) if before[0][field] else None
            after_seed = decrypt_field(after[0][field]) if after[0][field] else None
            assert after_seed == before_seed, (case, field)
        before_codes = json.loads(before[0]["mfa_backup_codes"])
        after_codes = json.loads(after[0]["mfa_backup_codes"])
        assert len(after_codes) == len(set(after_codes)), "No duplicate recovery hashes"
        assert set(after_codes) == set(before_codes)
        assert after[0]["token_version"] > max(17, before[0]["token_version"])
        assert after[1] == before[1]
        assert after[2] is False
        assert after[3][0] is True and after[3][1] is not None
        assert after[4] == "Archived site name"
