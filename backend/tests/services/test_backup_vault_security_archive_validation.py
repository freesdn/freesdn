# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Untrusted decoded vault content must not partially replace account security.

Uses the actual encrypted collector to build a valid archive, then deliberately
changes its decoded content at the contributor boundary. These are not claims
that AEAD transport authentication was bypassed. No expensive imported PHC is
authenticated. The actual dispatcher, PostgreSQL constraints and savepoint
rollback remain active, including when the failure follows a site update.
"""

import copy
import importlib.util
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.core.security_utils import encrypt_field
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import Site, UserSession, UserSiteAccess
from app.models.sso import SSOProvider
from app.services.backup import BackupService
from tests.services.test_backup_vault_existing_security import security_snapshot
from tests.services.test_backup_vault_security_roundtrip import export_vault, source_fixture
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db

USER_REQUIRED = (
    "id", "organization_id", "username", "email", "full_name", "language",
    "preferences", "hashed_password", "role", "is_active", "is_verified",
    "mfa_enabled", "mfa_secret", "mfa_backup_codes", "mfa_pending_secret",
    "mfa_pending_backup_codes", "mfa_last_totp_step", "token_version",
    "failed_login_attempts", "locked_until", "last_login", "auth_provider",
    "external_id", "sso_provider_id",
)
PROVIDER_REQUIRED = (
    "id", "organization_id", "name", "slug", "description", "protocol", "status",
    "icon_url", "display_order", "oidc_issuer", "oidc_client_id", "oidc_client_secret",
    "oidc_scopes", "oidc_discovery_url", "saml_entity_id", "saml_sso_url", "saml_slo_url",
    "saml_certificate", "saml_signing_key", "saml_name_id_format", "ldap_url",
    "ldap_bind_dn", "ldap_bind_password", "ldap_base_dn", "ldap_user_search_filter",
    "ldap_group_search_filter", "ldap_use_tls", "ldap_tls_ca_cert", "attribute_mapping",
    "role_mapping", "jit_provisioning", "default_role", "extra_settings",
)
MALFORMED = (
    "missing-format", "unknown-format", "users-not-list", "providers-not-list",
    "grants-not-list", "duplicate-user", "duplicate-provider", "duplicate-grant-id",
    "duplicate-grant-pair", "foreign-user", "foreign-provider", "unknown-provider",
    "unknown-grant-user", "unknown-grant-site", "unknown-role", "unknown-protocol",
    "unknown-status", "unknown-access-level", "boolean-counter", "negative-counter",
    "exhausted-counter", "negative-failed-count", "negative-consumed-step",
    "string-active", "numeric-verified", "missing-live-seed", "ciphertext-live-seed",
    "pending-code-without-seed", "plaintext-code", "duplicate-code", "too-many-codes",
    "high-cost-password", "high-cost-code", "active-unusable-password",
    "unbound-external-marker", "naive-lock-time", "oversized-preferences",
    "string-idp-mfa-trust", "provider-protocol-mismatch", "late-provider-conflict",
)


async def archive_fixture(vault_db, tmp_path, monkeypatch):
    f = await source_fixture(vault_db, tmp_path, monkeypatch, protocol="oidc")
    f.user.role = "operator"
    site = Site(organization_id=f.org.id, name="Archived earlier resource", slug=uuid4().hex)
    f.db.add(site)
    await f.db.flush()
    f.db.add(UserSiteAccess(user_id=f.user.id, site_id=site.id, access_level="write"))
    archive = await export_vault(f)
    site.name = "Current earlier resource"
    f.user.token_version = 1000
    _, prefix, key_hash = generate_api_key()
    key = APIKey(user_id=f.user.id, name="Owned archive validation key", key_prefix=prefix,
                 key_hash=key_hash, scopes=[], is_active=True)
    session = UserSession(user_id=f.user.id, created_at=datetime.now(UTC),
                          expires_at=datetime.now(UTC) + timedelta(minutes=30))
    f.db.add_all([key, session])
    await f.db.commit()
    ids = (f.user.id, site.id, key.id, session.id)
    # Preserve UUIDs before any savepoint rollback expires ORM attributes.
    org_id, provider_id = f.org.id, f.provider.id

    async def snapshot():
        security = await security_snapshot(f.db, *ids)
        provider = (await f.db.execute(select(*SSOProvider.__table__.columns)
                                      .where(SSOProvider.id == provider_id))).mappings().one()
        return security, dict(provider)

    return f, archive, org_id, snapshot


def damage(archive, case):
    data = archive.contributors["core"]
    user, provider, grant = data["users"][0], data["sso_providers"][0], data["user_site_access"][0]
    if case.startswith("missing-user-"):
        del user[case.removeprefix("missing-user-")]
    elif case.startswith("missing-provider-"):
        del provider[case.removeprefix("missing-provider-")]
    elif case == "missing-format":
        del data["account_security_format"]
    elif case == "unknown-format":
        data["account_security_format"] = "99.0.0"
    elif case.endswith("-not-list"):
        data[{"users-not-list": "users", "providers-not-list": "sso_providers",
              "grants-not-list": "user_site_access"}[case]] = {}
    elif case == "duplicate-user":
        data["users"].append(copy.deepcopy(user))
    elif case == "duplicate-provider":
        data["sso_providers"].append(copy.deepcopy(provider))
    elif case in {"duplicate-grant-id", "duplicate-grant-pair"}:
        new = copy.deepcopy(grant)
        if case == "duplicate-grant-pair":
            new["id"] = str(uuid4())
        data["user_site_access"].append(new)
    elif case in {"foreign-user", "foreign-provider"}:
        (user if case == "foreign-user" else provider)["organization_id"] = str(uuid4())
    elif case == "unknown-provider":
        user["sso_provider_id"] = str(uuid4())
    elif case == "unknown-grant-user":
        grant["user_id"] = str(uuid4())
    elif case == "unknown-grant-site":
        grant["site_id"] = str(uuid4())
    elif case == "unknown-role":
        user["role"] = "owned-invalid-role"
    elif case == "unknown-protocol":
        provider["protocol"] = "owned-invalid-protocol"
    elif case == "unknown-status":
        provider["status"] = "owned-invalid-status"
    elif case == "unknown-access-level":
        grant["access_level"] = "owned-invalid-access"
    elif case in {"boolean-counter", "negative-counter", "exhausted-counter"}:
        user["token_version"] = {"boolean-counter": True, "negative-counter": -1,
                                 "exhausted-counter": 2**31 - 1}[case]
    elif case == "negative-failed-count":
        user["failed_login_attempts"] = -1
    elif case == "negative-consumed-step":
        user["mfa_last_totp_step"] = -1
    elif case == "string-active":
        user["is_active"] = "false"
    elif case == "numeric-verified":
        user["is_verified"] = 0
    elif case == "missing-live-seed":
        user["mfa_secret"] = None
    elif case == "ciphertext-live-seed":
        user["mfa_secret"] = encrypt_field(user["mfa_secret"])
    elif case == "pending-code-without-seed":
        user["mfa_pending_secret"] = None
        user["mfa_pending_backup_codes"] = user["mfa_backup_codes"]
    elif case == "plaintext-code":
        user["mfa_backup_codes"] = json.dumps(["Owned-untrusted-recovery-code"])
    elif case in {"duplicate-code", "too-many-codes"}:
        user["mfa_backup_codes"] = json.dumps(json.loads(user["mfa_backup_codes"]) * (2 if case == "duplicate-code" else 11))
    elif case == "high-cost-password":
        user["hashed_password"] = user["hashed_password"].replace("m=65536", "m=2147483647")
    elif case == "high-cost-code":
        user["mfa_backup_codes"] = user["mfa_backup_codes"].replace("t=3", "t=999999")
    elif case == "active-unusable-password":
        user["hashed_password"] = "!"
    elif case == "unbound-external-marker":
        user.update(hashed_password="!SSO_MANAGED", auth_provider=None, external_id=None, sso_provider_id=None)
    elif case == "naive-lock-time":
        user["locked_until"] = "2099-01-01T00:00:00"
    elif case == "oversized-preferences":
        user["preferences"] = {"owned": "x" * 65537}
    elif case == "string-idp-mfa-trust":
        provider["extra_settings"]["trust_idp_mfa"] = "false"
    elif case == "provider-protocol-mismatch":
        provider["protocol"] = "saml"
    elif case == "late-provider-conflict":
        provider["oidc_client_id"] = "owned-changed-archive-client"
    else:
        raise AssertionError(case)


@pytest.mark.parametrize("dry_run", [False, True], ids=["apply", "preview"])
@pytest.mark.parametrize("case", [*("missing-user-" + f for f in USER_REQUIRED),
                                  *("missing-provider-" + f for f in PROVIDER_REQUIRED), *MALFORMED])
async def test_malformed_account_archive_refuses_without_partial_changes(vault_db, tmp_path, monkeypatch, case, dry_run):
    f, archive, org_id, snapshot = await archive_fixture(vault_db, tmp_path, monkeypatch)
    before = await snapshot()
    damage(archive, case)
    report = await BackupService(f.db)._dispatch_restore_via_contributors(
        archive, organization_id=org_id, dry_run=dry_run,
        restore_options={"overwrite_existing": True, "restore_users": True,
                         "restore_devices": False, "include_secrets": True},
    )
    await f.db.commit()
    assert report["summary"]["contributors_failed"] == 1, (case, dry_run, report["summary"])
    assert report["summary"]["total_created"] == report["summary"]["total_updated"] == 0
    assert await snapshot() == before, "Malformed data must not alter earlier resources or security/credentials"
    rendered = json.dumps(report)
    for secret in (f.seed, f.pending_seed, f.provider_secret, f.password, before[0][0]["hashed_password"]):
        assert secret not in rendered, "Safe refusal must not expose archived secrets"


@pytest.mark.parametrize("dry_run", [False, True], ids=["apply", "preview"])
@pytest.mark.parametrize("version", ["1.0.0", "1.99.99"])
async def test_legacy_full_account_refused_even_with_forged_new_security_fields(vault_db, tmp_path, monkeypatch, version, dry_run):
    f, archive, org_id, snapshot = await archive_fixture(vault_db, tmp_path, monkeypatch)
    before = await snapshot()
    archive.manifest.contributors[0].schema_version = version
    archive.contributors["core"]["_legacy_account_security"] = False
    report = await BackupService(f.db)._dispatch_restore_via_contributors(
        archive, organization_id=org_id, dry_run=dry_run,
        restore_options={"overwrite_existing": True, "restore_users": True,
                         "restore_devices": False, "include_secrets": True},
    )
    await f.db.commit()
    assert report["summary"]["contributors_failed"] == 1
    assert "Re-export" in json.dumps(report)
    assert await snapshot() == before


@pytest.mark.parametrize("dry_run", [False, True], ids=["apply", "preview"])
@pytest.mark.parametrize("mode", ["configuration", "infrastructure-only"])
async def test_legacy_safe_modes_keep_account_security(vault_db, tmp_path, monkeypatch, mode, dry_run):
    f, archive, org_id, snapshot = await archive_fixture(vault_db, tmp_path, monkeypatch)
    before = await snapshot()
    archive.manifest.contributors[0].schema_version = "1.0.0"
    # Actual legacy-shaped account data: do not manufacture MFA-off defaults.
    data = archive.contributors["core"]
    data.pop("account_security_format")
    data.pop("sso_providers")
    data["users"] = [{k: v for k, v in u.items() if k in {
        "id", "organization_id", "username", "email", "full_name", "role", "is_active", "hashed_password",
    }} for u in data["users"]]
    report = await BackupService(f.db)._dispatch_restore_via_contributors(
        archive, organization_id=org_id, dry_run=dry_run,
        restore_options={"overwrite_existing": True, "restore_users": mode == "configuration",
                         "restore_devices": False, "include_secrets": mode == "infrastructure-only"},
    )
    await f.db.commit()
    assert report["summary"]["contributors_failed"] == report["summary"]["total_errors"] == 0
    after = await snapshot()
    assert after[0][:4] == before[0][:4] and after[1] == before[1]
    assert after[0][4] == (before[0][4] if dry_run else "Archived earlier resource")


@pytest.mark.parametrize("dry_run", [False, True], ids=["apply", "preview"])
async def test_preserved_old_core_reader_refuses_new_vault_before_writes(vault_db, tmp_path, monkeypatch, dry_run):
    import app.services.backup_contributors as contributors

    f, archive, org_id, snapshot = await archive_fixture(vault_db, tmp_path, monkeypatch)
    before = await snapshot()
    assert archive.manifest.contributors[0].schema_version == "2.0.0"
    old_path = Path(__file__).parents[1] / "fixtures/vault_legacy_core_w175.py"
    spec = importlib.util.spec_from_file_location("app.services.backup_contributors._owned_old_core", old_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    registry = contributors.BackupContributorRegistry()
    registry.register(module.CoreBackupContributor())
    monkeypatch.setattr(contributors, "get_registry", lambda: registry)
    assert registry.get("core").schema_version == "1.0.0"
    report = await BackupService(f.db)._dispatch_restore_via_contributors(
        archive, organization_id=org_id, dry_run=dry_run,
        restore_options={"overwrite_existing": True, "restore_users": True,
                         "restore_devices": False, "include_secrets": True},
    )
    await f.db.commit()
    assert report["contributors"][0]["status"] == "schema_mismatch"
    assert report["summary"]["total_errors"] > 0
    assert await snapshot() == before


@pytest.mark.parametrize("protocol,secret_field", [("oidc", "oidc_client_secret"),
                                                   ("saml", "saml_signing_key"),
                                                   ("ldap", "ldap_bind_password")])
async def test_provider_plaintext_prefix_is_not_mistaken_for_source_ciphertext(vault_db, tmp_path, monkeypatch, protocol, secret_field):
    from app.core.security_utils import decrypt_field

    f = await source_fixture(vault_db, tmp_path, monkeypatch, protocol=protocol)
    secret = "fernet:Owned legitimate provider plaintext " + uuid4().hex
    setattr(f.provider, secret_field, encrypt_field(secret))
    archive = await export_vault(f)
    assert archive.contributors["core"]["sso_providers"][0][secret_field] == secret
    assert decrypt_field(getattr(f.provider, secret_field)) == secret
