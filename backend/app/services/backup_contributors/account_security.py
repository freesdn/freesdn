# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private complete-account payload implementation, not release qualified.

Account/provider/grant collection uses one PostgreSQL statement. This is not a
snapshot of every core/module resource. Export authority and encryption of the
whole archive remain caller duties; portable field secrets must never be logged.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, NoReturn, cast
from uuid import UUID

from sqlalchemy import Select, func, literal, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.functions import Function

from app.core.security_utils import decrypt_field, encrypt_field
from app.models.core import Site, User, UserRole, UserSiteAccess
from app.models.sso import SSOProtocol, SSOProvider, SSOProviderStatus

from .account_security_codec import (
    AccountSecurityFormatError,
    require_backup_code_hashes,
    require_password_hash,
    require_portable_seed,
)

FORMAT = "2.0.0"
USER_FIELDS = (
    "id",
    "organization_id",
    "username",
    "email",
    "full_name",
    "language",
    "preferences",
    "hashed_password",
    "role",
    "is_active",
    "is_verified",
    "mfa_enabled",
    "mfa_secret",
    "mfa_backup_codes",
    "mfa_pending_secret",
    "mfa_pending_backup_codes",
    "mfa_last_totp_step",
    "token_version",
    "failed_login_attempts",
    "locked_until",
    "last_login",
    "auth_provider",
    "external_id",
    "sso_provider_id",
)
PROVIDER_FIELDS = (
    "id",
    "organization_id",
    "name",
    "slug",
    "description",
    "protocol",
    "status",
    "icon_url",
    "display_order",
    "oidc_issuer",
    "oidc_client_id",
    "oidc_client_secret",
    "oidc_scopes",
    "oidc_discovery_url",
    "saml_entity_id",
    "saml_sso_url",
    "saml_slo_url",
    "saml_certificate",
    "saml_signing_key",
    "saml_name_id_format",
    "ldap_url",
    "ldap_bind_dn",
    "ldap_bind_password",
    "ldap_base_dn",
    "ldap_user_search_filter",
    "ldap_group_search_filter",
    "ldap_use_tls",
    "ldap_tls_ca_cert",
    "attribute_mapping",
    "role_mapping",
    "jit_provisioning",
    "default_role",
    "extra_settings",
)
PROVIDER_SECRETS = ("oidc_client_secret", "saml_signing_key", "ldap_bind_password")
USER_SEEDS = ("mfa_secret", "mfa_pending_secret")
GRANT_FIELDS = ("id", "user_id", "site_id", "access_level")
ROLES = frozenset(role.value for role in UserRole)


def administrator_bits(active: bool, role: str | None) -> tuple[bool, bool]:
    """Organization and platform administrator contributions of one account."""
    return active and role in {"org_admin", "super_admin"}, active and role == "super_admin"


async def require_administrator_survivors(
    session: AsyncSession,
    org_id: UUID,
    transitions: list[tuple[bool, bool, bool, bool]],
    *,
    dry_run: bool,
) -> None:
    """Check the final batch, allowing a valid replacement in either row order.

    Application must own the shared lifecycle transaction lock and flush all
    accepted rows first. Preview is advisory and projects the same accepted
    transitions over current counts; application revalidates under the lock.
    A fresh disabled profile alone is not an existing administrator removal.
    """
    removed_org = any(before_org and not after_org for before_org, _, after_org, _ in transitions)
    removed_platform = any(
        before_platform and not after_platform
        for _, before_platform, _, after_platform in transitions
    )
    if not removed_org and not removed_platform:
        return
    active = (User.deleted_at.is_(None), User.is_active.is_(True))
    org_count = await session.scalar(
        select(func.count(User.id)).where(
            *active,
            User.organization_id == org_id,
            User.role.in_(("org_admin", "super_admin")),
        )
    )
    platform_count = await session.scalar(
        select(func.count(User.id)).where(
            *active,
            User.role == "super_admin",
        )
    )
    # COUNT always returns one non-null scalar for these aggregate queries.
    org_count = cast(int, org_count)
    platform_count = cast(int, platform_count)
    if dry_run:
        org_count += sum(
            int(after_org) - int(before_org) for before_org, _, after_org, _ in transitions
        )
        platform_count += sum(
            int(after_platform) - int(before_platform)
            for _, before_platform, _, after_platform in transitions
        )
    if removed_platform and platform_count <= 0:
        raise AccountSecurityFormatError(
            "Vault restore would disable the last active platform super administrator."
        )
    if removed_org and org_count <= 0:
        raise AccountSecurityFormatError(
            "Vault restore would disable the last active administrator of this organization."
        )


def _fail() -> NoReturn:
    raise AccountSecurityFormatError("Incomplete or invalid portable account-security data.")


def _record(value: object, fields: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, dict) or not set(fields) <= value.keys():
        _fail()
    return {key: value[key] for key in fields}


def _uuid(value: object) -> str:
    if not isinstance(value, (str, UUID)):
        _fail()
    try:
        canonical = str(UUID(str(value)))
    except (ValueError, AttributeError):
        _fail()
    if str(value) != canonical:
        _fail()
    return canonical


def _string(value: object, maximum: int, *, nullable: bool = False, empty: bool = True) -> None:
    if nullable and value is None:
        return
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value):
        _fail()


def _boolean(value: object) -> None:
    if type(value) is not bool:
        _fail()


def _integer(value: object, maximum: int, *, minimum: int = 0, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if type(value) is not int or not minimum <= value <= maximum:
        _fail()


def _time(value: object) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and len(value) <= 40:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            _fail()
    else:
        _fail()
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail()
    return parsed


def _json_object(value: object) -> None:
    if not isinstance(value, dict):
        _fail()
    try:
        encoded = json.dumps(value, allow_nan=False).encode()
    except (ValueError, TypeError, RecursionError):
        _fail()
    if len(encoded) > 65536:
        _fail()


def validate_provider(record: object, org_id: UUID) -> dict[str, Any]:
    row = _record(record, PROVIDER_FIELDS)
    row["id"] = _uuid(row["id"])
    if _uuid(row["organization_id"]) != str(org_id):
        _fail()
    for field in ("protocol", "status", "default_role"):
        _string(row[field], 20, empty=False)
    if row["protocol"] not in {"oidc", "saml", "ldap"}:
        _fail()
    if row["status"] not in {"active", "inactive", "testing"} or row["default_role"] not in ROLES:
        _fail()
    for field, size in {"name": 255, "slug": 100, "default_role": 20}.items():
        _string(row[field], size, empty=False)
    for field in ("ldap_use_tls", "jit_provisioning"):
        _boolean(row[field])
    _integer(row["display_order"], 2**31 - 1, minimum=-(2**31))
    for field in ("attribute_mapping", "role_mapping", "extra_settings"):
        _json_object(row[field])
    if "trust_idp_mfa" in row["extra_settings"]:
        _boolean(row["extra_settings"]["trust_idp_mfa"])
    for field, maximum in (
        ("description", 65536),
        ("icon_url", 512),
        ("oidc_issuer", 512),
        ("oidc_client_id", 255),
        ("oidc_client_secret", 512),
        ("oidc_scopes", 500),
        ("oidc_discovery_url", 512),
        ("saml_entity_id", 512),
        ("saml_sso_url", 512),
        ("saml_slo_url", 512),
        ("saml_certificate", 65536),
        ("saml_signing_key", 65536),
        ("saml_name_id_format", 255),
        ("ldap_url", 512),
        ("ldap_bind_dn", 512),
        ("ldap_bind_password", 512),
        ("ldap_base_dn", 512),
        ("ldap_user_search_filter", 512),
        ("ldap_group_search_filter", 512),
        ("ldap_tls_ca_cert", 65536),
    ):
        _string(row[field], maximum, nullable=True)
    # The live OIDC/LDAP columns are VARCHAR(512), including the field cipher
    # envelope. Legacy plaintext can fit the source column but overflow after
    # re-encryption. Check the actual encoder's expansion (including UTF-8),
    # discard this temporary ciphertext, and refuse an unrestorable export.
    # Widening those columns is a separate schema/migration compatibility task.
    for field in ("oidc_client_secret", "ldap_bind_password"):
        if row[field] is not None and len(encrypt_field(row[field])) > 512:
            raise AccountSecurityFormatError(
                "Provider secret exceeds destination encrypted storage capacity; resolve the storage limit before vault recovery."
            )
    # Version2 provider fields explicitly carry plaintext after one source
    # decryption. A provider can legitimately issue a secret whose text starts
    # with the storage prefix; content is not an encryption-state marker here.
    # Portable MFA seeds have a separate canonical base32 contract.
    return row


def validate_user(
    record: object, org_id: UUID, providers: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    row = _record(record, USER_FIELDS)
    row["id"] = _uuid(row["id"])
    if _uuid(row["organization_id"]) != str(org_id):
        _fail()
    for field, size in (("username", 100), ("email", 255)):
        _string(row[field], size, empty=False)
    _string(row["full_name"], 255, nullable=True)
    _string(row["language"], 10, empty=False)
    _json_object(row["preferences"])
    _string(row["role"], 20, empty=False)
    if row["role"] not in ROLES:
        _fail()
    for field in ("is_active", "is_verified", "mfa_enabled"):
        _boolean(row[field])
    _integer(row["token_version"], 2**31 - 2)
    _integer(row["failed_login_attempts"], 2**31 - 1)
    _integer(row["mfa_last_totp_step"], 2**63 - 1, nullable=True)
    for field in ("last_login", "locked_until"):
        value = _time(row[field])
        row[field] = value.isoformat() if value else None
    for field in USER_SEEDS:
        require_portable_seed(row[field])
    for field in ("mfa_backup_codes", "mfa_pending_backup_codes"):
        require_backup_code_hashes(row[field])
    if row["mfa_enabled"] != bool(row["mfa_secret"]):
        _fail()
    if row["mfa_secret"] is None and row["mfa_backup_codes"] is not None:
        _fail()
    if (row["mfa_pending_secret"] is None) != (row["mfa_pending_backup_codes"] is None):
        _fail()
    mode = row["auth_provider"]
    _string(mode, 50, nullable=True, empty=False)
    external = mode in {"oidc", "saml", "ldap"}
    if external:
        _string(row["external_id"], 512, empty=False)
        row["sso_provider_id"] = _uuid(row["sso_provider_id"])
        provider = providers.get(row["sso_provider_id"])
        if provider is None or provider["protocol"] != mode:
            _fail()
    elif (
        mode not in {None, "local"}
        or row["external_id"] is not None
        or row["sso_provider_id"] is not None
    ):
        _fail()
    require_password_hash(
        row["hashed_password"], active=row["is_active"], external_binding_validated=external
    )
    return row


def validate_snapshot(data: object, org_id: UUID) -> dict[str, Any]:
    if not isinstance(data, dict) or data.get("account_security_format") != FORMAT:
        raise AccountSecurityFormatError(
            "This archive lacks complete account security; re-export a supported full vault."
        )
    for key in ("users", "sso_providers", "user_site_access"):
        if not isinstance(data.get(key), list):
            _fail()
    providers = {}
    for record in data["sso_providers"]:
        row = validate_provider(record, org_id)
        if row["id"] in providers:
            _fail()
        providers[row["id"]] = row
    users, external_bindings = {}, set()
    for record in data["users"]:
        row = validate_user(record, org_id, providers)
        if row["id"] in users:
            _fail()
        if row["sso_provider_id"] is not None:
            binding = (row["sso_provider_id"], row["external_id"])
            if binding in external_bindings:
                _fail()
            external_bindings.add(binding)
        users[row["id"]] = row
    grants, ids, pairs = [], set(), set()
    for record in data["user_site_access"]:
        row = _record(record, GRANT_FIELDS)
        for field in ("id", "user_id", "site_id"):
            row[field] = _uuid(row[field])
        _string(row["access_level"], 20, nullable=True, empty=False)
        pair = (row["user_id"], row["site_id"])
        if (
            row["id"] in ids
            or pair in pairs
            or row["user_id"] not in users
            or row["access_level"] not in {None, "read", "write", "admin"}
        ):
            _fail()
        ids.add(row["id"])
        pairs.add(pair)
        grants.append(row)
    return {
        "account_security_format": FORMAT,
        "users": list(users.values()),
        "sso_providers": list(providers.values()),
        "user_site_access": grants,
    }


def _json_rows(query: Select[Any]) -> Function[Any]:
    rows = query.subquery()
    return func.coalesce(
        select(func.jsonb_agg(func.to_jsonb(rows.table_valued()))).scalar_subquery(),
        literal([], type_=JSONB),
    )


async def collect_snapshot(
    session: AsyncSession, org_id: UUID, *, site_id: UUID | None = None
) -> dict[str, Any]:
    """Read fresh scalar records with one statement, without caller commit."""
    users = select(*(getattr(User, field) for field in USER_FIELDS)).where(
        User.organization_id == org_id,
        User.deleted_at.is_(None),
    )
    if site_id is not None:
        users = users.where(
            User.id.in_(
                select(UserSiteAccess.user_id)
                .join(
                    Site,
                    Site.id == UserSiteAccess.site_id,
                )
                .where(
                    Site.id == site_id, Site.organization_id == org_id, Site.deleted_at.is_(None)
                )
            )
        )
    chosen_users = users.cte("vault_security_users")
    providers = select(*(getattr(SSOProvider, field) for field in PROVIDER_FIELDS)).where(
        SSOProvider.organization_id == org_id,
        SSOProvider.deleted_at.is_(None),
    )
    grants = (
        select(
            *(getattr(UserSiteAccess, field) for field in GRANT_FIELDS),
            Site.organization_id.label("site_org"),
            Site.deleted_at.label("site_deleted"),
        )
        .select_from(UserSiteAccess)
        .join(chosen_users, chosen_users.c.id == UserSiteAccess.user_id)
        .outerjoin(
            Site,
            Site.id == UserSiteAccess.site_id,
        )
    )
    if site_id is not None:
        grants = grants.where(UserSiteAccess.site_id == site_id)
    statement = select(
        _json_rows(select(chosen_users)).label("users"),
        _json_rows(providers).label("sso_providers"),
        _json_rows(grants).label("user_site_access"),
    )
    snapshot = dict((await session.execute(statement)).mappings().one())
    for row in snapshot["users"]:
        for field in USER_SEEDS:
            if row[field] is not None:
                row[field] = decrypt_field(row[field])
    for row in snapshot["sso_providers"]:
        # PostgreSQL SAEnum stores the declared member name; the portable
        # format uses the public enum value. Unknown imported values are not
        # normalized here: validation below accepts only explicit values.
        row["protocol"] = row["protocol"].lower()
        row["status"] = row["status"].lower()
        for field in PROVIDER_SECRETS:
            if row[field] is not None:
                row[field] = decrypt_field(row[field])
    for row in snapshot["user_site_access"]:
        if row.pop("site_org") != str(org_id) or row.pop("site_deleted") is not None:
            _fail()
    snapshot["account_security_format"] = FORMAT
    return validate_snapshot(snapshot, org_id)


def destination_fields(record: dict[str, Any], *, provider: bool = False) -> dict[str, Any]:
    """Re-encrypt only validated portable fields under the destination key."""
    row = dict(record)
    for field in PROVIDER_SECRETS if provider else USER_SEEDS:
        if row[field] is not None:
            row[field] = encrypt_field(row[field])
    if provider:
        row["protocol"] = SSOProtocol(row["protocol"])
        row["status"] = SSOProviderStatus(row["status"])
        for field in ("oidc_client_secret", "ldap_bind_password"):
            if row[field] is not None and len(row[field]) > 512:
                _fail()
    else:
        for field in ("last_login", "locked_until"):
            row[field] = _time(row[field])
    return row


def merge_existing_user(
    archived: dict[str, Any],
    current: User,
    current_grants: set[tuple[str, str | None]],
    archived_grants: set[tuple[str, str | None]],
) -> dict[str, Any]:
    """Refuse identity/authority conflicts and preserve stricter live state.

    Caller must refresh and lock the destination account first and serialize
    all grant/security writers. This helper does not itself acquire locks.
    """
    for field in ("role", "hashed_password", "mfa_enabled", "auth_provider", "external_id"):
        if archived[field] != getattr(current, field):
            raise AccountSecurityFormatError(
                "Account identity or authority conflicts with newer destination state."
            )
    if archived["sso_provider_id"] != (
        str(current.sso_provider_id) if current.sso_provider_id else None
    ):
        _fail()
    if current_grants != archived_grants:
        raise AccountSecurityFormatError(
            "Account site permissions conflict with destination state."
        )
    for field in USER_SEEDS:
        existing = getattr(current, field)
        plain = decrypt_field(existing) if existing is not None else None
        require_portable_seed(plain)
        if archived[field] != plain:
            raise AccountSecurityFormatError("Account MFA state conflicts with destination state.")
    _integer(current.token_version, 2**31 - 2)
    _integer(current.failed_login_attempts, 2**31 - 1)
    _integer(current.mfa_last_totp_step, 2**63 - 1, nullable=True)
    _boolean(current.is_active)
    _boolean(current.is_verified)
    row = dict(archived)
    row["is_active"] = row["is_active"] and current.is_active
    row["is_verified"] = row["is_verified"] and current.is_verified
    row["failed_login_attempts"] = max(row["failed_login_attempts"], current.failed_login_attempts)
    for field in ("locked_until", "last_login"):
        times = [t for t in (_time(row[field]), _time(getattr(current, field))) if t is not None]
        row[field] = max(times).isoformat() if times else None
    steps = [s for s in (row["mfa_last_totp_step"], current.mfa_last_totp_step) if s is not None]
    row["mfa_last_totp_step"] = max(steps) if steps else None
    for field in ("mfa_backup_codes", "mfa_pending_backup_codes"):
        archived_codes = require_backup_code_hashes(row[field])
        existing_raw = getattr(current, field)
        existing_codes = require_backup_code_hashes(existing_raw)
        # None and [] both forbid reinstating an archived code, but their
        # distinct stored states are retained for future consistency checks.
        if existing_codes is None or archived_codes is None:
            row[field] = None
        else:
            remaining = set(archived_codes)
            row[field] = json.dumps([code for code in existing_codes if code in remaining])
    return row


def require_same_provider_security(archived: dict[str, Any], current: SSOProvider) -> None:
    """Refuse an older provider's credential, trust or authority configuration."""
    descriptive = {"id", "organization_id", "name", "description", "icon_url", "display_order"}
    for field in PROVIDER_FIELDS:
        if field in descriptive:
            continue
        value = getattr(current, field)
        if field in ("protocol", "status"):
            value = value.value
        if field in PROVIDER_SECRETS and value is not None:
            value = decrypt_field(value)
        if value != archived[field]:
            raise AccountSecurityFormatError(
                "Provider security conflicts with newer destination state."
            )
