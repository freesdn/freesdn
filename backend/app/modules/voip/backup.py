# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""VoIP backup contributor — PBX systems, extensions, ring groups,
config templates (NOT call logs / voicemail recordings).

This is the first MODULE-OWNED backup contributor (the Core one lives
centrally because it crosses module boundaries). It demonstrates the
full pattern module authors follow: a self-contained collect/restore
implementation registered via ``VoIPModule.get_backup_contributor()``.

Scope (the audit's "VoIP — PBX systems, extensions, ring groups,
voicemail config NOT recordings"):

  Included (portable configuration):
    - ``voip.pbx``             — PBX systems (secrets redacted)
    - ``voip.extensions``      — extensions incl. voicemail_enabled flag
    - ``voip.ring_groups``     — ring groups + membership
    - ``voip.config_templates`` — phone provisioning templates

  Excluded (transient / sensitive / instance-tied):
    - ``voip.call_logs``       — CDRs are operational telemetry, not config
    - ``voip.voicemail_messages`` — recordings, not config
    - ``voip.phones``          — physical-device discovery state, re-discovered
    - PBX ``*_enc`` columns    — Fernet ciphertexts tied to this instance's
                                  SECRET_KEY; useless on restore elsewhere AND
                                  a credential-exfil risk in a portable archive
    - ``extensions.voicemail_pin`` — a credential
    - any secret-shaped key inside the ``settings`` JSONB blobs

Tenant scoping: PBX + ConfigTemplate carry ``site_id`` (→ core.sites →
organization_id). Extensions + RingGroups FK to ``pbx_id``. Every
collect query filters to the caller's org via the site join; every
restore verifies the target site / pbx belongs to the caller's org
before writing (mirrors the Core contributor's tenant-isolation
invariants).

Restore order (FK dependency): PBX first (needs a Site, restored by the
``core`` contributor via ``depends_on=("core",)``), THEN extensions +
ring groups (need a PBX), THEN config templates (need a Site).
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import select

from app.services.backup_contributors import (
    ContributorPayload,
    NullableFK,
    RejectGuard,
    RestoreResult,
    restore_records,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


# Secret-shaped keys stripped from every settings/feature JSONB blob
# before it enters the archive. Superset of the VoIP service's own
# ``_SENSITIVE_SETTINGS_KEYS`` / ``_GENERIC_SENSITIVE_CACHE_KEYS`` so a
# new secret key added to settings can't silently leak into a backup.
_SECRET_SETTINGS_KEYS = frozenset(
    {
        "api_password",
        "api_key",
        "ami_secret",
        "ami_password",
        "ari_password",
        "web_password",
        "sip_password",
        "sip_secret",
        "secret",
        "password",
        "passwd",
        "ha1",
        "md5secret",
        "auth_password",
        "admin_password",
        "xml_password",
        "pjsip_password",
        "pjsip_secret",
        "authpassword",
        "api_client_secret",
        "client_secret",
        "token",
        "access_token",
        "refresh_token",
        "private_key",
    }
)


def _redact(blob: Any) -> Any:
    """Recursively drop secret-shaped keys from a JSONB value.

    Lists are walked element-wise (PBX/template settings nest dicts in
    lists — e.g. ``admin_users``, ``line_key_settings``). Non-container
    values pass through. Keys are matched case-insensitively against
    ``_SECRET_SETTINGS_KEYS``; the value is DROPPED (not masked) so the
    archive carries no trace of the secret's length or presence.
    """
    if isinstance(blob, dict):
        return {k: _redact(v) for k, v in blob.items() if k.lower() not in _SECRET_SETTINGS_KEYS}
    if isinstance(blob, list):
        return [_redact(v) for v in blob]
    return blob


# PBX secret columns, each encrypted INDIVIDUALLY via encrypt_credential (models.py).
# Excluded from a config snapshot; for a vault they're decrypted into the
# passphrase-sealed payload and re-encrypted under the target key at restore.
_PBX_SECRET_ENC_FIELDS = (
    "sip_password_enc",
    "admin_password_enc",
    "xml_password_enc",
    "ami_secret_enc",
    "ari_password_enc",
    "web_password_enc",
    "api_client_secret_enc",
)


def _vault_dec(value: Any) -> Any:
    """Decrypt a single encrypt_credential field for a vault payload (pass through
    plaintext / empty)."""
    from app.core.crypto import decrypt_credential, is_encrypted

    return decrypt_credential(value) if (isinstance(value, str) and is_encrypted(value)) else value


def _settings_for(blob: Any, include_secrets: bool) -> Any:
    """Vault keeps settings intact (sealed); config snapshot redacts secret keys."""
    return (blob or {}) if include_secrets else _redact(blob or {})


class VoipBackupContributor:
    """Backup/restore for the VoIP module's portable configuration."""

    contributor_id: str = "voip"
    schema_version: str = "1.0.0"
    # Extensions / config templates reference sites + the core contributor
    # restores sites first. PBX rows also reference sites.
    depends_on: tuple[str, ...] = ("core",)
    default_included: bool = True

    # ── collect ────────────────────────────────────────────────────────

    async def collect(
        self,
        session: AsyncSession,
        organization_id: UUID,
        options: dict[str, Any],
    ) -> ContributorPayload:
        from app.models.core import Site
        from app.modules.voip.models import (
            PBX,
            ConfigTemplate,
            Extension,
            RingGroup,
        )

        site_filter = options.get("site_id")
        include_secrets = bool(options.get("include_secrets", False))

        # --- PBX (org-scoped via Site join) ---
        pbx_q = (
            select(PBX)
            .join(Site, PBX.site_id == Site.id)
            .where(
                Site.organization_id == organization_id,
                Site.deleted_at.is_(None),
                PBX.deleted_at.is_(None),
            )
        )
        if site_filter:
            pbx_q = pbx_q.where(PBX.site_id == site_filter)
        pbx_rows = (await session.execute(pbx_q)).scalars().all()
        pbx_ids = [p.id for p in pbx_rows]

        pbx_data = [
            {
                "id": str(p.id),
                "site_id": str(p.site_id),
                "name": p.name,
                "description": p.description,
                "pbx_type": p.pbx_type,
                "ip_address": p.ip_address,
                "api_port": p.api_port,
                "sip_port": p.sip_port,
                "is_active": p.is_active,
                # api_client_id is opaque-but-not-secret (like a username);
                # safe to carry so the restored PBX keeps its OAuth app id.
                "api_client_id": p.api_client_id,
                "tls_verify_disabled_acknowledged": p.tls_verify_disabled_acknowledged,
                # Config snapshot: *_enc secrets excluded (operator re-enters). Vault:
                # decrypted into the passphrase-sealed payload; re-encrypted at restore.
                **(
                    {f: _vault_dec(getattr(p, f, None)) for f in _PBX_SECRET_ENC_FIELDS}
                    if include_secrets
                    else {}
                ),
                "settings": _settings_for(p.settings, include_secrets),
            }
            for p in pbx_rows
        ]

        # --- Extensions (scoped via pbx_id IN org's PBXes) ---
        ext_data: list[dict[str, Any]] = []
        if pbx_ids:
            ext_rows = (
                (
                    await session.execute(
                        select(Extension).where(
                            Extension.pbx_id.in_(pbx_ids),
                            Extension.deleted_at.is_(None),
                        )
                    )
                )
                .scalars()
                .all()
            )
            ext_data = [
                {
                    "id": str(e.id),
                    "pbx_id": str(e.pbx_id),
                    # user_id is carried but verified on restore (the user
                    # must exist in the target org or it's nulled).
                    "user_id": str(e.user_id) if e.user_id else None,
                    "extension_number": e.extension_number,
                    "display_name": e.display_name,
                    "caller_id_name": e.caller_id_name,
                    "caller_id_number": e.caller_id_number,
                    # voicemail_enabled is config; voicemail_pin is a credential —
                    # excluded from a config snapshot, included (plaintext) in a vault.
                    "voicemail_enabled": e.voicemail_enabled,
                    **({"voicemail_pin": e.voicemail_pin} if include_secrets else {}),
                    "is_active": e.is_active,
                    "settings": _settings_for(e.settings, include_secrets),
                }
                for e in ext_rows
            ]

        # --- Ring groups (scoped via pbx_id) ---
        rg_data: list[dict[str, Any]] = []
        if pbx_ids:
            rg_rows = (
                (
                    await session.execute(
                        select(RingGroup).where(
                            RingGroup.pbx_id.in_(pbx_ids),
                            RingGroup.deleted_at.is_(None),
                        )
                    )
                )
                .scalars()
                .all()
            )
            rg_data = [
                {
                    "id": str(r.id),
                    "pbx_id": str(r.pbx_id),
                    "name": r.name,
                    "description": r.description,
                    "group_number": r.group_number,
                    "ring_strategy": r.ring_strategy,
                    "ring_time": r.ring_time,
                    "members": r.members or [],
                    "is_active": r.is_active,
                    "settings": _redact(r.settings or {}),
                }
                for r in rg_rows
            ]

        # --- Config templates (org-scoped via Site join) ---
        ct_q = (
            select(ConfigTemplate)
            .join(Site, ConfigTemplate.site_id == Site.id)
            .where(
                Site.organization_id == organization_id,
                Site.deleted_at.is_(None),
                ConfigTemplate.deleted_at.is_(None),
            )
        )
        if site_filter:
            ct_q = ct_q.where(ConfigTemplate.site_id == site_filter)
        ct_rows = (await session.execute(ct_q)).scalars().all()
        ct_data = [
            {
                "id": str(c.id),
                "site_id": str(c.site_id),
                "name": c.name,
                "description": c.description,
                "vendor": c.vendor,
                "model_pattern": c.model_pattern,
                "is_default": c.is_default,
                "sip_settings": _redact(c.sip_settings or {}),
                "network_settings": _redact(c.network_settings or {}),
                "provisioning_settings": _redact(c.provisioning_settings or {}),
                # feature_settings often carries admin_password — redacted.
                "feature_settings": _redact(c.feature_settings or {}),
                "line_key_settings": _redact(c.line_key_settings or []),
                "raw_overrides": _redact(c.raw_overrides or {}),
                "firmware_version": c.firmware_version,
            }
            for c in ct_rows
        ]

        data = {
            "pbx": pbx_data,
            "extensions": ext_data,
            "ring_groups": rg_data,
            "config_templates": ct_data,
        }
        counts = {k: len(v) for k, v in data.items()}

        return ContributorPayload(
            schema_version=self.schema_version,
            counts=counts,
            data=data,
            metadata={
                "captured_at": time.time(),
                "source": "voip_contributor.collect",
                "secrets_excluded": True,
            },
        )

    # ── restore ────────────────────────────────────────────────────────

    async def restore(
        self,
        session: AsyncSession,
        organization_id: UUID,
        payload: ContributorPayload,
        *,
        dry_run: bool,
        options: dict[str, Any],
    ) -> RestoreResult:
        from app.models.core import Site, User
        from app.modules.voip.models import (
            PBX,
            ConfigTemplate,
            Extension,
            RingGroup,
        )

        start = time.monotonic()
        result = RestoreResult(
            contributor_id=self.contributor_id,
            status="dry_run_ok" if dry_run else "ok",
        )
        overwrite = options.get("overwrite_existing", False)
        include_secrets = bool(options.get("include_secrets", False))
        data = payload.data

        # Vault restore: the PBX *_enc fields arrived DECRYPTED in the passphrase-sealed
        # payload. Re-encrypt them under THIS instance's key before they touch the DB.
        if include_secrets:
            from app.core.crypto import encrypt_credential, is_encrypted

            for rec in data.get("pbx", []):
                for f in _PBX_SECRET_ENC_FIELDS:
                    v = rec.get(f)
                    if isinstance(v, str) and v and not is_encrypted(v):
                        rec[f] = encrypt_credential(v)

        # Pre-load the set of site ids that belong to this org — every
        # PBX / ConfigTemplate restore must reference one of these or
        # it's rejected as cross-tenant.
        org_site_ids = {
            str(s)
            for s in (
                await session.execute(
                    select(Site.id).where(
                        Site.organization_id == organization_id,
                        Site.deleted_at.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        }
        # User ids (for nulling dangling extension.user_id references).
        valid_user_ids = {str(u) for u in (await session.execute(select(User.id))).scalars().all()}

        # --- PBX first (FK target for extensions + ring groups) ---
        # blocked_fields mirrors the Core contributor's policy: never let
        # a restore overwrite identity / encrypted columns. PBX secrets
        # are already absent from the archive; this is belt-and-braces.
        restored_pbx_ids = await restore_records(
            session,
            model_cls=PBX,
            records=data.get("pbx", []),
            result=result,
            resource="pbx",
            dry_run=dry_run,
            overwrite=overwrite,
            reject_guards=[RejectGuard("site_id", org_site_ids, "cross-tenant")],
            # Config snapshot blocks the *_enc secrets (belt-and-braces; they aren't in
            # the archive anyway). Vault restores them (re-encrypted above).
            blocked_fields=(
                set()
                if include_secrets
                else {
                    "ami_secret_enc",
                    "ari_password_enc",
                    "web_password_enc",
                    "api_client_secret_enc",
                }
            ),
        )

        # --- Extensions (need a valid pbx_id; null dangling user_id) ---
        await restore_records(
            session,
            model_cls=Extension,
            records=data.get("extensions", []),
            result=result,
            resource="extensions",
            dry_run=dry_run,
            overwrite=overwrite,
            reject_guards=[RejectGuard("pbx_id", restored_pbx_ids, "orphan")],
            nullable_fks=[NullableFK("user_id", valid_user_ids)],
            blocked_fields=(set() if include_secrets else {"voicemail_pin"}),
        )

        # --- Ring groups (need a valid pbx_id) ---
        await restore_records(
            session,
            model_cls=RingGroup,
            records=data.get("ring_groups", []),
            result=result,
            resource="ring_groups",
            dry_run=dry_run,
            overwrite=overwrite,
            reject_guards=[RejectGuard("pbx_id", restored_pbx_ids, "orphan")],
        )

        # --- Config templates (org-scoped via site_id) ---
        await restore_records(
            session,
            model_cls=ConfigTemplate,
            records=data.get("config_templates", []),
            result=result,
            resource="config_templates",
            dry_run=dry_run,
            overwrite=overwrite,
            reject_guards=[RejectGuard("site_id", org_site_ids, "cross-tenant")],
        )

        if not dry_run:
            await session.flush()
        result.duration_sec = time.monotonic() - start
        return result


__all__ = ["VoipBackupContributor"]
