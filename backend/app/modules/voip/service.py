# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VoIP Module Service
=================================

Business logic for VoIP management — GDMS-style fleet operations.
"""

import asyncio
import contextlib
import logging
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import Integer, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_credential, encrypt_credential, is_encrypted

logger = logging.getLogger(__name__)


def _escape_like(value: str) -> str:
    """Escape SQL LIKE special characters to prevent pattern injection."""
    return value.replace("%", r"\%").replace("_", r"\_")


# Regex for validating AMI/SIP inputs — prevents CRLF injection
_SAFE_EXTENSION_RE = re.compile(r"^[0-9A-Za-z*#]+$")
_SAFE_CHANNEL_RE = re.compile(r"^(SIP|PJSIP|IAX2|Local|DAHDI)/[\w@/.\-]+$")
_ALLOWED_CONTEXTS = frozenset({"from-internal", "from-internal-additional"})


def _voip_live_writes_blocked() -> bool:
    """True (default-safe) when ``ADAPTER_READ_ONLY`` refuses live phone writes.

    The phone-control operations (reboot / factory-reset / SIP-config push)
    talk to the ``GrandstreamPhoneClient`` directly rather than through the
    adapter facade, so they must enforce the same read-only contract the
    adapter's gated write methods do. An approved staged-apply window
    (``apply_context``) still permits the write; otherwise live writes are
    refused unless the operator has cleared ``ADAPTER_READ_ONLY``.
    """
    try:
        from app.adapters.apply_context import in_apply_window
        from app.core.runtime_flags import is_adapter_read_only

        if in_apply_window():
            return False
        # Honor the LIVE Settings-UI/Redis read-only override (parity with every
        # other adapter + the staging service), not just the import-time env
        # default — so an operator's emergency "freeze writes" toggle covers VoIP.
        return is_adapter_read_only()
    except Exception:
        return True


# Fields that may be updated via generic setattr loops
_PBX_MUTABLE_FIELDS = frozenset(
    {
        "name",
        "description",
        "ip_address",
        "api_port",
        "sip_port",
        "pbx_type",
        "is_active",
        # OAuth2 + TLS-ack fields landed in the same PR as the
        # ``api_client_secret_enc`` column; ``api_client_id`` is plain.
        "api_client_id",
        "tls_verify_disabled_acknowledged",
    }
)
_EXTENSION_MUTABLE_FIELDS = frozenset(
    {
        "display_name",
        "caller_id_name",
        "caller_id_number",
        "voicemail_enabled",
        "voicemail_pin",
        "is_active",
        "settings",
    }
)
_PHONE_MUTABLE_FIELDS = frozenset(
    {
        "name",
        "mac_address",
        "model",
        "firmware_version",
        "sip_account",
        "sip_registrar",
        "location",
        "notes",
        "status",
        "is_active",
    }
)
_VOICEMAIL_MUTABLE_FIELDS = frozenset(
    {
        "is_read",
        "folder",
        "is_urgent",
    }
)

# Keys to strip from PBX settings before returning to the client
_SENSITIVE_SETTINGS_KEYS = frozenset(
    {
        "api_password",
        "api_key",
        "ami_secret",
        "ami_password",
        "ari_password",
        "web_password",
    }
)

# Credential fields that must be encrypted at rest
_CREDENTIAL_FIELDS = frozenset(
    {
        "api_password",
        "api_key",
        "ami_secret",
        "ami_password",
        "ari_password",
        "web_password",
    }
)

# Fields to strip from AMI manager data before caching
_AMI_MANAGER_SENSITIVE_KEYS = frozenset(
    {
        "secret",
        "password",
        "ha1",
        "md5secret",
    }
)

# Fields to strip from any synced-cache list of dicts before persisting.
# Applied to admin_users, ami_managers, trunks (PJSIP secrets) etc.
_GENERIC_SENSITIVE_CACHE_KEYS = frozenset(
    {
        "secret",
        "password",
        "ha1",
        "md5secret",
        "ari_password",
        "web_password",
        "sip_password",
        "auth_password",
        "admin_password",
        "xml_password",
        "pjsip_password",
        "pjsip_secret",
        "authpassword",
    }
)


def _scrub_cache_entries(items: Any) -> Any:
    """Recursively strip credential-like keys from a synced_cache value.

    Applied to every list-of-dicts and dict synced into ``pbx.settings.
    synced_cache``. Cache data is round-tripped to the UI on read, so
    plaintext credentials in here are a leak primitive. This function
    matches whatever ``redact_secrets`` would strip from a controller
    response — keeping the local cache in lock-step.
    """
    if isinstance(items, dict):
        return {
            k: ("***" if k.lower() in _GENERIC_SENSITIVE_CACHE_KEYS else _scrub_cache_entries(v))
            for k, v in items.items()
        }
    if isinstance(items, list):
        return [_scrub_cache_entries(i) for i in items]
    return items


def _encrypt_settings_credentials(settings: dict[str, Any]) -> dict[str, Any]:
    """Encrypt credential fields in a settings dict before DB persistence."""
    out = dict(settings)
    for key in _CREDENTIAL_FIELDS:
        if key in out and out[key] and not is_encrypted(str(out[key])):
            out[key] = encrypt_credential(str(out[key]))
    return out


def _decrypt_settings_credentials(settings: dict[str, Any]) -> dict[str, Any]:
    """Decrypt credential fields in a settings dict for runtime use."""
    out = dict(settings)
    for key in _CREDENTIAL_FIELDS:
        if key in out and out[key] and is_encrypted(str(out[key])):
            try:
                out[key] = decrypt_credential(str(out[key]))
            except ValueError:
                logger.warning("Failed to decrypt %s — may be plaintext", key)
    return out


def _decrypt_or_legacy(enc_value: str | None, legacy_value: str | None) -> str:
    """Resolve a credential from either the encrypted column or the legacy JSONB key.

    During the v2.6.0 to v2.7.0 migration window, existing PBX rows
    will have the credential in BOTH places: the new
    ``*_password_enc`` column (Fernet) and the legacy
    ``settings.api_password`` key. The original
    ``014_voip_secrets_encrypted`` migration (since squashed into the
    ``001_initial`` baseline) stripped the JSONB copy, but in-place
    upgrades from that era may still hit a partially-
    migrated row. We prefer the encrypted column when it's set,
    fall back to legacy plaintext otherwise.
    """
    if enc_value:
        try:
            return decrypt_credential(enc_value)
        except ValueError:
            logger.warning("Encrypted credential column failed to decrypt — falling back to legacy")
    return str(legacy_value or "")


def _sanitize_pbx_settings(settings: dict[str, Any] | None) -> dict[str, Any]:
    """Remove sensitive credential fields from settings before API response."""
    if not settings:
        return {}
    return {k: v for k, v in settings.items() if k not in _SENSITIVE_SETTINGS_KEYS}


def _validate_extension_input(value: str, label: str = "extension") -> str:
    """Validate extension/destination input against CRLF and injection."""
    if not _SAFE_EXTENSION_RE.match(value):
        raise VoIPError(f"Invalid {label}: must contain only digits, *, #")
    return value


def _validate_channel_input(value: str) -> str:
    """Validate AMI channel name."""
    if not _SAFE_CHANNEL_RE.match(value):
        raise VoIPError("Invalid channel format")
    return value


def _validate_context(value: str) -> str:
    """Validate Asterisk dial context against allowlist."""
    if value not in _ALLOWED_CONTEXTS:
        raise VoIPError(f"Invalid context: {value}")
    return value


# =============================================================================
# Exceptions
# =============================================================================


class VoIPError(Exception):
    """Base VoIP error."""

    pass


class CrossTenantError(VoIPError):
    """A client-supplied FK references a row outside the caller's organization.

    Mirrors the access_control module's CrossTenantError. Endpoints map this
    to HTTP 404 (not 403) to avoid leaking the existence of foreign rows.
    """

    pass


class PhoneNotFoundError(VoIPError):
    """Phone not found."""

    def __init__(self, phone_id: UUID):
        super().__init__(f"Phone not found: {phone_id}")


class PBXNotFoundError(VoIPError):
    """PBX not found."""

    def __init__(self, pbx_id: UUID):
        super().__init__(f"PBX not found: {pbx_id}")


class VoicemailNotFoundError(VoIPError):
    """Voicemail not found."""

    def __init__(self, vm_id: UUID):
        super().__init__(f"Voicemail not found: {vm_id}")


class DiscoveryScanNotFoundError(VoIPError):
    """Discovery scan not found."""

    def __init__(self, scan_id: UUID):
        super().__init__(f"Discovery scan not found: {scan_id}")


# =============================================================================
# VoIP Service
# =============================================================================


class VoIPService:
    """Service for VoIP management — GDMS-style fleet operations."""

    def __init__(
        self,
        db: AsyncSession,
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | None = None,
    ):
        self.db = db
        self.organization_id = organization_id
        # when set (site-limited caller), phone reads/lists are
        # further restricted to these sites. None = no per-site restriction.
        self.accessible_site_ids = accessible_site_ids

    def _sites_for_org(self):
        """Subquery of site IDs for the current organization.

        when the caller is site-limited
        (``accessible_site_ids`` set), the subquery is further narrowed to
        the granted sites. Because nearly every site-scoped VoIP query
        (``_pbx_ids_for_org``, ``get_pbx``, ``list_pbx_systems``, the
        ``_assert_*_in_org`` FK guards, bulk reboot, PBX enterprise reads)
        flows through this subquery, this single intersection enforces the
        per-user site grant across the whole module. It is a no-op for
        super_admin / org_admin (``accessible_site_ids`` is ``None``).
        """
        from app.models.core import Site

        query = select(Site.id).where(
            Site.organization_id == self.organization_id,
            Site.deleted_at.is_(None),
        )
        if self.accessible_site_ids is not None:
            query = query.where(Site.id.in_(self.accessible_site_ids))
        return query.subquery()

    def _require_org(self) -> None:
        """Raise if no organization context."""
        if not self.organization_id:
            raise ValueError("Organization context required for this operation")

    async def _audit_device_mutation(
        self,
        *,
        action: Any,
        resource_id: UUID | None = None,
        resource_name: str | None = None,
        extra_metadata: dict[str, Any] | None = None,
        status: str = "success",
    ) -> None:
        """Write a durable audit-log record for a live VoIP device mutation.

        These device-control operations (extension/ring-group delete, phone
        reboot / factory-reset / SIP push) talk to the vendor adapter directly
        rather than through ``AdapterStagingService``, so the staged-write
        audit trail never sees them. Persist an ``AuditLogRecord`` here so the
        mutation is non-repudiable. Actor / org / IP are pulled from the
        request context automatically by ``AuditService.log``. Best-effort:
        an audit failure must never mask or roll back the operation result, so
        it is swallowed (the real write already happened on the device).
        """
        try:
            from app.services.audit import AuditService, ResourceType

            await AuditService(self.db).log(
                action=action,
                resource_type=ResourceType.DEVICE,
                resource_id=resource_id,
                resource_name=resource_name,
                organization_id=self.organization_id,
                status=status,
                tags=["voip", "device-mutation"],
                extra_metadata=extra_metadata or {},
            )
            await self.db.commit()
        except Exception as exc:  # noqa: BLE001 - audit must not break the op
            logger.warning("Failed to write VoIP device-mutation audit record: %s", exc)
            with contextlib.suppress(Exception):
                await self.db.rollback()

    def _pbx_ids_for_org(self):
        """Subquery of PBX IDs belonging to the current organization's sites."""
        from app.modules.voip.models import PBX

        return (
            select(PBX.id)
            .where(
                PBX.site_id.in_(select(self._sites_for_org().c.id)),
                PBX.deleted_at.is_(None),
            )
            .subquery()
        )

    def _pbx_ids_for_site(self, site_id: UUID):
        """Subquery of PBX IDs at the given site.

        Used to scope PBX-child lists (extensions, ring_groups,
        call_logs, voicemails) by site even though those tables
        only carry pbx_id, not site_id directly.

        Layered query: callers should AND this subquery into any
        ``pbx_id IN (...)`` predicate, so multiple filters stack
        correctly. ``deleted_at IS NULL`` keeps soft-deleted PBXes
        out of the scope.
        """
        from app.modules.voip.models import PBX

        return (
            select(PBX.id)
            .where(
                PBX.site_id == site_id,
                PBX.deleted_at.is_(None),
            )
            .subquery()
        )

    # -------------------------------------------------------------------------
    # Cross-tenant FK guards
    #
    # PhoneCreate / PhoneOnboardRequest carry client-supplied site_id, pbx_id,
    # extension_id and config_template_id. FK constraints only validate row
    # EXISTENCE, not organization ownership, so without these guards a
    # site_admin in org A could bind a phone to org B's site/PBX/extension/
    # template (cross-tenant write + reference injection). These mirror the
    # access_control module's _assert_*_in_org helpers.
    # -------------------------------------------------------------------------

    async def _assert_site_in_org(self, site_id: UUID) -> None:
        """Reject a site_id outside the caller's org OR per-user site grant.

        the previous implementation checked only
        ``Site.organization_id`` and ignored ``accessible_site_ids``, so a
        site-limited operator (``site_admin`` with ``voip.manage_phones``)
        could place a phone into a SIBLING site of the same org by supplying
        its ``site_id``. The sibling FK guards (``_assert_pbx_in_org`` /
        ``_assert_extension_in_org`` / ``_assert_config_template_in_org``)
        already route through ``_sites_for_org()`` which intersects the grant;
        only this one bypassed it. Resolve the site through the same
        grant-aware subquery so the membership check covers both org AND the
        per-user grant. No-op for super_admin / org_admin
        (``accessible_site_ids`` is ``None``).
        """
        if not self.organization_id:
            return

        result = await self.db.execute(
            select(self._sites_for_org().c.id).where(self._sites_for_org().c.id == site_id)
        )
        if result.scalar_one_or_none() is None:
            raise CrossTenantError(f"site_id {site_id} is not in your organization")

    async def _assert_pbx_in_org(self, pbx_id: UUID) -> None:
        """Reject a pbx_id whose site is outside the caller's org."""
        if not self.organization_id:
            return
        from app.modules.voip.models import PBX

        result = await self.db.execute(
            select(PBX.id).where(
                PBX.id == pbx_id,
                PBX.deleted_at.is_(None),
                PBX.site_id.in_(select(self._sites_for_org().c.id)),
            )
        )
        if result.scalar_one_or_none() is None:
            raise CrossTenantError(f"pbx_id {pbx_id} is not in your organization")

    async def _assert_extension_in_org(self, extension_id: UUID) -> None:
        """Reject an extension_id whose PBX/site is outside the caller's org."""
        if not self.organization_id:
            return
        from app.modules.voip.models import Extension

        result = await self.db.execute(
            select(Extension.id).where(
                Extension.id == extension_id,
                Extension.deleted_at.is_(None),
                Extension.pbx_id.in_(select(self._pbx_ids_for_org().c.id)),
            )
        )
        if result.scalar_one_or_none() is None:
            raise CrossTenantError(f"extension_id {extension_id} is not in your organization")

    async def _assert_config_template_in_org(self, config_template_id: UUID) -> None:
        """Reject a config_template_id whose site is outside the caller's org."""
        if not self.organization_id:
            return
        from app.modules.voip.models import ConfigTemplate

        result = await self.db.execute(
            select(ConfigTemplate.id).where(
                ConfigTemplate.id == config_template_id,
                ConfigTemplate.deleted_at.is_(None),
                ConfigTemplate.site_id.in_(select(self._sites_for_org().c.id)),
            )
        )
        if result.scalar_one_or_none() is None:
            raise CrossTenantError(
                f"config_template_id {config_template_id} is not in your organization"
            )

    async def _assert_phone_fks_in_org(self, data: dict[str, Any]) -> None:
        """Validate every tenant-scoped FK present in a phone create/onboard payload."""
        if data.get("site_id") is not None:
            await self._assert_site_in_org(data["site_id"])
        if data.get("pbx_id") is not None:
            await self._assert_pbx_in_org(data["pbx_id"])
        if data.get("extension_id") is not None:
            await self._assert_extension_in_org(data["extension_id"])
        if data.get("config_template_id") is not None:
            await self._assert_config_template_in_org(data["config_template_id"])

    # -------------------------------------------------------------------------
    # Phone Management
    # -------------------------------------------------------------------------

    async def list_phones(
        self,
        site_id: UUID | None = None,
        pbx_id: UUID | None = None,
        status: str | None = None,
        lifecycle_state: str | None = None,
        vendor: str | None = None,
        config_template_id: UUID | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Any], int]:
        """List phones with optional filters. Returns (items, total_count)."""
        from app.modules.voip.models import Phone

        base = select(Phone).where(Phone.deleted_at.is_(None))

        # Organization isolation
        if self.organization_id:
            base = base.where(Phone.site_id.in_(select(self._sites_for_org().c.id)))
        # per-user site grant for list.
        if self.accessible_site_ids is not None:
            base = base.where(Phone.site_id.in_(self.accessible_site_ids))

        if site_id:
            base = base.where(Phone.site_id == site_id)
        if pbx_id:
            base = base.where(Phone.pbx_id == pbx_id)
        if status:
            base = base.where(Phone.status == status)
        if lifecycle_state:
            base = base.where(Phone.lifecycle_state == lifecycle_state)
        if vendor:
            base = base.where(Phone.vendor == vendor)
        if config_template_id:
            base = base.where(Phone.config_template_id == config_template_id)
        if search:
            pattern = f"%{_escape_like(search)}%"
            base = base.where(
                or_(
                    Phone.name.ilike(pattern, escape="\\"),
                    Phone.ip_address.ilike(pattern, escape="\\"),
                    Phone.mac_address.ilike(pattern, escape="\\"),
                    Phone.model.ilike(pattern, escape="\\"),
                    Phone.location.ilike(pattern, escape="\\"),
                )
            )

        # Total count (without limit/offset)
        count_result = await self.db.execute(select(func.count()).select_from(base.subquery()))
        total = count_result.scalar_one()

        query = base.order_by(Phone.name).limit(limit).offset(offset)
        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def get_phone(self, phone_id: UUID) -> Any:
        """Get a phone by ID."""
        from app.modules.voip.models import Phone

        query = select(Phone).where(
            Phone.id == phone_id,
            Phone.deleted_at.is_(None),
        )

        # Organization isolation
        if self.organization_id:
            query = query.where(Phone.site_id.in_(select(self._sites_for_org().c.id)))
        # per-user site grant (covers all phone get/action routes).
        if self.accessible_site_ids is not None:
            query = query.where(Phone.site_id.in_(self.accessible_site_ids))

        result = await self.db.execute(query)
        phone = result.scalar_one_or_none()

        if not phone:
            raise PhoneNotFoundError(phone_id)

        return phone

    async def get_phone_by_mac(self, mac_address: str) -> Any | None:
        """Get a phone by MAC address (returns None if not found)."""
        from app.modules.voip.models import Phone

        normalized = mac_address.replace("-", "").replace(".", "").lower()
        colon_mac = ":".join(normalized[i : i + 2] for i in range(0, 12, 2))

        query = select(Phone).where(
            Phone.mac_address == colon_mac,
            Phone.deleted_at.is_(None),
        )

        # Organization isolation
        if self.organization_id:
            query = query.where(Phone.site_id.in_(select(self._sites_for_org().c.id)))

        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def create_phone(self, data: dict[str, Any]) -> Any:
        """Create a new phone."""
        from app.modules.voip.models import Phone

        # every client-supplied FK must belong to the caller's org.
        await self._assert_phone_fks_in_org(data)

        phone = Phone(**data)
        self.db.add(phone)
        await self.db.commit()
        await self.db.refresh(phone)

        return phone

    async def update_phone(self, phone_id: UUID, data: dict[str, Any]) -> Any:
        """Update a phone."""
        phone = await self.get_phone(phone_id)

        for key, value in data.items():
            if key in _PHONE_MUTABLE_FIELDS and hasattr(phone, key):
                setattr(phone, key, value)

        await self.db.commit()
        await self.db.refresh(phone)

        return phone

    async def save_phone_credentials(self, phone_id: UUID, username: str, password: str) -> Any:
        """Save login credentials to a phone's settings JSONB field (encrypted)."""
        phone = await self.get_phone(phone_id)
        settings = phone.settings or {}
        settings["web_username"] = username
        settings["web_password"] = encrypt_credential(password)
        phone.settings = settings
        # Force SQLAlchemy to detect JSONB mutation
        from sqlalchemy.orm.attributes import flag_modified

        flag_modified(phone, "settings")
        await self.db.commit()
        await self.db.refresh(phone)
        return phone

    async def delete_phone(self, phone_id: UUID) -> bool:
        """Soft delete a phone."""
        phone = await self.get_phone(phone_id)
        phone.deleted_at = datetime.now(UTC)
        await self.db.commit()
        return True

    async def get_phone_stats(self, site_id: UUID | None = None) -> dict[str, int]:
        """Get phone statistics."""
        from app.modules.voip.models import Phone, PhoneStatus

        query = select(Phone.status, func.count(Phone.id)).where(Phone.deleted_at.is_(None))

        # Organization isolation
        if self.organization_id:
            query = query.where(Phone.site_id.in_(select(self._sites_for_org().c.id)))

        if site_id:
            query = query.where(Phone.site_id == site_id)

        query = query.group_by(Phone.status)

        result = await self.db.execute(query)
        stats = dict(result.all())

        return {
            "total": sum(stats.values()),
            "online": stats.get(PhoneStatus.ONLINE.value, 0),
            "offline": stats.get(PhoneStatus.OFFLINE.value, 0),
            "in_call": stats.get(PhoneStatus.IN_CALL.value, 0),
        }

    # -------------------------------------------------------------------------
    # Fleet Dashboard (GDMS-style)
    # -------------------------------------------------------------------------

    async def get_fleet_dashboard(self, site_id: UUID | None = None) -> dict[str, Any]:
        """Get comprehensive fleet dashboard metrics.

        Uses consolidated queries to minimize database round-trips.
        """
        from app.modules.voip.models import (
            Phone,
            PhoneStatus,
            ProvisionStatus,
        )

        base_filter = [Phone.deleted_at.is_(None)]

        # Organization isolation
        if self.organization_id:
            base_filter.append(Phone.site_id.in_(select(self._sites_for_org().c.id)))

        if site_id:
            base_filter.append(Phone.site_id == site_id)

        # ── Single-pass aggregation: status, SIP, recent, pending ──
        cutoff = datetime.now(UTC) - timedelta(hours=24)
        agg_q = select(
            func.count(Phone.id).label("total"),
            func.count(Phone.id).filter(Phone.sip_registered.is_(True)).label("sip_reg"),
            func.count(Phone.id).filter(Phone.sip_registered.is_(False)).label("sip_unreg"),
            func.count(Phone.id).filter(Phone.discovered_at >= cutoff).label("recent"),
            func.count(Phone.id)
            .filter(
                Phone.provision_status.in_(
                    [
                        ProvisionStatus.PENDING.value,
                        ProvisionStatus.STALE.value,
                    ]
                )
            )
            .label("pending"),
        ).where(*base_filter)
        agg_result = await self.db.execute(agg_q)
        agg = agg_result.one()

        # ── Breakdown queries (3 round-trips instead of 5) ──
        status_q = (
            select(Phone.status, func.count(Phone.id)).where(*base_filter).group_by(Phone.status)
        )
        lifecycle_q = (
            select(Phone.lifecycle_state, func.count(Phone.id))
            .where(*base_filter)
            .group_by(Phone.lifecycle_state)
        )
        vendor_q = (
            select(Phone.vendor, func.count(Phone.id))
            .where(*base_filter, Phone.vendor.isnot(None))
            .group_by(Phone.vendor)
        )
        model_q = (
            select(Phone.model, func.count(Phone.id))
            .where(*base_filter, Phone.model.isnot(None))
            .group_by(Phone.model)
        )
        fw_q = (
            select(Phone.firmware_version, func.count(Phone.id))
            .where(*base_filter, Phone.firmware_version.isnot(None))
            .group_by(Phone.firmware_version)
        )

        status_result = await self.db.execute(status_q)
        status_counts = dict(status_result.all())
        lifecycle_result = await self.db.execute(lifecycle_q)
        lifecycle_counts = dict(lifecycle_result.all())
        vendor_result = await self.db.execute(vendor_q)
        vendor_counts = dict(vendor_result.all())
        model_result = await self.db.execute(model_q)
        model_counts = dict(model_result.all())
        fw_result = await self.db.execute(fw_q)
        fw_counts = dict(fw_result.all())

        return {
            "total_phones": agg.total,
            "online": status_counts.get(PhoneStatus.ONLINE.value, 0),
            "offline": status_counts.get(PhoneStatus.OFFLINE.value, 0),
            "in_call": status_counts.get(PhoneStatus.IN_CALL.value, 0),
            "by_lifecycle": lifecycle_counts,
            "by_vendor": vendor_counts,
            "by_model": model_counts,
            "by_firmware": fw_counts,
            "sip_registered": agg.sip_reg,
            "sip_unregistered": agg.sip_unreg,
            "recently_discovered": agg.recent,
            "pending_provision": agg.pending,
        }

    # -------------------------------------------------------------------------
    # Device Lifecycle Management (GDMS-style)
    # -------------------------------------------------------------------------

    async def onboard_phone(
        self,
        phone_id: UUID,
        name: str | None = None,
        pbx_id: UUID | None = None,
        extension_id: UUID | None = None,
        config_template_id: UUID | None = None,
        location: str | None = None,
        tags: list[str] | None = None,
    ) -> Any:
        """
        Onboard a discovered phone into managed state.

        Transitions lifecycle: discovered → onboarding → managed.
        Optionally assigns PBX, extension, config template.
        """
        from app.modules.voip.models import PhoneLifecycleState, ProvisionStatus

        phone = await self.get_phone(phone_id)

        if phone.lifecycle_state not in (
            PhoneLifecycleState.DISCOVERED.value,
            PhoneLifecycleState.DECOMMISSIONED.value,
        ):
            raise VoIPError(
                f"Phone {phone_id} cannot be onboarded from state '{phone.lifecycle_state}'"
            )

        # get_phone() already org-scopes the target phone, but the
        # PBX / extension / config-template being assigned are client-supplied
        # and must also belong to the caller's org (reference injection guard).
        await self._assert_phone_fks_in_org(
            {
                "pbx_id": pbx_id,
                "extension_id": extension_id,
                "config_template_id": config_template_id,
            }
        )

        # Update fields
        phone.lifecycle_state = PhoneLifecycleState.ONBOARDING.value
        phone.onboarded_at = datetime.now(UTC)

        if name:
            phone.name = name
        if pbx_id:
            phone.pbx_id = pbx_id
        if extension_id:
            phone.extension_id = extension_id
        if config_template_id:
            phone.config_template_id = config_template_id
        if location:
            phone.location = location
        if tags is not None:
            phone.tags = tags

        phone.provision_status = ProvisionStatus.PENDING.value

        await self.db.commit()
        await self.db.refresh(phone)

        logger.info(
            "Onboarded phone %s (%s) — lifecycle → onboarding",
            phone.mac_address,
            phone.name,
        )
        return phone

    async def _grandstream_client_for_phone(self, phone: Any) -> Any:
        """Build a connected GrandstreamPhoneClient for the given phone.

        Centralises the credential lookup + ack-plaintext logic so
        reboot / factory_reset / live_status / push_sip_config all
        share the same connect path.

        Credentials are stored by ``save_phone_credentials`` into
        ``settings.web_password`` (Fernet-encrypted) — NOT in the
        ``admin_password_enc`` column (that column exists for an
        older Add-Phone form path). Look in the right place.
        """
        from app.adapters.grandstream.client import GrandstreamPhoneClient
        from app.core.crypto import decrypt_credential, is_encrypted

        if not phone.ip_address:
            raise VoIPError(f"Phone {phone.id} has no IP address")

        settings = phone.settings or {}
        enc_pw = settings.get("web_password")
        if not enc_pw:
            raise VoIPError(
                "Phone has no saved admin credentials — open the "
                "phone detail page and run Test Phone Connection "
                "with 'Save credentials' enabled first"
            )
        admin_pw = decrypt_credential(enc_pw) if is_encrypted(enc_pw) else enc_pw

        return GrandstreamPhoneClient(
            host=phone.ip_address,
            username=settings.get("web_username", "admin"),
            password=admin_pw,
            use_ssl=phone.use_ssl,
            acknowledge_plaintext=phone.acknowledge_plaintext,
        )

    async def reboot_phone(self, phone_id: UUID) -> dict[str, Any]:
        """Send a reboot command to the phone via the vendor adapter.

        The phone drops its HTTP socket as part of the reboot, so the
        adapter treats a mid-response disconnect as success. The phone
        record's ``last_reboot`` timestamp is updated on the way out.
        """
        phone = await self.get_phone(phone_id)
        if _voip_live_writes_blocked():
            raise VoIPError(
                "Refusing phone reboot: ADAPTER_READ_ONLY is set — set "
                "ADAPTER_READ_ONLY=false to allow live phone writes."
            )
        client = await self._grandstream_client_for_phone(phone)
        try:
            async with client:
                ok = await client.reboot()
        except Exception as exc:
            logger.warning(
                "reboot_phone failed for %s: %s",
                phone.ip_address,
                exc,
                exc_info=True,
            )
            raise VoIPError(f"Reboot failed: {type(exc).__name__}") from exc
        if ok:
            phone.last_reboot = datetime.now(UTC)
            await self.db.commit()
        await self._audit_device_mutation(
            action="reboot",
            resource_id=phone.id,
            resource_name=f"phone {phone.ip_address}",
            status="success" if ok else "failure",
            extra_metadata={"phone_ip": phone.ip_address},
        )
        return {
            "status": "success" if ok else "failed",
            "phone_id": str(phone.id),
            "phone_ip": phone.ip_address,
            "message": (
                f"Reboot command sent to {phone.ip_address}; the phone "
                "will be unavailable for ~30 seconds while it restarts."
                if ok
                else "Phone rejected the reboot command"
            ),
        }

    async def factory_reset_phone(self, phone_id: UUID) -> dict[str, Any]:
        """Send a factory-reset command. Destructive — wipes ALL config.

        Auto-clears the FreeSDN-side linkage as well — after a factory
        reset the phone has no SIP creds and will need to be re-onboarded.
        """
        phone = await self.get_phone(phone_id)
        if _voip_live_writes_blocked():
            raise VoIPError(
                "Refusing factory reset: ADAPTER_READ_ONLY is set — set "
                "ADAPTER_READ_ONLY=false to allow live phone writes."
            )
        client = await self._grandstream_client_for_phone(phone)
        try:
            async with client:
                ok = await client.factory_reset()
        except Exception as exc:
            logger.warning(
                "factory_reset_phone failed for %s: %s",
                phone.ip_address,
                exc,
                exc_info=True,
            )
            raise VoIPError(f"Factory reset failed: {type(exc).__name__}") from exc
        if ok:
            # Clear the linkage — the phone has no SIP config any more.
            phone.last_reboot = datetime.now(UTC)
            phone.sip_registered = False
            await self.db.commit()
        await self._audit_device_mutation(
            action="delete",
            resource_id=phone.id,
            resource_name=f"phone {phone.ip_address}",
            status="success" if ok else "failure",
            extra_metadata={"phone_ip": phone.ip_address, "operation": "factory_reset"},
        )
        return {
            "status": "success" if ok else "failed",
            "phone_id": str(phone.id),
            "phone_ip": phone.ip_address,
            "message": (
                f"Factory reset sent to {phone.ip_address}. The phone "
                "will reboot with default settings — re-onboard required."
                if ok
                else "Phone rejected the factory-reset command"
            ),
        }

    async def get_phone_live_status(self, phone_id: UUID) -> dict[str, Any]:
        """Cheap live-state probe — what's the phone doing RIGHT NOW.

        Returns phone_state ('available', 'in_call', 'ringing', ...),
        per-line activity, and lockout state. ~150-300 ms hot-path.

        Designed for FE polling at ~5 s intervals — does NOT update
        the DB so concurrent polls don't trample each other.
        """
        phone = await self.get_phone(phone_id)
        client = await self._grandstream_client_for_phone(phone)
        try:
            async with client:
                # Three small calls — total ~250 ms over the same session.
                from app.adapters.grandstream.constants import (
                    PHONE_API_GET_LINE_STATUS,
                    PHONE_API_GET_LOCKOUT,
                    PHONE_API_GET_PHONE_STATUS,
                )

                phone_state_resp = await client._request(
                    "GET",
                    PHONE_API_GET_PHONE_STATUS,
                )
                line_resp = await client._request(
                    "GET",
                    PHONE_API_GET_LINE_STATUS,
                )
                lockout_resp = await client._request(
                    "GET",
                    PHONE_API_GET_LOCKOUT,
                    include_sid=False,
                )
        except Exception as exc:
            logger.debug(
                "get_phone_live_status failed for %s: %s",
                phone.ip_address,
                exc,
            )
            raise VoIPError(f"Live status failed: {type(exc).__name__}") from exc

        # Normalise. Each GS endpoint returns a slightly different shape.
        phone_state = phone_state_resp.get("body") if isinstance(phone_state_resp, dict) else None
        lines = line_resp.get("body", []) if isinstance(line_resp, dict) else []
        lockout = lockout_resp.get("body") if isinstance(lockout_resp, dict) else None
        return {
            "phone_id": str(phone.id),
            "phone_ip": phone.ip_address,
            "phone_state": phone_state or "unknown",
            "active_lines": [
                {
                    "line": ln.get("line"),
                    "state": ln.get("state"),
                    "remote_name": ln.get("remotename"),
                    "remote_number": ln.get("remotenumber"),
                }
                for ln in (lines if isinstance(lines, list) else [])
                if ln.get("state") and ln.get("state") != "idle"
            ],
            "total_lines": len(lines) if isinstance(lines, list) else 0,
            "lockout": lockout or "unknown",
            "ts": datetime.now(UTC).isoformat(),
        }

    async def push_sip_config_to_phone(
        self,
        phone_id: UUID,
        *,
        sip_password: str,
        account_index: int = 1,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Push the bound extension's SIP credentials down to the phone.

        This is the FreeSDN → phone provisioning path (the inverse of
        the discovery/sync path). The phone must already be linked to
        a FreePBX extension (``phone.extension_id`` set via auto-link
        or manual onboard).

        Why the operator supplies the password: FreeSDN deliberately
        does NOT cache SIP secrets — the FreePBX adapter redacts them
        on the read path so they never land in our DB. For a one-shot
        provisioning event we want the secret to travel
        server-side-only: API → adapter → phone, never round-tripping
        through any persistent store.

        ``dry_run=True`` returns the P-value plan without writing.
        """
        from app.modules.voip.models import PBX, Extension

        phone = await self.get_phone(phone_id)
        if not phone.extension_id or not phone.pbx_id:
            raise VoIPError(
                f"Phone {phone_id} is not linked to a PBX extension — "
                "run auto-link first or pick an extension manually"
            )
        if not phone.ip_address:
            raise VoIPError(f"Phone {phone_id} has no IP address")

        # Refuse the live push under read-only (fail fast, before any DB
        # work). ``dry_run`` only previews the plan and writes nothing, so it
        # stays allowed. Same contract the adapter's write methods enforce —
        # this path talks to the GrandstreamPhoneClient directly so it gates here.
        if not dry_run and _voip_live_writes_blocked():
            raise VoIPError(
                "Refusing SIP-config push: ADAPTER_READ_ONLY is set — set "
                "ADAPTER_READ_ONLY=false to allow live phone writes (use "
                "dry_run=true to preview without writing)."
            )

        # Look up extension + PBX. Both already org-scoped via
        # get_phone, so the IDs are trusted.
        ext = (
            await self.db.execute(select(Extension).where(Extension.id == phone.extension_id))
        ).scalar_one_or_none()
        pbx = (
            await self.db.execute(select(PBX).where(PBX.id == phone.pbx_id))
        ).scalar_one_or_none()
        if not ext or not pbx:
            raise VoIPError("Phone bound to extension/PBX that no longer exists")

        # Grandstream P-value map for SIP account N (1-indexed):
        #   Account 1: P47 (server), P35 (user), P36 (auth_id),
        #              P34 (password), P3 (display), P271 (active),
        #              P48 (port).
        #   Account 2+ uses a stride of +100 (P147, P135, …) per the
        #   GS GXP21xx admin guide. For now we only support Account 1
        #   to keep the validated path narrow.
        if account_index != 1:
            raise VoIPError(
                f"account_index={account_index} not supported yet; "
                "only Account 1 push is implemented"
            )

        plan = {
            "P47": str(pbx.ip_address or ""),
            "P35": str(ext.extension_number),
            "P36": str(ext.extension_number),
            # ALWAYS redacted. `plan` is what goes back to the caller in the
            # HTTP response body; `write_plan` below is the only dict that ever
            # carries the real secret, and it never leaves this method.
            #
            # This used to read `"********" if dry_run else str(sip_password)`,
            # so the LIVE push -- the one an operator actually clicks -- returned
            # the SIP secret in cleartext, into the browser's react-query cache,
            # any HAR or devtools capture, and any reverse proxy or APM that
            # records response bodies. Only the dry run, which never carries a
            # secret worth protecting, was redacted. The two comments below
            # ("NEVER returned to the caller" and "password redacted before
            # returning") both described this intended behaviour rather than
            # what the code did.
            "P34": "********",
            "P3": str(ext.display_name or ext.extension_number),
            "P271": "1",
            "P48": "5060",
        }

        if dry_run:
            return {
                "status": "dry_run",
                "phone_id": str(phone.id),
                "phone_ip": phone.ip_address,
                "extension": ext.extension_number,
                "extension_display": ext.display_name,
                "pbx": pbx.name,
                "plan": plan,
                "message": (
                    f"Dry-run: would push extension {ext.extension_number} "
                    f"({ext.display_name}) → phone {phone.ip_address} "
                    f"as Account {account_index}. No write performed."
                ),
            }

        # Live write — connect via the same helper as reboot/live_status
        # so the credential-lookup logic stays in one place. The real
        # plan has the actual secret; build a new dict that's NEVER
        # returned to the caller.
        write_plan = {**plan, "P34": str(sip_password)}
        client = await self._grandstream_client_for_phone(phone)
        try:
            async with client:
                ok = await client.set_config(write_plan)
        except Exception as exc:
            logger.warning(
                "push_sip_config_to_phone failed for %s: %s",
                phone.ip_address,
                exc,
                exc_info=True,
            )
            raise VoIPError(f"Phone push failed: {type(exc).__name__}") from exc

        # Update last_provisioned_at so the UI reflects the operation.
        if ok:
            phone.last_provisioned_at = datetime.now(UTC)
            await self.db.commit()
            await self.db.refresh(phone)

        # Durable audit of the live SIP-credential push. The secret itself is
        # never recorded — only the device, extension and PBX identifiers.
        await self._audit_device_mutation(
            action="provision",
            resource_id=phone.id,
            resource_name=f"phone {phone.ip_address}",
            status="success" if ok else "failure",
            extra_metadata={
                "phone_ip": phone.ip_address,
                "extension": str(ext.extension_number),
                "pbx": pbx.name,
                "account_index": account_index,
                "operation": "sip_config_push",
            },
        )

        return {
            "status": "success" if ok else "failed",
            "phone_id": str(phone.id),
            "phone_ip": phone.ip_address,
            "extension": ext.extension_number,
            "extension_display": ext.display_name,
            "pbx": pbx.name,
            # Plan with the password redacted before returning.
            "plan": plan,
            "message": (
                f"Pushed extension {ext.extension_number} "
                f"({ext.display_name}) → phone {phone.ip_address} "
                f"as Account {account_index}"
                if ok
                else "Phone rejected the config_update write"
            ),
        }

    async def get_phones_by_extension_ids(self, ext_ids: set[UUID]) -> list[Any]:
        """Return all phones bound to any of the given extension IDs.

        Used by the PBX extensions listing to render bound-phone info
        per extension in one batched query (avoids N+1 detail-fetch
        from the FE).
        """
        from app.modules.voip.models import Phone

        if not ext_ids:
            return []
        q = select(Phone).where(
            Phone.extension_id.in_(ext_ids),
            Phone.deleted_at.is_(None),
        )
        if self.organization_id:
            q = q.where(Phone.site_id.in_(select(self._sites_for_org().c.id)))
        result = await self.db.execute(q)
        return list(result.scalars())

    async def get_pbx_systems_by_ids(self, pbx_ids: set[UUID]) -> dict[UUID, Any]:
        """Return ``{pbx_id: PBX}`` for the given IDs, org-scoped.

        Used by the phones list endpoint to batch-resolve the ``pbx.name``
        for each row so the UI can render bound-PBX info without N+1.
        """
        from app.modules.voip.models import PBX

        if not pbx_ids:
            return {}
        q = select(PBX).where(
            PBX.id.in_(pbx_ids),
            PBX.deleted_at.is_(None),
        )
        if self.organization_id:
            q = q.where(PBX.site_id.in_(select(self._sites_for_org().c.id)))
        result = await self.db.execute(q)
        return {p.id: p for p in result.scalars()}

    async def get_extensions_by_ids(self, ext_ids: set[UUID]) -> dict[UUID, Any]:
        """Return ``{extension_id: Extension}`` for the given IDs, org-scoped."""
        from app.modules.voip.models import PBX, Extension

        if not ext_ids:
            return {}
        q = select(Extension).where(
            Extension.id.in_(ext_ids),
            Extension.deleted_at.is_(None),
        )
        if self.organization_id:
            q = q.join(PBX, PBX.id == Extension.pbx_id).where(
                PBX.site_id.in_(select(self._sites_for_org().c.id))
            )
        result = await self.db.execute(q)
        return {e.id: e for e in result.scalars()}

    async def auto_link_phones_to_pbx(
        self,
        *,
        site_id: UUID | None = None,
        phone_ids: list[UUID] | None = None,
        onboard: bool = False,
    ) -> dict[str, Any]:
        """Match discovered phones to PBX extensions automatically.

        Linkage rule (deliberately simple so it's predictable):

          1. Phone's reported ``sip_registrar`` host must match a PBX
             record's ``ip_address`` (e.g. ``"pbx.example.com"``) in the
             same org.
          2. Phone's reported ``sip_user_id`` (from settings, populated
             at discovery time from the GS API ``user_id`` field) must
             match an Extension's ``extension_number`` for that PBX.

        Phones already linked to BOTH a pbx_id and extension_id are
        skipped. Conflicting matches (e.g. two PBXes serve the same
        host, or two extensions have the same number — should never
        happen, but defensively handled) skip and surface in
        ``conflicts``.

        ``onboard=True`` additionally promotes ``discovered`` phones
        to ``onboarding`` state so they're queued for provisioning.

        Returns a summary dict: linked / already_linked / skipped /
        conflicts with per-phone details.
        """
        from app.modules.voip.models import (
            PBX,
            Extension,
            Phone,
            PhoneLifecycleState,
            ProvisionStatus,
        )

        # Build a (pbx.ip_address → pbx_id) lookup, scoped to the
        # caller's org so we never reach across tenants.
        pbx_q = select(PBX).where(PBX.deleted_at.is_(None))
        if self.organization_id:
            pbx_q = pbx_q.where(PBX.site_id.in_(select(self._sites_for_org().c.id)))
        if site_id:
            pbx_q = pbx_q.where(PBX.site_id == site_id)
        pbx_result = await self.db.execute(pbx_q)
        pbxes = list(pbx_result.scalars())

        # registrar host → list of PBX records (defensive: usually 1)
        host_to_pbxes: dict[str, list[PBX]] = {}
        for p in pbxes:
            if p.ip_address:
                host_to_pbxes.setdefault(p.ip_address.lower(), []).append(p)

        # Pre-fetch all extensions for these PBXes — one query each.
        ext_lookup: dict[tuple[UUID, str], Extension] = {}
        if pbxes:
            ext_q = select(Extension).where(
                Extension.deleted_at.is_(None),
                Extension.pbx_id.in_([p.id for p in pbxes]),
            )
            ext_result = await self.db.execute(ext_q)
            for ext in ext_result.scalars():
                ext_lookup[(ext.pbx_id, str(ext.extension_number))] = ext

        # Now walk the candidate phones.
        phone_q = select(Phone).where(Phone.deleted_at.is_(None))
        if self.organization_id:
            phone_q = phone_q.where(Phone.site_id.in_(select(self._sites_for_org().c.id)))
        if site_id:
            phone_q = phone_q.where(Phone.site_id == site_id)
        if phone_ids:
            phone_q = phone_q.where(Phone.id.in_(phone_ids))
        phone_result = await self.db.execute(phone_q)
        phones = list(phone_result.scalars())

        linked: list[dict[str, Any]] = []
        already_linked: list[str] = []
        skipped: list[dict[str, Any]] = []
        conflicts: list[dict[str, Any]] = []

        for phone in phones:
            settings = phone.settings or {}
            registrar = (settings.get("sip_registrar") or phone.sip_server or "").lower().strip()
            sip_user = str(settings.get("sip_user_id") or "").strip()

            if not registrar or not sip_user:
                skipped.append(
                    {
                        "phone_id": str(phone.id),
                        "ip": phone.ip_address,
                        "reason": "no sip_registrar/sip_user_id captured at discovery",
                    }
                )
                continue

            # Already fully linked → leave it alone (idempotent re-run).
            if phone.pbx_id and phone.extension_id:
                already_linked.append(str(phone.id))
                continue

            candidates = host_to_pbxes.get(registrar, [])
            if not candidates:
                skipped.append(
                    {
                        "phone_id": str(phone.id),
                        "ip": phone.ip_address,
                        "reason": f"no PBX with ip_address={registrar!r}",
                    }
                )
                continue
            if len(candidates) > 1:
                conflicts.append(
                    {
                        "phone_id": str(phone.id),
                        "ip": phone.ip_address,
                        "reason": f"{len(candidates)} PBXes match host {registrar!r}",
                    }
                )
                continue
            pbx = candidates[0]

            ext = ext_lookup.get((pbx.id, sip_user))
            if not ext:
                skipped.append(
                    {
                        "phone_id": str(phone.id),
                        "ip": phone.ip_address,
                        "reason": f"no extension {sip_user!r} on PBX {pbx.name}",
                    }
                )
                continue

            # Link.
            phone.pbx_id = pbx.id
            phone.extension_id = ext.id
            if onboard and phone.lifecycle_state == PhoneLifecycleState.DISCOVERED.value:
                phone.lifecycle_state = PhoneLifecycleState.ONBOARDING.value
                phone.onboarded_at = datetime.now(UTC)
                phone.provision_status = ProvisionStatus.PENDING.value

            linked.append(
                {
                    "phone_id": str(phone.id),
                    "ip": phone.ip_address,
                    "mac": phone.mac_address,
                    "pbx": pbx.name,
                    "extension": ext.extension_number,
                    "extension_display": ext.display_name,
                }
            )
            logger.info(
                "Auto-linked phone %s (%s) → PBX %s ext %s (%s)",
                phone.ip_address,
                phone.mac_address,
                pbx.name,
                ext.extension_number,
                ext.display_name,
            )

        if linked:
            await self.db.commit()

        return {
            "linked": linked,
            "already_linked": already_linked,
            "skipped": skipped,
            "conflicts": conflicts,
            "counts": {
                "linked": len(linked),
                "already_linked": len(already_linked),
                "skipped": len(skipped),
                "conflicts": len(conflicts),
            },
        }

    async def mark_phone_managed(self, phone_id: UUID) -> Any:
        """Mark a phone as fully managed (post-provisioning)."""
        from app.modules.voip.models import PhoneLifecycleState

        phone = await self.get_phone(phone_id)
        phone.lifecycle_state = PhoneLifecycleState.MANAGED.value
        await self.db.commit()
        await self.db.refresh(phone)
        return phone

    async def decommission_phone(self, phone_id: UUID) -> Any:
        """Decommission a phone — remove from active management."""
        from app.modules.voip.models import PhoneLifecycleState

        phone = await self.get_phone(phone_id)
        phone.lifecycle_state = PhoneLifecycleState.DECOMMISSIONED.value
        phone.pbx_id = None
        phone.extension_id = None
        phone.config_template_id = None
        phone.provision_status = None

        await self.db.commit()
        await self.db.refresh(phone)
        logger.info("Decommissioned phone %s (%s)", phone.mac_address, phone.name)
        return phone

    async def set_maintenance_mode(self, phone_id: UUID, enabled: bool) -> Any:
        """Toggle maintenance mode on a phone."""
        from app.modules.voip.models import PhoneLifecycleState

        phone = await self.get_phone(phone_id)

        if enabled:
            phone.lifecycle_state = PhoneLifecycleState.MAINTENANCE.value
        else:
            # Return to managed if it was in maintenance
            if phone.lifecycle_state == PhoneLifecycleState.MAINTENANCE.value:
                phone.lifecycle_state = PhoneLifecycleState.MANAGED.value

        await self.db.commit()
        await self.db.refresh(phone)
        return phone

    # -------------------------------------------------------------------------
    # Discovery Scan Management
    # -------------------------------------------------------------------------

    async def create_discovery_scan(self, data: dict[str, Any]) -> Any:
        """Create a new discovery scan record."""
        from app.modules.voip.models import DiscoveryScan

        # FSDN-SG-003 (defence in depth): the route enforces the per-user site
        # grant on the supplied/auto-selected site, but fold it at the sink too
        # so the grant can never be bypassed by another caller of this service
        # method. No-op for super_admin / org_admin (accessible_site_ids None).
        if data.get("site_id") is not None:
            await self._assert_site_in_org(data["site_id"])

        scan = DiscoveryScan(**data)
        self.db.add(scan)
        await self.db.commit()
        await self.db.refresh(scan)
        return scan

    async def get_discovery_scan(self, scan_id: UUID) -> Any:
        """Get a discovery scan by ID (full record including results)."""
        from app.modules.voip.models import DiscoveryScan

        query = select(DiscoveryScan).where(DiscoveryScan.id == scan_id)

        # Organization isolation
        if self.organization_id:
            query = query.where(DiscoveryScan.site_id.in_(select(self._sites_for_org().c.id)))

        result = await self.db.execute(query)
        scan = result.scalar_one_or_none()
        if not scan:
            raise DiscoveryScanNotFoundError(scan_id)
        return scan

    async def get_discovery_scan_status(self, scan_id: UUID) -> dict[str, Any]:
        """Lightweight status query — skips heavy 'results' JSONB.

        Only loads the columns needed for progress polling, avoiding the
        potentially large results array.
        """
        from app.modules.voip.models import DiscoveryScan

        query = select(
            DiscoveryScan.id,
            DiscoveryScan.status,
            DiscoveryScan.devices_found,
            DiscoveryScan.started_at,
            DiscoveryScan.completed_at,
            DiscoveryScan.metadata_json,
            DiscoveryScan.error_message,
        ).where(DiscoveryScan.id == scan_id)

        # Organization isolation
        if self.organization_id:
            query = query.where(DiscoveryScan.site_id.in_(select(self._sites_for_org().c.id)))

        result = await self.db.execute(query)
        row = result.one_or_none()
        if not row:
            raise DiscoveryScanNotFoundError(scan_id)
        return {
            "id": row.id,
            "status": row.status,
            "devices_found": row.devices_found or 0,
            "started_at": row.started_at,
            "completed_at": row.completed_at,
            "metadata_json": row.metadata_json or {},
            "error_message": row.error_message,
        }

    async def cancel_discovery_scan(self, scan_id: UUID) -> Any:
        """Cancel a running/pending discovery scan."""
        from app.modules.voip.models import DiscoveryScan, ScanStatus

        query = select(DiscoveryScan).where(DiscoveryScan.id == scan_id)

        # Organization isolation
        if self.organization_id:
            query = query.where(DiscoveryScan.site_id.in_(select(self._sites_for_org().c.id)))

        result = await self.db.execute(query)
        scan = result.scalar_one_or_none()
        if not scan:
            raise DiscoveryScanNotFoundError(scan_id)

        if scan.status not in (ScanStatus.PENDING.value, ScanStatus.RUNNING.value):
            raise ValueError(f"Cannot cancel scan with status '{scan.status}'")

        scan.status = ScanStatus.CANCELLED.value
        scan.completed_at = datetime.now(UTC)
        scan.error_message = "Cancelled by user"
        meta = scan.metadata_json or {}
        meta["progress"] = {
            **(meta.get("progress") or {}),
            "phase": "cancelled",
            "message": "Scan cancelled by user",
        }
        scan.metadata_json = meta
        from sqlalchemy.orm.attributes import flag_modified

        flag_modified(scan, "metadata_json")
        await self.db.commit()
        await self.db.refresh(scan)
        return "Scan cancelled successfully"

    async def delete_discovery_scan(self, scan_id: UUID) -> None:
        """Permanently delete a discovery scan record."""
        from app.modules.voip.models import DiscoveryScan

        query = select(DiscoveryScan).where(DiscoveryScan.id == scan_id)

        # Organization isolation
        if self.organization_id:
            query = query.where(DiscoveryScan.site_id.in_(select(self._sites_for_org().c.id)))

        result = await self.db.execute(query)
        scan = result.scalar_one_or_none()
        if not scan:
            raise DiscoveryScanNotFoundError(scan_id)
        # Don't allow deletion of running scans
        if scan.status in ("running", "pending"):
            raise ValueError("Cannot delete a running or pending scan")
        await self.db.delete(scan)
        await self.db.commit()

    async def list_discovery_scans(
        self,
        site_id: UUID | None = None,
        status: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        """List discovery scans with optional filters.

        Returns (items, total) where items are lightweight dicts
        that EXCLUDE the heavy 'results' JSONB column.
        """
        from app.modules.voip.models import DiscoveryScan

        # Build filter conditions
        conditions = []

        # Organization isolation
        if self.organization_id:
            conditions.append(DiscoveryScan.site_id.in_(select(self._sites_for_org().c.id)))

        if site_id:
            conditions.append(DiscoveryScan.site_id == site_id)
        if status:
            conditions.append(DiscoveryScan.status == status)

        # Count query (single pass)
        count_q = select(func.count(DiscoveryScan.id))
        for cond in conditions:
            count_q = count_q.where(cond)
        total = (await self.db.execute(count_q)).scalar_one()

        # Select lightweight columns only — skip 'results' JSONB
        data_q = select(
            DiscoveryScan.id,
            DiscoveryScan.site_id,
            DiscoveryScan.scan_type,
            DiscoveryScan.subnet,
            DiscoveryScan.port_range,
            DiscoveryScan.status,
            DiscoveryScan.started_at,
            DiscoveryScan.completed_at,
            DiscoveryScan.devices_found,
            DiscoveryScan.new_devices,
            DiscoveryScan.updated_devices,
            DiscoveryScan.duration_seconds,
            DiscoveryScan.error_message,
            DiscoveryScan.created_at,
        )
        for cond in conditions:
            data_q = data_q.where(cond)
        data_q = data_q.order_by(DiscoveryScan.created_at.desc()).limit(limit).offset(offset)

        result = await self.db.execute(data_q)
        rows = result.all()

        items = [
            {
                "id": str(r.id),
                "site_id": str(r.site_id),
                "scan_type": r.scan_type,
                "subnet": r.subnet,
                "port_range": r.port_range,
                "status": r.status,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                "devices_found": r.devices_found or 0,
                "new_devices": r.new_devices or 0,
                "updated_devices": r.updated_devices or 0,
                "duration_seconds": r.duration_seconds or 0,
                "error_message": r.error_message,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]

        return items, total

    async def upsert_discovered_phone(
        self,
        site_id: UUID,
        ip_address: str,
        mac_address: str | None,
        vendor: str | None,
        model: str | None = None,
        firmware_version: str | None = None,
        serial_number: str | None = None,
        discovery_method: str = "arp_scan",
        *,
        sip_registered: bool = False,
        sip_account: str | None = None,
        sip_registrar: str | None = None,
        authenticated: bool = False,
        raw_data: dict[str, Any] | None = None,
    ) -> tuple[Any, bool]:
        """
        Upsert a discovered phone. Returns (phone, is_new).

        Matches by MAC address first, then by IP.
        Updates existing records with fresh data; creates new ones as 'discovered'.
        Persists SIP, network, and status data into dedicated columns and
        settings JSONB.
        """
        from sqlalchemy.orm.attributes import flag_modified

        from app.modules.voip.models import Phone, PhoneLifecycleState

        existing = None

        # Try MAC match first (most reliable)
        if mac_address:
            mac_query = select(Phone).where(
                Phone.mac_address == mac_address,
                Phone.deleted_at.is_(None),
            )
            # Organization isolation
            if self.organization_id:
                mac_query = mac_query.where(Phone.site_id.in_(select(self._sites_for_org().c.id)))
            result = await self.db.execute(mac_query)
            existing = result.scalar_one_or_none()

        # Fallback: IP match within same site
        if not existing:
            ip_query = select(Phone).where(
                Phone.ip_address == ip_address,
                Phone.site_id == site_id,
                Phone.deleted_at.is_(None),
            )
            # Organization isolation
            if self.organization_id:
                ip_query = ip_query.where(Phone.site_id.in_(select(self._sites_for_org().c.id)))
            result = await self.db.execute(ip_query)
            existing = result.scalar_one_or_none()

        now = datetime.now(UTC)
        rd = raw_data or {}

        def _apply_discovery_data(phone: Phone) -> None:
            """Apply all discovered data to a phone record."""
            # Dedicated columns
            phone.ip_address = ip_address
            phone.last_seen = now
            phone.status = "online"
            if vendor:
                phone.vendor = vendor
            if model:
                phone.model = model
            if firmware_version:
                phone.firmware_version = firmware_version
            if serial_number and not phone.serial_number:
                phone.serial_number = serial_number
            if mac_address and not phone.mac_address:
                phone.mac_address = mac_address
            if sip_registered:
                phone.sip_registered = True
            if sip_registrar:
                phone.sip_server = sip_registrar

            # Merge into settings JSONB (preserve credentials etc.)
            settings = phone.settings or {}
            if sip_account:
                settings["sip_user_id"] = sip_account
            if sip_registrar:
                settings["sip_registrar"] = sip_registrar
            if authenticated:
                settings["authenticated"] = True
                settings["last_authenticated_at"] = now.isoformat()

            # Structured data from raw_data
            if rd.get("_registered_accounts"):
                settings["registered_accounts"] = rd["_registered_accounts"]
            if rd.get("_phone_status"):
                settings["phone_status"] = rd["_phone_status"]
            if rd.get("_line_status"):
                settings["line_status"] = rd["_line_status"]

            phone.settings = settings
            flag_modified(phone, "settings")

        if existing:
            _apply_discovery_data(existing)
            await self.db.commit()
            await self.db.refresh(existing)
            return existing, False
        else:
            # Create new phone in 'discovered' state.
            #
            # use_ssl / acknowledge_plaintext: phones discovered via
            # http_probe were reached over plain HTTP, so we know they
            # speak HTTP at that IP. Default the new record to
            # use_ssl=False with the plaintext-ack flag set so later
            # actions (test-connection, push-config, live-status,
            # reboot) can use the same transport without manual DB
            # tweaking. The column default of use_ssl=True caused
            # every action-on-a-discovered-phone to time out trying
            # HTTPS against a port-80-only listener — see commit notes.
            http_discovered = "http" in (discovery_method or "").lower()
            phone = Phone(
                site_id=site_id,
                name=f"{vendor or 'Unknown'} {model or 'Phone'} ({ip_address})",
                ip_address=ip_address,
                mac_address=mac_address,
                vendor=vendor,
                model=model,
                firmware_version=firmware_version,
                serial_number=serial_number,
                status="online",
                lifecycle_state=PhoneLifecycleState.DISCOVERED.value,
                discovery_method=discovery_method,
                discovered_at=now,
                last_seen=now,
                use_ssl=not http_discovered,
                acknowledge_plaintext=http_discovered,
            )
            self.db.add(phone)
            # Apply SIP/status to newborn phone too
            _apply_discovery_data(phone)
            await self.db.commit()
            await self.db.refresh(phone)
            return phone, True

    # -------------------------------------------------------------------------
    # Firmware Compliance
    # -------------------------------------------------------------------------

    async def get_firmware_compliance(self, site_id: UUID | None = None) -> list[dict[str, Any]]:
        """Get firmware compliance report per vendor/model.

        Uses batch queries to avoid N+1 — one query for version
        distributions, one for recommended firmware tracks.
        """
        from app.modules.voip.models import FirmwareTrack, Phone

        base_filter = [Phone.deleted_at.is_(None)]

        # Organization isolation
        if self.organization_id:
            base_filter.append(Phone.site_id.in_(select(self._sites_for_org().c.id)))

        if site_id:
            base_filter.append(Phone.site_id == site_id)

        # Batch query: firmware version distribution per vendor/model
        dist_q = (
            select(
                Phone.vendor,
                Phone.model,
                Phone.firmware_version,
                func.count(Phone.id).label("cnt"),
            )
            .where(*base_filter, Phone.vendor.isnot(None), Phone.model.isnot(None))
            .group_by(Phone.vendor, Phone.model, Phone.firmware_version)
        )
        dist_result = await self.db.execute(dist_q)
        dist_rows = dist_result.all()

        # Batch query: all recommended firmware tracks
        rec_q = select(FirmwareTrack.vendor, FirmwareTrack.model, FirmwareTrack.version).where(
            FirmwareTrack.is_recommended.is_(True)
        )
        rec_result = await self.db.execute(rec_q)
        rec_map = {(row.vendor, row.model): row.version for row in rec_result.all()}

        # Build report from batch results
        combo_data: dict[tuple[str, str], dict[str | None, int]] = {}
        for vendor, model, fw_ver, cnt in dist_rows:
            key = (vendor, model)
            if key not in combo_data:
                combo_data[key] = {}
            combo_data[key][fw_ver] = cnt

        reports = []
        for (vendor, model), versions in combo_data.items():
            rec_version = rec_map.get((vendor, model))
            total = sum(versions.values())
            compliant = versions.get(rec_version, 0) if rec_version else 0
            unknown = versions.get(None, 0)

            reports.append(
                {
                    "vendor": vendor,
                    "model": model,
                    "recommended_version": rec_version,
                    "total_phones": total,
                    "compliant": compliant,
                    "non_compliant": total - compliant - unknown,
                    "unknown": unknown,
                    "versions": {k or "unknown": v for k, v in versions.items()},
                }
            )

        return reports

    async def list_firmware_tracks(
        self,
        site_id: UUID | None = None,
        vendor: str | None = None,
        model: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Any]:
        """List firmware tracks."""
        from app.modules.voip.models import FirmwareTrack

        query = select(FirmwareTrack)

        # Organization isolation
        if self.organization_id:
            query = query.where(FirmwareTrack.site_id.in_(select(self._sites_for_org().c.id)))

        if site_id:
            query = query.where(FirmwareTrack.site_id == site_id)
        if vendor:
            query = query.where(FirmwareTrack.vendor == vendor)
        if model:
            query = query.where(FirmwareTrack.model == model)
        query = (
            query.order_by(FirmwareTrack.vendor, FirmwareTrack.model).limit(limit).offset(offset)
        )

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def create_firmware_track(self, data: dict[str, Any]) -> Any:
        """Register a firmware version."""
        from app.modules.voip.models import FirmwareTrack

        # FSDN-SG (site-grant): a caller-supplied site_id must be inside the
        # caller's org AND per-user grant (mirrors create_discovery_scan /
        # create_phone). No-op for super_admin / org_admin (grant is None).
        if data.get("site_id") is not None:
            await self._assert_site_in_org(data["site_id"])

        track = FirmwareTrack(**data)
        self.db.add(track)
        await self.db.commit()
        await self.db.refresh(track)
        return track

    async def bulk_update_firmware(
        self,
        phone_ids: list[UUID],
        target_version: str,
        schedule_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Bulk-set firmware target on multiple phones (single UPDATE query)."""
        from app.modules.voip.models import Phone

        conditions = [Phone.id.in_(phone_ids), Phone.deleted_at.is_(None)]

        # Organization isolation
        if self.organization_id:
            conditions.append(Phone.site_id.in_(select(self._sites_for_org().c.id)))

        stmt = (
            update(Phone)
            .where(*conditions)
            .values(
                firmware_target=target_version,
                firmware_upgrade_scheduled=schedule_at,
            )
        )
        result = await self.db.execute(stmt)
        await self.db.commit()

        updated = result.rowcount
        return {
            "total": len(phone_ids),
            "succeeded": updated,
            "failed": len(phone_ids) - updated,
            "skipped": 0,
            "errors": [],
        }

    # -------------------------------------------------------------------------
    # PBX Management
    # -------------------------------------------------------------------------

    async def list_pbx_systems(
        self,
        site_id: UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Any], int]:
        """List PBX systems. Returns (items, total)."""
        from app.modules.voip.models import PBX

        base = select(PBX).where(PBX.deleted_at.is_(None))

        # Organization isolation
        if self.organization_id:
            base = base.where(PBX.site_id.in_(select(self._sites_for_org().c.id)))

        if site_id:
            base = base.where(PBX.site_id == site_id)

        count_result = await self.db.execute(select(func.count()).select_from(base.subquery()))
        total = count_result.scalar_one()

        query = base.order_by(PBX.name).limit(limit).offset(offset)
        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def get_pbx(self, pbx_id: UUID) -> Any:
        """Get a PBX by ID."""
        from app.modules.voip.models import PBX

        query = select(PBX).where(
            PBX.id == pbx_id,
            PBX.deleted_at.is_(None),
        )

        # Organization isolation
        if self.organization_id:
            query = query.where(PBX.site_id.in_(select(self._sites_for_org().c.id)))

        result = await self.db.execute(query)
        pbx = result.scalar_one_or_none()

        if not pbx:
            raise PBXNotFoundError(pbx_id)

        return pbx

    async def create_pbx(self, data: dict[str, Any]) -> Any:
        """Create a new PBX connection."""
        from app.modules.voip.models import PBX

        # Auto-resolve site_id when not provided (deterministic: earliest)
        if not data.get("site_id"):
            from app.models.core import Site

            site_query = select(Site.id).where(Site.deleted_at.is_(None))
            # Organization isolation
            if self.organization_id:
                site_query = site_query.where(Site.organization_id == self.organization_id)
            # a site-limited caller (voip.manage_phones, not
            # org_admin) must auto-select a GRANTED site, not the org's oldest
            # site. accessible_site_ids is None for super/org admin → no-op.
            if self.accessible_site_ids is not None:
                site_query = site_query.where(Site.id.in_(self.accessible_site_ids))
            site_query = site_query.order_by(Site.created_at).limit(1)
            result = await self.db.execute(site_query)
            site_id = result.scalar_one_or_none()
            if not site_id:
                raise VoIPError("No site found. Create a site first.")
            data["site_id"] = site_id
        else:
            # a client-supplied site_id must belong to the caller's
            # org AND (for a site-limited caller) the per-user grant. Reuse the
            # grant-aware FK guard which routes through _sites_for_org().
            await self._assert_site_in_org(data["site_id"])

        # Move credential fields into settings JSONB (encrypted at rest)
        settings = data.pop("settings", {}) or {}
        for cred_field in ("api_username", "api_password", "api_key"):
            val = data.pop(cred_field, None)
            if val is not None:
                settings[cred_field] = val
        data["settings"] = _encrypt_settings_credentials(settings)

        # OAuth2 client_credentials: ``api_client_id`` is plain, the
        # secret is encrypted into the dedicated ``api_client_secret_enc``
        # column (matches the pattern used for ami_secret / ari_password
        # / web_password).
        secret = data.pop("api_client_secret", None)
        if secret:
            data["api_client_secret_enc"] = encrypt_credential(str(secret))

        pbx = PBX(**data)
        self.db.add(pbx)
        await self.db.commit()
        await self.db.refresh(pbx)

        logger.info("Created PBX %s (%s) at %s", pbx.name, pbx.pbx_type, pbx.ip_address)
        return pbx

    async def update_pbx(self, pbx_id: UUID, data: dict[str, Any]) -> Any:
        """Update a PBX connection."""
        pbx = await self.get_pbx(pbx_id)

        # OAuth2: write client_id (plain) + secret (encrypted) into the
        # dedicated columns. Empty string clears; ``None`` keeps the
        # existing value (so PATCH-without-secret doesn't wipe creds).
        secret_in = data.pop("api_client_secret", None)
        if secret_in is not None:
            pbx.api_client_secret_enc = encrypt_credential(str(secret_in)) if secret_in else None

        # Merge credential fields into existing settings (encrypted at rest)
        for cred_field in ("api_username", "api_password", "api_key"):
            val = data.pop(cred_field, None)
            if val is not None:
                current_settings = dict(pbx.settings or {})
                current_settings[cred_field] = val
                pbx.settings = current_settings

        settings_update = data.pop("settings", None)
        if settings_update is not None:
            current_settings = dict(pbx.settings or {})
            current_settings.update(settings_update)
            pbx.settings = current_settings

        # Encrypt all credential fields before persisting
        pbx.settings = _encrypt_settings_credentials(dict(pbx.settings or {}))

        for key, value in data.items():
            if value is not None and key in _PBX_MUTABLE_FIELDS:
                setattr(pbx, key, value)

        # Persist changes
        from sqlalchemy.orm.attributes import flag_modified

        flag_modified(pbx, "settings")
        await self.db.commit()
        await self.db.refresh(pbx)
        return pbx

    async def delete_pbx(self, pbx_id: UUID) -> bool:
        """Soft delete a PBX."""
        pbx = await self.get_pbx(pbx_id)
        pbx.deleted_at = datetime.now(UTC)
        await self.db.commit()
        logger.info("Deleted PBX %s", pbx.name)
        return True

    async def test_pbx_connection(
        self,
        pbx_type: str,
        ip_address: str,
        api_port: int = 443,
        api_username: str | None = None,
        api_password: str | None = None,
        api_key: str | None = None,
        *,
        verify_ssl: bool = True,
        api_client_id: str | None = None,
        api_client_secret: str | None = None,
    ) -> dict[str, Any]:
        """Test connectivity to a PBX system using the real adapter.

        Read-only connectivity probe — never mutates the PBX. When
        ``api_client_id`` + ``api_client_secret`` are supplied the adapter
        exercises the OAuth2 + GraphQL path; ``verify_ssl`` controls TLS
        certificate verification for the test. These mirror the fields the
        UI collects so an operator can validate an OAuth2 / TLS-verify
        config before saving the PBX.

        Falls back to TCP check for non-FreePBX types.
        """
        import asyncio
        import time

        start = time.monotonic()

        # SSRF guard: this is an authenticated probe to an OPERATOR-SUPPLIED
        # host (not yet persisted/validated by an ip_address field_validator),
        # so before either the FreePBX adapter connect or the raw TCP fallback
        # below opens a socket we must drop loopback / link-local / cloud-
        # metadata targets. ``validate_target_host`` resolves hostnames before
        # checking (closes the "pbx.evil.com → 169.254.169.254" vector) while
        # intentionally allowing RFC1918 / on-prem hosts (allow_private=True),
        # so legitimate private PBXes still connect.
        from app.core.security_utils import validate_target_host

        try:
            validate_target_host(ip_address)
        except ValueError as exc:
            logger.warning("PBX connection test refused SSRF-unsafe host %s: %s", ip_address, exc)
            return {
                "status": "failed",
                "message": "Connection failed — target host is not permitted",
                "pbx_version": None,
                "extensions_found": None,
                "response_time_ms": round((time.monotonic() - start) * 1000, 1),
            }

        # For FreePBX, use the real adapter
        if pbx_type in ("freepbx", "asterisk"):
            adapter = None
            try:
                adapter = self._create_adapter(
                    host=ip_address,
                    username=api_username or "admin",
                    password=api_password or "",
                    web_port=api_port,
                    verify_ssl=verify_ssl,
                    api_client_id=api_client_id or None,
                    api_client_secret=api_client_secret or None,
                )
                result = await adapter.test_connection()
                elapsed = (time.monotonic() - start) * 1000

                if result.success:
                    data = result.data or {}
                    version = None
                    ext_count = None
                    if data.get("ami", {}).get("version"):
                        version = data["ami"]["version"]
                    # Filter response to safe subset only
                    safe_details = {
                        "ami": {
                            "connected": data.get("ami", {}).get("connected", False),
                            "version": version,
                        },
                        "ari": {"connected": data.get("ari", {}).get("connected", False)},
                        "rest": {"connected": data.get("rest", {}).get("connected", False)},
                    }
                    return {
                        "status": "success",
                        "message": f"FreePBX connected — AMI: ✓, ARI: {'✓' if data.get('ari', {}).get('connected') else '✗'}, REST: {'✓' if data.get('rest', {}).get('connected') else '✗'}",
                        "pbx_version": version,
                        "extensions_found": ext_count,
                        "response_time_ms": round(elapsed, 1),
                        "details": safe_details,
                    }
                else:
                    return {
                        "status": "auth_error" if "auth" in str(result.error).lower() else "failed",
                        "message": result.error or "Connection test failed",
                        "pbx_version": None,
                        "extensions_found": None,
                        "response_time_ms": round(elapsed, 1),
                    }
            except Exception as exc:
                elapsed = (time.monotonic() - start) * 1000
                logger.warning(
                    "PBX connection test failed for %s:%s: %s", ip_address, api_port, exc
                )
                return {
                    "status": "failed",
                    "message": "Connection failed — check credentials and network",
                    "pbx_version": None,
                    "extensions_found": None,
                    "response_time_ms": round(elapsed, 1),
                }
            finally:
                if adapter:
                    with contextlib.suppress(Exception):
                        await adapter.disconnect()

        # Fallback: TCP-only check for other PBX types
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip_address, api_port),
                timeout=5.0,
            )
            writer.close()
            await writer.wait_closed()
            elapsed = (time.monotonic() - start) * 1000

            return {
                "status": "success",
                "message": f"Successfully connected to {pbx_type} at {ip_address}:{api_port}",
                "pbx_version": None,
                "extensions_found": None,
                "response_time_ms": round(elapsed, 1),
            }
        except TimeoutError:
            return {
                "status": "timeout",
                "message": f"Connection timed out to {ip_address}:{api_port}",
                "pbx_version": None,
                "extensions_found": None,
                "response_time_ms": 5000.0,
            }
        except OSError as exc:
            return {
                "status": "failed",
                "message": f"Connection failed: {exc}",
                "pbx_version": None,
                "extensions_found": None,
                "response_time_ms": round((time.monotonic() - start) * 1000, 1),
            }

    def _create_adapter(
        self,
        host: str,
        username: str = "admin",
        password: str = "",
        *,
        web_port: int = 443,
        ami_username: str | None = None,
        ami_secret: str | None = None,
        ari_username: str | None = None,
        ari_password: str | None = None,
        allowed_outbound_prefixes: tuple[str, ...] = (),
        verify_ssl: bool = True,
        api_client_id: str | None = None,
        api_client_secret: str | None = None,
    ) -> Any:
        """Create a FreePBX adapter instance.

        When ``api_client_id`` + ``api_client_secret`` are supplied, the
        adapter's REST client activates the OAuth2 + GraphQL path
        (FreePBX 16+ Admin API). Without them, falls back to web-session
        auth + legacy AJAX endpoints.
        """
        from app.adapters.freepbx import FreePBXAdapter

        return FreePBXAdapter(
            host=host,
            username=username,
            password=password,
            ami_username=ami_username,
            ami_secret=ami_secret,
            ari_username=ari_username,
            ari_password=ari_password,
            web_port=web_port,
            allowed_outbound_prefixes=allowed_outbound_prefixes,
            verify_ssl=verify_ssl,
            api_client_id=api_client_id,
            api_client_secret=api_client_secret,
        )

    def _adapter_from_pbx(self, pbx: Any) -> Any:
        """Create a FreePBX adapter from a PBX database model.

        Delegates to the shared :func:`build_freepbx_adapter_from_pbx`
        factory so the staged-write bridge (``FreePBXServiceBase``) and
        this direct-call path build adapters identically — credential
        precedence, OAuth2-vs-session selection, and the TLS-verification
        acknowledgement gate live in exactly one place and cannot drift.
        """
        from app.modules.voip.adapter_factory import build_freepbx_adapter_from_pbx

        return build_freepbx_adapter_from_pbx(pbx)

    async def _with_adapter(self, pbx_id: UUID, operation: str, fn):
        """Connect adapter, run operation, disconnect. Returns result dict."""
        pbx = await self.get_pbx(pbx_id)

        if pbx.pbx_type not in ("freepbx", "asterisk"):
            raise VoIPError(f"Adapter not available for PBX type: {pbx.pbx_type}")

        adapter = self._adapter_from_pbx(pbx)
        try:
            await adapter.connect()
            result = await fn(adapter, pbx)

            # Update last_seen on successful connection
            pbx.last_seen = datetime.now(UTC)
            await self.db.commit()

            return result
        except Exception as exc:
            err_msg = str(exc) or type(exc).__name__
            logger.error("PBX %s %s failed: %s", pbx.name, operation, err_msg)
            raise VoIPError(f"{operation} failed: {err_msg}") from exc
        finally:
            with contextlib.suppress(Exception):
                await adapter.disconnect()

    async def connect_pbx(self, pbx_id: UUID) -> dict[str, Any]:
        """Full connection test for a saved PBX using the real adapter."""
        pbx = await self.get_pbx(pbx_id)

        if pbx.pbx_type not in ("freepbx", "asterisk"):
            raise VoIPError(f"Adapter not available for PBX type: {pbx.pbx_type}")

        adapter = self._adapter_from_pbx(pbx)
        try:
            await adapter.connect()
            result = await adapter.test_connection()
            data = result.data or {}

            pbx.last_seen = datetime.now(UTC)
            await self.db.commit()

            return {
                "status": "connected" if result.success else "failed",
                "message": result.message or str(result.error or ""),
                "ami": data.get("ami", {}),
                "ari": data.get("ari", {}),
                "rest": data.get("rest", {}),
            }
        except Exception as exc:
            return {
                "status": "failed",
                "message": str(exc),
                "ami": {},
                "ari": {},
                "rest": {},
            }
        finally:
            with contextlib.suppress(Exception):
                await adapter.disconnect()

    async def get_pbx_system_info(self, pbx_id: UUID) -> dict[str, Any]:
        """Get real-time system information from a PBX."""

        async def _op(adapter, pbx):
            result = await adapter.get_system_info()
            return result.data if result.success else {"error": result.error}

        return await self._with_adapter(pbx_id, "get_system_info", _op)

    async def get_pbx_dashboard(self, pbx_id: UUID) -> dict[str, Any]:
        """Get comprehensive PBX dashboard combining DB + optional adapter data."""
        from app.modules.voip.models import CallLog, Extension, RingGroup, VoicemailMessage

        pbx = await self.get_pbx(pbx_id)

        # DB stats
        ext_count = await self.db.execute(
            select(func.count()).select_from(
                select(Extension.id)
                .where(
                    Extension.pbx_id == pbx_id,
                    Extension.deleted_at.is_(None),
                )
                .subquery()
            )
        )
        total_extensions = ext_count.scalar_one()

        rg_count = await self.db.execute(
            select(func.count()).select_from(
                select(RingGroup.id)
                .where(
                    RingGroup.pbx_id == pbx_id,
                    RingGroup.deleted_at.is_(None),
                )
                .subquery()
            )
        )
        total_ring_groups = rg_count.scalar_one()

        # Today's calls
        today_start = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        calls_today_q = await self.db.execute(
            select(func.count()).select_from(
                select(CallLog.id)
                .where(
                    CallLog.pbx_id == pbx_id,
                    CallLog.start_time >= today_start,
                )
                .subquery()
            )
        )
        calls_today = calls_today_q.scalar_one()

        # Voicemail stats
        vm_q = await self.db.execute(
            select(
                func.count(VoicemailMessage.id).label("total"),
                func.sum(func.cast(~VoicemailMessage.is_read, Integer)).label("unread"),
            ).where(
                VoicemailMessage.pbx_id == pbx_id,
                VoicemailMessage.deleted_at.is_(None),
            )
        )
        vm_row = vm_q.one()

        dashboard = {
            "pbx_id": str(pbx.id),
            "name": pbx.name,
            "pbx_type": pbx.pbx_type,
            "status": "online"
            if pbx.last_seen and (datetime.now(UTC) - pbx.last_seen).total_seconds() < 600
            else "unknown",
            "ip_address": pbx.ip_address,
            "api_port": pbx.api_port,
            "sip_port": pbx.sip_port,
            "total_extensions": total_extensions,
            "online_extensions": 0,
            "total_trunks": 0,
            "active_calls": 0,
            "calls_today": calls_today,
            "voicemail_boxes": 0,
            "unread_voicemails": int(vm_row.unread or 0),
            "ring_groups": total_ring_groups,
            "queues": 0,
            "ivrs": 0,
            "dids": 0,
            "ami_connected": False,
            "ari_connected": False,
            "rest_available": False,
            "asterisk_version": None,
            "last_sync": pbx.last_seen.isoformat() if pbx.last_seen else None,
            # Set when a staged config change is applied to the FreePBX DB but
            # not yet reloaded into the running Asterisk; cleared on reload.
            # Drives the "Apply Config to activate" banner on the PBX page.
            "needs_reload": bool((pbx.settings or {}).get("needs_reload", False)),
        }

        # Populate counts from synced_cache (always available after sync)
        cache = (pbx.settings or {}).get("synced_cache", {})
        if cache:
            dashboard["total_trunks"] = len(cache.get("trunks", []))
            dashboard["queues"] = len(cache.get("queues", []))
            dashboard["ivrs"] = len(cache.get("ivrs", []))
            dashboard["dids"] = len(cache.get("dids", []))
            dashboard["voicemail_boxes"] = len(cache.get("voicemail_boxes", []))

        # Try to enrich with live adapter data (connection status, active calls)
        if pbx.pbx_type in ("freepbx", "asterisk"):
            adapter = self._adapter_from_pbx(pbx)
            try:
                await adapter.connect()

                dashboard["ami_connected"] = adapter.ami.connected
                dashboard["ari_connected"] = adapter.ari.connected
                dashboard["rest_available"] = adapter.rest.api_available
                dashboard["status"] = "online"

                # Active calls (only if AMI available)
                if adapter.ami.connected:
                    try:
                        calls_result = await adapter.get_active_calls()
                        if calls_result.success:
                            dashboard["active_calls"] = len(calls_result.data or [])
                    except Exception:
                        pass

                # If no cache, try live counts
                if not cache:
                    # Trunks count
                    try:
                        trunks_result = await adapter.list_trunks()
                        if trunks_result.success:
                            dashboard["total_trunks"] = len(trunks_result.data or [])
                    except Exception:
                        pass

                    # Queues count
                    try:
                        queues_result = await adapter.list_queues()
                        if queues_result.success:
                            dashboard["queues"] = len(queues_result.data or [])
                    except Exception:
                        pass

                    # IVR count
                    try:
                        ivrs_result = await adapter.list_ivrs()
                        if ivrs_result.success:
                            dashboard["ivrs"] = len(ivrs_result.data or [])
                    except Exception:
                        pass

                # Version
                try:
                    version = await adapter.ami.get_version()
                    dashboard["asterisk_version"] = version
                except Exception:
                    pass

                pbx.last_seen = datetime.now(UTC)
                await self.db.commit()

            except Exception as exc:
                err_msg = str(exc) or type(exc).__name__
                logger.warning("Dashboard adapter enrichment failed for %s: %s", pbx.name, err_msg)
                dashboard["status"] = "offline"
            finally:
                with contextlib.suppress(Exception):
                    await adapter.disconnect()

        return dashboard

    async def sync_pbx(
        self,
        pbx_id: UUID,
        *,
        progress_callback: Any = None,
    ) -> dict[str, Any]:
        """Sync extensions, ring groups, and data from a PBX via the adapter.

        Pulls data from the FreePBX adapter and upserts into the local DB.

        ``progress_callback`` is an optional ``(stage, current, total,
        message, data)`` callable. The Celery wrapper passes one that
        publishes ``pbx.sync.progress`` events to the WebSocket so the
        operator sees an interactive progress bar instead of a frozen
        Sync button. Best-effort — failures in the callback never
        break the sync itself.

        Stages (6 total):
            1. ``connecting``   — auth + handshake to the adapter
            2. ``extensions``   — list + DB upsert
            3. ``ring_groups``  — list + DB upsert
            4. ``live_data``    — fan-out fetch of 23 vendor endpoints
            5. ``persisting``   — commit synced_cache JSONB
            6. ``done``         — final summary emitted
        """

        def _emit(
            stage: str,
            current: int,
            total: int,
            message: str | None = None,
            data: dict[str, Any] | None = None,
        ) -> None:
            """Fire a progress event. Best-effort, swallow all errors."""
            if progress_callback is None:
                return
            try:
                progress_callback(stage, current, total, message, data or {})
            except Exception:
                logger.debug("progress_callback raised for stage=%s", stage, exc_info=True)

        pbx = await self.get_pbx(pbx_id)

        if pbx.pbx_type not in ("freepbx", "asterisk"):
            # For unsupported types, just update last_seen
            pbx.last_seen = datetime.now(UTC)
            await self.db.commit()
            _emit("done", 6, 6, "Sync not available for this PBX type", {})
            return {
                "status": "success",
                "message": f"Sync not available for {pbx.pbx_type} — marked as seen",
                "pbx_id": str(pbx.id),
                "extensions_synced": 0,
                "ring_groups_synced": 0,
            }

        _emit("connecting", 1, 6, f"Connecting to {pbx.name}", {"host": pbx.ip_address})
        adapter = self._adapter_from_pbx(pbx)
        extensions_synced = 0
        ring_groups_synced = 0
        trunks_found = 0
        errors: list[str] = []

        try:
            await adapter.connect()

            # ── Sync Extensions ──
            _emit("extensions", 2, 6, "Fetching extensions", {})
            try:
                ext_result = await adapter.list_extensions()
                if ext_result.success and ext_result.data:
                    extensions_synced = await self._upsert_extension_rows(pbx_id, ext_result.data)
            except Exception as exc:
                errors.append(f"Extension sync error: {exc}")
                logger.warning("Extension sync failed for %s: %s", pbx.name, exc)
            _emit(
                "extensions",
                2,
                6,
                f"Synced {extensions_synced} extensions",
                {"count": extensions_synced},
            )

            # ── Sync Ring Groups ──
            _emit("ring_groups", 3, 6, "Fetching ring groups", {})
            try:
                rg_result = await adapter.list_ring_groups()
                if rg_result.success and rg_result.data:
                    ring_groups_synced = await self._upsert_ring_group_rows(pbx_id, rg_result.data)
            except Exception as exc:
                errors.append(f"Ring group sync error: {exc}")
                logger.warning("Ring group sync failed for %s: %s", pbx.name, exc)
            _emit(
                "ring_groups",
                3,
                6,
                f"Synced {ring_groups_synced} ring groups",
                {"count": ring_groups_synced},
            )

            # ── Parallel fetch of all cache-only data ──
            _emit("live_data", 4, 6, "Fetching live data (trunks, queues, IVR, DIDs, ...)", {})

            # These don't touch the DB — just collect data for synced_cache.
            # Run them concurrently with asyncio.gather for ~10x speedup.
            async def _safe_fetch(coro, label: str):
                """Wrapper that catches errors and returns (data, error_msg)."""
                try:
                    result = await coro
                    if result.success and result.data:
                        return result.data, None
                    return ([] if not isinstance(result.data, dict) else {}), None
                except Exception as exc:
                    return (
                        [] if "settings" not in label and "parking" not in label else {}
                    ), f"{label} sync error: {exc}"

            (
                (trunks_data, e1),
                (queues_data, e2),
                (ivrs_data, e3),
                (dids_data, e4),
                (voicemail_data, e5),
                (outbound_routes_data, e6),
                (followme_data, e7),
                (announcements_data, e8),
                (paging_data, e9),
                (daynight_data, e10),
                (blacklist_data, e11),
                (certificates_data, e12),
                (admin_users_data, e13),
                (time_conditions_data, e14),
                (contacts_data, e15),
                (recordings_data, e16),
                (moh_data, e17),
                (ami_managers_data, e18),
                (backup_data, e19),
                (sip_settings_data, e20),
                (parking_data, e21),
                (feature_codes_data, e22),
                (modules_data, e23),
            ) = await asyncio.gather(
                _safe_fetch(adapter.list_trunks_with_details(), "Trunk"),
                _safe_fetch(adapter.list_queues(), "Queue"),
                _safe_fetch(adapter.list_ivrs(), "IVR"),
                _safe_fetch(adapter.list_dids(), "DID"),
                _safe_fetch(adapter.list_voicemail_boxes(), "Voicemail"),
                _safe_fetch(adapter.list_outbound_routes(), "Outbound routes"),
                _safe_fetch(adapter.list_followme(), "Follow-Me"),
                _safe_fetch(adapter.list_announcements(), "Announcements"),
                _safe_fetch(adapter.list_paging_groups(), "Paging"),
                _safe_fetch(adapter.list_daynight(), "Day/Night"),
                _safe_fetch(adapter.list_blacklist(), "Blacklist"),
                _safe_fetch(adapter.list_certificates(), "Certificate"),
                _safe_fetch(adapter.list_admin_users(), "Admin users"),
                _safe_fetch(adapter.list_time_conditions(), "Time conditions"),
                _safe_fetch(adapter.list_contacts(), "Contacts"),
                _safe_fetch(adapter.list_system_recordings(), "System recordings"),
                _safe_fetch(adapter.list_music_on_hold(), "Music on hold"),
                _safe_fetch(adapter.list_ami_managers(), "AMI managers"),
                _safe_fetch(adapter.list_backup_jobs(), "Backup jobs"),
                _safe_fetch(adapter.get_sip_settings(), "SIP settings"),
                _safe_fetch(adapter.get_parking_config(), "Parking config"),
                _safe_fetch(adapter.get_feature_codes(), "Feature codes"),
                _safe_fetch(adapter.get_installed_modules(), "Installed modules"),
            )
            trunks_found = len(trunks_data) if isinstance(trunks_data, list) else 0
            # Collect any errors from parallel fetches
            for err in (
                e1,
                e2,
                e3,
                e4,
                e5,
                e6,
                e7,
                e8,
                e9,
                e10,
                e11,
                e12,
                e13,
                e14,
                e15,
                e16,
                e17,
                e18,
                e19,
                e20,
                e21,
                e22,
                e23,
            ):
                if err:
                    errors.append(err)
                    logger.warning("%s for %s", err, pbx.name)

            # ── Persist all cached data into PBX settings ──
            # Every list-of-dicts is scrubbed of credential-like keys
            # via ``_scrub_cache_entries`` before going into the JSONB
            # blob. The original cache used to round-trip plaintext
            # AMI manager secrets, admin user passwords, and PJSIP
            # trunk secrets to the UI on every GET — the audit's
            # C2/C3 findings.
            synced_cache = {
                "trunks": _scrub_cache_entries(trunks_data),
                "queues": _scrub_cache_entries(queues_data),
                "ivrs": _scrub_cache_entries(ivrs_data),
                "dids": _scrub_cache_entries(dids_data),
                "voicemail_boxes": _scrub_cache_entries(voicemail_data),
                "outbound_routes": _scrub_cache_entries(outbound_routes_data),
                "followme": _scrub_cache_entries(followme_data),
                "announcements": _scrub_cache_entries(announcements_data),
                "paging_groups": _scrub_cache_entries(paging_data),
                "daynight": _scrub_cache_entries(daynight_data),
                "blacklist": _scrub_cache_entries(blacklist_data),
                "certificates": _scrub_cache_entries(certificates_data),
                "admin_users": _scrub_cache_entries(admin_users_data),
                "time_conditions": _scrub_cache_entries(time_conditions_data),
                "contacts": _scrub_cache_entries(contacts_data),
                "system_recordings": _scrub_cache_entries(recordings_data),
                "music_on_hold": _scrub_cache_entries(moh_data),
                "ami_managers": _scrub_cache_entries(ami_managers_data),
                "backup_jobs": _scrub_cache_entries(backup_data),
                "sip_settings": _scrub_cache_entries(sip_settings_data),
                "parking": _scrub_cache_entries(parking_data),
                "feature_codes": _scrub_cache_entries(feature_codes_data),
                "installed_modules": _scrub_cache_entries(modules_data),
                "synced_at": datetime.now(UTC).isoformat(),
            }
            pbx.settings = {**(pbx.settings or {}), "synced_cache": synced_cache}

            _emit("persisting", 5, 6, "Saving to database", {})
            pbx.last_seen = datetime.now(UTC)
            await self.db.commit()

            summary = {
                "extensions": extensions_synced,
                "ring_groups": ring_groups_synced,
                "trunks": trunks_found,
                "queues": len(queues_data) if isinstance(queues_data, list) else 0,
                "ivrs": len(ivrs_data) if isinstance(ivrs_data, list) else 0,
                "dids": len(dids_data) if isinstance(dids_data, list) else 0,
                "voicemail_boxes": len(voicemail_data) if isinstance(voicemail_data, list) else 0,
                "followme": len(followme_data) if isinstance(followme_data, list) else 0,
                "announcements": len(announcements_data)
                if isinstance(announcements_data, list)
                else 0,
                "paging_groups": len(paging_data) if isinstance(paging_data, list) else 0,
                "blacklist": len(blacklist_data) if isinstance(blacklist_data, list) else 0,
                "certificates": len(certificates_data)
                if isinstance(certificates_data, list)
                else 0,
                "admin_users": len(admin_users_data) if isinstance(admin_users_data, list) else 0,
                "modules": len(modules_data) if isinstance(modules_data, list) else 0,
            }
            _emit(
                "done",
                6,
                6,
                f"Sync complete for {pbx.name}",
                {"summary": summary, "errors": errors},
            )

            return {
                "status": "success",
                "message": (
                    f"Synced {extensions_synced} extensions, "
                    f"{ring_groups_synced} ring groups, "
                    f"{trunks_found} trunks, "
                    f"{len(queues_data)} queues, "
                    f"{len(ivrs_data)} IVRs, "
                    f"{len(dids_data)} DIDs, "
                    f"{len(followme_data)} follow-me, "
                    f"{len(announcements_data)} announcements, "
                    f"{len(paging_data)} paging, "
                    f"{len(certificates_data)} certs "
                    f"from {pbx.name}"
                ),
                "pbx_id": str(pbx.id),
                "pbx_type": pbx.pbx_type,
                "extensions_synced": extensions_synced,
                "ring_groups_synced": ring_groups_synced,
                "trunks_found": trunks_found,
                "queues_found": len(queues_data),
                "ivrs_found": len(ivrs_data),
                "dids_found": len(dids_data),
                "voicemail_boxes_found": len(voicemail_data),
                "outbound_routes_found": len(outbound_routes_data),
                "followme_found": len(followme_data),
                "announcements_found": len(announcements_data),
                "paging_found": len(paging_data),
                "daynight_found": len(daynight_data),
                "blacklist_found": len(blacklist_data),
                "certificates_found": len(certificates_data),
                "admin_users_found": len(admin_users_data),
                "errors": errors,
            }

        except Exception as exc:
            err_msg = str(exc) or type(exc).__name__
            logger.error("PBX sync failed for %s: %s", pbx.name, err_msg)
            _emit(
                "failed",
                6,
                6,
                f"Sync failed: {err_msg}",
                {"error": err_msg, "errors": errors + [err_msg]},
            )
            return {
                "status": "failed",
                "message": f"Sync failed: {err_msg}",
                "pbx_id": str(pbx.id),
                "pbx_type": pbx.pbx_type,
                "extensions_synced": extensions_synced,
                "ring_groups_synced": ring_groups_synced,
                "trunks_found": 0,
                "errors": errors + [err_msg],
            }
        finally:
            with contextlib.suppress(Exception):
                await adapter.disconnect()

    # -------------------------------------------------------------------------
    # PBX Live Operations (via adapter)
    # -------------------------------------------------------------------------

    async def list_pbx_trunks(self, pbx_id: UUID) -> list[dict[str, Any]]:
        """List SIP trunks — reads from synced cache, falls back to live adapter."""
        pbx = await self.get_pbx(pbx_id)
        cached = (pbx.settings or {}).get("synced_cache", {}).get("trunks")
        if cached is not None:
            return cached

        # Fallback: live adapter (with full PJSIP detail)
        async def _op(adapter, _pbx):
            result = await adapter.list_trunks_with_details()
            if not result.success:
                raise VoIPError(f"Failed to list trunks: {result.error}")
            return result.data or []

        return await self._with_adapter(pbx_id, "list_trunks", _op)

    async def get_trunk_detail(self, pbx_id: UUID, trunk_id: str) -> dict[str, Any]:
        """Get detailed information about a single SIP trunk."""
        # First check cached data
        pbx = await self.get_pbx(pbx_id)
        cached_trunks = (pbx.settings or {}).get("synced_cache", {}).get("trunks", [])
        cached_trunk = None
        for t in cached_trunks:
            tid = str(t.get("trunkid", t.get("channelid", t.get("trunk_id", ""))))
            if tid == trunk_id or t.get("name") == trunk_id:
                cached_trunk = t
                break

        # Try live adapter for richer data
        live_data = None
        try:

            async def _op(adapter, _pbx):
                result = await adapter.get_trunk(trunk_id)
                return result.data if result.success else None

            live_data = await self._with_adapter(pbx_id, "get_trunk", _op)
        except Exception:
            pass

        if live_data:
            detail = dict(live_data)
            detail["_source"] = "live"
            return detail

        if cached_trunk:
            detail = dict(cached_trunk)
            detail["_source"] = "cache"
            return detail

        raise VoIPError(f"Trunk {trunk_id} not found")

    # Trunk create/update/delete were removed: FreePBX exposes no API to write
    # trunks, so the direct (non-staged) trunk write methods only ever 502'd
    # and bypassed the staged dual-gate. The /trunks POST/PATCH/DELETE routes
    # now return 501 (see voip/api.py). Trunks remain read-only/listable.

    # ── Shared upsert helpers (full sync + targeted post-apply refresh) ──
    #
    # Extracted so the full ``sync_pbx`` loop and the lighter
    # ``refresh_*_from_live`` paths normalise FreePBX's loose field names
    # exactly the same way. Each returns the number of rows upserted; the
    # caller (``_with_adapter`` or ``sync_pbx``) owns the commit.

    async def _upsert_extension_rows(self, pbx_id: UUID, data: list[dict[str, Any]]) -> int:
        """Upsert a live extension list into the Extension table."""
        from app.modules.voip.models import Extension

        existing_q = await self.db.execute(
            select(Extension).where(
                Extension.pbx_id == pbx_id,
                Extension.deleted_at.is_(None),
            )
        )
        ext_map = {e.extension_number: e for e in existing_q.scalars().all()}

        count = 0
        for ext_data in data:
            ext_num = str(
                ext_data.get("extension")
                or ext_data.get("extension_number")
                or ext_data.get("id", "")
            )
            if not ext_num:
                continue
            display = ext_data.get("name") or ext_data.get("display_name") or ext_num
            cid_name = ext_data.get("caller_id_name") or ext_data.get("callerid", "")
            cid_num = ext_data.get("caller_id_number") or ext_data.get("outboundcid", "")
            vm_enabled = ext_data.get("voicemail_enabled", True)
            if isinstance(vm_enabled, str):
                vm_enabled = vm_enabled.lower() in ("yes", "true", "1", "enabled")

            ext = ext_map.get(ext_num)
            if ext:
                ext.display_name = display
                ext.caller_id_name = cid_name or ext.caller_id_name
                ext.caller_id_number = cid_num or ext.caller_id_number
                ext.voicemail_enabled = vm_enabled
                ext.settings = {**(ext.settings or {}), **ext_data}
            else:
                ext = Extension(
                    pbx_id=pbx_id,
                    extension_number=ext_num,
                    display_name=display,
                    caller_id_name=cid_name or None,
                    caller_id_number=cid_num or None,
                    voicemail_enabled=vm_enabled,
                    settings={**ext_data},
                )
                self.db.add(ext)
            count += 1
        return count

    async def _upsert_ring_group_rows(self, pbx_id: UUID, data: list[dict[str, Any]]) -> int:
        """Upsert a live ring-group list into the RingGroup table."""
        from app.modules.voip.models import RingGroup

        existing_rg_q = await self.db.execute(
            select(RingGroup).where(
                RingGroup.pbx_id == pbx_id,
                RingGroup.deleted_at.is_(None),
            )
        )
        rg_map = {rg.group_number: rg for rg in existing_rg_q.scalars().all()}

        count = 0
        for rg_data in data:
            grp_num = str(
                rg_data.get("grpnum") or rg_data.get("group_number") or rg_data.get("id", "")
            )
            if not grp_num:
                continue
            name = rg_data.get("description") or rg_data.get("name") or f"Ring Group {grp_num}"
            strategy = rg_data.get("strategy") or rg_data.get("ring_strategy") or "ringall"
            ring_time = int(rg_data.get("grptime") or rg_data.get("ring_time") or 20)
            members = rg_data.get("grplist") or rg_data.get("members") or []
            if isinstance(members, str):
                members = [m.strip() for m in members.split("-") if m.strip()]

            rg = rg_map.get(grp_num)
            if rg:
                rg.name = name
                rg.ring_strategy = strategy
                rg.ring_time = ring_time
                rg.members = members
                rg.settings = {**(rg.settings or {}), "synced_data": rg_data}
            else:
                rg = RingGroup(
                    pbx_id=pbx_id,
                    name=name,
                    group_number=grp_num,
                    ring_strategy=strategy,
                    ring_time=ring_time,
                    members=members,
                    settings={"synced_data": rg_data},
                )
                self.db.add(rg)
            count += 1
        return count

    # ── Targeted post-apply refreshers ──────────────────────────────────
    #
    # After a staged ``pbx.*`` change applies to the live device, the synced
    # view of that one entity is stale. These re-read just that entity from
    # the device so the operator sees the change immediately, without paying
    # for a full ``sync_pbx``. ``_with_adapter`` commits on success.

    async def _refresh_dids_cache(self, pbx_id: UUID) -> None:
        """Re-fetch DIDs / inbound routes and update synced_cache["dids"]."""

        async def _op(adapter, pbx):
            result = await adapter.list_dids()
            if result.success and result.data is not None:
                settings = dict(pbx.settings or {})
                cache = dict(settings.get("synced_cache", {}))
                cache["dids"] = result.data
                settings["synced_cache"] = cache
                pbx.settings = settings
                from sqlalchemy.orm.attributes import flag_modified

                flag_modified(pbx, "settings")
            return result.data if result.success else None

        await self._with_adapter(pbx_id, "list_dids", _op)

    async def refresh_extensions_from_live(self, pbx_id: UUID) -> None:
        """Re-fetch extensions from the device and upsert into the table."""

        async def _op(adapter, _pbx):
            result = await adapter.list_extensions()
            if result.success and result.data:
                await self._upsert_extension_rows(pbx_id, result.data)
            return None

        await self._with_adapter(pbx_id, "list_extensions", _op)

    async def refresh_ring_groups_from_live(self, pbx_id: UUID) -> None:
        """Re-fetch ring groups from the device and upsert into the table."""

        async def _op(adapter, _pbx):
            result = await adapter.list_ring_groups()
            if result.success and result.data:
                await self._upsert_ring_group_rows(pbx_id, result.data)
            return None

        await self._with_adapter(pbx_id, "list_ring_groups", _op)

    async def refresh_after_apply(self, pbx_id: UUID, feature: str) -> None:
        """Refresh the synced view of whichever entity an apply just mutated.

        Best-effort, called right after a staged ``pbx.*`` change applies to
        the live device. Only the entities with a working write path need a
        refresh (extensions / ring groups / inbound routes); trunks, queues,
        and IVRs have no apply path so nothing changed there.

        Also flags the PBX as needing a reload: the GraphQL write lands in the
        FreePBX DB but is inert on the running Asterisk until a doreload, so the
        PBX page shows an 'Apply Config to activate' banner until reload.
        """
        # Flag first (DB-only, commits) so the banner shows even if the live
        # entity refresh below fails.
        await self.set_needs_reload(pbx_id, True)
        if feature.startswith("pbx.extension."):
            await self.refresh_extensions_from_live(pbx_id)
        elif feature.startswith("pbx.ring_group."):
            await self.refresh_ring_groups_from_live(pbx_id)
        elif feature.startswith("pbx.inbound_route."):
            await self._refresh_dids_cache(pbx_id)

    async def list_pbx_queues(self, pbx_id: UUID) -> list[dict[str, Any]]:
        """List call queues — reads from synced cache, falls back to live adapter."""
        pbx = await self.get_pbx(pbx_id)
        cached = (pbx.settings or {}).get("synced_cache", {}).get("queues")
        if cached is not None:
            return cached

        async def _op(adapter, _pbx):
            result = await adapter.list_queues()
            if not result.success:
                raise VoIPError(f"Failed to list queues: {result.error}")
            return result.data or []

        return await self._with_adapter(pbx_id, "list_queues", _op)

    async def list_pbx_ivrs(self, pbx_id: UUID) -> list[dict[str, Any]]:
        """List IVR menus — reads from synced cache, falls back to live adapter."""
        pbx = await self.get_pbx(pbx_id)
        cached = (pbx.settings or {}).get("synced_cache", {}).get("ivrs")
        if cached is not None:
            return cached

        async def _op(adapter, _pbx):
            result = await adapter.list_ivrs()
            if not result.success:
                raise VoIPError(f"Failed to list IVRs: {result.error}")
            return result.data or []

        return await self._with_adapter(pbx_id, "list_ivrs", _op)

    async def get_pbx_active_calls(self, pbx_id: UUID) -> list[dict[str, Any]]:
        """Get active calls from the PBX via adapter.

        Returns empty list gracefully when AMI is not connected, instead of
        raising a 502 error.
        """

        async def _op(adapter, _pbx):
            if not adapter.ami.connected:
                # AMI not available — return empty instead of 502
                return []
            result = await adapter.get_active_calls()
            if not result.success:
                # Non-critical — return empty
                logger.debug("Active calls fetch failed: %s", result.error)
                return []
            return result.data or []

        try:
            return await self._with_adapter(pbx_id, "get_active_calls", _op)
        except VoIPError:
            # Connection failures are non-critical for active calls monitoring
            return []

    async def list_pbx_dids(self, pbx_id: UUID) -> list[dict[str, Any]]:
        """List DIDs / Inbound Routes — reads from synced cache."""
        pbx = await self.get_pbx(pbx_id)
        cached = (pbx.settings or {}).get("synced_cache", {}).get("dids")
        if cached is not None:
            return cached
        return []

    async def list_pbx_voicemail_boxes(self, pbx_id: UUID) -> list[dict[str, Any]]:
        """List voicemail boxes — reads from synced cache, falls back to live adapter."""
        pbx = await self.get_pbx(pbx_id)
        cached = (pbx.settings or {}).get("synced_cache", {}).get("voicemail_boxes")
        if cached is not None:
            return cached

        async def _op(adapter, _pbx):
            result = await adapter.list_voicemail_boxes()
            if not result.success:
                raise VoIPError(f"Failed to list voicemail boxes: {result.error}")
            return result.data or []

        return await self._with_adapter(pbx_id, "list_voicemail_boxes", _op)

    # ── New rich-data list methods ────────────────────────────

    async def _list_from_cache(self, pbx_id: UUID, cache_key: str) -> list[dict[str, Any]]:
        """Generic helper: read a list from synced_cache by key."""
        pbx = await self.get_pbx(pbx_id)
        return (pbx.settings or {}).get("synced_cache", {}).get(cache_key) or []

    async def list_pbx_outbound_routes(self, pbx_id: UUID) -> list[dict[str, Any]]:
        """Outbound routes from synced cache."""
        return await self._list_from_cache(pbx_id, "outbound_routes")

    async def list_pbx_followme(self, pbx_id: UUID) -> list[dict[str, Any]]:
        """Follow-Me entries from synced cache."""
        return await self._list_from_cache(pbx_id, "followme")

    async def list_pbx_announcements(self, pbx_id: UUID) -> list[dict[str, Any]]:
        """Announcements from synced cache."""
        return await self._list_from_cache(pbx_id, "announcements")

    async def list_pbx_paging_groups(self, pbx_id: UUID) -> list[dict[str, Any]]:
        """Paging / intercom groups from synced cache."""
        return await self._list_from_cache(pbx_id, "paging_groups")

    async def list_pbx_daynight(self, pbx_id: UUID) -> list[dict[str, Any]]:
        """Day/Night call-flow controls from synced cache."""
        return await self._list_from_cache(pbx_id, "daynight")

    async def list_pbx_blacklist(self, pbx_id: UUID) -> list[dict[str, Any]]:
        """Blacklisted numbers from synced cache."""
        return await self._list_from_cache(pbx_id, "blacklist")

    async def list_pbx_certificates(self, pbx_id: UUID) -> list[dict[str, Any]]:
        """SSL / TLS certificates from synced cache."""
        return await self._list_from_cache(pbx_id, "certificates")

    async def list_pbx_admin_users(self, pbx_id: UUID) -> list[dict[str, Any]]:
        """FreePBX admin (AMP) users from synced cache."""
        return await self._list_from_cache(pbx_id, "admin_users")

    async def get_pbx_full_config(self, pbx_id: UUID) -> dict[str, Any]:
        """Return the full synced configuration snapshot for a PBX.

        Includes extensions, ring groups, trunks, queues, IVRs, DIDs,
        voicemail, outbound routes, follow-me, announcements, paging,
        day/night, blacklist, certificates and admin users.
        """
        from app.modules.voip.models import Extension, RingGroup

        pbx = await self.get_pbx(pbx_id)
        cache = (pbx.settings or {}).get("synced_cache", {})

        # Also include DB-resident extensions & ring groups
        ext_q = await self.db.execute(
            select(Extension).where(
                Extension.pbx_id == pbx_id,
                Extension.deleted_at.is_(None),
            )
        )
        rg_q = await self.db.execute(
            select(RingGroup).where(
                RingGroup.pbx_id == pbx_id,
                RingGroup.deleted_at.is_(None),
            )
        )
        exts = ext_q.scalars().all()
        rgs = rg_q.scalars().all()

        def _flat_settings(s):
            """Flatten old synced_data nesting if present."""
            out = dict(s or {})
            if "synced_data" in out:
                synced = out.pop("synced_data")
                if isinstance(synced, dict):
                    out.update(synced)
            return out

        return {
            "pbx_id": str(pbx.id),
            "pbx_name": pbx.name,
            "pbx_type": pbx.pbx_type,
            "synced_at": cache.get("synced_at"),
            "extensions": [
                {
                    "id": str(e.id),
                    "extension_number": e.extension_number,
                    "display_name": e.display_name,
                    "is_active": e.is_active,
                    "settings": _flat_settings(e.settings),
                }
                for e in exts
            ],
            "ring_groups": [
                {
                    "id": str(r.id),
                    "group_number": r.group_number,
                    "name": r.name,
                    "strategy": r.ring_strategy,
                    "ring_time": r.ring_time,
                    "members": r.members,
                    "is_active": r.is_active,
                    "settings": r.settings,
                }
                for r in rgs
            ],
            "trunks": cache.get("trunks", []),
            "queues": cache.get("queues", []),
            "ivrs": cache.get("ivrs", []),
            "dids": cache.get("dids", []),
            "voicemail_boxes": cache.get("voicemail_boxes", []),
            "outbound_routes": cache.get("outbound_routes", []),
            "followme": cache.get("followme", []),
            "announcements": cache.get("announcements", []),
            "paging_groups": cache.get("paging_groups", []),
            "daynight": cache.get("daynight", []),
            "blacklist": cache.get("blacklist", []),
            "certificates": cache.get("certificates", []),
            "admin_users": cache.get("admin_users", []),
            "time_conditions": cache.get("time_conditions", []),
            "contacts": cache.get("contacts", []),
            "system_recordings": cache.get("system_recordings", []),
            "music_on_hold": cache.get("music_on_hold", []),
            "ami_managers": cache.get("ami_managers", []),
            "backup_jobs": cache.get("backup_jobs", []),
            "sip_settings": cache.get("sip_settings", {}),
            "parking": cache.get("parking", {}),
            "feature_codes": cache.get("feature_codes", []),
            "installed_modules": cache.get("installed_modules", []),
        }

    async def create_pbx_extension(self, pbx_id: UUID, data: dict[str, Any]) -> dict[str, Any]:
        """Create a new extension on the PBX via adapter + save to DB."""
        from app.modules.voip.models import Extension

        ext_number = data.get("extension_number", "")
        display_name = data.get("display_name", ext_number)

        async def _op(adapter, pbx):
            result = await adapter.create_extension(ext_number, data)
            if not result.success:
                raise VoIPError(f"Failed to create extension: {result.error}")

            # Save to DB
            ext = Extension(
                pbx_id=pbx_id,
                extension_number=ext_number,
                display_name=display_name,
                caller_id_name=data.get("caller_id_name"),
                caller_id_number=data.get("caller_id_number"),
                voicemail_enabled=data.get("voicemail_enabled", True),
                voicemail_pin=data.get("voicemail_pin"),
                settings=data.get("settings", {}),
            )
            self.db.add(ext)
            await self.db.commit()
            await self.db.refresh(ext)

            return {
                "id": str(ext.id),
                "extension_number": ext_number,
                "display_name": display_name,
                "message": f"Extension {ext_number} created",
            }

        return await self._with_adapter(pbx_id, "create_extension", _op)

    async def update_pbx_extension(
        self, pbx_id: UUID, ext_number: str, data: dict[str, Any]
    ) -> dict[str, Any]:
        """Update an extension on the PBX via adapter + update DB."""
        from app.modules.voip.models import Extension

        async def _op(adapter, pbx):
            result = await adapter.update_extension(ext_number, data)
            if not result.success:
                raise VoIPError(f"Failed to update extension: {result.error}")

            # Update DB
            existing = await self.db.execute(
                select(Extension).where(
                    Extension.pbx_id == pbx_id,
                    Extension.extension_number == ext_number,
                    Extension.deleted_at.is_(None),
                )
            )
            ext = existing.scalar_one_or_none()
            if ext:
                for key, value in data.items():
                    if value is not None and key in _EXTENSION_MUTABLE_FIELDS:
                        setattr(ext, key, value)
                await self.db.commit()

            return {
                "extension_number": ext_number,
                "message": f"Extension {ext_number} updated",
            }

        return await self._with_adapter(pbx_id, "update_extension", _op)

    async def delete_pbx_extension(self, pbx_id: UUID, ext_number: str) -> dict[str, Any]:
        """Delete an extension from the PBX via adapter + remove from DB."""
        from app.modules.voip.models import Extension

        async def _op(adapter, pbx):
            result = await adapter.delete_extension(ext_number)
            if not result.success:
                raise VoIPError(f"Failed to delete extension: {result.error}")

            # Soft-delete from DB
            existing = await self.db.execute(
                select(Extension).where(
                    Extension.pbx_id == pbx_id,
                    Extension.extension_number == ext_number,
                    Extension.deleted_at.is_(None),
                )
            )
            ext = existing.scalar_one_or_none()
            ext_db_id = ext.id if ext else None
            if ext:
                ext.deleted_at = datetime.now(UTC)
                await self.db.commit()

            await self._audit_device_mutation(
                action="delete",
                resource_id=ext_db_id,
                resource_name=f"extension {ext_number}",
                extra_metadata={"pbx_id": str(pbx_id), "extension_number": ext_number},
            )

            return {
                "extension_number": ext_number,
                "message": f"Extension {ext_number} deleted",
            }

        return await self._with_adapter(pbx_id, "delete_extension", _op)

    async def originate_call(
        self,
        pbx_id: UUID,
        extension: str,
        destination: str,
        caller_id: str | None = None,
        context: str = "from-internal",
    ) -> dict[str, Any]:
        """Originate a call via the PBX adapter.

        The endpoint already gates on ``voip.manage_phones`` + the
        site-admin role; reaching here means the caller has authority
        to issue writes, so we pass ``force=True`` to satisfy the
        adapter's dual-gate contract.
        """
        _validate_extension_input(extension, "extension")
        _validate_extension_input(destination, "destination")
        _validate_context(context)
        channel = f"SIP/{extension}"

        async def _op(adapter, pbx):
            result = await adapter.originate_call(
                channel=channel,
                exten=destination,
                context=context,
                caller_id=caller_id or extension,
                force=True,
            )
            if not result.success:
                raise VoIPError(f"Failed to originate call: {result.error}")
            return {
                "status": "originated",
                "channel": channel,
                "destination": destination,
                "data": result.data,
            }

        return await self._with_adapter(pbx_id, "originate_call", _op)

    async def hangup_call(self, pbx_id: UUID, channel: str) -> dict[str, Any]:
        """Hang up an active call via the PBX adapter."""
        _validate_channel_input(channel)

        async def _op(adapter, pbx):
            result = await adapter.hangup_call(channel, force=True)
            if not result.success:
                raise VoIPError(f"Failed to hang up: {result.error}")
            return {"status": "hungup", "channel": channel}

        return await self._with_adapter(pbx_id, "hangup_call", _op)

    async def transfer_call(
        self,
        pbx_id: UUID,
        channel: str,
        destination: str,
        context: str = "from-internal",
    ) -> dict[str, Any]:
        """Transfer an active call via the PBX adapter."""
        _validate_channel_input(channel)
        _validate_extension_input(destination, "destination")
        _validate_context(context)

        async def _op(adapter, pbx):
            result = await adapter.transfer_call(channel, destination, context, force=True)
            if not result.success:
                raise VoIPError(f"Failed to transfer: {result.error}")
            return {"status": "transferred", "channel": channel, "destination": destination}

        return await self._with_adapter(pbx_id, "transfer_call", _op)

    async def reload_pbx_config(self, pbx_id: UUID) -> dict[str, Any]:
        """Apply pending PBX configuration changes (doreload) and clear the
        ``needs_reload`` flag so the 'Apply Config' banner goes away."""

        async def _op(adapter, pbx):
            result = await adapter.reload_pbx_config(force=True)
            if not result.success:
                raise VoIPError(f"Failed to reload: {result.error}")
            settings = dict(pbx.settings or {})
            if settings.get("needs_reload"):
                settings["needs_reload"] = False
                pbx.settings = settings
                from sqlalchemy.orm.attributes import flag_modified

                flag_modified(pbx, "settings")
            return {"status": "reloaded", "message": result.message, "data": result.data}

        return await self._with_adapter(pbx_id, "reload_config", _op)

    async def set_needs_reload(self, pbx_id: UUID, value: bool) -> None:
        """Set/clear the PBX ``needs_reload`` flag (DB-only, no device call).

        A staged config change applies to the FreePBX DB but is inert on the
        running Asterisk until a doreload, so the apply path flags this and the
        PBX page shows an 'Apply Config to activate' banner until reload.
        """
        pbx = await self.get_pbx(pbx_id)
        settings = dict(pbx.settings or {})
        if bool(settings.get("needs_reload")) == value:
            return
        settings["needs_reload"] = value
        pbx.settings = settings
        from sqlalchemy.orm.attributes import flag_modified

        flag_modified(pbx, "settings")
        await self.db.commit()

    async def queue_add_member(
        self,
        pbx_id: UUID,
        queue_name: str,
        interface: str,
        member_name: str = "",
    ) -> dict[str, Any]:
        """Add a member to a call queue."""

        async def _op(adapter, pbx):
            # Live AMI write — force=False so the adapter's read-only gate
            # (ADAPTER_READ_ONLY env) blocks it under a production lockdown.
            # (force=True would BYPASS the env lock, which is the bug we're
            # closing — queue-member previously mutated even in read-only.)
            result = await adapter.queue_add_member(queue_name, interface, member_name)
            if not result.success:
                raise VoIPError(f"Failed to add queue member: {result.error}")
            return {"status": "added", "queue": queue_name, "interface": interface}

        return await self._with_adapter(pbx_id, "queue_add_member", _op)

    async def queue_remove_member(
        self,
        pbx_id: UUID,
        queue_name: str,
        interface: str,
    ) -> dict[str, Any]:
        """Remove a member from a call queue."""

        async def _op(adapter, pbx):
            # Live AMI write — force=False so the read-only env gate blocks it
            # under lockdown (force=True would bypass the env lock).
            result = await adapter.queue_remove_member(queue_name, interface)
            if not result.success:
                raise VoIPError(f"Failed to remove queue member: {result.error}")
            return {"status": "removed", "queue": queue_name, "interface": interface}

        return await self._with_adapter(pbx_id, "queue_remove_member", _op)

    async def search_pbx_call_logs(
        self,
        pbx_id: UUID,
        start_date: str | None = None,
        end_date: str | None = None,
        src: str | None = None,
        dst: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Search call logs from the PBX adapter (live CDR)."""

        async def _op(adapter, pbx):
            result = await adapter.search_call_logs(
                start_date=start_date,
                end_date=end_date,
                src=src,
                dst=dst,
                limit=limit,
                offset=offset,
            )
            if not result.success:
                raise VoIPError(f"Failed to search CDR: {result.error}")
            return result.data or []

        return await self._with_adapter(pbx_id, "search_cdr", _op)

    # -------------------------------------------------------------------------
    # Extension Management
    # -------------------------------------------------------------------------

    async def get_extension_detail(
        self,
        pbx_id: UUID,
        ext_number: str,
    ) -> dict[str, Any]:
        """Get full extension detail: DB record + live adapter data merged."""
        from app.modules.voip.models import Extension

        # Fetch from DB
        ext_query = select(Extension).where(
            Extension.pbx_id == pbx_id,
            Extension.extension_number == ext_number,
            Extension.deleted_at.is_(None),
        )

        # Organization isolation (via PBX ownership)
        if self.organization_id:
            ext_query = ext_query.where(Extension.pbx_id.in_(select(self._pbx_ids_for_org().c.id)))

        q = await self.db.execute(ext_query)
        db_ext = q.scalar_one_or_none()
        if not db_ext:
            raise VoIPError(f"Extension {ext_number} not found")

        # Flatten settings: merge synced_data into top-level if old nesting exists
        raw_settings = dict(db_ext.settings or {})
        if "synced_data" in raw_settings:
            synced = raw_settings.pop("synced_data")
            if isinstance(synced, dict):
                raw_settings.update(synced)

        # redact SIP secrets FreePBX sync may stuff into settings before
        # returning them on the extension-detail read path.
        from app.core.redaction import redact_secrets

        detail: dict[str, Any] = {
            "id": str(db_ext.id),
            "pbx_id": str(db_ext.pbx_id),
            "extension_number": db_ext.extension_number,
            "display_name": db_ext.display_name,
            "caller_id_name": db_ext.caller_id_name,
            "caller_id_number": db_ext.caller_id_number,
            "voicemail_enabled": db_ext.voicemail_enabled,
            "ext_type": raw_settings.get("tech", "pjsip"),
            "is_active": db_ext.is_active,
            "settings": redact_secrets(raw_settings),
            "created_at": db_ext.created_at.isoformat() if db_ext.created_at else None,
            "updated_at": db_ext.updated_at.isoformat() if db_ext.updated_at else None,
        }

        # Try to enrich with live adapter data
        try:

            async def _op(adapter, pbx):
                result = await adapter.get_extension(ext_number)
                return result.data if result.success else None

            live_data = await self._with_adapter(pbx_id, "get_extension", _op)
            if live_data and isinstance(live_data, dict):
                # the live FreePBX AJAX grid returns the SIP secret
                # (secret/sippasswd) in cleartext — redact it the same way the DB
                # path above does, so a voip.view caller never sees the live secret.
                detail["live"] = redact_secrets(live_data)
        except Exception:
            detail["live"] = None

        return detail

    async def list_extensions(
        self,
        pbx_id: UUID,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[Any], int]:
        """List extensions for a PBX. Returns (items, total)."""
        from app.modules.voip.models import Extension

        base = select(Extension).where(
            Extension.pbx_id == pbx_id,
            Extension.deleted_at.is_(None),
        )

        # Organization isolation (via PBX ownership)
        if self.organization_id:
            base = base.where(Extension.pbx_id.in_(select(self._pbx_ids_for_org().c.id)))

        count_result = await self.db.execute(select(func.count()).select_from(base.subquery()))
        total = count_result.scalar_one()

        query = base.order_by(Extension.extension_number).limit(limit).offset(offset)
        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def list_all_extensions(
        self,
        limit: int = 100,
        offset: int = 0,
        site_id: UUID | None = None,
    ) -> tuple[list[Any], int]:
        """List all extensions across all PBX systems. Returns (items, total).

        Pass ``site_id`` to scope to a single site (via the PBX's
        ``site_id``). Extensions live under PBXes, not directly under
        sites, so the filter has to join through ``voip.pbx``.
        """
        from app.modules.voip.models import Extension

        base = select(Extension).where(Extension.deleted_at.is_(None))

        # Organization isolation (via PBX ownership)
        if self.organization_id:
            base = base.where(Extension.pbx_id.in_(select(self._pbx_ids_for_org().c.id)))
        if site_id:
            base = base.where(Extension.pbx_id.in_(select(self._pbx_ids_for_site(site_id).c.id)))

        count_result = await self.db.execute(select(func.count()).select_from(base.subquery()))
        total = count_result.scalar_one()

        query = base.order_by(Extension.extension_number).limit(limit).offset(offset)
        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def list_ring_groups(
        self,
        pbx_id: UUID | None = None,
        limit: int = 100,
        offset: int = 0,
        site_id: UUID | None = None,
    ) -> tuple[list[Any], int]:
        """List ring groups. Returns (items, total).

        ``site_id`` scopes to one site via the PBX-site join (ring
        groups inherit their site from the PBX they belong to).
        """
        from app.modules.voip.models import RingGroup

        base = select(RingGroup).where(RingGroup.deleted_at.is_(None))

        # Organization isolation (via PBX ownership)
        if self.organization_id:
            base = base.where(RingGroup.pbx_id.in_(select(self._pbx_ids_for_org().c.id)))

        if pbx_id:
            base = base.where(RingGroup.pbx_id == pbx_id)
        if site_id:
            base = base.where(RingGroup.pbx_id.in_(select(self._pbx_ids_for_site(site_id).c.id)))

        count_result = await self.db.execute(select(func.count()).select_from(base.subquery()))
        total = count_result.scalar_one()

        query = base.order_by(RingGroup.group_number).limit(limit).offset(offset)
        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def create_ring_group(self, data: dict[str, Any]) -> dict[str, Any]:
        """Create a ring group on the PBX via adapter + save to DB.

        Twin of :meth:`create_pbx_extension` — push to the device through
        the adapter first, then persist the local mirror row. ``pbx_id`` is
        resolved through :meth:`get_pbx`, which enforces organization
        isolation, so a caller can never create a ring group on a PBX
        outside their org.
        """
        from app.modules.voip.models import RingGroup

        pbx_id = data["pbx_id"]
        group_number = data["group_number"]
        name = data.get("name", group_number)

        # Adapter payload — FreePBX ring-group keys. ``grpnum``/``grplist``
        # are the field names the adapter/REST surface expects; ``members``
        # is joined into the dial list FreePBX stores ("-" separated).
        adapter_payload: dict[str, Any] = {
            "grpnum": group_number,
            "description": name,
            "grplist": "-".join(str(m) for m in data.get("members", [])),
            "strategy": data.get("ring_strategy", "ringall"),
            "grptime": data.get("ring_time", 20),
        }

        async def _op(adapter, pbx):
            result = await adapter.create_ring_group(adapter_payload)
            if not result.success:
                raise VoIPError(f"Failed to create ring group: {result.error}")

            rg = RingGroup(
                pbx_id=pbx_id,
                group_number=group_number,
                name=name,
                description=data.get("description"),
                ring_strategy=data.get("ring_strategy", "ringall"),
                ring_time=data.get("ring_time", 20),
                members=data.get("members", []),
                settings=data.get("settings", {}),
            )
            self.db.add(rg)
            await self.db.commit()
            await self.db.refresh(rg)

            return {
                "id": str(rg.id),
                "pbx_id": str(pbx_id),
                "group_number": group_number,
                "name": name,
                "message": f"Ring group {group_number} created",
            }

        return await self._with_adapter(pbx_id, "create_ring_group", _op)

    async def delete_ring_group(self, ring_group_id: UUID) -> dict[str, Any]:
        """Delete a ring group from the PBX via adapter + soft-delete the row.

        The row is looked up first so we can (a) resolve the owning PBX
        and group number, and (b) enforce organization isolation via the
        ``_pbx_ids_for_org`` subquery — a caller cannot delete a ring
        group belonging to another org's PBX.
        """
        from app.modules.voip.models import RingGroup

        query = select(RingGroup).where(
            RingGroup.id == ring_group_id,
            RingGroup.deleted_at.is_(None),
        )
        if self.organization_id:
            query = query.where(RingGroup.pbx_id.in_(select(self._pbx_ids_for_org().c.id)))

        result = await self.db.execute(query)
        rg = result.scalar_one_or_none()
        if not rg:
            raise VoIPError(f"Ring group {ring_group_id} not found")

        pbx_id = rg.pbx_id
        group_number = rg.group_number

        async def _op(adapter, pbx):
            result = await adapter.delete_ring_group(group_number)
            if not result.success:
                raise VoIPError(f"Failed to delete ring group: {result.error}")

            rg.deleted_at = datetime.now(UTC)
            await self.db.commit()

            await self._audit_device_mutation(
                action="delete",
                resource_id=ring_group_id,
                resource_name=f"ring group {group_number}",
                extra_metadata={"pbx_id": str(pbx_id), "group_number": str(group_number)},
            )

            return {
                "id": str(ring_group_id),
                "group_number": group_number,
                "message": f"Ring group {group_number} deleted",
            }

        return await self._with_adapter(pbx_id, "delete_ring_group", _op)

    # -------------------------------------------------------------------------
    # Call Logs
    # -------------------------------------------------------------------------

    async def extension_counts(self, pbx_ids: list[UUID]) -> dict[UUID, int]:
        """Count non-deleted extensions per PBX (for list/detail badges).

        Grouped in one query to avoid an N+1 when the PBX list renders an
        extension-count column for every row.
        """
        from app.modules.voip.models import Extension

        if not pbx_ids:
            return {}
        rows = await self.db.execute(
            select(Extension.pbx_id, func.count())
            .where(Extension.pbx_id.in_(pbx_ids), Extension.deleted_at.is_(None))
            .group_by(Extension.pbx_id)
        )
        return dict(rows.all())

    async def create_call_log(self, pbx_id: UUID, **record: Any) -> Any:
        """Persist one adapter CDR record as a ``CallLog`` row.

        Called by the CDR-sync task per record returned from
        ``adapter.search_call_logs``. Tolerant of BOTH already-normalized
        records (``caller_number``/``callee_number``/``direction``/``status``/
        ``start_time``/``duration_seconds``) AND raw Asterisk/FreePBX CDR keys
        (``src``/``clid``/``cnum``, ``dst``, ``disposition``, ``calldate``,
        ``duration``, ``billsec``, ``uniqueid``, ``recordingfile``) so it works
        regardless of how a given adapter shapes its CDR.

        Does NOT commit — the caller owns the transaction. Idempotent on
        ``unique_id``: an existing ``(pbx_id, unique_id)`` row is returned
        rather than duplicated, so repeated syncs don't pile up dupes.
        """
        from app.modules.voip.models import CallLog

        def _first(*keys: str, default: Any = None) -> Any:
            for k in keys:
                v = record.get(k)
                if v not in (None, ""):
                    return v
            return default

        def _to_dt(value: Any) -> datetime | None:
            if value is None or value == "":
                return None
            if isinstance(value, datetime):
                return value
            if isinstance(value, (int, float)):
                with contextlib.suppress(Exception):
                    return datetime.fromtimestamp(float(value), tz=UTC)
                return None
            text = str(value).strip()
            # epoch-as-string
            if text.isdigit():
                with contextlib.suppress(Exception):
                    return datetime.fromtimestamp(int(text), tz=UTC)
            # ISO / "YYYY-MM-DD HH:MM:SS" (Asterisk calldate)
            with contextlib.suppress(Exception):
                return datetime.fromisoformat(text.replace("Z", "+00:00"))
            return None

        def _to_int(value: Any) -> int:
            with contextlib.suppress(Exception):
                return int(float(value))
            return 0

        unique_id = _first("unique_id", "uniqueid", "linkedid")
        if unique_id is not None:
            unique_id = str(unique_id)[:100]
            existing = await self.db.scalar(
                select(CallLog).where(
                    CallLog.pbx_id == pbx_id,
                    CallLog.unique_id == unique_id,
                )
            )
            if existing is not None:
                return existing

        # Disposition (ANSWERED / NO ANSWER / BUSY / FAILED) → our status vocab
        raw_status = str(_first("status", "disposition", default="unknown")).strip().lower()
        status_map = {
            "answered": "completed",
            "no answer": "no_answer",
            "noanswer": "no_answer",
            "busy": "busy",
            "failed": "failed",
            "congestion": "failed",
            "completed": "completed",
        }
        status = (status_map.get(raw_status, raw_status) or "unknown")[:20]

        direction = (str(_first("direction", default="")).strip().lower() or "unknown")[:20]

        call = CallLog(
            pbx_id=pbx_id,
            unique_id=unique_id,
            caller_number=str(_first("caller_number", "src", "cnum", "clid", default="unknown"))[
                :50
            ],
            caller_name=(_first("caller_name", "cnam") or None),
            callee_number=str(_first("callee_number", "dst", "dnis", default="unknown"))[:50],
            callee_name=(_first("callee_name") or None),
            direction=direction,
            status=status,
            start_time=_to_dt(_first("start_time", "calldate", "start", "eventtime"))
            or datetime.now(UTC),
            answer_time=_to_dt(_first("answer_time", "answer")),
            end_time=_to_dt(_first("end_time", "end")),
            duration_seconds=_to_int(_first("duration_seconds", "duration", default=0)),
            ring_duration_seconds=_to_int(_first("ring_duration_seconds", "billsec", default=0)),
            recording_path=(_first("recording_path", "recordingfile") or None),
            metadata_json={},
        )
        self.db.add(call)
        return call

    async def search_call_logs(
        self,
        pbx_id: UUID | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        direction: str | None = None,
        status: str | None = None,
        caller: str | None = None,
        callee: str | None = None,
        limit: int = 100,
        offset: int = 0,
        site_id: UUID | None = None,
    ) -> tuple[list[Any], int]:
        """Search call logs with pagination. Returns (items, total).

        ``site_id`` scopes to one site via PBX (CDR is PBX-scoped, so
        site filtering joins through voip.pbx).
        """
        from app.modules.voip.models import CallLog

        base = select(CallLog)

        # Organization isolation (via PBX ownership)
        if self.organization_id:
            base = base.where(CallLog.pbx_id.in_(select(self._pbx_ids_for_org().c.id)))

        if pbx_id:
            base = base.where(CallLog.pbx_id == pbx_id)
        if site_id:
            base = base.where(CallLog.pbx_id.in_(select(self._pbx_ids_for_site(site_id).c.id)))
        if start_time:
            base = base.where(CallLog.start_time >= start_time)
        if end_time:
            base = base.where(CallLog.start_time <= end_time)
        if direction:
            base = base.where(CallLog.direction == direction)
        if status:
            # The CDR normalizer (_normalize_and_store_cdr) stores answered
            # calls as "completed" and never stores "answered"/"missed".
            # Accept the canonical-enum / human synonyms an API client (or the
            # old FE dropdown) may send so the filter doesn't silently match
            # zero rows. "missed" maps to "no_answer" (the stored equivalent).
            status_synonyms = {"answered": "completed", "missed": "no_answer"}
            base = base.where(CallLog.status == status_synonyms.get(status, status))
        if caller:
            base = base.where(CallLog.caller_number.ilike(f"%{_escape_like(caller)}%", escape="\\"))
        if callee:
            base = base.where(CallLog.callee_number.ilike(f"%{_escape_like(callee)}%", escape="\\"))

        count_result = await self.db.execute(select(func.count()).select_from(base.subquery()))
        total = count_result.scalar_one()

        query = base.order_by(CallLog.start_time.desc()).limit(limit).offset(offset)
        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def get_call_stats(
        self,
        pbx_id: UUID | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        site_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Get call statistics, optionally scoped to a single site."""
        from app.modules.voip.models import CallLog

        query = select(
            func.count(CallLog.id).label("total_calls"),
            func.sum(CallLog.duration_seconds).label("total_duration"),
            func.avg(CallLog.duration_seconds).label("avg_duration"),
        )

        # Organization isolation (via PBX ownership)
        if self.organization_id:
            query = query.where(CallLog.pbx_id.in_(select(self._pbx_ids_for_org().c.id)))

        if pbx_id:
            query = query.where(CallLog.pbx_id == pbx_id)
        if site_id:
            query = query.where(CallLog.pbx_id.in_(select(self._pbx_ids_for_site(site_id).c.id)))
        if start_time:
            query = query.where(CallLog.start_time >= start_time)
        if end_time:
            query = query.where(CallLog.start_time <= end_time)

        result = await self.db.execute(query)
        row = result.one()

        return {
            "total_calls": row.total_calls or 0,
            "total_duration": row.total_duration or 0,
            "avg_duration": float(row.avg_duration or 0),
        }

    # -------------------------------------------------------------------------
    # Voicemail Management
    # -------------------------------------------------------------------------

    async def list_voicemails(
        self,
        extension_number: str | None = None,
        folder: str | None = None,
        is_read: bool | None = None,
        limit: int = 100,
        offset: int = 0,
        site_id: UUID | None = None,
    ) -> tuple[list[Any], int]:
        """List voicemail messages. Returns (items, total).

        ``site_id`` scopes to one site via PBX (voicemails are
        PBX-scoped, so the filter joins through voip.pbx).
        """
        from app.modules.voip.models import VoicemailMessage

        base = select(VoicemailMessage).where(VoicemailMessage.deleted_at.is_(None))

        # Organization isolation (via PBX ownership)
        if self.organization_id:
            base = base.where(VoicemailMessage.pbx_id.in_(select(self._pbx_ids_for_org().c.id)))

        if extension_number:
            base = base.where(VoicemailMessage.extension_number == extension_number)
        if folder:
            base = base.where(VoicemailMessage.folder == folder)
        if is_read is not None:
            base = base.where(VoicemailMessage.is_read == is_read)
        if site_id:
            base = base.where(
                VoicemailMessage.pbx_id.in_(select(self._pbx_ids_for_site(site_id).c.id))
            )

        count_result = await self.db.execute(select(func.count()).select_from(base.subquery()))
        total = count_result.scalar_one()

        query = base.order_by(VoicemailMessage.message_date.desc()).limit(limit).offset(offset)

        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def get_voicemail(self, vm_id: UUID) -> Any:
        """Get a voicemail by ID."""
        from app.modules.voip.models import VoicemailMessage

        query = select(VoicemailMessage).where(
            VoicemailMessage.id == vm_id,
            VoicemailMessage.deleted_at.is_(None),
        )

        # Organization isolation (via PBX ownership)
        if self.organization_id:
            query = query.where(VoicemailMessage.pbx_id.in_(select(self._pbx_ids_for_org().c.id)))

        result = await self.db.execute(query)
        vm = result.scalar_one_or_none()

        if not vm:
            raise VoicemailNotFoundError(vm_id)

        return vm

    async def update_voicemail(self, vm_id: UUID, data: dict[str, Any]) -> Any:
        """Update a voicemail (mark read, move folder, etc.)."""
        vm = await self.get_voicemail(vm_id)

        for key, value in data.items():
            if value is not None and key in _VOICEMAIL_MUTABLE_FIELDS:
                setattr(vm, key, value)

        await self.db.commit()
        await self.db.refresh(vm)
        return vm

    async def delete_voicemail(self, vm_id: UUID) -> bool:
        """Soft-delete a voicemail message."""
        vm = await self.get_voicemail(vm_id)
        vm.deleted_at = datetime.now(UTC)
        await self.db.commit()
        return True

    async def mark_voicemail_read(self, vm_id: UUID) -> Any:
        """Mark a voicemail as read."""
        return await self.update_voicemail(vm_id, {"is_read": True})

    async def get_voicemail_stats(
        self,
        extension_number: str | None = None,
        site_id: UUID | None = None,
    ) -> dict[str, int]:
        """Get voicemail statistics, optionally scoped to one site."""
        from app.modules.voip.models import VoicemailMessage

        query = select(
            func.count(VoicemailMessage.id).label("total"),
            func.sum(func.cast(~VoicemailMessage.is_read, Integer)).label("unread"),
            func.sum(func.cast(VoicemailMessage.is_urgent, Integer)).label("urgent"),
        ).where(VoicemailMessage.deleted_at.is_(None))

        # Organization isolation (via PBX ownership)
        if self.organization_id:
            query = query.where(VoicemailMessage.pbx_id.in_(select(self._pbx_ids_for_org().c.id)))

        if extension_number:
            query = query.where(VoicemailMessage.extension_number == extension_number)
        if site_id:
            query = query.where(
                VoicemailMessage.pbx_id.in_(select(self._pbx_ids_for_site(site_id).c.id))
            )

        result = await self.db.execute(query)
        row = result.one()

        return {
            "total": row.total or 0,
            "unread": int(row.unread or 0),
            "urgent": int(row.urgent or 0),
        }
