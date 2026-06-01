# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Gateway Integration Service
===========================================

Orchestration layer that abstracts vendor differences when talking to
OPNsense / pfSense / MikroTik gateways.  All database and adapter I/O
is centralised here; the API layer stays thin.
"""

import asyncio
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.adapters.base import AdapterResult, BaseAdapter
from app.adapters.cache import adapter_cache
from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConnectionError,
    AdapterTimeoutError,
)
from app.adapters.registry import adapter_registry
from app.core.crypto import decrypt_dict, encrypt_dict
from app.modules.firewall.models import (
    GatewayConnection,
    GatewaySyncLog,
    GatewaySyncStatus,
    GatewayVendor,
)
from app.modules.firewall.schemas import FORBIDDEN_ADAPTER_SETTINGS

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Exceptions
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayError(Exception):
    """Base gateway error."""

    pass


class GatewayNotFoundError(GatewayError):
    def __init__(self, gw_id: UUID):
        super().__init__(f"Gateway connection not found: {gw_id}")
        self.gateway_id = gw_id


class GatewayConnectionTestError(GatewayError):
    pass


# ═══════════════════════════════════════════════════════════════════════════════
# Error sanitisation helpers
# ═══════════════════════════════════════════════════════════════════════════════


def _sanitize_adapter_error(exc: Exception) -> str:
    """Map adapter exceptions to user-safe messages.

    Internal details (stack traces, raw messages) are never returned to clients.
    Callers are responsible for logging the full exception server-side before
    invoking this helper.
    """
    if isinstance(exc, AdapterAuthenticationError):
        return "Authentication failed - check credentials"
    if isinstance(exc, AdapterConnectionError):
        return "Connection failed - check host and port"
    if isinstance(exc, AdapterTimeoutError):
        return "Connection timed out - device may be unreachable"
    return "An unexpected error occurred"


# ═══════════════════════════════════════════════════════════════════════════════
# Service
# ═══════════════════════════════════════════════════════════════════════════════


class GatewayService:
    """
    Business logic for managing external firewall/router gateway integrations.
    """

    def __init__(self, db: AsyncSession, accessible_site_ids: set[UUID] | None = None):
        self.db = db
        # per-user site grant; gateway connections are
        # site-scoped, so a site-limited caller must not reach a non-granted one.
        self.accessible_site_ids = accessible_site_ids

    # ─── helpers ─────────────────────────────────────────────────────────

    def _build_adapter(self, gw: GatewayConnection) -> BaseAdapter:
        """Instantiate the correct vendor adapter from a GatewayConnection row."""
        creds = decrypt_dict(gw.credentials or {})

        if gw.vendor in (GatewayVendor.OPNSENSE, GatewayVendor.PFSENSE):
            username = creds.get("api_key", "")
            password = creds.get("api_secret", "")
        else:  # mikrotik, openwrt
            username = creds.get("username", "")
            password = creds.get("password", "")

        # SECURITY (write-path audit, CRITICAL): never forward write-gate control
        # keys (direct_write_force, etc.) from operator-supplied settings into the
        # adapter constructor - that would bypass ADAPTER_READ_ONLY. The schema
        # strips these on write; this is the defense-in-depth backstop for any
        # pre-existing or out-of-band row.
        safe_settings = {
            k: v
            for k, v in (gw.settings or {}).items()
            if str(k).lower() not in FORBIDDEN_ADAPTER_SETTINGS
        }
        return adapter_registry.create_adapter(
            adapter_id=gw.vendor,
            host=gw.host,
            username=username,
            password=password,
            port=gw.port,
            verify_ssl=gw.verify_ssl,
            **safe_settings,
        )

    def _build_adapter_from_raw(
        self,
        vendor: str,
        host: str,
        port: int,
        verify_ssl: bool,
        *,
        api_key: str | None = None,
        api_secret: str | None = None,
        username: str | None = None,
        password: str | None = None,
        **extra: Any,
    ) -> BaseAdapter:
        """Instantiate adapter from raw credentials (e.g. a test request)."""
        if vendor in (GatewayVendor.OPNSENSE, GatewayVendor.PFSENSE):
            u, p = api_key or "", api_secret or ""
        else:
            u, p = username or "", password or ""

        safe_extra = {
            k: v
            for k, v in (extra or {}).items()
            if str(k).lower() not in FORBIDDEN_ADAPTER_SETTINGS
        }
        return adapter_registry.create_adapter(
            adapter_id=vendor,
            host=host,
            username=u,
            password=p,
            port=port,
            verify_ssl=verify_ssl,
            **safe_extra,
        )

    async def _get_gw(self, gw_id: UUID, org_id: UUID) -> GatewayConnection:
        result = await self.db.execute(
            select(GatewayConnection).where(
                GatewayConnection.id == gw_id,
                GatewayConnection.org_id == org_id,
                GatewayConnection.deleted_at.is_(None),
            )
        )
        gw = result.scalar_one_or_none()
        if not gw:
            raise GatewayNotFoundError(gw_id)
        if self.accessible_site_ids is not None and gw.site_id not in self.accessible_site_ids:
            raise GatewayNotFoundError(gw_id)
        return gw

    # ═══════════════════════════════════════════════════════════════════════
    # CRUD
    # ═══════════════════════════════════════════════════════════════════════

    async def list_gateways(
        self,
        org_id: UUID,
        *,
        site_id: UUID | None = None,
        vendor: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[GatewayConnection], int]:
        """List gateway connections with optional filters."""
        q = (
            select(GatewayConnection)
            .where(
                GatewayConnection.org_id == org_id,
                GatewayConnection.deleted_at.is_(None),
            )
            .options(selectinload(GatewayConnection.sync_logs))
            .order_by(GatewayConnection.created_at.desc())
        )
        count_q = (
            select(func.count())
            .select_from(GatewayConnection)
            .where(
                GatewayConnection.org_id == org_id,
                GatewayConnection.deleted_at.is_(None),
            )
        )

        if site_id:
            q = q.where(GatewayConnection.site_id == site_id)
            count_q = count_q.where(GatewayConnection.site_id == site_id)
        if self.accessible_site_ids is not None:
            q = q.where(GatewayConnection.site_id.in_(self.accessible_site_ids))
            count_q = count_q.where(GatewayConnection.site_id.in_(self.accessible_site_ids))
        if vendor:
            q = q.where(GatewayConnection.vendor == vendor)
            count_q = count_q.where(GatewayConnection.vendor == vendor)

        total = (await self.db.execute(count_q)).scalar() or 0
        items = list((await self.db.execute(q.limit(limit).offset(offset))).scalars().all())
        return items, total

    async def get_gateway(self, gw_id: UUID, org_id: UUID) -> GatewayConnection:
        return await self._get_gw(gw_id, org_id)

    async def create_gateway(
        self,
        org_id: UUID,
        *,
        name: str,
        vendor: str,
        host: str,
        port: int = 443,
        verify_ssl: bool = False,
        site_id: UUID | None = None,
        api_key: str | None = None,
        api_secret: str | None = None,
        username: str | None = None,
        password: str | None = None,
        sync_enabled: bool = True,
        sync_interval_seconds: int = 300,
        settings: dict[str, Any] | None = None,
        description: str | None = None,
    ) -> GatewayConnection:
        """Create a new gateway connection.

        Tenant-scoped + SSRF-validated. Both checks were missing in the
        pre-May-2026 implementation: a caller with org A's token could
        pass an org B site_id and the create would succeed (effectively
        moving a gateway under a foreign tenant's site), and the host
        was accepted without checking against the SSRF blocklist that
        every Controller/Site form already runs through. Aligned to the
        canonical ``_validate_controller_host`` chokepoint and a tenant
        site lookup.
        """
        # Late import keeps the firewall module decoupled from the
        # core models package at import time (the gateway_service is
        # eagerly loaded during app init and the Site model is
        # registered later in the autoload sequence).
        from app.models.core import Site
        from app.services.adapter_base import GatewayServiceBase as GatewayFeatureService

        # SSRF chokepoint — refuses cloud-metadata IPs / loopback /
        # FreeSDN's own host. RFC1918 is intentionally permitted.
        GatewayFeatureService._validate_controller_host(host)

        if site_id is None and self.accessible_site_ids is not None:
            # FSDN-SG-002: a site-limited caller must NOT create an org-global
            # (null-site) gateway. Otherwise device_sync parents the resulting
            # shadow Device under an arbitrary fallback site that may be outside
            # the caller's grant (and, before the device_sync fix, another
            # tenant). Org admins (accessible_site_ids is None) may still create
            # org-wide gateways. Raise a clean 422 (the create route does not
            # map GatewayNotFoundError).
            from fastapi import HTTPException

            raise HTTPException(
                status_code=422,
                detail="site_id is required when your access is limited to specific sites",
            )

        if site_id is not None:
            site = await self.db.get(Site, site_id)
            if site is None or site.organization_id != org_id:
                # Use the same opaque "not found" shape we use elsewhere
                # so a tenant probing for another tenant's site IDs
                # can't distinguish "site exists but isn't mine" from
                # "site doesn't exist".
                raise GatewayNotFoundError(site_id)
            # a site-limited caller must hold a grant on the
            # target site, mirroring the read-path check in ``_get_gw``.
            if self.accessible_site_ids is not None and site_id not in self.accessible_site_ids:
                raise GatewayNotFoundError(site_id)

        if vendor in (GatewayVendor.OPNSENSE, GatewayVendor.PFSENSE):
            creds = {"api_key": api_key or "", "api_secret": api_secret or ""}
        else:
            creds = {"username": username or "", "password": password or ""}

        gw = GatewayConnection(
            org_id=org_id,
            site_id=site_id,
            name=name,
            description=description,
            vendor=vendor,
            host=host,
            port=port,
            verify_ssl=verify_ssl,
            credentials=encrypt_dict(creds),
            sync_enabled=sync_enabled,
            sync_interval_seconds=sync_interval_seconds,
            settings=settings or {},
        )
        self.db.add(gw)
        await self.db.flush()
        await self.db.refresh(gw)
        return gw

    async def update_gateway(
        self,
        gw_id: UUID,
        org_id: UUID,
        **fields: Any,
    ) -> GatewayConnection:
        """Partial-update a gateway connection.

        Both ``host`` (SSRF) and ``site_id`` (tenant boundary) must be
        re-validated on update for the same reasons documented in
        ``create_gateway`` — without these checks an operator could
        switch a gateway from a permitted host to a cloud-metadata IP,
        or attach a gateway to another tenant's site, mid-lifecycle.
        """
        from app.models.core import Site
        from app.services.adapter_base import GatewayServiceBase as GatewayFeatureService

        gw = await self._get_gw(gw_id, org_id)

        if fields.get("host") is not None:
            GatewayFeatureService._validate_controller_host(fields["host"])
        if fields.get("site_id") is not None:
            site = await self.db.get(Site, fields["site_id"])
            if site is None or site.organization_id != org_id:
                raise GatewayNotFoundError(fields["site_id"])
            # a site-limited caller cannot reassign a gateway
            # to a sibling site they lack a grant for.
            if (
                self.accessible_site_ids is not None
                and fields["site_id"] not in self.accessible_site_ids
            ):
                raise GatewayNotFoundError(fields["site_id"])

        simple_fields = {
            "name",
            "description",
            "host",
            "port",
            "verify_ssl",
            "site_id",
            "sync_enabled",
            "sync_interval_seconds",
            "settings",
        }
        for key in simple_fields:
            if key in fields and fields[key] is not None:
                setattr(gw, key, fields[key])

        # Credential updates — decrypt existing, merge, re-encrypt
        creds = decrypt_dict(gw.credentials or {})
        if gw.vendor in (GatewayVendor.OPNSENSE, GatewayVendor.PFSENSE):
            if fields.get("api_key") is not None:
                creds["api_key"] = fields["api_key"]
            if fields.get("api_secret") is not None:
                creds["api_secret"] = fields["api_secret"]
        else:
            if fields.get("username") is not None:
                creds["username"] = fields["username"]
            if fields.get("password") is not None:
                creds["password"] = fields["password"]
        gw.credentials = encrypt_dict(creds)

        await self.db.flush()
        await self.db.refresh(gw)
        return gw

    async def delete_gateway(self, gw_id: UUID, org_id: UUID) -> None:
        """Soft-delete a gateway connection.

        Also purges any ``SiteRoleAssignment`` rows that reference
        this gateway. The FK declares ``ondelete="CASCADE"`` but
        cascades only fire on hard DELETE — soft-deleting the parent
        gateway leaves role assignments orphaned with a dangling
        ``gateway_id``. Subsequent reconciliation queries would fail
        gracefully but the role map UI shows a dead brain/limb
        assignment, and if the same gateway is later undeleted the
        role map silently re-activates.
        """
        gw = await self._get_gw(gw_id, org_id)
        gw.deleted_at = datetime.now(UTC)

        # Cascade soft-delete to role assignments referencing this
        # gateway. Use a DELETE statement (the audit-trail value of
        # keeping the row is low — the gateway's gone, the assignment
        # is meaningless without it).
        try:
            from sqlalchemy import delete as sql_delete

            from app.modules.gateway.models import SiteRoleAssignment

            await self.db.execute(
                sql_delete(SiteRoleAssignment).where(
                    SiteRoleAssignment.gateway_id == gw_id,
                )
            )
        except Exception:
            # Gateway module may not be loaded in every deployment
            # (e.g., minimal-install pipelines). The delete itself
            # must not fail because of a downstream cleanup hiccup.
            import logging

            logging.getLogger(__name__).warning(
                "role-assignment cleanup skipped for deleted gateway %s — orphans may remain",
                gw_id,
                exc_info=True,
            )

        await self.db.flush()

    # ═══════════════════════════════════════════════════════════════════════
    # Connection Test
    # ═══════════════════════════════════════════════════════════════════════

    async def test_connection(
        self,
        vendor: str,
        host: str,
        port: int,
        verify_ssl: bool,
        *,
        api_key: str | None = None,
        api_secret: str | None = None,
        username: str | None = None,
        password: str | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        """Test connection to a gateway without persisting. Returns a result dict."""
        adapter = self._build_adapter_from_raw(
            vendor,
            host,
            port,
            verify_ssl,
            api_key=api_key,
            api_secret=api_secret,
            username=username,
            password=password,
            **extra,
        )

        t0 = time.monotonic()
        try:
            result: AdapterResult = await adapter.test_connection()
            latency = int((time.monotonic() - t0) * 1000)

            if not result.success:
                return {
                    "success": False,
                    "message": result.message or "Connection test failed",
                    "vendor": vendor,
                    "latency_ms": latency,
                }

            data = result.data or {}
            hostname = (
                data.get("hostname")
                or data.get("identity", {}).get("name")
                or data.get("status", {}).get("name")
            )
            version = (
                data.get("version")
                or data.get("resource", {}).get("version")
                or (data.get("status", {}).get("product_version") if "status" in data else None)
            )

            return {
                "success": True,
                "message": result.message or "Connection successful",
                "vendor": vendor,
                "hostname": hostname,
                "version": str(version) if version else None,
                "model": data.get("model"),
                "latency_ms": latency,
                "capabilities": [],  # could be expanded later
            }
        except Exception as exc:
            latency = int((time.monotonic() - t0) * 1000)
            logger.error("Connection test failed for %s: %s", vendor, exc, exc_info=True)
            return {
                "success": False,
                "message": _sanitize_adapter_error(exc),
                "vendor": vendor,
                "latency_ms": latency,
            }

    async def test_existing_gateway(
        self,
        gw_id: UUID,
        org_id: UUID,
        *,
        verify_ssl: bool | None = None,
    ) -> dict[str, Any]:
        """Test an already-saved gateway connection against its STORED host.

        the decrypted stored credentials are ONLY ever sent to the
        gateway's persisted ``host``/``port`` — never a caller-supplied
        destination — so this read-tier test cannot be used to exfiltrate the
        firewall's admin secrets to an attacker-chosen host. ``verify_ssl`` may
        still be toggled (it does not redirect where the secret goes).
        """
        gw = await self._get_gw(gw_id, org_id)
        creds = decrypt_dict(gw.credentials or {})
        result = await self.test_connection(
            vendor=gw.vendor,
            host=gw.host,
            port=gw.port,
            verify_ssl=gw.verify_ssl if verify_ssl is None else verify_ssl,
            api_key=creds.get("api_key"),
            api_secret=creds.get("api_secret"),
            username=creds.get("username"),
            password=creds.get("password"),
        )

        # Persist detected metadata on successful test
        if result.get("success"):
            if result.get("hostname"):
                gw.detected_hostname = result["hostname"]
            if result.get("version"):
                gw.detected_version = result["version"]
            if result.get("model"):
                gw.detected_model = result["model"]
            gw.is_online = True
            gw.last_seen_at = datetime.now(UTC)
            await self.db.flush()
        else:
            gw.is_online = False
            await self.db.flush()

        return result

    # ═══════════════════════════════════════════════════════════════════════
    # Live Data (proxied through adapter)
    # ═══════════════════════════════════════════════════════════════════════

    async def _with_adapter(self, gw: GatewayConnection):
        """Return a connected adapter as async context manager."""
        adapter = self._build_adapter(gw)
        return adapter

    async def _adapter_for(self, gw_id: UUID, org_id: UUID):
        """Fetch gateway + build + connect adapter, yielding it in a context manager.

        Usage::

            async with self._adapter_for(gw_id, org_id) as (gw, adapter):
                result = await adapter.get_device_status(str(gw.id))
        """

        @asynccontextmanager
        async def _ctx() -> AsyncIterator[tuple[GatewayConnection, BaseAdapter]]:
            gw = await self._get_gw(gw_id, org_id)
            adapter = self._build_adapter(gw)
            try:
                await adapter.connect()
                yield gw, adapter
            finally:
                try:
                    await adapter.disconnect()
                except Exception as exc:
                    logger.debug(
                        "Adapter disconnect failed for gateway %s: %s",
                        gw_id,
                        exc,
                    )

        return _ctx()

    async def preflight_preview(
        self,
        gw_id: UUID,
        org_id: UUID,
        feature: str,
        operation: str,
        payload: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Dry-run a prospective staged write: classify its destructiveness and
        whether it will require ``confirmed=true`` at apply time, WITHOUT staging
        anything or touching the device.

        Mirrors the runtime gate: the catastrophic-op block
        (``enforce_opnsense_preflight``) only acts on ``opnsense.*`` features, so
        a non-opnsense feature previews as safe/not-gated — the preview reflects
        exactly what apply will do.
        """
        from app.services.adapter_opnsense_preflight import assess

        # Tenant-scope + existence (raises if the gateway isn't this org's).
        await self._get_gw(gw_id, org_id)

        if not (feature or "").startswith("opnsense."):
            return {
                "feature": feature,
                "operation": operation,
                "risk": "safe",
                "requires_confirmation": False,
                "warnings": [],
                "impact": {},
            }
        result = await assess(feature, operation, payload or {}, adapter=None)
        return result.to_dict()

    async def get_live_status(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        """Pull live system status from the gateway."""
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_device_status(str(gw.id))

            # Update online state
            gw.is_online = result.success
            gw.last_seen_at = datetime.now(UTC) if result.success else gw.last_seen_at
            await self.db.flush()

            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "is_online": result.success,
                **(result.data or {}),
            }

    async def get_live_firewall_rules(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_firewall_rules()
            if not result.success:
                # Upstream unreachable/error is a gateway failure, not "0 rules"
                # with HTTP 200 (which the UI read as an empty ruleset).
                raise AdapterConnectionError(result.error or "Gateway is unreachable")
            data = result.data if result.success else {}
            # Normalise to a list
            rules = data if isinstance(data, list) else data.get("rows", data.get("rules", []))
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "rules": rules if isinstance(rules, list) else [],
                "total": len(rules) if isinstance(rules, list) else 0,
            }

    async def get_live_nat_rules(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_nat_rules()
            if not result.success:
                raise AdapterConnectionError(result.error or "Gateway is unreachable")
            data = result.data if result.success else {}
            rules = data if isinstance(data, list) else data.get("rows", data.get("rules", []))
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "rules": rules if isinstance(rules, list) else [],
                "total": len(rules) if isinstance(rules, list) else 0,
            }

    async def get_live_vpn_status(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_vpn_status()
            if not result.success:
                raise AdapterConnectionError(result.error or "Gateway is unreachable")
            # Redact PSKs / WireGuard private keys / OpenVPN tls_keys
            # / certificate bodies before returning. The legacy
            # ``/firewall/gateways/{id}/vpn`` endpoint is gated only
            # by ``firewall.view`` so any read-tier operator could
            # otherwise lift VPN secrets straight off the wire.
            from app.services.adapter_redaction import redact_secrets

            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "tunnels": redact_secrets(result.data) if result.success else {},
            }

    async def get_live_interfaces(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_interfaces()
            if not result.success:
                raise AdapterConnectionError(result.error or "Gateway is unreachable")
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "interfaces": data.get("interfaces", data) if isinstance(data, dict) else data,
                "statistics": data.get("statistics", {}) if isinstance(data, dict) else {},
            }

    async def get_live_dhcp_leases(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_dhcp_leases()
            if not result.success:
                raise AdapterConnectionError(result.error or "Gateway is unreachable")
            data = result.data if result.success else {}
            leases = data if isinstance(data, list) else data.get("rows", data.get("leases", []))
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "leases": leases if isinstance(leases, list) else [],
                "total": len(leases) if isinstance(leases, list) else 0,
            }

    async def get_live_services(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_services()
            if not result.success:
                raise AdapterConnectionError(result.error or "Gateway is unreachable")
            data = result.data if result.success else {}
            services = data.get("services", []) if isinstance(data, dict) else []
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "services": services,
                "total": len(services),
            }

    # ═══════════════════════════════════════════════════════════════════════
    # Live Data — deep integration (DNS, DHCP-static, port fwd, aliases,
    #   WireGuard, OpenVPN, IPsec, routing, ARP, gateways, IDS, shaper,
    #   backup, firmware, diagnostics, logs, dashboard, service control)
    # ═══════════════════════════════════════════════════════════════════════

    # --- DNS host overrides -----------------------------------------------

    async def get_live_dns_overrides(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_dns_overrides()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "overrides": data.get("overrides", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    async def create_live_dns_override(
        self,
        gw_id: UUID,
        org_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.create_dns_override(payload)
            return self._write_result(result)

    async def update_live_dns_override(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.update_dns_override(vendor_id, payload)
            return self._write_result(result)

    async def delete_live_dns_override(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.delete_dns_override(vendor_id)
            return self._write_result(result)

    # --- DNS domain overrides ---------------------------------------------

    async def get_live_dns_domain_overrides(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_dns_domain_overrides()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "domain_overrides": data.get("domain_overrides", [])
                if isinstance(data, dict)
                else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    async def create_live_dns_domain_override(
        self,
        gw_id: UUID,
        org_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.create_dns_domain_override(payload)
            return self._write_result(result)

    async def update_live_dns_domain_override(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.update_dns_domain_override(vendor_id, payload)
            return self._write_result(result)

    async def delete_live_dns_domain_override(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.delete_dns_domain_override(vendor_id)
            return self._write_result(result)

    # --- DHCP static mappings ---------------------------------------------

    async def get_live_dhcp_static_mappings(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_dhcp_static_mappings()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "static_mappings": data.get("static_mappings", [])
                if isinstance(data, dict)
                else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    async def create_live_dhcp_static_mapping(
        self,
        gw_id: UUID,
        org_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.create_dhcp_static_mapping(payload)
            return self._write_result(result)

    async def update_live_dhcp_static_mapping(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.update_dhcp_static_mapping(vendor_id, payload)
            return self._write_result(result)

    async def delete_live_dhcp_static_mapping(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.delete_dhcp_static_mapping(vendor_id)
            return self._write_result(result)

    # --- Port forwards / DNAT ---------------------------------------------

    async def get_live_port_forwards(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_port_forwards()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "port_forwards": data.get("port_forwards", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    async def create_live_port_forward(
        self,
        gw_id: UUID,
        org_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.create_port_forward(payload)
            return self._write_result(result)

    async def update_live_port_forward(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.update_port_forward(vendor_id, payload)
            return self._write_result(result)

    async def delete_live_port_forward(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.delete_port_forward(vendor_id)
            return self._write_result(result)

    # --- Source NAT -------------------------------------------------------

    async def create_live_source_nat_rule(
        self,
        gw_id: UUID,
        org_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.create_source_nat_rule(payload)
            return self._write_result(result)

    async def delete_live_source_nat_rule(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.delete_source_nat_rule(vendor_id)
            return self._write_result(result)

    # --- Aliases ----------------------------------------------------------

    async def get_live_aliases(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_aliases()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "aliases": data.get("aliases", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    async def create_live_alias(
        self,
        gw_id: UUID,
        org_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.create_alias(payload)
            return self._write_result(result)

    async def update_live_alias(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.update_alias(vendor_id, payload)
            return self._write_result(result)

    async def delete_live_alias(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.delete_alias(vendor_id)
            return self._write_result(result)

    # --- WireGuard --------------------------------------------------------

    async def get_live_wireguard(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            servers, peers, hs = await asyncio.gather(
                adapter.get_wireguard_servers(),
                adapter.get_wireguard_peers(),
                adapter.get_wireguard_handshakes(),
            )
            s_data = servers.data if servers.success else {}
            p_data = peers.data if peers.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "servers": s_data.get("servers", []) if isinstance(s_data, dict) else [],
                "peers": p_data.get("peers", []) if isinstance(p_data, dict) else [],
                "handshakes": hs.data if hs.success else {},
                "count": (s_data.get("count", 0) if isinstance(s_data, dict) else 0)
                + (p_data.get("count", 0) if isinstance(p_data, dict) else 0),
            }

    async def create_live_wireguard_server(
        self,
        gw_id: UUID,
        org_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.create_wireguard_server(payload)
            return self._write_result(result)

    async def delete_live_wireguard_server(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.delete_wireguard_server(vendor_id)
            return self._write_result(result)

    async def create_live_wireguard_peer(
        self,
        gw_id: UUID,
        org_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.create_wireguard_peer(payload)
            return self._write_result(result)

    async def delete_live_wireguard_peer(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.delete_wireguard_peer(vendor_id)
            return self._write_result(result)

    # --- OpenVPN ----------------------------------------------------------

    async def get_live_openvpn(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_openvpn_status()
            data = result.data if result.success else {}
            # OpenVPN instance rows include ``tls_key``, ``tls_auth``,
            # ``tls_crypt``, ``cert``, ``key``, ``auth_user_pass`` —
            # all secret. Redact the whole shape before returning.
            from app.services.adapter_redaction import redact_secrets

            instances = data.get("instances", []) if isinstance(data, dict) else []
            sessions = data.get("sessions", []) if isinstance(data, dict) else []
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "instances": redact_secrets(instances),
                "sessions": redact_secrets(sessions),
            }

    async def create_live_openvpn_instance(
        self,
        gw_id: UUID,
        org_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.create_openvpn_instance(payload)
            return self._write_result(result)

    async def delete_live_openvpn_instance(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.delete_openvpn_instance(vendor_id)
            return self._write_result(result)

    async def kill_live_openvpn_session(
        self,
        gw_id: UUID,
        org_id: UUID,
        session_id: str,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.kill_openvpn_session(session_id)
            return self._write_result(result)

    # --- IPsec ------------------------------------------------------------

    async def get_live_ipsec(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            tunnels, ipsec_status = await asyncio.gather(
                adapter.get_ipsec_tunnels(),
                adapter.get_ipsec_status(),
            )
            t_data = tunnels.data if tunnels.success else {}
            s_data = ipsec_status.data if ipsec_status.success else {}
            # IPsec phase1/phase2 rows ship the ``psk``/``pre-shared-key``
            # field raw on most vendors. Redact before returning.
            from app.services.adapter_redaction import redact_secrets

            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "phase1": redact_secrets(
                    t_data.get("phase1", []) if isinstance(t_data, dict) else []
                ),
                "phase2": redact_secrets(
                    t_data.get("phase2", []) if isinstance(t_data, dict) else []
                ),
                "sad": s_data.get("sad", []) if isinstance(s_data, dict) else [],
                "spd": s_data.get("spd", []) if isinstance(s_data, dict) else [],
            }

    async def connect_live_ipsec_tunnel(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.connect_ipsec_tunnel(vendor_id)
            return self._write_result(result)

    async def disconnect_live_ipsec_tunnel(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.disconnect_ipsec_tunnel(vendor_id)
            return self._write_result(result)

    # --- Static Routes ----------------------------------------------------

    async def get_live_static_routes(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_static_routes()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "routes": data.get("routes", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    async def create_live_static_route(
        self,
        gw_id: UUID,
        org_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.create_static_route(payload)
            return self._write_result(result)

    async def delete_live_static_route(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.delete_static_route(vendor_id)
            return self._write_result(result)

    async def get_live_routing_table(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_routing_table()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "routing_table": data.get("routing_table", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    # --- ARP table --------------------------------------------------------

    async def get_live_arp_table(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_arp_table()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "arp_entries": data.get("arp_entries", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    # --- Gateway health (WAN gateways) ------------------------------------

    async def get_live_gateway_health(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_gateway_status()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "gateways": data.get("gateways", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    # --- IDS / IPS --------------------------------------------------------

    async def get_live_ids_settings(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_ids_settings()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                **(data if isinstance(data, dict) else {}),
            }

    async def update_live_ids_settings(
        self,
        gw_id: UUID,
        org_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.update_ids_settings(payload)
            return self._write_result(result)

    async def get_live_ids_alerts(
        self,
        gw_id: UUID,
        org_id: UUID,
        limit: int = 500,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_ids_alerts(limit)
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "alerts": data.get("alerts", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    # --- Traffic Shaper ---------------------------------------------------

    async def get_live_shaper_pipes(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_shaper_pipes()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "pipes": data.get("pipes", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    async def create_live_shaper_pipe(
        self,
        gw_id: UUID,
        org_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.create_shaper_pipe(payload)
            return self._write_result(result)

    async def delete_live_shaper_pipe(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.delete_shaper_pipe(vendor_id)
            return self._write_result(result)

    async def get_live_shaper_queues(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_shaper_queues()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "queues": data.get("queues", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    async def get_live_shaper_rules(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_shaper_rules()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "rules": data.get("rules", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    # --- Traffic Shaper — CRUD completions --------------------------------

    async def update_live_shaper_pipe(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.update_shaper_pipe(vendor_id, payload)
            return self._write_result(result)

    async def create_live_shaper_queue(
        self,
        gw_id: UUID,
        org_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.create_shaper_queue(payload)
            return self._write_result(result)

    async def update_live_shaper_queue(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.update_shaper_queue(vendor_id, payload)
            return self._write_result(result)

    async def delete_live_shaper_queue(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.delete_shaper_queue(vendor_id)
            return self._write_result(result)

    async def create_live_shaper_rule(
        self,
        gw_id: UUID,
        org_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.create_shaper_rule(payload)
            return self._write_result(result)

    async def update_live_shaper_rule(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.update_shaper_rule(vendor_id, payload)
            return self._write_result(result)

    async def delete_live_shaper_rule(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.delete_shaper_rule(vendor_id)
            return self._write_result(result)

    # --- Backups ----------------------------------------------------------

    async def get_live_backups(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_backup_list()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "backups": data.get("backups", []) if isinstance(data, dict) else [],
                "count": len(data.get("backups", [])) if isinstance(data, dict) else 0,
            }

    async def create_live_backup(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.create_backup()
            return self._write_result(result)

    async def revert_live_backup(
        self,
        gw_id: UUID,
        org_id: UUID,
        filename: str,
    ) -> dict[str, Any]:
        import re

        if not filename or not re.match(r"^[a-zA-Z0-9._\-]+$", filename):
            raise ValueError("Invalid backup filename")
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.revert_backup(filename)
            return self._write_result(result)

    # --- Firmware ---------------------------------------------------------

    async def get_live_firmware(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        cache_key = f"fw:firmware:{gw_id}"
        cached = adapter_cache.get(cache_key)
        if cached is not None:
            return cached
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_firmware_info()
            data = {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "firmware": result.data if result.success else {},
            }
            adapter_cache.set(cache_key, data, ttl=300)  # 5 min TTL
            return data

    # --- Diagnostics (ping / traceroute / DNS) ----------------------------

    async def run_live_ping(
        self,
        gw_id: UUID,
        org_id: UUID,
        host: str,
        count: int = 3,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.run_ping(host, count)
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "result": result.data if result.success else {"error": result.message},
            }

    async def run_live_traceroute(
        self,
        gw_id: UUID,
        org_id: UUID,
        host: str,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.run_traceroute(host)
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "result": result.data if result.success else {"error": result.message},
            }

    async def run_live_dns_lookup(
        self,
        gw_id: UUID,
        org_id: UUID,
        hostname: str,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.run_dns_lookup(hostname)
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "result": result.data if result.success else {"error": result.message},
            }

    # --- Logs / System ----------------------------------------------------

    async def get_live_system_log(
        self,
        gw_id: UUID,
        org_id: UUID,
        limit: int = 100,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_system_log(limit)
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "logs": result.data if result.success else [],
            }

    async def get_live_firewall_log(
        self,
        gw_id: UUID,
        org_id: UUID,
        limit: int = 100,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_firewall_log(limit)
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "logs": result.data if result.success else [],
            }

    # --- Device summary ---------------------------------------------------

    async def get_live_device_summary(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_device_summary()
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "summary": result.data if result.success else {},
            }

    # --- Service control --------------------------------------------------

    async def control_live_service(
        self,
        gw_id: UUID,
        org_id: UUID,
        service_name: str,
        action: str,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            if action == "start":
                result = await adapter.start_service(service_name)
            elif action == "stop":
                result = await adapter.stop_service(service_name)
            else:
                result = await adapter.restart_service(service_name)
            return self._write_result(result)

    # --- Reboot -----------------------------------------------------------

    async def reboot_live_gateway(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.reboot_device(str(gw.id))
            return self._write_result(result)

    # ─── write-result helper ─────────────────────────────────────────────

    @staticmethod
    def _write_result(result: AdapterResult) -> dict[str, Any]:
        """Convert a SUCCESSFUL AdapterResult to a standardised write-response dict.

        A failed write raises (via the central mapper) so it surfaces the right
        HTTP status (read-only->403, not-found->404, timeout->504, generic->502)
        instead of HTTP 200 with success:false — matching the gateway live-reads
        which already raise on failure. Single chokepoint for
        every gateway write endpoint.
        """
        from app.core.adapter_result import raise_for_adapter_result

        raise_for_adapter_result(result)
        return {
            "success": result.success,
            "message": result.message or ("OK" if result.success else "Failed"),
            "vendor_id": (
                result.data.get("uuid") or result.data.get("id")
                if isinstance(result.data, dict)
                else None
            ),
            "data": result.data if isinstance(result.data, dict) else {},
        }

    # ═══════════════════════════════════════════════════════════════════════
    # Missing UPDATE operations (6 resources)
    # ═══════════════════════════════════════════════════════════════════════

    # --- Source NAT update ------------------------------------------------

    async def update_live_source_nat_rule(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.update_source_nat_rule(vendor_id, payload)
            return self._write_result(result)

    # --- WireGuard update -------------------------------------------------

    async def update_live_wireguard_server(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.update_wireguard_server(vendor_id, payload)
            return self._write_result(result)

    async def update_live_wireguard_peer(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.update_wireguard_peer(vendor_id, payload)
            return self._write_result(result)

    # --- OpenVPN update ---------------------------------------------------

    async def update_live_openvpn_instance(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.update_openvpn_instance(vendor_id, payload)
            return self._write_result(result)

    # --- Static Route update ----------------------------------------------

    async def update_live_static_route(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.update_static_route(vendor_id, payload)
            return self._write_result(result)

    # ═══════════════════════════════════════════════════════════════════════
    # Newly-exposed adapter methods (previously unwired)
    # ═══════════════════════════════════════════════════════════════════════

    # --- System — halt ----------------------------------------------------

    async def halt_live_gateway(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.halt_device(str(gw.id))
            return self._write_result(result)

    # --- Firmware extras --------------------------------------------------

    async def get_live_firmware_changelog(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_firmware_changelog()
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "changelog": result.data if result.success else {},
            }

    async def firmware_check(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.firmware_check()
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "result": result.data if result.success else {},
            }

    async def firmware_update(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.firmware_update()
            return self._write_result(result)

    async def firmware_upgrade_status(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.firmware_upgrade_status()
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "result": result.data if result.success else {},
            }

    async def get_live_installed_packages(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        cache_key = f"fw:packages:{gw_id}"
        cached = adapter_cache.get(cache_key)
        if cached is not None:
            return cached
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_installed_packages()
            data = result.data if result.success else {}
            resp = {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "packages": data.get("packages", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }
            adapter_cache.set(cache_key, resp, ttl=300)
            return resp

    async def get_live_installed_plugins(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        cache_key = f"fw:plugins:{gw_id}"
        cached = adapter_cache.get(cache_key)
        if cached is not None:
            return cached
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_installed_plugins()
            data = result.data if result.success else {}
            resp = {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "plugins": data.get("plugins", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }
            adapter_cache.set(cache_key, resp, ttl=300)
            return resp

    # --- Backup extras ----------------------------------------------------

    async def delete_live_backup(
        self,
        gw_id: UUID,
        org_id: UUID,
        filename: str,
    ) -> dict[str, Any]:
        import re

        if not filename or not re.match(r"^[a-zA-Z0-9._\-]+$", filename):
            raise ValueError("Invalid backup filename")
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.delete_backup(filename)
            return self._write_result(result)

    async def download_live_config(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.download_config()
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "config": result.data if result.success else {},
            }

    # --- Interfaces extras ------------------------------------------------

    async def get_live_ndp_table(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_ndp_table()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "ndp_entries": data.get("ndp_entries", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    async def flush_live_arp(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.flush_arp()
            return self._write_result(result)

    async def get_live_vip_status(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_vip_status()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "virtual_ips": data.get("virtual_ips", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    # --- Firewall extras --------------------------------------------------

    async def toggle_live_firewall_rule(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_rule_id: str,
        enabled: bool = True,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.toggle_firewall_rule(vendor_rule_id, enabled=enabled)
            return self._write_result(result)

    async def update_live_firewall_rule(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_rule_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            vendor_rule = self._translate_rule_to_vendor(gw.vendor, payload)
            result = await adapter.update_firewall_rule(vendor_rule_id, vendor_rule)
            return self._write_result(result)

    # --- DNS extras -------------------------------------------------------

    async def get_live_unbound_status(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_unbound_status()
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "status": result.data if result.success else {},
            }

    # --- WireGuard extras -------------------------------------------------

    async def get_live_wireguard_handshakes(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_wireguard_handshakes()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "handshakes": data.get("handshakes", []) if isinstance(data, dict) else [],
            }

    # --- OpenVPN extras ---------------------------------------------------

    async def get_live_openvpn_sessions(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_openvpn_sessions()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "sessions": data.get("sessions", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    # --- IPsec extras -----------------------------------------------------

    async def get_live_ipsec_status(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_ipsec_status()
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "status": result.data if result.success else {},
            }

    async def apply_live_ipsec_changes(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.apply_ipsec_changes()
            return self._write_result(result)

    # --- IDS/IPS extras ---------------------------------------------------

    async def get_live_ids_rulesets(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_ids_rulesets()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "rulesets": data.get("rulesets", []) if isinstance(data, dict) else [],
            }

    async def get_live_ids_rules(
        self,
        gw_id: UUID,
        org_id: UUID,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            # Only allow known safe params to prevent kwarg injection
            result = await adapter.get_ids_rules()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "rules": data.get("rules", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    async def toggle_live_ids_rule(
        self,
        gw_id: UUID,
        org_id: UUID,
        sid: str,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.toggle_ids_rule(sid)
            return self._write_result(result)

    async def drop_live_ids_alert_log(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.drop_ids_alert_log()
            return self._write_result(result)

    async def get_live_ids_status(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_ids_status()
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "status": result.data if result.success else {},
            }

    async def control_live_ids(
        self,
        gw_id: UUID,
        org_id: UUID,
        action: str,
    ) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            if action == "start":
                result = await adapter.start_ids()
            elif action == "stop":
                result = await adapter.stop_ids()
            elif action == "restart":
                result = await adapter.restart_ids()
            elif action == "update-rules":
                result = await adapter.update_ids_rules()
            else:
                return {"success": False, "message": f"Unknown IDS action: {action}"}
            return self._write_result(result)

    # --- Diagnostics extras -----------------------------------------------

    async def get_live_connections(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_connections()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "connections": data.get("connections", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    async def get_live_pf_info(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_pf_info()
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "pf_info": result.data if result.success else {},
            }

    async def get_live_pf_statistics(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_pf_statistics()
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "pf_statistics": result.data if result.success else {},
            }

    # --- Monitoring extras ------------------------------------------------

    async def get_live_temperature(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_temperature()
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "temperature": result.data if result.success else {},
            }

    async def get_live_disk_usage(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_disk_usage()
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "disk_usage": result.data if result.success else {},
            }

    async def get_live_traffic_stats(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_traffic_stats()
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "traffic": result.data if result.success else {},
            }

    # --- System extras ----------------------------------------------------

    async def get_live_cron_jobs(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_cron_jobs()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "cron_jobs": data.get("cron_jobs", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    # --- Health check (deep adapter health) -------------------------------

    async def health_check_live(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.health_check()
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "health": result.data if result.success else {},
                "healthy": result.success,
            }

    # --- Tailscale VPN ---------------------------------------------------

    async def get_live_tailscale_status(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_tailscale_status()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                **(data if isinstance(data, dict) else {}),
            }

    # --- VLAN / LAGG / Virtual IP Devices --------------------------------

    async def get_live_vlan_devices(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_vlan_devices()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "vlans": data.get("vlans", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    async def get_live_lagg_devices(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_lagg_devices()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "laggs": data.get("laggs", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    async def get_live_virtual_ips(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_virtual_ips()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "virtual_ips": data.get("virtual_ips", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    # ═══════════════════════════════════════════════════════════════════════
    # Rule Push (Tier A)
    # ═══════════════════════════════════════════════════════════════════════

    async def push_firewall_rule(
        self,
        gw_id: UUID,
        org_id: UUID,
        rule: dict[str, Any],
    ) -> dict[str, Any]:
        """Push a vendor-normalised firewall rule to the gateway."""
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            # Translate normalised → vendor-specific payload
            vendor_rule = self._translate_rule_to_vendor(gw.vendor, rule)
            result = await adapter.create_firewall_rule(vendor_rule)

            return {
                "success": result.success,
                "message": result.message or ("Rule pushed" if result.success else "Push failed"),
                "vendor_rule_id": self._extract_vendor_rule_id(gw.vendor, result),
                "applied": result.success,
            }

    async def delete_vendor_rule(
        self,
        gw_id: UUID,
        org_id: UUID,
        vendor_rule_id: str,
    ) -> dict[str, Any]:
        """Delete a rule on the gateway by its vendor-native ID."""
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.delete_firewall_rule(vendor_rule_id)
            return {
                "success": result.success,
                "message": result.message
                or ("Rule deleted" if result.success else "Delete failed"),
            }

    # ─── vendor translation helpers ──────────────────────────────────────

    @staticmethod
    def _translate_rule_to_vendor(vendor: str, rule: dict[str, Any]) -> dict[str, Any]:
        """Convert a normalised FreeSDN rule dict to vendor-specific format."""
        action = rule.get("action", "pass")
        protocol = rule.get("protocol", "any")
        src = rule.get("source_address", "")
        src_port = rule.get("source_port", "")
        dst = rule.get("dest_address", "")
        dst_port = rule.get("dest_port", "")
        desc = rule.get("description", "FreeSDN managed rule")
        enabled = rule.get("enabled", True)
        log = rule.get("log", False)

        if vendor == GatewayVendor.OPNSENSE:
            opn_action_map = {
                "allow": "pass",
                "deny": "block",
                "reject": "reject",
                "pass": "pass",
                "block": "block",
            }
            return {
                "action": opn_action_map.get(action, "pass"),
                "quick": "1",
                "interface": rule.get("interface", "lan"),
                "direction": "in",
                "ipprotocol": "inet",
                "protocol": protocol.upper() if protocol != "any" else "",
                "source_net": src or "any",
                "source_port": src_port or "",
                "destination_net": dst or "any",
                "destination_port": dst_port or "",
                "description": desc,
                "disabled": "0" if enabled else "1",
                "log": "1" if log else "0",
            }

        elif vendor == GatewayVendor.PFSENSE:
            pf_type_map = {
                "allow": "pass",
                "deny": "block",
                "reject": "reject",
                "pass": "pass",
                "block": "block",
            }
            r: dict[str, Any] = {
                "type": pf_type_map.get(action, "pass"),
                "interface": rule.get("interface", "lan"),
                "ipprotocol": "inet",
                "protocol": protocol if protocol != "any" else "any",
                "src": src or "any",
                "dst": dst or "any",
                "descr": desc,
                "disabled": not enabled,
            }
            if src_port:
                r["srcport"] = src_port
            if dst_port:
                r["dstport"] = dst_port
            return r

        elif vendor == GatewayVendor.MIKROTIK:
            mt_action_map = {
                "allow": "accept",
                "deny": "drop",
                "reject": "reject",
                "pass": "accept",
                "block": "drop",
            }
            r = {
                "chain": rule.get("chain", "forward"),
                "action": mt_action_map.get(action, "accept"),
                "comment": desc,
                "disabled": "true" if not enabled else "false",
            }
            if protocol and protocol != "any":
                r["protocol"] = protocol
            if src:
                r["src-address"] = src
            if dst:
                r["dst-address"] = dst
            if dst_port:
                r["dst-port"] = dst_port
            if log:
                r["log"] = "true"
            return r

        return rule  # fallback: pass through

    @staticmethod
    def _extract_vendor_rule_id(vendor: str, result: AdapterResult) -> str | None:
        """Try to pull the vendor-native rule ID from the adapter result."""
        if not result.success or not result.data:
            return None
        data = result.data
        if isinstance(data, dict):
            return (
                data.get("uuid")
                or data.get("id")
                or data.get(".id")
                or data.get("rule_id")
                or str(data.get("result"))
                if data.get("result")
                else None
            )
        return None

    # ═══════════════════════════════════════════════════════════════════════
    # Sync
    # ═══════════════════════════════════════════════════════════════════════

    async def trigger_sync(
        self, gw_id: UUID, org_id: UUID, *, full: bool = False
    ) -> dict[str, Any]:
        """
        Trigger a sync that pulls remote state into the local DB.
        For now this records the sync attempt + pulls basic info to update
        the gateway row.  Full rule-sync into local models is a Tier B feature.
        """
        gw = await self._get_gw(gw_id, org_id)
        log = GatewaySyncLog(
            gateway_id=gw.id,
            started_at=datetime.now(UTC),
            status="syncing",
        )
        self.db.add(log)

        adapter = self._build_adapter(gw)
        t0 = time.monotonic()
        try:
            await adapter.connect()

            # Discover device info
            devices = await adapter.discover_devices()

            elapsed = int((time.monotonic() - t0) * 1000)

            if devices:
                dev = devices[0]
                gw.detected_hostname = dev.name
                gw.detected_model = dev.model
                gw.detected_version = dev.firmware_version

            gw.is_online = True
            gw.last_seen_at = datetime.now(UTC)
            gw.sync_status = GatewaySyncStatus.SUCCESS
            gw.last_sync_at = datetime.now(UTC)
            gw.last_sync_error = None
            gw.last_sync_duration_ms = elapsed

            log.finished_at = datetime.now(UTC)
            log.duration_ms = elapsed
            log.status = "success"
            log.items_synced = 1
            log.details = {
                "hostname": gw.detected_hostname,
                "version": gw.detected_version,
                "model": gw.detected_model,
            }

            await self.db.flush()
            return {
                "status": "success",
                "duration_ms": elapsed,
                "hostname": gw.detected_hostname,
                "version": gw.detected_version,
            }

        except Exception as exc:
            elapsed = int((time.monotonic() - t0) * 1000)
            logger.error(
                "Gateway sync failed for %s: %s",
                gw_id,
                exc,
                exc_info=True,
            )
            sanitized_msg = _sanitize_adapter_error(exc)
            gw.sync_status = GatewaySyncStatus.FAILED
            gw.last_sync_at = datetime.now(UTC)
            gw.last_sync_error = sanitized_msg
            gw.last_sync_duration_ms = elapsed
            gw.is_online = False

            log.finished_at = datetime.now(UTC)
            log.duration_ms = elapsed
            log.status = "failed"
            log.error = sanitized_msg

            await self.db.flush()
            return {
                "status": "failed",
                "duration_ms": elapsed,
                "error": sanitized_msg,
            }
        finally:
            with suppress(Exception):
                await adapter.disconnect()

    async def get_sync_logs(
        self,
        gw_id: UUID,
        org_id: UUID,
        *,
        limit: int = 20,
    ) -> list[GatewaySyncLog]:
        """Get recent sync logs for a gateway."""
        # Validate ownership first
        await self._get_gw(gw_id, org_id)

        result = await self.db.execute(
            select(GatewaySyncLog)
            .where(GatewaySyncLog.gateway_id == gw_id)
            .order_by(GatewaySyncLog.started_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    # ═══════════════════════════════════════════════════════════════════════
    # Summary / Stats
    # ═══════════════════════════════════════════════════════════════════════

    async def get_summary(self, org_id: UUID, site_id: UUID | None = None) -> dict[str, Any]:
        """Aggregate stats across all gateways in the org using SQL."""

        # a site-limited caller must not see an org-wide
        # aggregate (omitting site_id) nor probe a non-granted sibling
        # site (passing a foreign site_id). Reject an explicit out-of-grant
        # site_id with the same opaque "not found" shape used by _get_gw /
        # create_gateway, and fold the grant into the aggregate below.
        if (
            site_id is not None
            and self.accessible_site_ids is not None
            and site_id not in self.accessible_site_ids
        ):
            raise GatewayNotFoundError(site_id)

        base_filter = [
            GatewayConnection.org_id == org_id,
            GatewayConnection.deleted_at.is_(None),
        ]
        # the summary stat cards ignored the selected site while
        # the gateway table below filtered by it — the counts mismatched.
        if site_id:
            base_filter.append(GatewayConnection.site_id == site_id)
        # confine the org-wide aggregate to the caller's granted
        # sites. Guard on `is not None` so admins/org-admins/background
        # (unrestricted) are unaffected and we never build in_(None).
        if self.accessible_site_ids is not None:
            base_filter.append(GatewayConnection.site_id.in_(self.accessible_site_ids))

        # Single query that counts everything in SQL
        q = select(
            func.count().label("total"),
            func.count().filter(GatewayConnection.is_online.is_(True)).label("online"),
            func.count()
            .filter(GatewayConnection.sync_status == GatewaySyncStatus.SUCCESS)
            .label("sync_success"),
            func.count()
            .filter(GatewayConnection.sync_status == GatewaySyncStatus.FAILED)
            .label("sync_failed"),
            func.count()
            .filter(GatewayConnection.sync_status == GatewaySyncStatus.IDLE)
            .label("sync_idle"),
            func.count()
            .filter(GatewayConnection.sync_status == GatewaySyncStatus.NEVER)
            .label("sync_never"),
        ).where(*base_filter)

        row = (await self.db.execute(q)).one()

        # Vendor breakdown in a separate lightweight query
        vendor_q = (
            select(GatewayConnection.vendor, func.count().label("cnt"))
            .where(*base_filter)
            .group_by(GatewayConnection.vendor)
        )
        vendor_rows = (await self.db.execute(vendor_q)).all()
        by_vendor = dict(vendor_rows)

        total = row.total or 0
        online = row.online or 0

        return {
            "total_gateways": total,
            "online": online,
            "offline": total - online,
            "sync_success": row.sync_success or 0,
            "sync_failed": row.sync_failed or 0,
            "sync_idle": row.sync_idle or 0,
            "sync_never": row.sync_never or 0,
            "by_vendor": by_vendor,
        }

    # ═══════════════════════════════════════════════════════════════════════
    # HAProxy — Load Balancer
    # ═══════════════════════════════════════════════════════════════════════

    async def get_live_haproxy_status(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_haproxy_status()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                **(data if isinstance(data, dict) else {}),
            }

    async def get_live_haproxy_servers(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_haproxy_servers()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "servers": data.get("servers", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    async def get_live_haproxy_backends(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_haproxy_backends()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "backends": data.get("backends", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    async def get_live_haproxy_frontends(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_haproxy_frontends()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "frontends": data.get("frontends", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    # ═══════════════════════════════════════════════════════════════════════
    # Certificate Management (Trust store)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_live_trust_overview(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_trust_overview()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                **(data if isinstance(data, dict) else {}),
            }

    async def get_live_certificates(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_certificates()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "certificates": data.get("certificates", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    async def get_live_certificate_authorities(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_certificate_authorities()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "certificate_authorities": data.get("certificate_authorities", [])
                if isinstance(data, dict)
                else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    # ═══════════════════════════════════════════════════════════════════════
    # ACME / Let's Encrypt
    # ═══════════════════════════════════════════════════════════════════════

    async def get_live_acme_overview(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_acme_overview()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                **(data if isinstance(data, dict) else {}),
            }

    async def get_live_acme_certificates(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_acme_certificates()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "acme_certificates": data.get("acme_certificates", [])
                if isinstance(data, dict)
                else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    # ═══════════════════════════════════════════════════════════════════════
    # Syslog Forwarding
    # ═══════════════════════════════════════════════════════════════════════

    async def get_live_syslog_destinations(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_syslog_destinations()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "syslog_destinations": data.get("syslog_destinations", [])
                if isinstance(data, dict)
                else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    # ═══════════════════════════════════════════════════════════════════════
    # Dynamic DNS
    # ═══════════════════════════════════════════════════════════════════════

    async def get_live_dyndns_accounts(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_dyndns_accounts()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "dyndns_accounts": data.get("dyndns_accounts", [])
                if isinstance(data, dict)
                else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    # ═══════════════════════════════════════════════════════════════════════
    # Captive Portal
    # ═══════════════════════════════════════════════════════════════════════

    async def get_live_captive_portal_zones(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_captive_portal_zones()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "captive_portal_zones": data.get("captive_portal_zones", [])
                if isinstance(data, dict)
                else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    async def get_live_captive_portal_sessions(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_captive_portal_sessions()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "captive_portal_sessions": data.get("captive_portal_sessions", [])
                if isinstance(data, dict)
                else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    # ═══════════════════════════════════════════════════════════════════════
    # High Availability / Config Sync
    # ═══════════════════════════════════════════════════════════════════════

    async def get_live_ha_status(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_ha_status()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                **(data if isinstance(data, dict) else {}),
            }

    # ═══════════════════════════════════════════════════════════════════════
    # Kea DHCP (DHCPv4 + DHCPv6 + Reservations)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_live_kea_dhcpv4_subnets(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_kea_dhcpv4_subnets()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "kea_dhcpv4_subnets": data.get("kea_dhcpv4_subnets", [])
                if isinstance(data, dict)
                else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    async def get_live_kea_dhcpv4_reservations(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_kea_dhcpv4_reservations()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "kea_reservations": data.get("kea_reservations", [])
                if isinstance(data, dict)
                else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    async def get_live_kea_dhcpv4_leases(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_kea_dhcpv4_leases()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "kea_leases": data.get("kea_leases", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    async def get_live_kea_dhcpv6_subnets(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_kea_dhcpv6_subnets()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "kea_dhcpv6_subnets": data.get("kea_dhcpv6_subnets", [])
                if isinstance(data, dict)
                else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    # ═══════════════════════════════════════════════════════════════════════
    # 1:1 NAT
    # ═══════════════════════════════════════════════════════════════════════

    async def get_live_onetoone_nat_rules(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_onetoone_nat_rules()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "onetoone_nat_rules": data.get("onetoone_nat_rules", [])
                if isinstance(data, dict)
                else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    # ═══════════════════════════════════════════════════════════════════════
    # Network Bridges
    # ═══════════════════════════════════════════════════════════════════════

    async def get_live_bridges(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_bridges()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "bridges": data.get("bridges", []) if isinstance(data, dict) else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    # ═══════════════════════════════════════════════════════════════════════
    # DHCP Relay
    # ═══════════════════════════════════════════════════════════════════════

    async def get_live_dhcp_relay(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_dhcp_relay_status()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "dhcp_relay": data.get("dhcp_relay") if isinstance(data, dict) else None,
            }

    # ═══════════════════════════════════════════════════════════════════════
    # Web Proxy / Squid
    # ═══════════════════════════════════════════════════════════════════════

    async def get_live_proxy_settings(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_proxy_settings()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "proxy": data.get("proxy", {}) if isinstance(data, dict) else {},
            }

    async def get_live_proxy_blacklists(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_proxy_blacklists()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "proxy_blacklists": data.get("proxy_blacklists", [])
                if isinstance(data, dict)
                else [],
                "count": data.get("count", 0) if isinstance(data, dict) else 0,
            }

    # ═══════════════════════════════════════════════════════════════════════
    # CrowdSec
    # ═══════════════════════════════════════════════════════════════════════

    async def get_live_crowdsec_status(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_crowdsec_status()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "crowdsec": data.get("crowdsec", {}) if isinstance(data, dict) else {},
            }

    # ═══════════════════════════════════════════════════════════════════════
    # Telegraf
    # ═══════════════════════════════════════════════════════════════════════

    async def get_live_telegraf_status(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_telegraf_status()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "telegraf": data.get("telegraf", {}) if isinstance(data, dict) else {},
            }

    # ═══════════════════════════════════════════════════════════════════════
    # Monit
    # ═══════════════════════════════════════════════════════════════════════

    async def get_live_monit_status(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_monit_status()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "monit": data.get("monit", {}) if isinstance(data, dict) else {},
            }

    # ═══════════════════════════════════════════════════════════════════════
    # NetFlow / sFlow
    # ═══════════════════════════════════════════════════════════════════════

    async def get_live_netflow_status(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            result = await adapter.get_netflow_status()
            data = result.data if result.success else {}
            return {
                "gateway_id": str(gw.id),
                "vendor": gw.vendor,
                "netflow": data.get("netflow", {}) if isinstance(data, dict) else {},
            }

    # ═══════════════════════════════════════════════════════════════════
    # Cross-cutting: Bulk Rule Operations
    # ═══════════════════════════════════════════════════════════════════

    async def bulk_rule_operation(
        self,
        gw_id: UUID,
        org_id: UUID,
        action: str,
        rule_uuids: list[str],
    ) -> dict[str, Any]:
        """Execute a bulk operation (enable/disable/delete) on firewall rules.

        SECURITY (write-path audit, HIGH): every per-rule mutation goes through the
        *public* adapter method (``delete_firewall_rule`` / ``toggle_firewall_rule``)
        rather than reaching into the private ``adapter._api`` client. The public
        methods thread ``self._direct_write_force`` (default False) into the client,
        so a bulk mutation is still refused by the read-only gate under
        ``ADAPTER_READ_ONLY`` — the prior ``_api`` shortcut silently bypassed that
        gate and could mass-delete up to 200 prod firewall rules with read-only ON.
        """
        if action not in ("delete", "enable", "disable"):
            raise ValueError(f"Unknown action: {action}")

        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            results: dict[str, list[Any]] = {"success": [], "failed": []}
            for uuid in rule_uuids:
                try:
                    if action == "delete":
                        result = await adapter.delete_firewall_rule(uuid)
                    elif action == "enable":
                        result = await adapter.toggle_firewall_rule(uuid, enabled=True)
                    else:  # disable
                        result = await adapter.toggle_firewall_rule(uuid, enabled=False)

                    # Public methods return AdapterResult (they don't raise on a
                    # device-side failure / read-only refusal), so honour .success
                    # instead of treating "no exception" as success.
                    if getattr(result, "success", True):
                        results["success"].append(uuid)
                    else:
                        results["failed"].append({"uuid": uuid, "error": "Operation failed"})
                except Exception as exc:
                    logger.error("Bulk rule action failed for %s: %s", uuid, exc, exc_info=True)
                    results["failed"].append({"uuid": uuid, "error": "Operation failed"})

            # Reconcile pending changes once after the batch. The per-rule public
            # methods already apply on most vendors; this is the trailing flush.
            # Do NOT silently swallow a failure — a write that didn't reconcile is
            # not a success, so surface it to the caller. Vendors that apply
            # immediately (e.g. MikroTik) expose no apply_firewall_changes(); for
            # them there is nothing to reconcile, so absence is not an error.
            apply_error: str | None = None
            apply_fn = getattr(adapter, "apply_firewall_changes", None)
            if apply_fn is not None:
                try:
                    apply_result = await apply_fn()
                    if not getattr(apply_result, "success", True):
                        apply_error = "apply_failed"
                except Exception as exc:
                    logger.error(
                        "Bulk rule apply_firewall_changes failed for gateway %s: %s",
                        gw_id,
                        exc,
                        exc_info=True,
                    )
                    apply_error = "apply_failed"

            return {
                "gateway_id": str(gw.id),
                "action": action,
                "total": len(rule_uuids),
                "succeeded": len(results["success"]),
                "failed": len(results["failed"]),
                "details": results,
                "applied": apply_error is None,
                **({"apply_error": apply_error} if apply_error else {}),
            }

    # ═══════════════════════════════════════════════════════════════════
    # Cross-cutting: Config Diff
    # ═══════════════════════════════════════════════════════════════════

    async def get_config_diff(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        """Get diff between current running config and last backup."""
        import difflib

        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            # Fetch current config and backup list in parallel
            current_result, backups_result = await asyncio.gather(
                adapter.download_config(),
                adapter.get_backup_list(),
                return_exceptions=True,
            )

            # Parse current config
            if isinstance(current_result, Exception) or not getattr(
                current_result, "success", False
            ):
                current_xml = ""
            else:
                current_xml = (
                    current_result.data.get("config_xml", "") if current_result.success else ""
                )

            # Parse backup list
            backup_xml = ""
            if not isinstance(backups_result, Exception) and getattr(
                backups_result, "success", False
            ):
                backups = []
                if isinstance(backups_result.data, dict):
                    backups = backups_result.data.get("backups", [])
                if backups:
                    latest = backups[0] if isinstance(backups, list) else {}
                    backup_xml = latest.get("config_xml", "") or latest.get("content", "")

            # Generate unified diff
            if current_xml and backup_xml:
                diff_lines = list(
                    difflib.unified_diff(
                        backup_xml.splitlines(keepends=True),
                        current_xml.splitlines(keepends=True),
                        fromfile="Last Backup",
                        tofile="Running Config",
                        lineterm="",
                    )
                )
                has_changes = len(diff_lines) > 0
            else:
                diff_lines = []
                has_changes = False

            return {
                "gateway_id": str(gw.id),
                "has_changes": has_changes,
                "diff_lines": diff_lines,
                "current_size": len(current_xml),
                "backup_size": len(backup_xml),
                "summary": f"{sum(1 for l in diff_lines if l.startswith('+') and not l.startswith('+++'))} additions, "
                f"{sum(1 for l in diff_lines if l.startswith('-') and not l.startswith('---'))} deletions",
            }

    # ═══════════════════════════════════════════════════════════════════
    # Cross-cutting: Config Backup Trigger
    # ═══════════════════════════════════════════════════════════════════

    async def trigger_config_backup(self, gw_id: UUID, org_id: UUID) -> dict[str, Any]:
        """Download and store a config backup from the gateway."""
        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            try:
                result = await adapter.download_config()
                if result.success:
                    config_data = result.data or {}
                    return {
                        "gateway_id": str(gw.id),
                        "success": True,
                        "message": "Configuration backup captured successfully",
                        "config_size": len(str(config_data.get("config_xml", ""))),
                        "timestamp": datetime.now(UTC).isoformat(),
                    }
                else:
                    return {
                        "gateway_id": str(gw.id),
                        "success": False,
                        "message": f"Backup failed: {result.error}",
                    }
            except Exception as exc:
                logger.error("Config backup failed for gateway %s: %s", gw_id, exc)
                return {
                    "gateway_id": str(gw.id),
                    "success": False,
                    "message": "Backup operation failed",
                }

    # ═══════════════════════════════════════════════════════════════════
    # Cross-cutting: Certificate Lifecycle
    # ═══════════════════════════════════════════════════════════════════

    async def get_certificate_expiry(
        self, gw_id: UUID, org_id: UUID, days_threshold: int = 30
    ) -> dict[str, Any]:
        """Check gateway certificates for upcoming expiry."""
        from datetime import datetime, timedelta

        async with await self._adapter_for(gw_id, org_id) as (gw, adapter):
            try:
                result = await adapter.get_trust_cert_list()
                certs = []
                if result.success and isinstance(result.data, dict):
                    certs = result.data.get("certificates", [])
            except Exception:
                certs = []

            now = datetime.now(UTC)
            threshold = now + timedelta(days=days_threshold)
            expiring = []
            valid = []
            expired = []

            for cert in certs:
                not_after = cert.get("not_after") or cert.get("valid_to") or cert.get("notAfter")
                if not not_after:
                    continue
                try:
                    # Try multiple date formats
                    exp_date = None
                    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%b %d %H:%M:%S %Y %Z", "%Y-%m-%d %H:%M:%S"):
                        try:
                            exp_date = datetime.strptime(str(not_after), fmt)
                            if exp_date.tzinfo is None:
                                exp_date = exp_date.replace(tzinfo=UTC)
                            break
                        except ValueError:
                            continue

                    if exp_date is None:
                        continue

                    cert_info = {
                        "name": cert.get("descr")
                        or cert.get("description")
                        or cert.get("cn", "Unknown"),
                        "common_name": cert.get("cn") or cert.get("common_name", ""),
                        "expires": exp_date.isoformat(),
                        "days_remaining": (exp_date - now).days,
                    }

                    if exp_date < now:
                        cert_info["status"] = "expired"
                        expired.append(cert_info)
                    elif exp_date < threshold:
                        cert_info["status"] = "expiring_soon"
                        expiring.append(cert_info)
                    else:
                        cert_info["status"] = "valid"
                        valid.append(cert_info)
                except Exception:
                    continue

            return {
                "gateway_id": str(gw.id),
                "days_threshold": days_threshold,
                "total_certificates": len(certs),
                "expired": expired,
                "expiring_soon": expiring,
                "valid_count": len(valid),
                "needs_attention": len(expired) + len(expiring) > 0,
            }
