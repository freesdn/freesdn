# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Plugin SDK
==========================

Base class and typed SDK interfaces for third-party plugins.

Provides:
- FreeSDNPlugin: Base class for plugin authors
- PluginContext: Restricted access to FreeSDN internals
- DeviceSDK, AlertSDK, EventSDK: Read/write access to core data
- PluginSettingsSDK: Scoped key-value settings with secret encryption
- PluginHTTPClient: SSRF-protected outbound HTTP

Plugin authors import FreeSDNPlugin as the base for their plugin class.
All SDK access goes through self.ctx after on_start() is called.
"""

from __future__ import annotations

import builtins
import logging
from contextvars import ContextVar, Token
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID

from fastapi import APIRouter

from app.modules.base import BaseModule
from app.modules.manifest import ModuleManifest

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)
_request_plugin_runtime: ContextVar[FreeSDNPlugin | None] = ContextVar(
    "freesdn_request_plugin_runtime",
    default=None,
)


def bind_request_plugin_runtime(plugin: FreeSDNPlugin) -> Token[FreeSDNPlugin | None]:
    """Bind a plugin runtime instance to the current request context."""
    return _request_plugin_runtime.set(plugin)


def reset_request_plugin_runtime(token: Token[FreeSDNPlugin | None]) -> None:
    """Reset the request-scoped plugin runtime binding."""
    _request_plugin_runtime.reset(token)


def get_request_plugin_runtime() -> FreeSDNPlugin | None:
    """Return the plugin runtime instance bound to the current request, if any."""
    return _request_plugin_runtime.get()


# the caller (CurrentUser) of an authenticated plugin REST route, bound
# so privileged SDK operations run with the INTERSECTION of the plugin's declared
# capabilities AND the caller's own FreeSDN permissions — closing the confused-
# deputy where a low-privilege user invoked a plugin route to exercise a capability
# (e.g. alerts.write) they do not themselves hold. Left None for non-user contexts
# (public/HMAC routes, automation/AI/scheduled plugin work), where the plugin acts
# with its own declared authority by design.
_request_caller: ContextVar[Any | None] = ContextVar(
    "freesdn_request_plugin_caller",
    default=None,
)


def bind_request_caller(caller: Any) -> Token[Any | None]:
    """Bind the authenticated caller (CurrentUser) to the current request context."""
    return _request_caller.set(caller)


def reset_request_caller(token: Token[Any | None]) -> None:
    """Reset the request-scoped caller binding."""
    _request_caller.reset(token)


def get_request_caller() -> Any | None:
    """Return the caller (CurrentUser) bound to the current request, if any."""
    return _request_caller.get()


# =============================================================================
# SDK Interfaces
# =============================================================================


class _PermissionMixin:
    """Shared permission checking for SDK classes."""

    # maps each SDK capability to the FreeSDN core permission the CALLER
    # must hold for it. When an authenticated user invokes a plugin route, the
    # plugin may only exercise a capability the caller could exercise directly.
    _CAPABILITY_CORE_PERMISSION: dict[str, str] = {
        "devices.read": "device:read",
        "devices.write": "device:write",
        "alerts.read": "alert:read",
        "alerts.write": "alert:write",
    }

    def __init__(self, plugin_id: str, declared_permissions: list[str]) -> None:
        self._plugin_id = plugin_id
        self._declared_permissions = declared_permissions

    def _require_permission(self, needed: str) -> None:
        """Verify the plugin declared this capability AND that the
        authenticated caller — if any — holds the mapped FreeSDN permission."""
        if needed not in self._declared_permissions:
            raise PermissionError(
                f"Plugin '{self._plugin_id}' requires undeclared permission '{needed}'. "
                f"Add it to plugin.yaml permissions."
            )
        # when an authenticated user is driving this
        # request, the plugin cannot exercise a capability the caller lacks. No
        # caller bound (public/HMAC route, automation/AI/scheduled task) → the
        # plugin runs with its own declared authority, as designed.
        caller = get_request_caller()
        if caller is not None:
            core_perm = self._CAPABILITY_CORE_PERMISSION.get(needed)
            if core_perm is not None:
                has_perm = getattr(caller, "has_permission", None)
                if not (callable(has_perm) and has_perm(core_perm)):
                    raise PermissionError(
                        f"Caller lacks the '{core_perm}' permission required to "
                        f"invoke plugin '{self._plugin_id}' capability '{needed}'."
                    )


class DeviceSDK(_PermissionMixin):
    """Read-only access to the device inventory."""

    def __init__(
        self,
        plugin_id: str,
        declared_permissions: list[str],
        org_id: UUID,
        db: AsyncSession,
    ) -> None:
        super().__init__(plugin_id, declared_permissions)
        self._org_id = org_id
        self._db = db

    async def list(
        self,
        status: str | None = None,
        site_id: UUID | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """List devices visible to this organization."""
        self._require_permission("devices.read")
        from sqlalchemy import select

        from app.core.site_access import (
            assert_site_access_for_request,
            site_ids_for_request,
        )

        try:
            from app.models.core import Site
            from app.models.devices import Device
        except ImportError:
            return []
        # Device is tenant-scoped via site_id → Site.organization_id;
        # it has no organization_id column (the prior reference raised
        # AttributeError at runtime — the type:ignore masked it).
        q = (
            select(Device)
            .join(Site, Device.site_id == Site.id)
            .where(Site.organization_id == self._org_id)
        )
        if status:
            q = q.where(Device.status == status)
        if site_id:
            # an explicit site_id target must pass the per-user
            # site grant of the bound caller (no-op for admins / no caller).
            assert_site_access_for_request(site_id, detail="Site not found")
            q = q.where(Device.site_id == site_id)
        # scope the LIST to the bound caller's granted sites when the
        # request is driven by a site-limited user. Reads the request-scoped
        # contextvar — None (admin / public-HMAC / background) is a no-op.
        granted = site_ids_for_request()
        if granted is not None:
            q = q.where(Device.site_id.in_(list(granted)))
        q = q.limit(max(1, min(limit, 500)))
        result = await self._db.execute(q)
        rows = result.scalars().all()
        return [
            {
                "id": str(r.id),
                "name": getattr(r, "name", None),
                "type": getattr(r, "device_type", None),
                "status": getattr(r, "status", None),
                "ip": getattr(r, "ip_address", None),
                "mac": getattr(r, "mac_address", None),
                "site_id": str(r.site_id) if getattr(r, "site_id", None) else None,
            }
            for r in rows
        ]

    async def get(self, device_id: UUID) -> dict[str, Any] | None:
        """Get a single device by ID."""
        self._require_permission("devices.read")
        from sqlalchemy import select

        from app.core.site_access import site_ids_for_request

        try:
            from app.models.core import Site
            from app.models.devices import Device
        except ImportError:
            return None
        # Tenant-scope via site join (no Device.organization_id column).
        q = (
            select(Device)
            .join(Site, Device.site_id == Site.id)
            .where(
                Device.id == device_id,
                Site.organization_id == self._org_id,
            )
        )
        # a site-limited bound caller may only fetch devices in a
        # granted site. Fold into the query so a sibling-site device returns
        # None (same "not found" shape — no existence oracle). No-op when the
        # contextvar is unbound (public/HMAC/background) or caller is an admin.
        granted = site_ids_for_request()
        if granted is not None:
            q = q.where(Device.site_id.in_(list(granted)))
        result = await self._db.execute(q)
        r = result.scalar_one_or_none()
        if not r:
            return None
        return {
            "id": str(r.id),
            "name": getattr(r, "name", None),
            "type": getattr(r, "device_type", None),
            "status": getattr(r, "status", None),
            "ip": getattr(r, "ip_address", None),
            "mac": getattr(r, "mac_address", None),
            "site_id": str(r.site_id) if getattr(r, "site_id", None) else None,
            "model": getattr(r, "model", None),
            "firmware": getattr(r, "firmware_version", None),
        }

    async def register_device(self, device_data: dict[str, Any]) -> dict[str, Any]:
        """Register or update a device in the core inventory.

        Requires ``devices.write`` permission declared in plugin.yaml.
        The ``external_id`` must start with ``plugin.{plugin_id}:``.

        Security: prefix namespacing, SSRF IP blocking, metadata validation,
        device count cap (1,000), org-scoped site_id, atomic upsert + audit.
        """
        self._require_permission("devices.write")

        ext_prefix = f"plugin.{self._plugin_id}"
        ext_id = device_data.get("external_id", "")
        if not ext_id or not ext_id.startswith(f"{ext_prefix}:"):
            raise PermissionError(f"external_id must start with '{ext_prefix}:' — got '{ext_id}'")

        name = str(device_data.get("name", "Unknown"))[:255]
        device_type = str(device_data.get("device_type", "other"))
        site_id = device_data.get("site_id")
        ip_address = device_data.get("ip_address")

        # SSRF: block internal IPs
        if ip_address:
            from app.services.device_sync import _is_safe_ip

            if not _is_safe_ip(str(ip_address)):
                raise ValueError(f"IP address {ip_address} is in a blocked range")

        # Metadata size check
        metadata = device_data.get("metadata")
        if metadata:
            from app.services.device_sync import _validate_metadata

            if _validate_metadata(metadata) is None:
                raise ValueError("Metadata exceeds size or depth limits")

        # Device count cap
        from sqlalchemy import func as sa_func
        from sqlalchemy import select as sa_select

        try:
            from app.models.devices import Device as DeviceModel
        except ImportError:
            raise RuntimeError("Device model not available")

        count_result = await self._db.execute(
            sa_select(sa_func.count(DeviceModel.id)).where(
                DeviceModel.external_id.like(f"{ext_prefix}:%")
            )
        )
        if (count_result.scalar() or 0) >= 1_000:
            raise PermissionError("Plugin device limit (1,000) reached")

        # Org-scoped site_id validation
        if not site_id:
            raise ValueError("site_id is required")
        from app.models.core import Site

        valid = (
            await self._db.execute(
                sa_select(Site.id).where(
                    Site.id == site_id,
                    Site.organization_id == self._org_id,
                )
            )
        ).scalar()
        if not valid:
            raise PermissionError("site_id does not belong to plugin's organization")

        # a site-limited bound caller may only register devices into a
        # site they are granted. No-op for admins / non-user contexts (the
        # contextvar is unbound on public/HMAC/automation routes).
        from app.core.site_access import assert_site_access_for_request

        assert_site_access_for_request(
            site_id if isinstance(site_id, UUID) else UUID(str(site_id)),
            detail="site_id does not belong to plugin's organization",
        )

        # Atomic upsert
        from app.services.device_sync import DeviceSyncService

        device_id = await DeviceSyncService.upsert_single(
            self._db,
            external_id=ext_id,
            name=name,
            device_type=device_type,
            site_id=site_id,
            manufacturer=device_data.get("manufacturer"),
            model=device_data.get("model"),
            firmware_version=device_data.get("firmware_version"),
            ip_address=ip_address,
            mac_address=device_data.get("mac_address"),
            serial_number=device_data.get("serial_number"),
            status=device_data.get("status", "unknown"),
        )

        # Audit trail
        try:
            from app.services.audit import AuditAction, AuditService, ResourceType

            audit = AuditService(self._db)
            await audit.log(
                action=AuditAction.CREATE,
                resource_type=ResourceType.DEVICE,
                resource_id=device_id,
                resource_name=name,
                actor_type="plugin",
                actor_name=self._plugin_id,
                tags=["device_sync", "plugin", self._plugin_id],
            )
        except Exception:
            logger.warning(
                "Plugin %s: audit log failed for device %s (non-blocking)",
                self._plugin_id,
                device_id,
                exc_info=True,
            )

        return {"id": str(device_id), "external_id": ext_id, "name": name}

    async def get_ports(self, device_id: UUID) -> builtins.list[dict[str, Any]]:
        """Get ports for a device (verifies device belongs to this org)."""
        self._require_permission("devices.read")
        from sqlalchemy import select

        from app.core.site_access import site_ids_for_request

        try:
            from app.models.core import Site
            from app.models.devices import Device, DevicePort
        except ImportError:
            return []
        # Verify device belongs to this organization (prevent cross-tenant
        # access). Device is org-scoped via site_id → Site.organization_id,
        # so chain DevicePort → Device → Site.
        q = (
            select(DevicePort)
            .join(Device, DevicePort.device_id == Device.id)
            .join(Site, Device.site_id == Site.id)
            .where(
                DevicePort.device_id == device_id,
                Site.organization_id == self._org_id,
            )
        )
        # a site-limited bound caller may only read ports of devices in
        # a granted site; a sibling-site device returns [] (no existence oracle).
        granted = site_ids_for_request()
        if granted is not None:
            q = q.where(Device.site_id.in_(list(granted)))
        result = await self._db.execute(q)
        rows = result.scalars().all()
        return [
            {
                "id": str(r.id),
                "name": getattr(r, "name", None),
                "port_number": getattr(r, "port_number", None),
                "status": getattr(r, "status", None),
                "speed": getattr(r, "speed", None),
                "poe_enabled": getattr(r, "poe_enabled", None),
            }
            for r in rows
        ]


class AlertSDK(_PermissionMixin):
    """Read/write access to alerts."""

    def __init__(
        self,
        plugin_id: str,
        declared_permissions: list[str],
        org_id: UUID,
        db: AsyncSession,
    ) -> None:
        super().__init__(plugin_id, declared_permissions)
        self._org_id = org_id
        self._db = db

    async def list(
        self,
        severity: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """List active alerts for this organization."""
        self._require_permission("alerts.read")
        from sqlalchemy import select

        from app.core.site_access import site_ids_for_request

        try:
            from app.models.alert_rules import Alert
        except ImportError:
            return []
        q = select(Alert).where(Alert.organization_id == self._org_id)
        if severity:
            q = q.where(Alert.severity == severity)
        # scope to the bound caller's granted sites. Alerts carry a
        # nullable site_id; an org-level (site_id NULL) alert aggregates across
        # sites, so a site-limited caller must NOT see it — restrict strictly to
        # the granted set (fail-closed). No-op when unbound / admin caller.
        granted = site_ids_for_request()
        if granted is not None:
            q = q.where(Alert.site_id.in_(list(granted)))
        q = q.limit(max(1, min(limit, 200)))
        result = await self._db.execute(q)
        rows = result.scalars().all()
        return [
            {
                "id": str(r.id),
                "title": getattr(r, "title", None),
                "message": getattr(r, "message", None),
                "severity": getattr(r, "severity", None),
                "status": getattr(r, "status", None),
                "device_id": str(r.device_id) if getattr(r, "device_id", None) else None,
            }
            for r in rows
        ]

    _VALID_SEVERITIES = frozenset({"info", "warning", "error", "critical"})

    async def create(
        self,
        title: str,
        message: str,
        severity: str = "warning",
        device_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Create a new alert."""
        self._require_permission("alerts.write")
        if severity not in self._VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{severity}'. "
                f"Must be one of: {', '.join(sorted(self._VALID_SEVERITIES))}"
            )
        from sqlalchemy import select

        try:
            from app.models.alert_rules import Alert
        except ImportError:
            raise RuntimeError("Alert model not available")
        import hashlib

        from app.core.site_access import assert_site_access_for_request, site_ids_for_request

        # when the alert targets a device, resolve that device's site
        # (org-scoped) and enforce the bound caller's per-user site grant — a
        # site-limited operator cannot raise an alert against a sibling-site
        # device. We also stamp the resolved site_id onto the alert so it is
        # correctly scoped on subsequent list/resolve calls.
        site_id: UUID | None = None
        if device_id is not None:
            try:
                from app.models.core import Site
                from app.models.devices import Device
            except ImportError:
                Device = Site = None  # type: ignore[assignment]
            if Device is not None and Site is not None:
                dev_site = (
                    await self._db.execute(
                        select(Device.site_id)
                        .join(Site, Device.site_id == Site.id)
                        .where(
                            Device.id == device_id,
                            Site.organization_id == self._org_id,
                        )
                    )
                ).scalar_one_or_none()
                if dev_site is None:
                    # Unknown / cross-tenant device → reject (no existence oracle).
                    raise PermissionError("device_id does not belong to plugin's organization")
                assert_site_access_for_request(dev_site, detail="Not found")
                site_id = dev_site
        else:
            # an org-level (no device, no site) alert
            # aggregates across the whole org. A site-limited bound caller must
            # not create one — require a granted scope.
            if site_ids_for_request() is not None:
                raise PermissionError(
                    "Site-limited callers must target a device when creating an alert."
                )

        # Get or create a system AlertRule for plugin-generated alerts
        rule_id = await self._get_or_create_plugin_rule()
        # Generate dedup fingerprint from plugin_id + title + severity
        fp_input = f"plugin:{self._plugin_id}:{title}:{severity}"
        fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()[:64]
        alert = Alert(
            organization_id=self._org_id,
            rule_id=rule_id,
            title=title[:200],
            message=message[:2000],
            severity=severity,
            fingerprint=fingerprint,
            device_id=device_id,
            site_id=site_id,
        )
        self._db.add(alert)
        await self._db.flush()
        return {"id": str(alert.id), "title": alert.title, "severity": alert.severity}

    async def _get_or_create_plugin_rule(self) -> UUID:
        """Find or create the system AlertRule for plugin-generated alerts."""
        from sqlalchemy import select

        from app.models.alert_rules import AlertRule

        rule_name = f"__plugin_alerts_{self._plugin_id}"
        result = await self._db.execute(
            select(AlertRule.id).where(
                AlertRule.organization_id == self._org_id,
                AlertRule.name == rule_name,
                AlertRule.is_system == True,  # noqa: E712
            )
        )
        rule_id = result.scalar_one_or_none()
        if rule_id:
            return rule_id
        rule = AlertRule(
            organization_id=self._org_id,
            name=rule_name,
            description=f"System rule for alerts generated by plugin '{self._plugin_id}'",
            rule_type="custom",
            status="active",
            severity="warning",
            is_system=True,
            conditions={},
        )
        self._db.add(rule)
        await self._db.flush()
        return rule.id

    async def resolve(self, alert_id: UUID, resolution: str = "") -> None:
        """Resolve an existing alert."""
        self._require_permission("alerts.write")
        from sqlalchemy import select

        from app.core.site_access import site_ids_for_request

        try:
            from app.models.alert_rules import Alert
        except ImportError:
            return
        q = select(Alert).where(
            Alert.id == alert_id,
            Alert.organization_id == self._org_id,
        )
        # a site-limited bound caller may only resolve alerts in a
        # granted site; a sibling-site (or org-level NULL-site) alert resolves
        # to no-op (no existence oracle). No-op when unbound / admin caller.
        granted = site_ids_for_request()
        if granted is not None:
            q = q.where(Alert.site_id.in_(list(granted)))
        result = await self._db.execute(q)
        alert = result.scalar_one_or_none()
        if alert:
            alert.status = "resolved"
            if hasattr(alert, "resolution"):
                alert.resolution = resolution[:2000]


class EventSDK(_PermissionMixin):
    """Publish and subscribe to the FreeSDN event bus."""

    def __init__(
        self,
        plugin_id: str,
        declared_permissions: list[str],
        event_subscriptions: list[str] | None = None,
        organization_id: UUID | None = None,
    ) -> None:
        super().__init__(plugin_id, declared_permissions)
        self._allowed_patterns = event_subscriptions or []
        self._organization_id = organization_id

    async def emit(self, event_type: str, payload: dict[str, Any]) -> None:
        """
        Publish an event. Automatically prefixed with ``plugin.{plugin_id}.``.

        Example: ``self.ctx.events.emit("threshold", {"value": 95})``
        publishes ``plugin.acme-monitoring.threshold``.
        """
        from app.core.events import Event, event_bus

        prefixed = f"plugin.{self._plugin_id}.{event_type}"
        await event_bus.publish(
            Event(
                event_type=prefixed,
                payload=payload,
                source=f"plugin:{self._plugin_id}",
                organization_id=str(self._organization_id) if self._organization_id else None,
            )
        )

    def subscribe(self, event_pattern: str) -> None:
        """
        Validate that the plugin is allowed to subscribe to this pattern.

        Plugins can only subscribe to patterns declared in their plugin.yaml.
        Bare ``*`` wildcards are not allowed.
        """
        if event_pattern == "*" or event_pattern == "#":
            raise PermissionError(
                f"Plugin '{self._plugin_id}' cannot subscribe to bare wildcard '{event_pattern}'. "
                f"Declare specific event patterns in plugin.yaml."
            )
        if event_pattern not in self._allowed_patterns:
            raise PermissionError(
                f"Plugin '{self._plugin_id}' cannot subscribe to '{event_pattern}'. "
                f"Add it to event_subscriptions in plugin.yaml."
            )


class PluginSettingsSDK:
    """Scoped key-value settings with secret encryption."""

    def __init__(
        self,
        plugin_id: str,
        org_id: UUID,
        db: AsyncSession,
    ) -> None:
        self._plugin_id = plugin_id
        self._org_id = org_id
        self._db = db

    async def get(self, key: str, default: Any = None) -> Any:
        """Read a plugin setting."""
        from sqlalchemy import select

        from app.models.plugins import PluginSetting

        result = await self._db.execute(
            select(PluginSetting).where(
                PluginSetting.plugin_id == self._plugin_id,
                PluginSetting.organization_id == self._org_id,
                PluginSetting.key == key,
            )
        )
        row = result.scalar_one_or_none()
        return row.value if row else default

    async def set(self, key: str, value: Any) -> None:
        """Write a plugin setting."""
        from sqlalchemy import select

        from app.models.plugins import PluginSetting

        result = await self._db.execute(
            select(PluginSetting).where(
                PluginSetting.plugin_id == self._plugin_id,
                PluginSetting.organization_id == self._org_id,
                PluginSetting.key == key,
            )
        )
        row = result.scalar_one_or_none()
        if row:
            row.value = value
        else:
            self._db.add(
                PluginSetting(
                    plugin_id=self._plugin_id,
                    organization_id=self._org_id,
                    key=key,
                    value=value,
                )
            )

    async def get_secret(self, key: str) -> str | None:
        """Read an encrypted setting. Returns decrypted plaintext."""
        stored = await self.get(f"{key}:encrypted")
        if stored is None:
            return None
        from app.core.security_utils import decrypt_webhook_secret

        return decrypt_webhook_secret(str(stored))

    async def set_secret(self, key: str, value: str) -> None:
        """Encrypt and store a secret setting."""
        from app.core.security_utils import encrypt_webhook_secret

        encrypted = encrypt_webhook_secret(value)
        await self.set(f"{key}:encrypted", encrypted)


class PluginHTTPClient:
    """SSRF-protected HTTP client for outbound API calls.

    Security measures:
    - All URLs validated against SSRF blocklist before request
    - Redirects disabled to prevent redirect-based SSRF bypass
    - kwargs allowlisted to prevent transport/auth injection
    - Timeout capped at 60 seconds max
    - Response size limited to 10 MB
    """

    #: Maximum allowed timeout in seconds
    MAX_TIMEOUT = 60.0
    #: Maximum response body size (10 MB)
    MAX_RESPONSE_SIZE = 10 * 1024 * 1024
    #: Allowed kwargs for requests (prevents transport injection)
    _ALLOWED_KWARGS = frozenset(
        {
            "json",
            "data",
            "params",
            "content",
            "cookies",
        }
    )
    #: Blocked HTTP header names (prevents header injection attacks)
    _BLOCKED_HEADERS = frozenset(
        {
            "authorization",
            "host",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-real-ip",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "transfer-encoding",
        }
    )

    def __init__(self, plugin_id: str, version: str, timeout: float = 30.0) -> None:
        self._plugin_id = plugin_id
        self._version = version
        self._timeout = min(timeout, self.MAX_TIMEOUT)
        self._user_agent = f"FreeSDN-Plugin/{plugin_id}/{version}"

    def _validate_url(self, url: str) -> str:
        """Return the URL unchanged — SSRF validation is performed inside
        :func:`safe_http_request` which pins the hostname to a validated IP,
        avoiding the DNS-rebinding TOCTOU in :func:`validate_url_ssrf`.
        """
        return url

    async def get(self, url: str, **kwargs: Any) -> Any:
        """Send a GET request."""
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> Any:
        """Send a POST request."""
        return await self._request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> Any:
        """Send a PUT request."""
        return await self._request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> Any:
        """Send a DELETE request."""
        return await self._request("DELETE", url, **kwargs)

    async def _request(self, method: str, url: str, **kwargs: Any) -> Any:
        """Execute an HTTP request with DNS-rebinding-safe SSRF protection."""
        from app.core.security_utils import safe_http_request

        # Filter kwargs to prevent transport/auth/proxy injection
        filtered = {k: v for k, v in kwargs.items() if k in self._ALLOWED_KWARGS}

        # Sanitize headers — block security-sensitive header names
        raw_headers = kwargs.get("headers", {})
        if isinstance(raw_headers, dict):
            safe_headers = {
                k: v for k, v in raw_headers.items() if k.lower() not in self._BLOCKED_HEADERS
            }
        else:
            safe_headers = {}
        safe_headers["User-Agent"] = self._user_agent
        filtered["headers"] = safe_headers

        # DNS-rebinding-safe HTTP request with redirects disabled.
        response = await safe_http_request(
            method,
            url,
            timeout=self._timeout,
            follow_redirects=False,
            **filtered,
        )
        # Enforce response size limit (works for both Content-Length
        # and chunked responses since httpx reads the full body)
        body_size = len(response.content)
        if body_size > self.MAX_RESPONSE_SIZE:
            raise ValueError(
                f"Response too large ({body_size} bytes). Max: {self.MAX_RESPONSE_SIZE} bytes."
            )
        return response


# =============================================================================
# Plugin Context
# =============================================================================


@dataclass
class PluginContext:
    """
    Typed context provided to plugins after on_start().

    All plugin access to FreeSDN internals goes through this object.

    Example::

        class MyPlugin(FreeSDNPlugin):
            async def on_start(self, org_id, db):
                await super().on_start(org_id, db)
                devices = await self.ctx.devices.list(status="offline")
                for d in devices:
                    await self.ctx.alerts.create(
                        title=f"Device {d['name']} is offline",
                        message="Detected during plugin startup scan",
                        severity="warning",
                        device_id=UUID(d["id"]),
                    )
    """

    plugin_id: str
    organization_id: UUID
    devices: DeviceSDK
    alerts: AlertSDK
    events: EventSDK
    settings: PluginSettingsSDK
    http: PluginHTTPClient
    logger: logging.Logger


# =============================================================================
# FreeSDNPlugin Base Class
# =============================================================================


class FreeSDNPlugin(BaseModule):
    """
    Base class for third-party FreeSDN plugins.

    Extends BaseModule with:
    - Plugin-specific lifecycle hooks (on_install, on_upgrade, on_uninstall)
    - Typed SDK context (self.ctx) for safe access to FreeSDN internals
    - Bridge methods for registering automation triggers/actions and AI tools

    Example plugin.py::

        from app.plugins.sdk import FreeSDNPlugin
        from fastapi import APIRouter

        class AcmePlugin(FreeSDNPlugin):
            async def on_start(self, org_id, db):
                await super().on_start(org_id, db)
                # self.ctx is now available
                devices = await self.ctx.devices.list()

            def get_router(self) -> APIRouter:
                router = APIRouter()

                @router.get("/status")
                async def status():
                    return {"ok": True}

                return router
    """

    # Set by PluginLoader during install/load
    _plugin_dir: Path = Path("/data/plugins")
    _plugin_manifest_data: Any = None

    def __init__(self) -> None:
        super().__init__()
        self._ctx: PluginContext | None = None
        self._event_subscription_ids: list[str] = []

    @property
    def ctx(self) -> PluginContext | None:
        """Return the org-scoped context for this runtime or active request."""
        if self._ctx is not None:
            return self._ctx
        runtime = get_request_plugin_runtime()
        if runtime is None or runtime is self:
            return None
        return runtime._ctx

    @ctx.setter
    def ctx(self, value: PluginContext | None) -> None:
        self._ctx = value

    @property
    def manifest(self) -> ModuleManifest:
        """Auto-generated from plugin.yaml. Plugins should NOT override this."""
        if self._plugin_manifest_data is None:
            raise RuntimeError(
                f"Plugin {self.__class__.__name__} has no manifest data. "
                "Was it loaded via PluginLoader?"
            )
        result: ModuleManifest = self._plugin_manifest_data.to_module_manifest()
        return result

    def get_router(self) -> APIRouter:
        """Return a FastAPI router for this plugin's API endpoints.

        Default: empty router (plugin has no routes).
        Override this to expose endpoints.
        """
        return APIRouter()

    def get_models(self) -> list[type]:
        """Return SQLAlchemy model classes defined by this plugin."""
        return []

    # ── Plugin-specific lifecycle hooks ──────────────────────────────────────

    async def on_install(self, db: Any) -> None:
        """Called once when the plugin is first installed.

        Use this to create DB tables, seed initial data, or set defaults.
        """

    async def on_upgrade(self, from_version: str, db: Any) -> None:
        """Called when the plugin is upgraded from a previous version.

        Args:
            from_version: The version string of the previously installed version.
        """

    async def on_uninstall(self, db: Any) -> None:
        """Called just before the plugin is removed.

        Use this to clean up DB records, files, and any external resources.
        """

    # ── SDK Context Initialization ───────────────────────────────────────────

    async def on_start(self, organization_id: UUID, db: Any = None) -> None:
        """Start plugin for an organization. Initializes the SDK context."""
        if db is not None:
            self._init_context(organization_id, db)
        await super().on_start(organization_id, db)

    async def on_stop(self, organization_id: UUID, db: Any = None) -> None:
        """Stop plugin for an organization and clean up runtime subscriptions."""
        self.unbind_event_subscriptions()
        self.ctx = None
        await super().on_stop(organization_id, db)

    async def on_event(self, event: Any) -> None:
        """Default event handler for plugins declaring event subscriptions."""
        logger.debug(
            "Plugin %s received event %s",
            self.manifest.id,
            getattr(event, "event_type", "<unknown>"),
        )

    async def health_check(self) -> dict[str, Any]:
        """Return plugin runtime health details for the active organization."""
        if not self.ctx:
            return {"status": "inactive"}
        return {
            "status": "ok",
            "organization_id": str(self.ctx.organization_id),
        }

    def _init_context(self, org_id: UUID, db: AsyncSession) -> None:
        """Build the typed PluginContext for this plugin + org."""
        manifest_data = self._plugin_manifest_data
        plugin_id = manifest_data.id if manifest_data else "unknown"
        version = manifest_data.version if manifest_data else "0.0.0"

        # Collect declared permission codes from the manifest
        declared = []
        if manifest_data and manifest_data.permissions:
            declared = [p.code for p in manifest_data.permissions]

        # Collect declared event subscriptions
        event_subs: list[str] = []
        if manifest_data and hasattr(manifest_data, "event_subscriptions"):
            event_subs = manifest_data.event_subscriptions or []

        self.ctx = PluginContext(
            plugin_id=plugin_id,
            organization_id=org_id,
            devices=DeviceSDK(plugin_id, declared, org_id, db),
            alerts=AlertSDK(plugin_id, declared, org_id, db),
            events=EventSDK(plugin_id, declared, event_subs, org_id),
            settings=PluginSettingsSDK(plugin_id, org_id, db),
            http=PluginHTTPClient(plugin_id, version),
            logger=logging.getLogger(f"freesdn.plugin.{plugin_id}"),
        )

    def bind_event_subscriptions(self) -> None:
        """Bind declared plugin event subscriptions to the shared event bus."""
        if not self.ctx or self._event_subscription_ids:
            return

        org_id = str(self.ctx.organization_id)
        manifest_data = self._plugin_manifest_data
        patterns = getattr(manifest_data, "event_subscriptions", []) or []
        if not patterns:
            return

        from app.core.events import event_bus

        for pattern in patterns:
            self.ctx.events.subscribe(pattern)

            async def _handle_event(event: Any, *, bound_org_id: str = org_id) -> None:
                event_org_id = getattr(event, "organization_id", None)
                # Fail CLOSED: an org-bound plugin must NOT receive an event that
                # carries no organization_id — those route to the "system" scope
                # and may contain another tenant's data in the payload (the
                # camera.status / ai.budget cross-tenant-leak class). Only events
                # explicitly scoped to this plugin's org are delivered.
                if not event_org_id or event_org_id != bound_org_id:
                    return
                await self.on_event(event)

            subscription_id = event_bus.subscribe(pattern, _handle_event)
            if isinstance(subscription_id, str):
                self._event_subscription_ids.append(subscription_id)

    def unbind_event_subscriptions(self) -> None:
        """Remove all event bus subscriptions associated with this runtime instance."""
        if not self._event_subscription_ids:
            return

        from app.core.events import event_bus

        for subscription_id in self._event_subscription_ids:
            event_bus.unsubscribe(subscription_id)
        self._event_subscription_ids.clear()

    # ── Convenience helpers (backwards compat) ───────────────────────────────

    async def emit_event(self, event_type: str, payload: dict[str, Any]) -> None:
        """Publish an event to the FreeSDN event bus.

        Always prefixed with ``plugin.{plugin_id}.`` to prevent spoofing
        core system events. Prefer ``self.ctx.events.emit()`` when available.
        """
        if self.ctx:
            await self.ctx.events.emit(event_type, payload)
            return
        # Fallback for pre-context calls — ALWAYS prefix with plugin namespace
        try:
            from app.core.events import Event, event_bus

            prefixed = f"plugin.{self.manifest.id}.{event_type}"
            await event_bus.publish(
                Event(
                    event_type=prefixed,
                    payload=payload,
                    source=f"plugin:{self.manifest.id}",
                )
            )
        except Exception as exc:
            logger.warning("Plugin %s failed to emit event: %s", self.manifest.id, exc)

    async def get_setting(self, db: Any, org_id: UUID, key: str, default: Any = None) -> Any:
        """Read a plugin org-scoped setting from the plugin_settings table."""
        if self.ctx:
            return await self.ctx.settings.get(key, default)
        try:
            from sqlalchemy import select

            from app.models.plugins import PluginSetting

            result = await db.execute(
                select(PluginSetting).where(
                    PluginSetting.plugin_id == self.manifest.id,
                    PluginSetting.organization_id == org_id,
                    PluginSetting.key == key,
                )
            )
            row = result.scalar_one_or_none()
            return row.value if row else default
        except Exception as exc:
            logger.warning("Plugin get_setting failed: %s", exc)
            return default

    async def set_setting(self, db: Any, org_id: UUID, key: str, value: Any) -> None:
        """Write a plugin org-scoped setting to the plugin_settings table."""
        if self.ctx:
            await self.ctx.settings.set(key, value)
            return
        try:
            from sqlalchemy import select

            from app.models.plugins import PluginSetting

            result = await db.execute(
                select(PluginSetting).where(
                    PluginSetting.plugin_id == self.manifest.id,
                    PluginSetting.organization_id == org_id,
                    PluginSetting.key == key,
                )
            )
            row = result.scalar_one_or_none()
            if row:
                row.value = value
            else:
                row = PluginSetting(
                    plugin_id=self.manifest.id,
                    organization_id=org_id,
                    key=key,
                    value=value,
                )
                db.add(row)
            await db.flush()
        except Exception as exc:
            logger.warning("Plugin set_setting failed: %s", exc)

    # ── Bridge Methods (Plugin ↔ Automation / AI) ────────────────────────────

    def register_automation_trigger(
        self,
        trigger_type: str,
        description: str,
        schema: dict[str, Any],
    ) -> None:
        """Register a custom automation trigger type.

        Called in on_start() to make this plugin's events available as
        automation triggers. The trigger fires when the plugin emits a
        matching event via self.ctx.events.emit().

        Args:
            trigger_type: Short name (e.g., "threshold_exceeded").
                          Registered as ``plugin.{plugin_id}.{trigger_type}``.
            description: Human-readable description for the automation UI.
            schema: JSON Schema describing the event payload.
        """
        try:
            from app.plugins.bridges import automation_bridge

            manifest = self._plugin_manifest_data
            automation_bridge.register_plugin_trigger(
                manifest.id if manifest else "unknown",
                trigger_type,
                description,
                schema,
            )
        except Exception as exc:
            logger.warning("Failed to register automation trigger: %s", exc)

    def register_automation_action(
        self,
        action_type: str,
        handler: Any,
        description: str,
        params_schema: dict[str, Any],
    ) -> None:
        """Register a custom automation action.

        Args:
            action_type: Short name (e.g., "sync_data").
                         Registered as ``plugin.{plugin_id}.{action_type}``.
            handler: Async callable(params: dict) -> dict.
            description: Human-readable description for the automation UI.
            params_schema: JSON Schema describing the action parameters.
        """
        try:
            from app.plugins.bridges import automation_bridge

            manifest = self._plugin_manifest_data
            automation_bridge.register_plugin_action(
                manifest.id if manifest else "unknown",
                action_type,
                handler,
                description,
                params_schema,
            )
        except Exception as exc:
            logger.warning("Failed to register automation action: %s", exc)

    def register_ai_tool(
        self,
        name: str,
        description: str,
        parameters: dict[str, Any],
        handler: Any,
        permission: str | None = None,
    ) -> None:
        """Register a tool callable by the AI assistant.

        Args:
            name: Tool name (auto-prefixed with ``plugin_{plugin_id}_``).
            description: Description the LLM sees.
            parameters: JSON Schema for the tool parameters.
            handler: Async callable(user, db, **kwargs) -> dict.
            permission: Required FreeSDN permission (from plugin.yaml).
        """
        try:
            from app.modules.ai.tools import AITool
            from app.plugins.bridges import ai_bridge

            manifest = self._plugin_manifest_data
            plugin_id = manifest.id if manifest else "unknown"
            ai_bridge.register_plugin_tool(
                plugin_id,
                AITool(
                    name=name,
                    description=description,
                    parameters=parameters,
                    handler=handler,
                    permission=permission,
                ),
            )
        except Exception as exc:
            logger.warning("Failed to register AI tool: %s", exc)
