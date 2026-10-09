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

import asyncio
import builtins
import contextlib
import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextvars import ContextVar, Token
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

from fastapi import APIRouter
from sqlalchemy.engine import CursorResult

from app.modules.base import BaseModule
from app.modules.manifest import ModuleManifest
from app.plugins.capabilities import core_permissions_for
from app.plugins.supervision import PluginNotReady

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


# One database session per plugin ENTRY POINT -- a route call, an event, a
# scheduled run -- rather than one per plugin runtime.
#
# Every SDK object took the session captured at ``on_start`` and held it for the
# life of the runtime. asyncpg permits exactly one operation in flight per
# connection, and SQLAlchemy enforces that:
#
#     InvalidRequestError: This session is provisioning a new connection;
#     concurrent operations are not permitted
#
# So two overlapping calls into one plugin -- two operators hitting the same
# route, or a route landing while an event handler is mid-query -- raced on one
# connection and one of them failed. It stayed rare only because nothing ran
# plugin code unattended. Scheduling changes that: a scan that takes a minute
# overlaps anything an operator does in that minute.
#
# The session must be the SDK's own, not the request's. ``_persist`` commits,
# and committing the REQUEST's session would land a half-finished request
# transaction -- which is precisely why the SDK was given a private session in
# the first place. Keep that property; drop the sharing.
_plugin_session: ContextVar[AsyncSession | None] = ContextVar(
    "freesdn_plugin_session",
    default=None,
)


@contextlib.asynccontextmanager
async def plugin_session_scope() -> AsyncIterator[AsyncSession]:
    """Bind a fresh session for the duration of one call into plugin code.

    Entry points wrap themselves in this; SDK objects read it through
    ``_SessionBound._db``. Nested scopes are fine -- the innermost wins and the
    token restores the outer one, so an event handler invoked from inside a
    route does not steal the route's session.
    """
    from app.db import async_session_factory

    async with async_session_factory() as session:
        token = _plugin_session.set(session)
        try:
            yield session
        except Exception:
            # The session is discarded either way; roll back so a failure cannot
            # leave uncommitted work that a later commit on this connection
            # would pick up.
            with contextlib.suppress(Exception):
                await session.rollback()
            raise
        finally:
            _plugin_session.reset(token)


class _SessionBound:
    """Gives an SDK object the session of the call it is serving.

    Falls back to the startup session when nothing bound one, which keeps
    ``on_start`` working -- it runs before any entry point exists -- and keeps
    every existing ``self._db.execute(...)`` call site unchanged.
    """

    _startup_db: AsyncSession

    @property
    def _db(self) -> AsyncSession:
        return _plugin_session.get() or self._startup_db


# =============================================================================
# SDK Interfaces
# =============================================================================


async def _persist(db: AsyncSession) -> None:
    """Commit a plugin's pending writes.

    Every SDK write path used to end at ``add()`` or a bare attribute mutation,
    and two of them added a ``flush()``. None of them committed, and the session
    factory runs with ``autoflush=False``. The result was that plugin writes did
    not merely fail to persist across requests -- ``settings.set()`` followed
    immediately by ``settings.get()`` in the SAME call returned None, because
    the pending object was never flushed and the SELECT could not see it. The
    SDK reported success throughout: ``alerts.create()`` returns the alert id,
    which exists after a flush whether or not the row is ever committed.

    Committing here is safe because the SDK owns a long-lived session bound at
    plugin start, not the request's session. Verified: the same session object
    serves consecutive requests, is_active, with no transaction open between
    them. So this commits the plugin's own work and cannot land a half-finished
    request transaction.
    """
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise


class _PermissionMixin:
    """Shared permission checking for SDK classes.

    The capability vocabulary and its mapping onto FreeSDN's own permissions
    live in ``app.plugins.capabilities``, which the manifest validator reads
    too. Keeping a second copy here is what let ``alerts.write`` map to
    ``alert:write`` -- a permission that exists nowhere in FreeSDN -- and so
    refuse a site_admin, who holds ``alert:create`` and ``alert:update`` and is
    precisely the role that drives a plugin route.
    """

    def __init__(self, plugin_id: str, declared_permissions: list[str]) -> None:
        self._plugin_id = plugin_id
        self._declared_permissions = declared_permissions

    def _require_permission(self, needed: str) -> None:
        """Verify the plugin declared this capability AND that the
        authenticated caller — if any — holds a permission that satisfies it."""
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
        if caller is None:
            return

        accepted = core_permissions_for(needed)
        if not accepted:
            return
        has_perm = getattr(caller, "has_permission", None)
        if not callable(has_perm):
            raise PermissionError(
                f"Caller cannot be evaluated for plugin '{self._plugin_id}' capability '{needed}'."
            )
        # ANY of them satisfies: FreeSDN splits writes by verb (alert:create /
        # alert:update) where the plugin surface is one write capability.
        if not any(has_perm(perm) for perm in accepted):
            wanted = " or ".join(sorted(accepted))
            raise PermissionError(
                f"Caller lacks the {wanted} permission required to "
                f"invoke plugin '{self._plugin_id}' capability '{needed}'."
            )


class DeviceSDK(_SessionBound, _PermissionMixin):
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
        self._startup_db = db

    async def list(
        self,
        status: str | None = None,
        site_id: UUID | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """One page of devices visible to this organization.

        ``limit`` is CAPPED at 500 per call and always has been. A plugin asking
        for 2000 silently received 500 -- which nobody notices on a lab estate
        and makes a drift scan quietly wrong on a real one. The cap is not the
        bug; the silence was. Use :meth:`iter_all` to walk the whole inventory.
        """
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
        # Soft-deleted rows are NOT visible to plugins. They were, until
        # 2026-08-22: the soft-delete CI guard scans api/services/tasks/modules/
        # core and did not scan ``plugins``, so this SDK was the one place the
        # check never reached. On the dev estate that meant 24 of 40 devices,
        # and 48 of 59 alerts raised in six hours were about devices the
        # operator had already deleted -- noise that the new unattended sweep
        # would have produced every thirty minutes, forever.
        q = (
            select(Device)
            .join(Site, Device.site_id == Site.id)
            .where(Site.organization_id == self._org_id, Device.alive(), Site.alive())
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
        # Deterministic order. Offset paging over an unordered query can skip
        # and duplicate rows between pages, so iter_all below would silently
        # return a wrong set -- worse than the truncation it exists to fix.
        q = q.order_by(Device.id).offset(max(0, offset)).limit(max(1, min(limit, 500)))
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
                # Identity fields. Their absence was not cosmetic: snipe-it-sync
                # keys every asset on a serial, found neither ``serial`` nor
                # ``serial_number`` in this dict, and skipped 100% of devices --
                # then reported the miss as "your adapters do not report serials",
                # blaming the operator's gear for an omission here. netbox-sync
                # wants ``manufacturer`` for the same reason.
                "serial_number": getattr(r, "serial_number", None),
                "manufacturer": getattr(r, "manufacturer", None),
                "site_id": str(r.site_id) if getattr(r, "site_id", None) else None,
                # Required to stage a change against this device: stage_change()
                # takes a controller_id and nothing else here could supply one, so
                # devices.stage was unusable without it. Found by writing a plugin
                # that tried: the only id available was the device's own, which
                # failed on the controllers foreign key.
                "controller_id": (
                    str(r.controller_id) if getattr(r, "controller_id", None) else None
                ),
            }
            for r in rows
        ]

    #: Ceiling on iter_all. A plugin walking an unbounded inventory in one pass
    #: is a memory profile nobody signed up for; stopping loudly beats degrading
    #: quietly. Raise it deliberately if an estate genuinely needs more.
    MAX_ITER_ROWS = 50_000

    async def iter_all(
        self,
        status: str | None = None,
        site_id: UUID | None = None,
        page_size: int = 500,
    ) -> AsyncIterator[dict[str, Any]]:
        """Every device visible to this organization, a page at a time.

        The honest way to scan an estate. ``list()`` caps at 500 per call, so a
        plugin that asked for more got 500 and no indication there were others
        -- a drift report or an inventory sync built on that is simply wrong
        above 500 devices, and right below it, which is the worst way for a bug
        to behave.

        Usage::

            async for device in self.ctx.devices.iter_all():
                ...

        Raises ``RuntimeError`` rather than truncating if the inventory exceeds
        MAX_ITER_ROWS: a plugin author needs to know their assumptions broke.
        """
        offset = 0
        seen = 0
        page_size = max(1, min(page_size, 500))
        while True:
            page = await self.list(status=status, site_id=site_id, limit=page_size, offset=offset)
            if not page:
                return
            for row in page:
                seen += 1
                if seen > self.MAX_ITER_ROWS:
                    raise RuntimeError(
                        f"Plugin '{self._plugin_id}' iterated more than "
                        f"{self.MAX_ITER_ROWS} devices; refusing to continue. "
                        "Narrow the query with status= or site_id=."
                    )
                yield row
            if len(page) < page_size:
                return
            offset += page_size

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
        # A deleted device must read as absent, not as data -- see list().
        q = (
            select(Device)
            .join(Site, Device.site_id == Site.id)
            .where(
                Device.id == device_id,
                Site.organization_id == self._org_id,
                Device.alive(),
                Site.alive(),
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
            # Required to stage a change against this device: stage_change()
            # takes a controller_id and nothing else here could supply one, so
            # devices.stage was unusable without it. Found by writing a plugin
            # that tried: the only id available was the device's own, which
            # failed on the controllers foreign key.
            "controller_id": (str(r.controller_id) if getattr(r, "controller_id", None) else None),
            "model": getattr(r, "model", None),
            "firmware": getattr(r, "firmware_version", None),
            # Kept in step with DeviceSDK.list above -- a plugin that walks
            # iter_all() and one that calls list() must see the same device.
            "serial_number": getattr(r, "serial_number", None),
            "manufacturer": getattr(r, "manufacturer", None),
        }

    async def register_device(self, device_data: dict[str, Any]) -> dict[str, Any]:
        """Register or update a device in the core inventory.

        Requires the ``devices.register`` capability. It was called
        ``devices.write``, which read as "may change devices" and meant only
        "may create an inventory record" -- it never carried any authority over
        a device's configuration. Proposing a configuration change is
        ``devices.stage``, a separate capability with a separate consent line.

        The ``external_id`` must start with ``plugin.{plugin_id}:``.

        Security: prefix namespacing, SSRF IP blocking, metadata validation,
        device count cap (1,000), org-scoped site_id, atomic upsert + audit.
        """
        self._require_permission("devices.register")

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

        # Deleted devices do not count against the budget. Without
        # ``alive()`` a plugin that registers and removes devices as part of
        # normal operation walks its own counter to 1,000 and is then locked
        # out permanently, by rows nothing can see any more.
        count_result = await self._db.execute(
            sa_select(sa_func.count(DeviceModel.id)).where(
                DeviceModel.external_id.like(f"{ext_prefix}:%"),
                DeviceModel.alive(),
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
                    # Registering into a deleted site would create a device
                    # nothing lists and nobody can reach.
                    Site.alive(),
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
                # A deleted device has no ports to report, for the same reason
                # ``get`` returns None for it.
                Device.alive(),
                Site.alive(),
            )
        )
        # a site-limited bound caller may only read ports of devices in
        # a granted site; a sibling-site device returns [] (no existence oracle).
        granted = site_ids_for_request()
        if granted is not None:
            q = q.where(Device.site_id.in_(list(granted)))
        result = await self._db.execute(q)
        rows = result.scalars().all()
        # ``getattr(r, "speed")`` and ``getattr(r, "poe_enabled")`` were BOTH
        # always None: the columns are ``speed_mbps`` and ``is_poe_enabled``.
        # Two of the six fields this method claimed to return had never carried
        # a value, and the default silenced it -- a plugin reading them saw a
        # port with no speed rather than a bug. Confirmed against a live port
        # holding speed_mbps=1000, is_poe_enabled=True.
        #
        # The rest are here because a port is where the questions actually are:
        # is it enabled but dark, which VLAN is it on, is it negotiating half
        # duplex, is the error counter climbing. Answering any of those meant
        # leaving the SDK.
        return [
            {
                "id": str(r.id),
                "name": getattr(r, "name", None),
                "port_number": getattr(r, "port_number", None),
                "port_type": getattr(r, "port_type", None),
                "status": getattr(r, "status", None),
                "is_enabled": getattr(r, "is_enabled", None),
                "speed_mbps": getattr(r, "speed_mbps", None),
                "duplex": getattr(r, "duplex", None),
                "vlan_id": getattr(r, "vlan_id", None),
                "poe_enabled": getattr(r, "is_poe_enabled", None),
                "poe_power_watts": getattr(r, "poe_power_watts", None),
                "poe_class": getattr(r, "poe_class", None),
                "tx_bytes": getattr(r, "tx_bytes", None),
                "rx_bytes": getattr(r, "rx_bytes", None),
                "errors": getattr(r, "errors", None),
                # Kept as an alias so a plugin written against the old shape
                # does not break -- it was always None, so nothing can be
                # relying on a value, only on the key existing.
                "speed": getattr(r, "speed_mbps", None),
            }
            for r in rows
        ]

    #: The staged-change notes column is Text; a plugin must not be able to fill it.
    MAX_NOTE_CHARS = 2000

    def _provenance_note(self, notes: str | None) -> str:
        """The note recorded on a staged change, always naming the plugin.

        The operator approving a pending change has to see where the proposal
        came from before they apply it. The prefix is PREPENDED, never
        substituted, so a plugin cannot suppress it by supplying its own note,
        and cannot spoof another plugin's id by embedding one: whatever it
        writes lands after this prefix, not instead of it.
        """
        provenance = f"[plugin:{self._plugin_id}]"
        supplied = (notes or "").strip()
        combined = f"{provenance} {supplied}" if supplied else provenance
        return combined[: self.MAX_NOTE_CHARS]

    async def stage_change(
        self,
        *,
        controller_id: UUID,
        feature: str,
        operation: str,
        payload: dict[str, Any],
        site_id: UUID | None = None,
        target_id: str | None = None,
        notes: str | None = None,
    ) -> dict[str, Any]:
        """Propose a device configuration change. Staged only, never applied.

        This is the capability that makes a plugin more than an observer, and
        the reason it is safe to grant is that it does not shorten the path to a
        device by one step. ``stage_change()`` records intent in the staging
        table; a change still reaches hardware only when an operator applies it,
        behind the same two gates as every other write: ADAPTER_READ_ONLY=false
        AND an explicit per-request apply. A plugin cannot apply, and there is
        deliberately no SDK method that can.

        Provenance is not optional. The staged row's notes always begin with
        ``[plugin:<id>]`` so the operator reading the pending-changes list sees
        where the proposal came from before approving it. A plugin's own note is
        appended, never substituted.

        Everything else is the platform's existing chokepoint, unchanged: the
        per-user site grant is enforced inside ``stage_change`` itself, the
        controller-containment rule still applies, and ``operation`` must be
        create, update or delete.

        Args:
            controller_id: The controller that owns the target.
            feature: Adapter feature key, e.g. ``"omada.vlan"``.
            operation: ``create`` | ``update`` | ``delete``.
            payload: The change body the applier will send.
            site_id: Target site. Required for site-scoped features.
            target_id: Vendor-side id of the object being changed, if any.
            notes: Why. Shown to the operator deciding whether to apply.

        Returns:
            The staged change: ``id``, ``status``, ``feature``, ``operation``.
        """
        self._require_permission("devices.stage")

        from app.services.adapter_staging import AdapterStagingService

        actor_id = None
        caller = get_request_caller()
        if caller is not None:
            actor_id = getattr(caller, "id", None)

        service = AdapterStagingService(self._db)
        change = await service.stage_change(
            organization_id=self._org_id,
            controller_id=controller_id,
            feature=feature,
            operation=operation,
            payload=payload,
            site_id=site_id,
            target_id=target_id,
            notes=self._provenance_note(notes),
            actor_id=actor_id,
        )
        return {
            "id": str(change.id),
            "status": getattr(change, "status", None),
            "feature": getattr(change, "feature", None),
            "operation": getattr(change, "operation", None),
            "site_id": str(change.site_id) if getattr(change, "site_id", None) else None,
        }


class SiteSDK(_SessionBound, _PermissionMixin):
    """Read the sites in this organization.

    Plugins could already read devices, and every device carries a ``site_id``,
    but there was no way to turn that id into a name, an address or a timezone.
    An author's only options were to render a raw UUID at the operator or to
    keep their own copy of the site list, which goes stale.

    Scoping matches DeviceSDK exactly: organization first, then the bound
    caller's per-user site grants. A site-limited user driving a plugin route
    sees the sites they are granted and no others.
    """

    def __init__(
        self,
        plugin_id: str,
        declared_permissions: list[str],
        org_id: UUID,
        db: AsyncSession,
    ) -> None:
        super().__init__(plugin_id, declared_permissions)
        self._org_id = org_id
        self._startup_db = db

    @staticmethod
    def _serialize(row: Any) -> dict[str, Any]:
        return {
            "id": str(row.id),
            "name": getattr(row, "name", None),
            "description": getattr(row, "description", None),
            "address": getattr(row, "address", None),
            "city": getattr(row, "city", None),
            "country": getattr(row, "country", None),
            "timezone": getattr(row, "timezone", None),
            "is_active": getattr(row, "is_active", None),
        }

    async def list(self, limit: int = 100, offset: int = 0) -> builtins.list[dict[str, Any]]:
        """One page of sites in this organization that the caller may see.

        Capped at 500 per call, like DeviceSDK.list. Use :meth:`iter_all` when
        you need all of them.
        """
        self._require_permission("sites.read")
        from sqlalchemy import select

        from app.core.site_access import site_ids_for_request

        try:
            from app.models.core import Site
        except ImportError:  # pragma: no cover - core models always present
            return []

        # Soft-deleted rows are NOT visible to plugins. They were, until
        # 2026-08-22: the soft-delete CI guard scans api/services/tasks/modules/
        # core and did not scan ``plugins``, so this SDK was the one place the
        # check never reached. On the dev estate that meant 24 of 40 devices,
        # and 48 of 59 alerts raised in six hours were about devices the
        # operator had already deleted -- noise that the new unattended sweep
        # would have produced every thirty minutes, forever.
        q = select(Site).where(Site.organization_id == self._org_id, Site.alive())
        granted = site_ids_for_request()
        if granted is not None:
            q = q.where(Site.id.in_(list(granted)))
        # Order by id, not name: two sites may share a name, and offset paging
        # over a non-unique sort can repeat and skip rows between pages.
        q = q.order_by(Site.id).offset(max(0, offset)).limit(max(1, min(limit, 500)))
        result = await self._db.execute(q)
        return [self._serialize(r) for r in result.scalars().all()]

    async def iter_all(self, page_size: int = 500) -> AsyncIterator[dict[str, Any]]:
        """Every site the caller may see, a page at a time."""
        offset = 0
        page_size = max(1, min(page_size, 500))
        while True:
            page = await self.list(limit=page_size, offset=offset)
            if not page:
                return
            for row in page:
                yield row
            if len(page) < page_size:
                return
            offset += page_size

    async def get(self, site_id: UUID) -> dict[str, Any] | None:
        """One site, or None. None rather than a raised error, so a plugin
        cannot use this to probe whether a site it may not see exists."""
        self._require_permission("sites.read")
        from sqlalchemy import select

        from app.core.site_access import site_ids_for_request

        try:
            from app.models.core import Site
        except ImportError:  # pragma: no cover
            return None

        granted = site_ids_for_request()
        if granted is not None and site_id not in granted:
            return None

        # A deleted site reads as absent, like a site in another org.
        result = await self._db.execute(
            select(Site).where(
                Site.id == site_id, Site.organization_id == self._org_id, Site.alive()
            )
        )
        row = result.scalar_one_or_none()
        return self._serialize(row) if row else None


#: How long two identical plugin alerts are treated as the same incident.
#: AlertRuleService reads this per-rule from ``dedupe_window_seconds``; the
#: synthetic per-plugin rule is not operator-tunable, so it is fixed here.
_PLUGIN_ALERT_DEDUPE_WINDOW_SECONDS = 3600


class AlertSDK(_SessionBound, _PermissionMixin):
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
        self._startup_db = db

    async def list(
        self,
        severity: str | None = None,
        limit: int = 50,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        """List alerts for this organization.

        ``status`` filters on the alert lifecycle ("firing", "acknowledged",
        "resolved"). It was missing while the serialiser below already emitted a
        ``status`` field and the sibling ``DeviceSDK.list`` already took one, so
        five shipped plugins called ``alerts.list(status="firing")`` to find the
        alert they had raised and got a TypeError instead. Each of them caught it
        at debug level, so their resolve paths silently did nothing.
        """
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
        if status:
            q = q.where(Alert.status == status)
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
                            # A deleted device is not a valid alert target. It
                            # reads as unknown here, which is the same rejection
                            # a cross-tenant id gets -- no existence oracle.
                            Device.alive(),
                            Site.alive(),
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

        # The rule object, not just its id: its notification_channels are what
        # the operator configured for this plugin's alerts.
        rule = await self._get_or_create_plugin_rule()
        rule_id = rule.id
        # Generate dedup fingerprint from plugin_id + title + severity
        fp_input = f"plugin:{self._plugin_id}:{title}:{severity}"
        fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()[:64]

        # Deduplicate, exactly as AlertRuleService does.
        #
        # This fingerprint was computed and stored but never QUERIED, so every
        # call wrote a new row. A plugin on a schedule therefore produced one
        # fresh alert per finding per run -- port-hygiene, enabled by default on
        # a daily schedule, raises four per half-duplex port per day forever --
        # and each one dispatched its own notification. Six plugins had hand-
        # rolled an ``open_by_title`` scan to work around it; hello-world, the
        # copy-paste template, had not, which is how the anti-pattern spread.
        #
        # Mirrors app/services/alert_rules.py:437-473: same status set, same
        # ordering, same occurrence_count bump. The window is fixed here rather
        # than read from rule.dedupe_window_seconds because the synthetic
        # per-plugin rule is not operator-tunable.
        from datetime import UTC, datetime, timedelta

        from sqlalchemy import select as _select

        cutoff = datetime.now(UTC) - timedelta(seconds=_PLUGIN_ALERT_DEDUPE_WINDOW_SECONDS)
        existing = (
            await self._db.execute(
                _select(Alert)
                .where(
                    Alert.rule_id == rule_id,
                    Alert.fingerprint == fingerprint,
                    Alert.status.in_(["firing", "acknowledged"]),
                    Alert.fired_at >= cutoff,
                )
                .order_by(Alert.fired_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

        # Raising the alert matters more than deduplicating it. If the lookup
        # returns anything other than an Alert, fall through and create the row
        # rather than letting a dedup anomaly suppress a real alert.
        if isinstance(existing, Alert):
            existing.occurrence_count = (existing.occurrence_count or 1) + 1
            if hasattr(existing, "last_occurrence_at"):
                existing.last_occurrence_at = datetime.now(UTC)
            await _persist(self._db)
            # Deliberately no re-notify: the operator has already been told about
            # this condition and it has not been resolved.
            return {
                "id": str(existing.id),
                "title": existing.title,
                "severity": existing.severity,
                "deduplicated": True,
            }

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
        await _persist(self._db)

        # A plugin alert must behave like every other alert. Until 2026-08-22 it
        # did not, and the gap was total: this method wrote the row and stopped.
        # No notification was dispatched and no event was published, so an alert
        # raised by a plugin reached the alert LIST and nothing else -- no
        # email, no Slack, no webhook, even with all of them configured. The
        # operator's only way to learn that a plugin had found something was to
        # go looking.
        #
        # It also made plugins unable to hear each other: notify-hub subscribes
        # to ``alert.fired``, which only ``AlertRuleService`` published, so the
        # one plugin whose entire job is forwarding alerts could not forward an
        # alert raised by another plugin.
        await self._notify(alert, rule)
        await self._publish_fired(alert, rule)

        return {
            "id": str(alert.id),
            "title": alert.title,
            "severity": alert.severity,
            "deduplicated": False,
        }

    async def _notify(self, alert: Any, rule: Any) -> None:
        """Deliver through the operator's configured channels for this plugin.

        The channels live on the plugin's own system AlertRule, which is a real,
        operator-editable row: Alert Rules -> "Plugin alerts: {name}" -> notification
        channels. That is deliberately the same control an operator already uses
        for every other rule, rather than a second notification concept that
        only applies to plugins.

        Empty config is the default and means "no delivery", which is the right
        default for something installed at runtime: a freshly installed plugin
        does not start paging anyone until an operator says where.

        Best-effort, like the native path: a delivery failure must not undo an
        alert that is already recorded.
        """
        channels = getattr(rule, "notification_channels", None)
        if not channels:
            return
        try:
            from app.services.notification_helpers import dispatch_notifications

            await dispatch_notifications(
                db=self._db,
                channels_config=channels,
                title=alert.title,
                body=alert.message,
                organization_id=self._org_id,
            )
            await _persist(self._db)
        except Exception:
            logger.warning(
                "Plugin %s: alert notification dispatch or persistence failed", self._plugin_id
            )

    async def _publish_fired(self, alert: Any, rule: Any) -> None:
        """Publish ``alert.fired`` with the same payload the native path uses.

        Same event type and same keys on purpose. A subscriber must not have to
        care whether an alert came from a rule evaluation or from a plugin, and
        a second event type would mean every existing subscriber silently
        ignores half the alerts on the system.
        """
        try:
            from app.core.events import Event, EventCategory, EventPriority, get_event_bus

            await get_event_bus().publish(
                Event(
                    event_type="alert.fired",
                    category=EventCategory.SECURITY,
                    priority=EventPriority.HIGH,
                    organization_id=str(self._org_id),
                    payload={
                        "alert_id": str(alert.id),
                        "rule_id": str(rule.id),
                        "rule_name": rule.name,
                        "severity": alert.severity,
                        "title": alert.title,
                        "message": alert.message,
                        "device_id": str(alert.device_id) if alert.device_id else None,
                        "site_id": str(alert.site_id) if alert.site_id else None,
                        # The one addition: which plugin raised it. A subscriber
                        # forwarding to chat wants to say so, and without it the
                        # rule name is the only clue.
                        "plugin_id": self._plugin_id,
                    },
                )
            )
        except Exception:
            logger.exception("Plugin %s: alert.fired publish failed", self._plugin_id)

    async def _get_or_create_plugin_rule(self) -> Any:
        """The operator-editable AlertRule that owns this plugin's alerts.

        Returns the ROW, not just its id: ``create`` needs its
        ``notification_channels`` to know where the operator wants these alerts
        delivered.

        The name is what an operator reads in the Alert Rules list, and it used
        to be ``__plugin_alerts_new-device-watch``. That was fine while nothing
        pointed at it; now that it is the control for "where do this plugin's
        alerts go", it needs to look like something a person is meant to open.
        Renamed in place on first read, so an operator who already configured
        channels against the old row keeps them.
        """
        from sqlalchemy import select

        from app.models.alert_rules import AlertRule

        legacy_name = f"__plugin_alerts_{self._plugin_id}"
        rule_name = f"Plugin alerts: {self._plugin_id}"

        result = await self._db.execute(
            select(AlertRule).where(
                AlertRule.organization_id == self._org_id,
                AlertRule.name.in_([rule_name, legacy_name]),
                AlertRule.is_system == True,  # noqa: E712
                # Reusing a soft-deleted system rule would hang every plugin
                # alert off a row the rest of the platform treats as gone.
                # Recreating is safe: the name carries no unique constraint.
                # Same fix as the automation engine's twin.
                AlertRule.alive(),
            )
        )
        rule = result.scalars().first()
        if rule is not None:
            if rule.name != rule_name:
                rule.name = rule_name
                await self._db.flush()
            return rule

        rule = AlertRule(
            organization_id=self._org_id,
            name=rule_name,
            description=(
                f"Alerts raised by the '{self._plugin_id}' plugin. Set notification "
                "channels here to choose where they are delivered."
            ),
            rule_type="custom",
            status="active",
            severity="warning",
            is_system=True,
            conditions={},
        )
        self._db.add(rule)
        await self._db.flush()
        return rule

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
            await _persist(self._db)


class MetricsSDK(_PermissionMixin):
    """Read the time-series FreeSDN already records.

    Without this, a plugin could see that a device is offline RIGHT NOW and
    nothing else. Every question worth asking about an estate is a question
    about time -- has this AP been flapping, is that uplink degrading, which
    site got worse this week -- and none of them could be asked. A whole
    category of plugin could not exist.

    SCOPED BY SITE, NOT BY ORGANIZATION, and that is deliberate rather than
    convenient. The ``organization_id`` column on ``metric_data`` was NULL on
    every row ever written, because the collector recorded ``site_id`` and
    ``device_id`` and skipped the third. The platform's own
    ``/analytics/metrics/query`` filters on ``organization_id`` for tenant
    isolation, so it matched nothing: 25,720 rows in the hypertable and an
    empty ``data_points`` for every operator, always. That collector is fixed
    in this same change -- but every row written before the fix still has NULL,
    and scoping this SDK by organization would have made it return nothing on
    exactly the historical data a trend plugin needs.

    Resolving the organization's sites first and filtering on those is correct
    for old and new rows alike, and it composes with per-user site grants for
    free: a site-limited operator driving a plugin route sees the series for
    the sites they hold and no others.

    LogDB is a SEPARATE DATABASE. It gets its own session per call rather than
    reusing the plugin's, and when it is not configured every method returns
    empty rather than raising -- time-series is an optional tier, and a plugin
    installed on a lite deployment should degrade, not crash.
    """

    #: Ceiling on rows returned by one call. A metrics table is the largest
    #: thing a plugin can ask for by a wide margin: an unbounded query over a
    #: hypertable is how one plugin takes the API process down.
    MAX_POINTS = 5_000

    #: How far back a single query may reach. Not a storage limit -- a
    #: politeness limit, for the same reason.
    MAX_RANGE_DAYS = 90

    def __init__(
        self,
        plugin_id: str,
        declared_permissions: list[str],
        org_id: UUID,
        db: AsyncSession,
    ) -> None:
        super().__init__(plugin_id, declared_permissions)
        self._org_id = org_id
        self._startup_db = db

    @property
    def _db(self) -> AsyncSession:
        # Site resolution runs against the PRIMARY database, so it wants the
        # entry point's session like every other SDK; only the metric query
        # itself goes to LogDB.
        return _plugin_session.get() or self._startup_db

    async def _visible_site_ids(self) -> builtins.list[UUID]:
        """The sites this call may read: organization first, then caller grants."""
        from sqlalchemy import select

        from app.core.site_access import site_ids_for_request
        from app.models.core import Site

        q = select(Site.id).where(Site.organization_id == self._org_id, Site.alive())
        granted = site_ids_for_request()
        if granted is not None:
            q = q.where(Site.id.in_(list(granted)))
        result = await self._db.execute(q)
        return [row[0] for row in result.all()]

    @staticmethod
    def _logdb_factory() -> Any:
        from app.db import session as db_session

        return getattr(db_session, "logdb_session_factory", None)

    async def available(self) -> bool:
        """Is the time-series tier configured on this deployment?

        Worth calling before reporting "no data": on a lite deployment with no
        LogDB, empty and absent look identical to a plugin, and telling an
        operator "no metrics in the last 24 hours" when the database was never
        configured is a wrong answer delivered confidently.
        """
        self._require_permission("metrics.read")
        return self._logdb_factory() is not None

    async def query(
        self,
        metric_name: str,
        *,
        hours: float = 24.0,
        device_id: UUID | None = None,
        site_id: UUID | None = None,
        limit: int = 1000,
    ) -> builtins.list[dict[str, Any]]:
        """Raw points for one metric, newest first.

        Args:
            metric_name: e.g. ``device.status``. See :meth:`metric_names`.
            hours: how far back to look, capped at ``MAX_RANGE_DAYS``.
            device_id: narrow to one device. Not trusted -- the site filter
                still applies, so passing another tenant's device returns
                nothing rather than their data.
            site_id: narrow to one site, intersected with what the caller may
                see, for the same reason.
            limit: capped at ``MAX_POINTS``.
        """
        self._require_permission("metrics.read")
        factory = self._logdb_factory()
        if factory is None:
            return []

        site_ids = await self._visible_site_ids()
        if site_id is not None:
            # INTERSECT rather than replace. A plugin handed a site id by a
            # caller must not be able to widen its own scope with it.
            site_ids = [s for s in site_ids if s == site_id]
        if not site_ids:
            return []

        from datetime import UTC, datetime, timedelta

        from sqlalchemy import select

        from app.models.analytics import MetricDataPoint

        hours = max(0.0, min(float(hours), self.MAX_RANGE_DAYS * 24))
        since = datetime.now(UTC) - timedelta(hours=hours)

        q = (
            select(MetricDataPoint)
            .where(
                MetricDataPoint.metric_name == str(metric_name),
                MetricDataPoint.time >= since,
                MetricDataPoint.site_id.in_(site_ids),
            )
            .order_by(MetricDataPoint.time.desc())
            .limit(max(1, min(limit, self.MAX_POINTS)))
        )
        if device_id is not None:
            q = q.where(MetricDataPoint.device_id == device_id)

        async with factory() as logdb:
            result = await logdb.execute(q)
            return [
                {
                    "time": row.time.isoformat(),
                    "metric_name": row.metric_name,
                    "value": row.value,
                    "labels": row.labels or {},
                    "site_id": str(row.site_id) if row.site_id else None,
                    "device_id": str(row.device_id) if row.device_id else None,
                }
                for row in result.scalars().all()
            ]

    async def latest(
        self,
        metric_name: str,
        *,
        device_id: UUID | None = None,
        hours: float = 24.0,
    ) -> dict[str, Any] | None:
        """The most recent point, or None.

        None rather than raising when there is nothing: "this device has no
        recent data" is an ordinary answer, not an error, and a plugin that has
        to wrap every read in a try block writes worse code.
        """
        points = await self.query(metric_name, hours=hours, device_id=device_id, limit=1)
        return points[0] if points else None

    async def series(
        self,
        metric_name: str,
        *,
        hours: float = 24.0,
        bucket_minutes: int = 60,
        device_id: UUID | None = None,
        site_id: UUID | None = None,
        aggregation: str = "avg",
    ) -> builtins.list[dict[str, Any]]:
        """Bucketed points, oldest first, for a chart or a trend.

        Aggregated in the database rather than handing a plugin 25,000 raw rows
        to reduce in Python: a week of per-minute data for one site is already
        past ``MAX_POINTS``, so the raw call would silently answer with a
        truncated slice -- right for the last few hours, wrong for the week that
        was asked for, and nothing to say which.
        """
        self._require_permission("metrics.read")
        factory = self._logdb_factory()
        if factory is None:
            return []

        allowed = {"avg", "min", "max", "sum", "count"}
        if aggregation not in allowed:
            raise ValueError(f"aggregation must be one of {sorted(allowed)}; got {aggregation!r}")

        site_ids = await self._visible_site_ids()
        if site_id is not None:
            site_ids = [s for s in site_ids if s == site_id]
        if not site_ids:
            return []

        from datetime import UTC, datetime, timedelta

        from sqlalchemy import func, select

        from app.models.analytics import MetricDataPoint

        hours = max(0.0, min(float(hours), self.MAX_RANGE_DAYS * 24))
        bucket = timedelta(minutes=max(1, min(int(bucket_minutes), 1440)))
        since = datetime.now(UTC) - timedelta(hours=hours)

        # date_bin, not TimescaleDB time_bucket: plain Postgres has had it since
        # 14, so this works whether or not the Timescale extension is installed.
        # A LogDB without Timescale is a supported shape.
        bucketed = func.date_bin(bucket, MetricDataPoint.time, since).label("bucket")
        agg = getattr(func, aggregation)(MetricDataPoint.value).label("value")

        q = (
            select(bucketed, agg, func.count().label("samples"))
            .where(
                MetricDataPoint.metric_name == str(metric_name),
                MetricDataPoint.time >= since,
                MetricDataPoint.site_id.in_(site_ids),
            )
            .group_by(bucketed)
            .order_by(bucketed)
            .limit(self.MAX_POINTS)
        )
        if device_id is not None:
            q = q.where(MetricDataPoint.device_id == device_id)

        async with factory() as logdb:
            result = await logdb.execute(q)
            return [
                {
                    "time": row.bucket.isoformat(),
                    "value": float(row.value) if row.value is not None else None,
                    "samples": int(row.samples),
                }
                for row in result.all()
            ]

    async def metric_names(self, *, hours: float = 24.0) -> builtins.list[str]:
        """What is actually being recorded, for this caller's sites.

        Guessing a metric name gets you an empty list that looks exactly like
        "nothing happened". This is how a plugin discovers what exists instead
        of hard-coding a name a future release renames.
        """
        self._require_permission("metrics.read")
        factory = self._logdb_factory()
        if factory is None:
            return []

        site_ids = await self._visible_site_ids()
        if not site_ids:
            return []

        from datetime import UTC, datetime, timedelta

        from sqlalchemy import select

        from app.models.analytics import MetricDataPoint

        hours = max(0.0, min(float(hours), self.MAX_RANGE_DAYS * 24))
        since = datetime.now(UTC) - timedelta(hours=hours)

        q = (
            select(MetricDataPoint.metric_name)
            .where(
                MetricDataPoint.time >= since,
                MetricDataPoint.site_id.in_(site_ids),
            )
            .distinct()
            .order_by(MetricDataPoint.metric_name)
            .limit(500)
        )
        async with factory() as logdb:
            result = await logdb.execute(q)
            return [row[0] for row in result.all()]


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


class PluginSettingsSDK(_SessionBound):
    """Scoped key-value settings with secret encryption."""

    def __init__(
        self,
        plugin_id: str,
        org_id: UUID,
        db: AsyncSession,
    ) -> None:
        self._plugin_id = plugin_id
        self._org_id = org_id
        self._startup_db = db

    async def get(self, key: str, default: Any = None) -> Any:
        """Read a plugin setting, transparently including secret ones.

        A property declared ``secret: true`` in ``settings_schema`` is stored by
        the platform under ``<key>:encrypted`` with the plaintext blanked. If
        ``get`` only looked at the plain key, adding ``secret: true`` to a
        manifest would BREAK every plugin that reads that field -- the value
        would silently become empty string, and an empty credential is
        indistinguishable from an unconfigured one.

        Falling back here makes the declaration purely additive: an author marks
        a field secret and their existing ``settings.get("api_token")`` keeps
        working, now reading an encrypted value. ``get_secret`` remains for an
        author who wants to be explicit about it.
        """
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
        value = row.value if row else None
        if value not in (None, ""):
            return value

        # Empty or absent: the value may live in the encrypted twin. Do not
        # recurse through get_secret's own get() -- read the twin directly.
        if not key.endswith(":encrypted"):
            twin = await self._db.execute(
                select(PluginSetting).where(
                    PluginSetting.plugin_id == self._plugin_id,
                    PluginSetting.organization_id == self._org_id,
                    PluginSetting.key == f"{key}:encrypted",
                )
            )
            twin_row = twin.scalar_one_or_none()
            if twin_row is not None and twin_row.value:
                from app.core.security_utils import decrypt_webhook_secret

                try:
                    return decrypt_webhook_secret(str(twin_row.value))
                except Exception:
                    logger.warning(
                        "Plugin %s: could not decrypt setting %r; treating as unset",
                        self._plugin_id,
                        key,
                    )
                    return default

        return value if row else default

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
        await _persist(self._db)

    async def delete(self, key: str) -> bool:
        """Remove a plugin setting entirely. Returns whether anything was there.

        The verb the SDK was missing. Without it the only way to retire a key
        was ``set(key, "")``, which leaves the row behind for ever -- fine for a
        handful of configuration fields, and a slow leak for the pattern the
        ticketing plugins use, where the key is per-ALERT
        (``__jira_issue__<alert_id>``). One row per alert that ever fired,
        accumulating in a table shared by every plugin and organisation.

        Deletes the encrypted twin as well, so a secret really is gone rather
        than half-gone: ``set_secret`` writes to ``<key>:encrypted``, and
        removing only the plaintext row would leave the credential readable to
        ``get_secret``.
        """
        from sqlalchemy import delete as sql_delete

        from app.models.plugins import PluginSetting

        result = await self._db.execute(
            sql_delete(PluginSetting).where(
                PluginSetting.plugin_id == self._plugin_id,
                PluginSetting.organization_id == self._org_id,
                PluginSetting.key.in_([key, f"{key}:encrypted"]),
            )
        )
        await _persist(self._db)
        return bool(cast(CursorResult[Any], result).rowcount)

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
    #: Blocked HTTP header names (prevents header injection attacks).
    #:
    #: ``authorization`` is NOT here, and its absence is deliberate. It was
    #: blocked, which made it impossible for a plugin to authenticate to any
    #: external API that uses a bearer or token header -- NetBox, Grafana,
    #: PagerDuty, most of them. The header was dropped SILENTLY, so the author
    #: saw a 401 from the remote service and no reason for it.
    #:
    #: Blocking it bought nothing. The request goes to a host the plugin chose,
    #: so there is no FreeSDN credential to forge; reaching FreeSDN's own API is
    #: already refused by the SSRF guard, which is the control that actually
    #: applies; and a plugin bent on exfiltrating a token can put it in a body
    #: or a query string just as easily.
    #:
    #: ``proxy-authorization`` STAYS blocked, because that one authenticates to
    #: an intermediary rather than the destination -- a different trust
    #: boundary, and not one a plugin has any business addressing.
    _BLOCKED_HEADERS = frozenset(
        {
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

    async def patch(self, url: str, **kwargs: Any) -> Any:
        """Send a PATCH request.

        Its absence was not theoretical: servicenow-incidents dispatches through
        ``ctx.http.patch`` to close and annotate an incident, so incidents opened
        and could never be resolved. PATCH is the standard verb for the partial
        updates every ticketing API expects, and ``_request`` already takes an
        arbitrary method string, so this was a missing one-liner rather than a
        missing capability.
        """
        return await self._request("PATCH", url, **kwargs)

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
            # Say when a header is removed. Dropping one silently is how an
            # author ends up debugging the remote service instead of their own
            # call: the request is well-formed, it just is not the one they
            # wrote.
            dropped = sorted(k for k in raw_headers if k.lower() in self._BLOCKED_HEADERS)
            if dropped:
                logger.warning(
                    "Plugin %s: dropped disallowed request header(s) %s",
                    self._plugin_id,
                    ", ".join(dropped),
                )
        else:
            safe_headers = {}
        safe_headers["User-Agent"] = self._user_agent
        filtered["headers"] = safe_headers

        # DNS-rebinding-safe HTTP request with redirects disabled.
        # Deploy-owner trust list, mirroring FABRIC_WEBHOOK_ALLOWED_HOSTS. A
        # plugin could otherwise only reach the public internet, which rules out
        # nearly everything a self-hosted operator would integrate with -- their
        # NetBox, their Gotify, their Grafana. Read from settings on each call
        # rather than cached at construction, so changing it does not require
        # reinstalling every plugin.
        from app.core.config import settings as _settings

        allow_hosts = frozenset(
            h.strip() for h in (_settings.PLUGIN_HTTP_ALLOWED_HOSTS or "").split(",") if h.strip()
        )

        response = await safe_http_request(
            method,
            url,
            timeout=self._timeout,
            follow_redirects=False,
            allow_hosts=allow_hosts,
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
    sites: SiteSDK
    alerts: AlertSDK
    metrics: MetricsSDK
    events: EventSDK
    settings: PluginSettingsSDK
    http: PluginHTTPClient
    logger: logging.Logger


# =============================================================================
# FreeSDNPlugin Base Class
# =============================================================================


class PluginCoordinator:
    """One fetch, shared by everything in a plugin that needs it.

    Modelled on Home Assistant's ``DataUpdateCoordinator``, and it exists here
    for the reason it exists there: without it every consumer polls
    independently. In FreeSDN that showed up as four shipped sync plugins each
    hand-rolling the same retry loop, the same transient-vs-permanent
    classification, and the same "did the last fetch work" bookkeeping -- four
    chances to get it subtly different, and four places to fix anything wrong.

    What it adds beyond a cached call:

    ONE IN-FLIGHT FETCH
        Concurrent callers share a single request rather than stampeding. A
        route call landing while a scheduled run is mid-fetch waits for that
        fetch instead of starting a second one against the same remote.

    A CACHE WITH A STATED AGE
        ``data`` is served from the last successful fetch until it is older
        than ``update_interval``. The age is reported, so a caller can tell
        fresh data from data that happens to still be around.

    FAILURE THAT DOES NOT ERASE
        A failed refresh does not throw away the last good data. An operator
        looking at a report during an outage should see the last known state
        marked stale, not an empty page -- and ``last_update_success`` says
        which they are looking at.

    THE RIGHT KIND OF FAILURE
        A fetch that raises ``PluginNotReady`` is a remote outage: it backs off
        and never counts against the plugin. Anything else is a fault and is
        reported as one. See ``PluginNotReady``.
    """

    #: Multiplied per consecutive failure, capped. Deliberately not the same as
    #: the supervisor's: this is one plugin backing off one remote, not the
    #: platform protecting itself from a plugin.
    BACKOFF_BASE_SECONDS = 30.0
    BACKOFF_MAX_SECONDS = 600.0

    def __init__(
        self,
        ctx: PluginContext,
        name: str,
        update_method: Callable[[], Awaitable[Any]],
        *,
        update_interval: float = 300.0,
    ) -> None:
        self._ctx = ctx
        self.name = name
        self._update = update_method
        self.update_interval = float(update_interval)

        self.data: Any = None
        self.last_update_success: bool = False
        self.last_exception: BaseException | None = None
        self.last_updated: float | None = None
        self.consecutive_failures: int = 0

        self._lock = asyncio.Lock()
        self._next_attempt: float = 0.0

    # ── state a caller can act on ───────────────────────────────

    @property
    def age(self) -> float | None:
        """Seconds since the last SUCCESSFUL fetch, or None if there has been none."""
        if self.last_updated is None:
            return None
        return time.monotonic() - self.last_updated

    @property
    def is_stale(self) -> bool:
        """Is the cached data older than the interval it was promised at?"""
        age = self.age
        return age is None or age > self.update_interval

    def snapshot(self) -> dict[str, Any]:
        """What to put in a status route, so an operator can see the same thing."""
        return {
            "name": self.name,
            "last_update_success": self.last_update_success,
            "age_seconds": round(self.age, 1) if self.age is not None else None,
            "stale": self.is_stale,
            "consecutive_failures": self.consecutive_failures,
            "last_error": str(self.last_exception)[:300] if self.last_exception else None,
        }

    # ── fetching ────────────────────────────────────────────────

    async def async_get(self) -> Any:
        """The data, fetching only if what is cached has gone stale."""
        if not self.is_stale and self.last_update_success:
            return self.data
        await self.async_refresh()
        return self.data

    async def async_refresh(self, *, force: bool = False) -> bool:
        """Fetch now. Returns whether it succeeded.

        Never raises for a failed fetch -- callers get ``False`` and the previous
        data. A coordinator that threw would put a try block around every
        consumer, which is most of what it exists to remove. ``PluginNotReady``
        is re-raised, because that one is not a failure to swallow: the
        supervisor needs to see it to back off correctly.
        """
        # Serialised, so concurrent callers share one fetch instead of
        # stampeding a remote that is already struggling.
        async with self._lock:
            # Another caller may have refreshed while this one waited.
            if not force and not self.is_stale and self.last_update_success:
                return True

            now = time.monotonic()
            if not force and now < self._next_attempt:
                # Still backing off. Returning the cached state beats hammering
                # a remote that has already said no.
                return self.last_update_success

            try:
                self.data = await self._update()
            except PluginNotReady as exc:
                self._record_failure(exc)
                raise
            except Exception as exc:  # noqa: BLE001 - reported, not swallowed
                self._record_failure(exc)
                self._ctx.logger.warning(
                    "Coordinator %s: refresh failed (%d consecutive): %s",
                    self.name,
                    self.consecutive_failures,
                    exc,
                )
                return False

            self.last_update_success = True
            self.last_exception = None
            self.last_updated = time.monotonic()
            self.consecutive_failures = 0
            self._next_attempt = 0.0
            return True

    def _record_failure(self, exc: BaseException) -> None:
        self.last_update_success = False
        self.last_exception = exc
        self.consecutive_failures += 1
        # The previous ``data`` is deliberately kept. During an outage a report
        # showing the last known state marked stale is more use than an empty
        # one, and ``last_update_success`` is what says which it is.
        self._next_attempt = time.monotonic() + min(
            self.BACKOFF_BASE_SECONDS * (2 ** min(self.consecutive_failures - 1, 5)),
            self.BACKOFF_MAX_SECONDS,
        )


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
    def runtime(self) -> FreeSDNPlugin:
        """The per-organization instance serving the current request.

        There are TWO kinds of instance, and the difference is invisible until
        it bites:

        * ONE shared template instance, created at load time. Its ``get_router``
          is what builds the FastAPI routes, so ``self`` inside a route handler
          is the template.
        * ONE runtime instance PER ORGANIZATION, created at start time. Lifecycle
          hooks and ``on_event`` run on these.

        So a plugin that records something in ``on_event`` and reads it back
        from a route finds nothing: the write went to the per-org instance and
        the read came from the template. Nothing raises, the event genuinely
        arrived, and the data is simply somewhere else.

        ``self.ctx`` already resolves through the request-bound runtime, which is
        why SDK calls in routes work correctly. This exposes the instance itself
        for the same reason::

            @router.get("/count")
            async def count():
                return {"seen": len(self.runtime.seen_events)}

        Outside a request (a lifecycle hook, an event handler, a scheduled task)
        ``self`` is already the runtime instance and this returns ``self``.
        """
        bound = get_request_plugin_runtime()
        return bound if bound is not None else self

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

        ``self.ctx`` is None here. Install runs ONCE for the appliance, before
        any per-organisation runtime exists, so there is no context to hand it:
        use ``db`` and a module-level logger. This caught the first-party example
        plugin, whose on_install called ``self.ctx.logger`` and raised
        AttributeError on every single install.
        """

    async def on_upgrade(self, from_version: str, db: Any) -> None:
        """Called when the plugin is upgraded from a previous version.

        ``self.ctx`` is None here too, for the same reason as ``on_install``.

        Args:
            from_version: The version string of the previously installed version.
        """

    async def on_uninstall(self, db: Any) -> None:
        """Called just before the plugin is removed.

        Use this to clean up DB records, files, and any external resources.

        ``self.ctx`` is None here, as in ``on_install`` and ``on_upgrade``. The
        per-organisation runtimes have already been stopped by the time this
        runs, so there is nothing left to give it a context from.
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

    async def async_validate_config(self) -> str | None:
        """Check the current settings actually work. Optional.

        Called when an operator saves settings, and again on demand. Return None
        if everything is usable, or a short sentence naming what is wrong.

        Modelled on Home Assistant's config flow, which validates a connection
        BEFORE the entry is created rather than letting the first poll discover
        it. Without it the feedback loop is terrible: an operator pastes a
        token, sees "Saved", and learns six hours later from an alert -- or
        never, because the plugin's schedule is the only thing that would have
        told them and it fails quietly into a log.

            async def async_validate_config(self) -> str | None:
                config = await self._config()
                if config is None:
                    return "netbox_url and netbox_token are both required"
                ok, body = await self._get(*config, "/status/")
                if not ok:
                    return f"NetBox did not accept the token: {body}"
                return None

        Failure here is ADVISORY. The settings are saved either way, because an
        operator half-way through configuring a plugin should not be blocked by
        a remote that happens to be down, and because a plugin whose validator
        is wrong must not be able to lock its own configuration.
        """
        return None

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
            sites=SiteSDK(plugin_id, declared, org_id, db),
            alerts=AlertSDK(plugin_id, declared, org_id, db),
            metrics=MetricsSDK(plugin_id, declared, org_id, db),
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

                # Supervised. The bus already swallows handler exceptions and
                # caps each at 10s, which keeps the BUS healthy but tells nobody
                # which plugin is failing: it logs "Error in event handler for
                # device.updated" with no plugin in it. A plugin that raised on
                # every event did so forever, invisibly.
                #
                # The guard attributes the failure, counts it, and quarantines a
                # plugin that keeps failing so the platform stops paying the
                # timeout on every event.
                from app.plugins.supervision import PluginQuarantined, supervisor

                plugin_id = self.manifest.id
                try:
                    # Its own session: an event can land while a route call is
                    # mid-query, and asyncpg allows one operation per connection.
                    async with (
                        plugin_session_scope(),
                        supervisor.guard(plugin_id, "event"),
                    ):
                        await self.on_event(event)
                except PluginQuarantined:
                    # Expected while quarantined. Already logged at the trip;
                    # logging every suppressed event would be the noise the
                    # quarantine exists to stop.
                    return

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
        """Advertise an action this plugin can perform.

        READ THIS BEFORE RELYING ON IT. The action is published to the Fabric
        catalogue as ``plugin.{plugin_id}.{action_type}``, where an operator or
        the AI assistant can SEE that your plugin offers it. An automation rule
        cannot currently invoke it, and the docstring here used to imply
        otherwise -- it said "when an automation rule uses this action type, the
        handler ...", which no rule could do.

        The obstacle is tenancy, not effort. A plugin has one runtime instance
        PER ORGANIZATION, while the Fabric registry is process-wide and holds a
        single Operation per id. A handler captured here belongs to whichever
        organization started the plugin first, so invoking it from a rule in a
        different organization would run one tenant's plugin against another
        tenant's context. Every execution path therefore gates on NATIVE
        operations, and plugin operations carry no executable handler by design.

        What DOES work today, and is usually what you wanted:

        * ``ctx.events.emit("x")`` publishes ``plugin.{id}.x``, and an
          automation rule with ``event_pattern: "plugin.{id}.*"`` fires on it.
          That direction is fully wired.
        * Your plugin's own REST route, which runs on the right per-organization
          runtime because the request carries the caller's organization.

        Args:
            action_type: Short name (e.g., "sync_data").
                         Published as ``plugin.{plugin_id}.{action_type}``.
            handler: Async callable(params: dict) -> dict. Held for a future
                     per-organization dispatch path; not called today.
            description: Human-readable description for the catalogue.
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
