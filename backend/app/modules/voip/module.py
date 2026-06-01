# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN VoIP Module - Main Module Class
=======================================

The VoIP module provides GDMS-style voice communication management:
  - Phone fleet management with full lifecycle
  - Network discovery & auto-provisioning
  - PBX integration (FreePBX, Grandstream UCM)
  - Config templates & firmware compliance
  - Call detail records & voicemail
"""

import logging
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter

from app.modules.base import BaseModule, DeviceSource, ModuleCapability
from app.modules.manifest import (
    ModuleCategory,
    ModuleManifest,
    ModuleNavItem,
    ModulePermission,
    ModuleWidget,
)

logger = logging.getLogger(__name__)


async def _fabric_phone_status_handler(ctx: Any) -> Any:
    """Fabric read handler for ``voip.phone.live_status`` — live registration +
    line state for a phone (org-scoped via VoIPService.get_phone)."""
    from uuid import UUID

    from app.core.fabric.execution import OperationResult

    if ctx.db is None:
        return OperationResult.fail("voip.phone.live_status requires a DB session", "NO_DB")
    raw = ctx.params.get("phone_id")
    if not raw:
        return OperationResult.fail("voip.phone.live_status requires 'phone_id'", "NO_TARGET")
    try:
        phone_id = UUID(str(raw))
    except (ValueError, TypeError):
        return OperationResult.fail("invalid phone_id", "BAD_TARGET")
    try:
        from app.modules.voip.service import VoIPService

        svc = VoIPService(
            ctx.db,
            organization_id=ctx.organization_id,
            # thread the caller's per-user site grant so a
            # site-limited principal can't originate/read against a sibling-site PBX.
            accessible_site_ids=getattr(ctx, "accessible_site_ids", None),
        )
        status = await svc.get_phone_live_status(phone_id)
    except Exception as exc:  # noqa: BLE001
        return OperationResult.fail(f"voip.phone.live_status failed: {exc}", "READ_ERROR")
    return OperationResult.ok(output=status if isinstance(status, dict) else {"status": status})


def _pbx_id_from(ctx: Any):
    """Parse + validate the ``pbx_id`` param shared by the VoIP Fabric ops."""
    from uuid import UUID

    raw = ctx.params.get("pbx_id")
    if not raw:
        return None, "requires 'pbx_id'"
    try:
        return UUID(str(raw)), None
    except (ValueError, TypeError):
        return None, "invalid pbx_id"


async def _fabric_active_calls_handler(ctx: Any) -> Any:
    """Fabric read handler for ``voip.pbx.active_calls`` — live active calls on a
    PBX. Safe, org-scoped; useful as an automation condition (e.g. only reload
    when the PBX is idle)."""
    from app.core.fabric.execution import OperationResult

    if ctx.db is None:
        return OperationResult.fail("voip.pbx.active_calls requires a DB session", "NO_DB")
    pbx_id, err = _pbx_id_from(ctx)
    if err:
        return OperationResult.fail(f"voip.pbx.active_calls {err}", "BAD_TARGET")
    try:
        from app.modules.voip.service import VoIPService

        svc = VoIPService(
            ctx.db,
            organization_id=ctx.organization_id,
            # thread the caller's per-user site grant so a
            # site-limited principal can't originate/read against a sibling-site PBX.
            accessible_site_ids=getattr(ctx, "accessible_site_ids", None),
        )
        calls = await svc.get_pbx_active_calls(pbx_id)
    except Exception as exc:  # noqa: BLE001
        return OperationResult.fail(f"voip.pbx.active_calls failed: {exc}", "READ_ERROR")
    return OperationResult.ok(output={"count": len(calls), "calls": calls})


async def _fabric_list_extensions_handler(ctx: Any) -> Any:
    """Fabric read handler for ``voip.pbx.list_extensions`` — the extensions
    synced for a PBX (number/name/active). Org-scoped."""
    from app.core.fabric.execution import OperationResult

    if ctx.db is None:
        return OperationResult.fail("voip.pbx.list_extensions requires a DB session", "NO_DB")
    pbx_id, err = _pbx_id_from(ctx)
    if err:
        return OperationResult.fail(f"voip.pbx.list_extensions {err}", "BAD_TARGET")
    try:
        from app.modules.voip.service import VoIPService

        svc = VoIPService(
            ctx.db,
            organization_id=ctx.organization_id,
            # thread the caller's per-user site grant so a
            # site-limited principal can't originate/read against a sibling-site PBX.
            accessible_site_ids=getattr(ctx, "accessible_site_ids", None),
        )
        items, total = await svc.list_extensions(pbx_id, limit=500)
    except Exception as exc:  # noqa: BLE001
        return OperationResult.fail(f"voip.pbx.list_extensions failed: {exc}", "READ_ERROR")
    return OperationResult.ok(
        output={
            "total": total,
            "extensions": [
                {
                    "extension": e.extension_number,
                    "name": e.display_name,
                    "active": bool(e.is_active),
                }
                for e in items
            ],
        }
    )


async def _fabric_originate_handler(ctx: Any) -> Any:
    """Fabric LIVE-ACTION handler for ``voip.pbx.originate_call``.

    Unlike the staged config-write ops, call origination is a real-time
    operational action meant to fire automatically from an automation (e.g.
    "security alarm -> call the on-call extension"), so it executes immediately
    rather than staging for sign-off. It is gated by the ``voip.manage_phones``
    permission (enforced by the negotiator against the Connection author) and
    the adapter's ADAPTER_READ_ONLY env lock.
    """
    from app.core.fabric.execution import OperationResult

    if ctx.db is None:
        return OperationResult.fail("voip.pbx.originate_call requires a DB session", "NO_DB")
    pbx_id, err = _pbx_id_from(ctx)
    if err:
        return OperationResult.fail(f"voip.pbx.originate_call {err}", "BAD_TARGET")
    extension = str(ctx.params.get("extension") or "").strip()
    destination = str(ctx.params.get("destination") or "").strip()
    if not extension or not destination:
        return OperationResult.fail(
            "voip.pbx.originate_call requires 'extension' and 'destination'", "BAD_PARAMS"
        )
    try:
        from app.modules.voip.service import VoIPService

        svc = VoIPService(
            ctx.db,
            organization_id=ctx.organization_id,
            # thread the caller's per-user site grant so a
            # site-limited principal can't originate/read against a sibling-site PBX.
            accessible_site_ids=getattr(ctx, "accessible_site_ids", None),
        )
        result = await svc.originate_call(
            pbx_id,
            extension,
            destination,
            caller_id=ctx.params.get("caller_id") or None,
            context=str(ctx.params.get("context") or "from-internal"),
        )
    except Exception as exc:  # noqa: BLE001
        return OperationResult.fail(f"voip.pbx.originate_call failed: {exc}", "ORIGINATE_ERROR")
    return OperationResult.ok(output=result if isinstance(result, dict) else {"result": result})


class VoIPModule(BaseModule):
    """
    VoIP Module for FreeSDN.

    Provides GDMS-style device management capabilities:
    - IP Phone fleet management with lifecycle states
    - Network discovery (ARP, SIP, HTTP probing)
    - Zero-touch provisioning with config templates
    - PBX system integration (FreePBX, UCM)
    - Extension management & ring groups
    - Call detail records (CDR) & voicemail
    - Firmware tracking & compliance
    """

    @classmethod
    def get_manifest(cls) -> ModuleManifest:
        """Return the module manifest."""
        return ModuleManifest(
            id="voip",
            name="VoIP & Telephony",
            version="1.0.0",
            description=(
                "GDMS-style IP phone fleet management — discovery, provisioning, "
                "PBX integration, firmware compliance, and call management"
            ),
            author="FreeSDN Team",
            license="AGPL-3.0-only",
            category=ModuleCategory.COMMUNICATION,
            icon="phone",
            color="#8B5CF6",  # Purple
            # Dependencies
            dependencies=[],
            # Capabilities this module provides
            capabilities=[
                ModuleCapability.PHONE_MANAGEMENT,
                ModuleCapability.PBX_MANAGEMENT,
                ModuleCapability.CALL_LOGS,
                ModuleCapability.EXTENSIONS,
                ModuleCapability.RING_GROUPS,
            ],
            # Required capabilities from other modules
            required_capabilities=[],
            # Device types this module supports
            device_types=[
                "ip_phone",
                "pbx",
                "sip_gateway",
                "analog_adapter",
                "conference_phone",
                "dect_base",
            ],
            # Permissions
            permissions=[
                ModulePermission(
                    code="voip.view",
                    name="View VoIP",
                    description="View phones, templates, and fleet dashboard",
                    resource="voip",
                    action="read",
                ),
                ModulePermission(
                    code="voip.manage_phones",
                    name="Manage Phones",
                    description="Add, edit, provision, and lifecycle-manage IP phones",
                    resource="phone",
                    action="update",
                ),
                ModulePermission(
                    code="voip.manage_extensions",
                    name="Manage Extensions",
                    description="Configure extensions and ring groups",
                    resource="extension",
                    action="update",
                ),
                ModulePermission(
                    code="voip.manage_pbx",
                    name="Manage PBX",
                    description="Configure PBX systems",
                    resource="pbx",
                    action="update",
                ),
                ModulePermission(
                    code="voip.view_calls",
                    name="View Call Logs",
                    description="Access call detail records",
                    resource="call_log",
                    action="read",
                ),
                ModulePermission(
                    code="voip.discovery",
                    name="Run Discovery",
                    description="Trigger network discovery scans for VoIP devices",
                    resource="discovery",
                    action="create",
                ),
            ],
            # Navigation items
            nav_items=[
                ModuleNavItem(
                    path="/voip",
                    label="VoIP",
                    icon="phone",
                    order=25,
                    permission="voip.view",
                ),
                ModuleNavItem(
                    path="/voip/fleet",
                    label="Fleet Dashboard",
                    icon="layout-dashboard",
                    order=0,
                    parent="/voip",
                    permission="voip.view",
                ),
                ModuleNavItem(
                    path="/voip/phones",
                    label="Phones",
                    icon="smartphone",
                    order=1,
                    parent="/voip",
                    permission="voip.view",
                ),
                ModuleNavItem(
                    path="/voip/discovery",
                    label="Discovery",
                    icon="radar",
                    order=2,
                    parent="/voip",
                    permission="voip.manage_phones",
                ),
                ModuleNavItem(
                    path="/voip/templates",
                    label="Config Templates",
                    icon="file-cog",
                    order=3,
                    parent="/voip",
                    permission="voip.manage_phones",
                ),
                ModuleNavItem(
                    path="/voip/firmware",
                    label="Firmware",
                    icon="hard-drive-download",
                    order=4,
                    parent="/voip",
                    permission="voip.manage_phones",
                ),
                ModuleNavItem(
                    path="/voip/extensions",
                    label="Extensions",
                    icon="hash",
                    order=5,
                    parent="/voip",
                    permission="voip.view",
                ),
                ModuleNavItem(
                    path="/voip/ring-groups",
                    label="Ring Groups",
                    icon="users",
                    order=6,
                    parent="/voip",
                    permission="voip.manage_extensions",
                ),
                ModuleNavItem(
                    path="/voip/call-logs",
                    label="Call Logs",
                    icon="phone-call",
                    order=7,
                    parent="/voip",
                    permission="voip.view_calls",
                ),
                ModuleNavItem(
                    path="/voip/voicemails",
                    label="Voicemail",
                    icon="voicemail",
                    order=8,
                    parent="/voip",
                    permission="voip.view",
                ),
                ModuleNavItem(
                    path="/voip/pbx",
                    label="PBX Systems",
                    icon="server",
                    order=9,
                    parent="/voip",
                    permission="voip.manage_pbx",
                ),
            ],
            # Dashboard widgets
            widgets=[
                ModuleWidget(
                    id="fleet_overview",
                    name="Fleet Overview",
                    description="Phone fleet status, lifecycle, and health at a glance",
                    component="FleetOverviewWidget",
                    default_size="large",
                    refresh_interval=30,
                    permission="voip.view",
                ),
                ModuleWidget(
                    id="phone_status",
                    name="Phone Status",
                    description="Online/offline phone status summary",
                    component="PhoneStatusWidget",
                    default_size="small",
                    refresh_interval=60,
                    permission="voip.view",
                ),
                ModuleWidget(
                    id="discovery_activity",
                    name="Discovery Activity",
                    description="Recent discovery scans and newly found devices",
                    component="DiscoveryActivityWidget",
                    default_size="medium",
                    refresh_interval=120,
                    permission="voip.view",
                ),
                ModuleWidget(
                    id="firmware_compliance",
                    name="Firmware Compliance",
                    description="Fleet firmware version compliance status",
                    component="FirmwareComplianceWidget",
                    default_size="small",
                    refresh_interval=300,
                    permission="voip.view",
                ),
                ModuleWidget(
                    id="recent_calls",
                    name="Recent Calls",
                    description="Recent call activity",
                    component="RecentCallsWidget",
                    default_size="medium",
                    refresh_interval=30,
                    permission="voip.view_calls",
                ),
            ],
            # Settings schema
            settings_schema={
                "type": "object",
                "properties": {
                    "default_codec": {
                        "type": "string",
                        "enum": ["g711u", "g711a", "g722", "g729", "opus"],
                        "default": "g711u",
                        "description": "Default audio codec",
                    },
                    "sip_port": {
                        "type": "integer",
                        "default": 5060,
                        "description": "SIP signaling port",
                    },
                    "rtp_port_start": {
                        "type": "integer",
                        "default": 10000,
                        "description": "RTP port range start",
                    },
                    "rtp_port_end": {
                        "type": "integer",
                        "default": 20000,
                        "description": "RTP port range end",
                    },
                    "cdr_retention_days": {
                        "type": "integer",
                        "minimum": 30,
                        "maximum": 365,
                        "default": 90,
                        "description": "Call log retention period",
                    },
                    "discovery_default_subnet": {
                        "type": "string",
                        "default": "",
                        "description": "Default subnet for discovery scans (CIDR)",
                    },
                    "provisioning_base_url": {
                        "type": "string",
                        "default": "",
                        "description": "Base URL for phone provisioning (e.g. http://freesdn:8000/api/v1/voip/provisioning)",
                    },
                    "auto_provision_on_discovery": {
                        "type": "boolean",
                        "default": False,
                        "description": "Automatically provision phones when discovered",
                    },
                    "health_check_interval": {
                        "type": "integer",
                        "minimum": 60,
                        "maximum": 3600,
                        "default": 300,
                        "description": "Phone health check interval in seconds",
                    },
                },
            },
            # Default settings
            default_settings={
                "default_codec": "g711u",
                "sip_port": 5060,
                "rtp_port_start": 10000,
                "rtp_port_end": 20000,
                "cdr_retention_days": 90,
                "discovery_default_subnet": "",
                "provisioning_base_url": "",
                "auto_provision_on_discovery": False,
                "health_check_interval": 300,
            },
        )

    @property
    def manifest(self) -> ModuleManifest:
        """Return the module manifest."""
        return self.get_manifest()

    def get_router(self) -> APIRouter:
        """Return the FastAPI router for VoIP endpoints.

        Assembles sub-routers in correct order — specific prefixes first,
        then routers with path-param catch-alls (phones, pbx) last.
        """
        from app.modules.voip.api import (
            call_logs_router,
            discovery_router,
            extensions_router,
            firmware_router,
            fleet_router,
            pbx_router,
            phones_router,
            provisioning_router,
            ring_groups_router,
            templates_router,
            voicemails_router,
        )

        parent = APIRouter()
        # Fixed-prefix routers first (no path-param ambiguity)
        parent.include_router(discovery_router)
        parent.include_router(templates_router)
        parent.include_router(provisioning_router)
        parent.include_router(fleet_router)
        parent.include_router(firmware_router)
        parent.include_router(extensions_router)
        parent.include_router(ring_groups_router)
        parent.include_router(call_logs_router)
        parent.include_router(voicemails_router)
        # Routers with /{id} catch-all patterns last
        parent.include_router(pbx_router)
        parent.include_router(phones_router)
        return parent

    def get_device_sources(self) -> list[DeviceSource]:
        """Declare VoIP phones as devices managed by this module."""
        from app.modules.voip.models import Phone

        return [
            DeviceSource(
                model=Phone,
                device_type="voip_phone",
                external_id_prefix="voip_phone",
                status_map={
                    "online": "online",
                    "registered": "online",
                    "ringing": "online",
                    "in_call": "online",
                    "offline": "offline",
                    "error": "error",
                    "maintenance": "maintenance",
                },
            )
        ]

    def get_models(self) -> list[type]:
        """Return SQLAlchemy models for this module."""
        from app.modules.voip.models import (
            PBX,
            CallLog,
            ConfigTemplate,
            DiscoveryScan,
            Extension,
            FirmwareTrack,
            Phone,
            RingGroup,
            VoicemailMessage,
        )

        return [
            Phone,
            PBX,
            Extension,
            RingGroup,
            CallLog,
            VoicemailMessage,
            ConfigTemplate,
            FirmwareTrack,
            DiscoveryScan,
        ]

    def get_backup_contributor(self):  # type: ignore[no-untyped-def]
        """Expose the VoIP portable-config contributor to the backup
        framework. Discovered by BackupContributorRegistry.
        discover_from_modules() — see app/modules/voip/backup.py for
        the captured/excluded scope."""
        from app.modules.voip.backup import VoipBackupContributor

        return VoipBackupContributor()

    def get_tasks(self) -> dict[str, Callable[..., Any]]:
        """Return Celery tasks for this module."""
        from app.modules.voip.tasks import (
            bulk_reboot,
            check_firmware_compliance,
            generate_provisioning_files,
            health_check,
            poll_extension_states,
            reboot_phone,
            run_discovery_scan_task,
            sync_cdr,
            sync_extensions,
            sync_phones,
        )

        return {
            "voip.sync_phones": sync_phones,
            "voip.sync_cdr": sync_cdr,
            "voip.sync_extensions": sync_extensions,
            "voip.generate_provisioning_files": generate_provisioning_files,
            "voip.poll_extension_states": poll_extension_states,
            "voip.reboot_phone": reboot_phone,
            "voip.run_discovery_scan": run_discovery_scan_task,
            "voip.health_check": health_check,
            "voip.check_firmware_compliance": check_firmware_compliance,
            "voip.bulk_reboot": bulk_reboot,
        }

    def get_operations(self):  # type: ignore[no-untyped-def]
        """Fabric operations — making FreePBX a first-class control-plane
        participant that automations can DRIVE:

        * Reads (handler, immediate): phone live status, PBX active calls,
          extension list — safe org-scoped data for conditions/steps.
        * Live action (handler, immediate): ``voip.pbx.originate_call`` —
          real-time call origination from an automation.
        * Staged config write (``write=True``, ``feature=pbx.*``):
          ``voip.pbx.inbound_route_create`` routes through the
          AdapterStagingService dual-gate (stage -> operator applies), the same
          hardened pipeline the REST staged-write endpoints use.
        """
        from app.core.fabric.operations import Operation, OperationTier

        _pbx_prop = {"pbx_id": {"type": "string", "format": "uuid"}}
        return [
            Operation(
                id="voip.phone.live_status",
                title="Phone live status",
                description="Live registration + line state for a phone (queries the device).",
                input_schema={
                    "type": "object",
                    "properties": {"phone_id": {"type": "string", "format": "uuid"}},
                    "required": ["phone_id"],
                },
                produces=("application/json",),
                permission="voip.view",
                write=False,
                handler=_fabric_phone_status_handler,
                tier=OperationTier.NATIVE,
                provider_id="voip",
            ),
            Operation(
                id="voip.pbx.active_calls",
                title="PBX active calls",
                description="Live active calls on a PBX (count + channels). Empty when the PBX is idle.",
                input_schema={
                    "type": "object",
                    "properties": _pbx_prop,
                    "required": ["pbx_id"],
                },
                produces=("application/json",),
                permission="voip.view_calls",
                write=False,
                handler=_fabric_active_calls_handler,
                tier=OperationTier.NATIVE,
                provider_id="voip",
            ),
            Operation(
                id="voip.pbx.list_extensions",
                title="PBX extensions",
                description="Extensions synced for a PBX (number / name / active).",
                input_schema={
                    "type": "object",
                    "properties": _pbx_prop,
                    "required": ["pbx_id"],
                },
                produces=("application/json",),
                permission="voip.view",
                write=False,
                handler=_fabric_list_extensions_handler,
                tier=OperationTier.NATIVE,
                provider_id="voip",
            ),
            Operation(
                id="voip.pbx.originate_call",
                title="Originate a call",
                description=(
                    "Place a call from an extension to a destination. A real-time "
                    "action that fires immediately (not staged) — e.g. 'alarm -> "
                    "call the on-call'. Gated by voip.manage_phones + the read-only env lock."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        **_pbx_prop,
                        "extension": {"type": "string"},
                        "destination": {"type": "string"},
                        "caller_id": {"type": "string"},
                        "context": {"type": "string"},
                    },
                    "required": ["pbx_id", "extension", "destination"],
                },
                produces=("application/json",),
                permission="voip.manage_phones",
                write=False,
                handler=_fabric_originate_handler,
                tier=OperationTier.NATIVE,
                provider_id="voip",
            ),
            Operation(
                id="voip.pbx.inbound_route_create",
                title="Create inbound route (DID)",
                description=(
                    "Stage a new inbound route / DID on a PBX. Routes through the "
                    "staged-change dual-gate (stage -> operator applies), never an "
                    "auto-applied device write. 'controller_id' is the PBX id."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "controller_id": {
                            "type": "string",
                            "format": "uuid",
                            "description": "The PBX id (staging controller).",
                        },
                        "extension": {"type": "string", "description": "DID number."},
                        "cidnum": {"type": "string"},
                        "description": {"type": "string"},
                        "destination": {
                            "type": "string",
                            "description": "Where matching calls route, e.g. from-did-direct,200,1",
                        },
                    },
                    "required": ["controller_id", "destination"],
                },
                permission="voip.manage_phones",
                write=True,
                feature="pbx.inbound_route.create",
                tier=OperationTier.NATIVE,
                provider_id="voip",
            ),
        ]

    def get_emitted_events(self):  # type: ignore[no-untyped-def]
        """Fabric event sources: PBX sync lifecycle + PBX/phone action results
        (voip/tasks.py), published to the bus via record_pbx_action /
        record_phone_action. Pure data events — voicemail audio is not brokered.

        These result-events can TRIGGER cross-system automations today (e.g.
        ``pbx.originate_call.ok`` -> notify). Rich real-time call events
        (call.started/answered/ended, extension.registered, voicemail.received)
        require a persistent per-PBX AMI listener that does not exist yet — a
        future increment — so they are intentionally not declared here until
        they actually fire on the bus.
        """
        from app.core.fabric.operations import EventSpec, OperationTier

        def _ev(et, title, desc, fields):
            return EventSpec(
                event_type=et,
                title=title,
                description=desc,
                payload_schema={
                    "type": "object",
                    "properties": {f: {"type": "string"} for f in fields},
                },
                tier=OperationTier.NATIVE,
                provider_id="voip",
            )

        return [
            _ev(
                "pbx.sync.started",
                "PBX sync started",
                "A PBX inventory sync began.",
                ["task_id", "actor_id"],
            ),
            _ev(
                "pbx.sync.progress",
                "PBX sync progress",
                "A PBX sync emitted progress.",
                ["task_id", "stage", "percent", "message"],
            ),
            _ev(
                "pbx.sync.completed",
                "PBX sync completed",
                "A PBX inventory sync finished.",
                ["task_id", "result"],
            ),
            _ev(
                "pbx.sync.failed",
                "PBX sync failed",
                "A PBX inventory sync failed.",
                ["task_id", "error"],
            ),
            _ev(
                "pbx.originate_call.ok",
                "Call originated",
                "A click-to-call originate succeeded.",
                ["pbx_id", "extension", "destination"],
            ),
            _ev(
                "pbx.originate_call.failed",
                "Call originate failed",
                "A click-to-call originate failed.",
                ["pbx_id", "extension", "destination"],
            ),
            _ev(
                "pbx.reload.ok",
                "PBX reloaded",
                "A PBX dialplan/config reload succeeded.",
                ["pbx_id"],
            ),
            _ev(
                "pbx.reload.failed",
                "PBX reload failed",
                "A PBX dialplan/config reload failed.",
                ["pbx_id"],
            ),
            _ev(
                "phone.provision.ok",
                "Phone provisioned",
                "A phone provision succeeded.",
                ["phone_id"],
            ),
            _ev(
                "phone.provision.failed",
                "Phone provision failed",
                "A phone provision failed.",
                ["phone_id"],
            ),
            _ev("phone.reboot.ok", "Phone rebooted", "A phone reboot succeeded.", ["phone_id"]),
            _ev(
                "phone.reboot.failed", "Phone reboot failed", "A phone reboot failed.", ["phone_id"]
            ),
        ]

    async def on_load(self) -> None:
        """Called when module is loaded."""
        await super().on_load()
        logger.info("VoIP module loaded (v2.0.0 — GDMS-style fleet management)")

    async def on_unload(self) -> None:
        """Called when module is unloaded."""
        await super().on_unload()
        logger.info("VoIP module unloaded")
