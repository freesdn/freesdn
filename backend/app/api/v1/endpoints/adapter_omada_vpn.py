# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway-VPN endpoints
================================

Per-controller VPN configuration on managed gateways (Omada today;
extensible to OPNsense / pfSense later). All routes scope on
``controller_id`` + ``site_id`` so multi-tenant isolation is structural.

Read paths talk live to the controller. Write paths stage every change
in ``core.adapter_pending_changes`` and never push to the live device
unless ``OMADA_READ_ONLY=false`` AND the apply call is made with
``force=true``. Default-safe for production.

URL layout::

    GET     /api/v1/gateway-vpn/{controller_id}/sites/{site_id}/{protocol}/config
    GET     /api/v1/gateway-vpn/{controller_id}/sites/{site_id}/{protocol}/users
    GET     /api/v1/gateway-vpn/{controller_id}/sites/{site_id}/{protocol}/status
    GET     /api/v1/gateway-vpn/{controller_id}/sites/{site_id}/ipsec/policies
    GET     /api/v1/gateway-vpn/{controller_id}/sites/{site_id}/wireguard/peers
    GET     /api/v1/gateway-vpn/{controller_id}/sites/{site_id}/gre/tunnels

    POST    /api/v1/gateway-vpn/{controller_id}/sites/{site_id}/changes
            (body: {feature, operation, payload, target_id?, notes?})
    GET     /api/v1/gateway-vpn/{controller_id}/sites/{site_id}/changes
    POST    /api/v1/gateway-vpn/changes/{change_id}/apply
    POST    /api/v1/gateway-vpn/changes/{change_id}/discard
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import (
    CurrentUser,
    get_current_user,
    require_permissions,
)
from app.core.site_access import assert_can_access_site
from app.db.session import get_session
from app.schemas.gateway_vpn import (
    ApplyPendingChangeRequest,
    GatewayVPNDetailResponse,
    GatewayVPNListResponse,
    PendingChangeRequest,
    PendingChangeResponse,
    VPNStatusResponse,
)
from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_mikrotik_capsman import (
    GatewayMikrotikCapsmanService,
)
from app.services.adapter_mikrotik_dhcp import GatewayMikrotikDHCPService
from app.services.adapter_mikrotik_dns import GatewayMikrotikDNSService
from app.services.adapter_mikrotik_firewall import (
    GatewayMikrotikFirewallService,
)
from app.services.adapter_mikrotik_hotspot import (
    GatewayMikrotikHotspotService,
)
from app.services.adapter_mikrotik_interfaces import (
    GatewayMikrotikInterfacesService,
)
from app.services.adapter_mikrotik_ip import GatewayMikrotikIPService
from app.services.adapter_mikrotik_ppp import GatewayMikrotikPppService
from app.services.adapter_mikrotik_queues import (
    GatewayMikrotikQueuesService,
)
from app.services.adapter_mikrotik_routing import (
    GatewayMikrotikRoutingService,
)
from app.services.adapter_mikrotik_security import (
    GatewayMikrotikSecurityService,
)
from app.services.adapter_mikrotik_system import (
    GatewayMikrotikSystemService,
)
from app.services.adapter_mikrotik_vpn import GatewayMikrotikVpnService
from app.services.adapter_omada_bulk import GatewayBulkService
from app.services.adapter_omada_firewall import GatewayFirewallService
from app.services.adapter_omada_firmware import GatewayFirmwareService
from app.services.adapter_omada_hotspot import GatewayHotspotService
from app.services.adapter_omada_profiles import GatewayProfilesService
from app.services.adapter_omada_routing import GatewayRoutingService
from app.services.adapter_omada_switch_advanced import GatewaySwitchAdvancedService
from app.services.adapter_omada_system import GatewaySystemService
from app.services.adapter_omada_vpn import GatewayVPNService
from app.services.adapter_omada_wifi import GatewayWifiService
from app.services.adapter_opnsense_cron import GatewayOpnsenseCronService
from app.services.adapter_opnsense_dhcp import GatewayOpnsenseDhcpService
from app.services.adapter_opnsense_diagnostics import (
    GatewayOpnsenseDiagnosticsService,
)
from app.services.adapter_opnsense_dns import GatewayOpnsenseDnsService
from app.services.adapter_opnsense_firewall import (
    GatewayOpnsenseFirewallService,
)
from app.services.adapter_opnsense_ids import GatewayOpnsenseIdsService
from app.services.adapter_opnsense_interfaces import (
    GatewayOpnsenseInterfacesService,
)
from app.services.adapter_opnsense_nat import GatewayOpnsenseNatService
from app.services.adapter_opnsense_routing import (
    GatewayOpnsenseRoutingService,
)
from app.services.adapter_opnsense_services import (
    GatewayOpnsenseServicesService,
)
from app.services.adapter_opnsense_shaper import (
    GatewayOpnsenseShaperService,
)
from app.services.adapter_opnsense_system import (
    GatewayOpnsenseSystemService,
)
from app.services.adapter_opnsense_vpn import GatewayOpnsenseVpnService
from app.services.adapter_pfsense_dhcp import GatewayPfsenseDhcpService
from app.services.adapter_pfsense_diagnostics import (
    GatewayPfsenseDiagnosticsService,
)
from app.services.adapter_pfsense_dns import GatewayPfsenseDnsService
from app.services.adapter_pfsense_firewall import (
    GatewayPfsenseFirewallService,
)
from app.services.adapter_pfsense_interfaces import (
    GatewayPfsenseInterfacesService,
)
from app.services.adapter_pfsense_nat import GatewayPfsenseNatService
from app.services.adapter_pfsense_routing import (
    GatewayPfsenseRoutingService,
)
from app.services.adapter_pfsense_services import (
    GatewayPfsenseServicesService,
)
from app.services.adapter_pfsense_system import (
    GatewayPfsenseSystemService,
)
from app.services.adapter_pfsense_vpn import GatewayPfsenseVpnService
from app.services.adapter_proxmox_backup import (
    GatewayProxmoxBackupService,
)
from app.services.adapter_proxmox_ceph import GatewayProxmoxCephService
from app.services.adapter_proxmox_cluster import GatewayProxmoxClusterService
from app.services.adapter_proxmox_container import (
    GatewayProxmoxContainerService,
)
from app.services.adapter_proxmox_firewall import (
    GatewayProxmoxFirewallService,
)
from app.services.adapter_proxmox_ha import GatewayProxmoxHaService
from app.services.adapter_proxmox_node import GatewayProxmoxNodeService
from app.services.adapter_proxmox_replication import (
    GatewayProxmoxReplicationService,
)
from app.services.adapter_proxmox_sdn import GatewayProxmoxSdnService
from app.services.adapter_proxmox_snapshot import (
    GatewayProxmoxSnapshotService,
)
from app.services.adapter_proxmox_storage import (
    GatewayProxmoxStorageService,
)
from app.services.adapter_proxmox_vm import GatewayProxmoxVmService
from app.services.adapter_staging import AdapterStagingService

# Maps a change.feature prefix to the permission required to APPLY it.
# Apply is now feature-agnostic at the URL level, so we have to
# Device-rooting MikroTik features escalate to controller:write —
# RouterOS subfeatures where ``network:write`` is too low because
# they create admin users, manage CAs, manage AAA servers, overwrite
# the entire config, or pivot to SSRF.
#
# Two collections so the matching is precise:
# * ``_MIKROTIK_CONTROLLER_TIER_NAMESPACES`` — true namespace
#   prefixes (must match via ``startswith``); every sub-feature
#   under them is admin-tier.
# * ``_MIKROTIK_CONTROLLER_TIER_FEATURES`` — exact feature codes;
#   matched via set membership so a hypothetical future feature
#   like ``mikrotik.system.reboot_schedule`` does NOT silently
#   inherit. Each one has to be added explicitly.
_MIKROTIK_CONTROLLER_TIER_NAMESPACES = (
    "mikrotik.security.",  # users, certs, SNMP, RADIUS — admin-tier
)
_MIKROTIK_CONTROLLER_TIER_FEATURES = frozenset(
    {
        "mikrotik.system.reboot",
        "mikrotik.system.shutdown",
        "mikrotik.system.backup_load",
        "mikrotik.system.file_delete",
        "mikrotik.system.tool_fetch",  # SSRF pivot from the router
        "mikrotik.system.export_config",  # writes secrets to file system
        # additions matching the catastrophic list above.
        "mikrotik.system.firmware.install",
        "mikrotik.system.package.uninstall",
        "mikrotik.system.backup.restore",
    }
)

# UniFi destructive features that lift from ``network:write`` to
# ``controller:write``. Same rationale as the MikroTik list — these
# can take a device offline, wipe historical state, or pivot to a
# more privileged operation. New entries land here as we add UniFi
# write features that root the device or destroy non-recoverable
# state.
_UNIFI_CONTROLLER_TIER_FEATURES = frozenset(
    {
        # ``forget_client`` is irreversible — drops the DHCP fingerprint,
        # alias, group membership; the client re-appears as brand-new
        # on its next association. Strictly more destructive than
        # block (which is a reversible policy bit).
        "unifi.clients.forget",
        # Device-level destructive operations on AP / switch / gateway —
        # a restart takes the device offline for ~60-90s; a disable
        # takes it offline indefinitely. Same tier as
        # ``mikrotik.system.reboot`` so the permission boundary
        # matches the catastrophic gate.
        "unifi.devices.restart",
        "unifi.devices.disable",
    }
)

# Catastrophic features require ``site_admin`` minimum role IN
# ADDITION to the permission gate. These are the platform's most
# destructive ops — VM destroy, node shutdown, snapshot rollback,
# backup restore, RouterOS reboot/config-overwrite, firewall halt,
# firmware upgrade. The role gate is checked at apply AND stage
# time alongside the permission gate so a misconfigured RBAC tenant
# where ``hypervisor:write`` is granted to operators still can't
# trigger these without an admin role.
_CATASTROPHIC_FEATURE_PREFIXES = (
    # Proxmox catastrophics — vm/container/snapshot/backup/storage
    # destruction, node power management, certificate upload (replaces
    # the cluster's TLS), remote-migrate-with-delete-source.
    "proxmox.vm.destroy",
    "proxmox.vm.guest_agent_exec",
    "proxmox.vm.guest_agent_file_write",
    "proxmox.vm.remote_migrate",  # default delete_source=True
    "proxmox.vm.cloudinit",  # writes credentials to VM
    "proxmox.container.destroy",
    "proxmox.container.remote_migrate",  # default delete_source=True
    "proxmox.snapshot.rollback",
    "proxmox.snapshot.delete",
    "proxmox.backup.restore",
    "proxmox.backup.prune",
    "proxmox.storage.delete_volume",
    "proxmox.node.shutdown",
    "proxmox.node.reboot",
    "proxmox.node.certificate_upload",
    "proxmox.node.certificate_delete",
    # OPNsense catastrophics — reboot/halt the firewall, firmware
    # update (can brick the box), config-restore (overwrites
    # everything), backup-restore (same).
    "opnsense.system.reboot",
    "opnsense.system.halt",
    "opnsense.system.firmware_update",
    "opnsense.system.firmware_upgrade",
    "opnsense.system.backup_restore",
    "opnsense.system.config_restore",
    # pfSense catastrophics — same shape as OPNsense.
    "pfsense.system.reboot",
    "pfsense.system.halt",
    "pfsense.system.firmware_update",
    "pfsense.system.firmware_upgrade",
    "pfsense.system.backup_restore",
    "pfsense.system.config_restore",
    # MikroTik catastrophics — RouterOS reboot/shutdown, backup load
    # (overwrites entire config), tool_fetch (SSRF pivot from the
    # router), export_config (writes secrets to RouterOS file system).
    "mikrotik.system.reboot",
    "mikrotik.system.shutdown",
    "mikrotik.system.backup_load",
    "mikrotik.system.tool_fetch",
    "mikrotik.system.export_config",
    # additions: firmware install reboots the router, package
    # uninstall takes effect on next reboot but can disable critical
    # services (routing, firewall), backup restore overwrites the
    # entire running config including admin accounts.
    "mikrotik.system.firmware.install",
    "mikrotik.system.package.uninstall",
    "mikrotik.system.backup.restore",
    # UniFi catastrophics — device-level destructive ops. Restart
    # cycles the AP/switch for 60-90s (effectively a single-device
    # outage); disable leaves it offline until manually re-enabled;
    # upgrade flashes firmware + reboots (can brick the device and is
    # not cleanly revertible). All require typed-APPLY + site_admin to
    # prevent accidental clicks. KEEP IN SYNC with the UniFi preflight's
    # ``_CATASTROPHIC_FEATURES`` (adapter_unifi_preflight.py).
    "unifi.devices.restart",
    "unifi.devices.disable",
    "unifi.devices.upgrade",
    # Omada catastrophics — firmware upgrade (can brick a fleet),
    # batch device factory_reset/reboot, system admin user changes,
    # SSL cert replacement, full backup restore.
    "firmware.upgrade",
    "bulk.device.factory_reset",
    "bulk.device.reboot",
    # ``forget`` unadopts the device and drops its controller-side config —
    # irreversible without re-adopting and re-provisioning. Same blast
    # radius as factory_reset/reboot, so it must require typed-APPLY +
    # site_admin rather than being applyable with bare network:write.
    "bulk.device.forget",
    "system.admin",
    "system.backup.restore",
    "system.ssl_cert",
    "system.controller_factory_reset",
)


# re-check the privilege boundary that the original stage endpoint
# enforced — otherwise a vpn:write user could apply a system.admin
# change a different operator staged.
def _required_apply_permission(feature: str) -> str:
    if feature.startswith(("system.", "monitoring.")):
        return "controller:write"
    # Overlay (daemon) VPN writes are vpn-tier — same grant as the Omada ``vpn.``
    # family and the /vpn REST endpoints. WITHOUT this the ``overlay.`` prefix would
    # fall through to the ``network:write`` default below — a privilege UNDER-gate.
    if feature.startswith("overlay.") or feature.startswith("vpn."):
        return "vpn:write"
    # All ``opnsense.*`` sub-features are firewall-tier — OPNsense
    # IS the firewall, every sub-feature ultimately edits the same
    # underlying config. Same permission tier as Omada's
    # ``firewall.*``.
    if (
        feature.startswith("firewall.")
        or feature.startswith("opnsense.")
        or feature.startswith("pfsense.")
        # OpenWrt IS the firewall on a single-box gateway; every OpenWrt
        # stage gate (firewall + dhcp/dns) requires ``firewall:write``
        # (adapter_openwrt_firewall.py / adapter_openwrt_dhcp.py). Apply
        # must match the stage tier — otherwise a bare ``network:write``
        # operator could apply an OpenWrt change someone with
        # ``firewall:write`` staged.
        or feature.startswith("openwrt.")
    ):
        return "firewall:write"
    # Firmware upgrade is staged behind the admin-only ``firmware:upgrade``
    # permission (adapter_omada_firmware.py). Apply must demand the same
    # tier so the deliberately admin-only firmware boundary isn't defeated
    # by the default ``network:write`` fallback (the catastrophic role gate
    # is additional, not a substitute for the permission tier).
    if feature.startswith("firmware."):
        return "firmware:upgrade"
    # All ``proxmox.*`` sub-features are hypervisor-tier — Proxmox
    # IS the hypervisor module. VM destroy / node shutdown / snapshot
    # rollback are the most catastrophic writes in the platform; we
    # apply the strictest tier the hypervisor module exposes.
    if feature.startswith("proxmox."):
        return "hypervisor:write"
    # FreePBX / VoIP config writes — the VoIP module's manage tier. Matches
    # the permission the direct voip/api.py write endpoints already enforce.
    if feature.startswith("pbx."):
        return "voip.manage_phones"
    # MikroTik is a network device — every sub-feature inherits the
    # network operator tier (lower than firewall:write because
    # MikroTik isn't strictly a firewall) EXCEPT for device-rooting
    # subfeatures (security.*, system.reboot/shutdown/backup_load/
    # file_delete) which escalate to controller:write.
    if feature.startswith("mikrotik."):
        if (
            feature.startswith(_MIKROTIK_CONTROLLER_TIER_NAMESPACES)
            or feature in _MIKROTIK_CONTROLLER_TIER_FEATURES
        ):
            return "controller:write"
        return "network:write"
    # UniFi is a network controller — same tiering rationale as
    # MikroTik. Each sub-feature is ``network:write`` by default; the
    # destructive subset (device restart, factory reset, client forget
    # which clears historical state) lifts up to ``controller:write``.
    if feature.startswith("unifi."):
        # Firmware flash is the platform's admin-only ``firmware:upgrade`` tier
        # everywhere else (Omada ``firmware.upgrade`` above, adapter_omada_firmware
        # stage gate, dependencies.py reserves it from org_admin). A UniFi upgrade
        # flashes + reboots the device — same blast radius — so it must NOT fall
        # through to the ``network:write`` default. (The catastrophic role gate
        # below also adds ``site_admin`` on top.)
        if feature == "unifi.devices.upgrade":
            return "firmware:upgrade"
        if feature in _UNIFI_CONTROLLER_TIER_FEATURES:
            return "controller:write"
        return "network:write"
    # All other feature domains (firmware, profile, wifi, hotspot,
    # routing, switch, bulk, site.*) are site-operator scope.
    return "network:write"


def _required_apply_role(feature: str) -> str | None:
    """Minimum role tier required to apply / discard a change.

    Returns ``site_admin`` for catastrophic features (VM destroy,
    node shutdown, RouterOS reboot, backup restore — anything that
    can wipe data or take a controller offline) and ``None`` for
    every other feature. ``None`` means the permission gate alone
    governs access; non-None enforces ``has_min_role(role)`` on top
    of the permission check.
    """
    if feature.startswith(_CATASTROPHIC_FEATURE_PREFIXES):
        return "site_admin"
    return None


def _service_for_feature(feature: str, session: AsyncSession) -> GatewayServiceBase:
    """Pick the right gateway service based on the change's feature key.

    The apply path is feature-agnostic but the build_applier logic is
    not — every feature module knows how to dispatch its own
    (feature, operation) pairs to client methods.
    """
    # Appliance-local overlay (daemon) VPN writes — NO controller, NO adapter
    # client. Checked first; ``overlay.`` does not collide with the Omada ``vpn.``
    # gateway family below.
    if feature.startswith("overlay."):
        from app.services.adapter_overlay_vpn import OverlayVPNApplierService

        return OverlayVPNApplierService(session)
    if feature.startswith("vpn."):
        return GatewayVPNService(session)
    # OPNsense per-domain services — checked BEFORE the generic
    # ``firewall.`` prefix so the right vendor service handles it.
    # Order doesn't matter among the OPNsense branches because
    # each one is a distinct ``opnsense.<domain>.`` prefix.
    if feature.startswith("opnsense.firewall."):
        return GatewayOpnsenseFirewallService(session)
    if feature.startswith("opnsense.nat."):
        return GatewayOpnsenseNatService(session)
    if feature.startswith("opnsense.dhcp."):
        return GatewayOpnsenseDhcpService(session)
    if feature.startswith("opnsense.dns."):
        return GatewayOpnsenseDnsService(session)
    if feature.startswith("opnsense.vpn."):
        return GatewayOpnsenseVpnService(session)
    if feature.startswith("opnsense.routing."):
        return GatewayOpnsenseRoutingService(session)
    if feature.startswith("opnsense.services."):
        return GatewayOpnsenseServicesService(session)
    if feature.startswith("opnsense.system."):
        return GatewayOpnsenseSystemService(session)
    if feature.startswith("opnsense.diagnostics."):
        return GatewayOpnsenseDiagnosticsService(session)
    if feature.startswith("opnsense.ids."):
        return GatewayOpnsenseIdsService(session)
    if feature.startswith("opnsense.shaper."):
        return GatewayOpnsenseShaperService(session)
    if feature.startswith("opnsense.interfaces."):
        return GatewayOpnsenseInterfacesService(session)
    if feature.startswith("opnsense.cron."):
        return GatewayOpnsenseCronService(session)
    # Proxmox per-domain services. ``proxmox.*`` is hypervisor-tier.
    # Every prefix maps to its dedicated service so the applier can
    # dispatch by feature without overlap.
    if feature.startswith("proxmox.vm."):
        return GatewayProxmoxVmService(session)
    if feature.startswith("proxmox.container."):
        return GatewayProxmoxContainerService(session)
    if feature.startswith("proxmox.snapshot."):
        return GatewayProxmoxSnapshotService(session)
    if feature.startswith("proxmox.storage."):
        return GatewayProxmoxStorageService(session)
    if feature.startswith("proxmox.cluster."):
        return GatewayProxmoxClusterService(session)
    if feature.startswith("proxmox.ha."):
        return GatewayProxmoxHaService(session)
    if feature.startswith("proxmox.replication."):
        return GatewayProxmoxReplicationService(session)
    if feature.startswith("proxmox.sdn."):
        return GatewayProxmoxSdnService(session)
    if feature.startswith("proxmox.ceph."):
        return GatewayProxmoxCephService(session)
    if feature.startswith("proxmox.backup."):
        return GatewayProxmoxBackupService(session)
    if feature.startswith("proxmox.firewall."):
        return GatewayProxmoxFirewallService(session)
    if feature.startswith("proxmox.node."):
        return GatewayProxmoxNodeService(session)
    # Storage (TrueNAS) staged writes — Fabric storage.store_blob lands here.
    # Both the bare ``storage.`` domain (the Fabric op feature) and an explicit
    # ``truenas.storage.`` vendor-scoped prefix route to the same service.
    if feature.startswith("storage.") or feature.startswith("truenas.storage."):
        from app.services.adapter_truenas_storage import GatewayTrueNASStorageService

        return GatewayTrueNASStorageService(session)
    # pfSense per-domain services. ``pfsense.*`` is firewall-tier
    # (sibling to OPNsense). Each prefix maps to its dedicated
    # service.
    if feature.startswith("pfsense.firewall."):
        return GatewayPfsenseFirewallService(session)
    if feature.startswith("pfsense.nat."):
        return GatewayPfsenseNatService(session)
    if feature.startswith("pfsense.dhcp."):
        return GatewayPfsenseDhcpService(session)
    if feature.startswith("pfsense.dns."):
        return GatewayPfsenseDnsService(session)
    if feature.startswith("pfsense.vpn."):
        return GatewayPfsenseVpnService(session)
    if feature.startswith("pfsense.routing."):
        return GatewayPfsenseRoutingService(session)
    if feature.startswith("pfsense.services."):
        return GatewayPfsenseServicesService(session)
    if feature.startswith("pfsense.system."):
        return GatewayPfsenseSystemService(session)
    if feature.startswith("pfsense.diagnostics."):
        return GatewayPfsenseDiagnosticsService(session)
    if feature.startswith("pfsense.interfaces."):
        return GatewayPfsenseInterfacesService(session)
    # OpenWrt per-domain services. ``openwrt.*`` shares the
    # firewall-tier alongside pfSense / OPNsense — the gateway is also
    # the firewall on a single-box deployment. Each prefix maps to its
    # dedicated service so the apply dispatch is vendor-uniform.
    if feature.startswith("openwrt.firewall."):
        from app.services.adapter_openwrt_firewall import (
            GatewayOpenWrtFirewallService,
        )

        return GatewayOpenWrtFirewallService(session)
    if feature.startswith(("openwrt.dhcp.", "openwrt.dns.")):
        from app.services.adapter_openwrt_dhcp import (
            GatewayOpenWrtDhcpService,
        )

        return GatewayOpenWrtDhcpService(session)
    # MikroTik per-domain services. ``mikrotik.*`` is network-tier.
    if feature.startswith("mikrotik.firewall."):
        return GatewayMikrotikFirewallService(session)
    if feature.startswith("mikrotik.interfaces."):
        return GatewayMikrotikInterfacesService(session)
    if feature.startswith("mikrotik.ip."):
        return GatewayMikrotikIPService(session)
    if feature.startswith("mikrotik.dhcp."):
        return GatewayMikrotikDHCPService(session)
    if feature.startswith("mikrotik.dns."):
        return GatewayMikrotikDNSService(session)
    if feature.startswith("mikrotik.vpn."):
        return GatewayMikrotikVpnService(session)
    if feature.startswith("mikrotik.routing."):
        return GatewayMikrotikRoutingService(session)
    if feature.startswith("mikrotik.queues."):
        return GatewayMikrotikQueuesService(session)
    if feature.startswith("mikrotik.ppp."):
        return GatewayMikrotikPppService(session)
    if feature.startswith("mikrotik.hotspot."):
        return GatewayMikrotikHotspotService(session)
    if feature.startswith("mikrotik.capsman."):
        return GatewayMikrotikCapsmanService(session)
    if feature.startswith("mikrotik.security."):
        return GatewayMikrotikSecurityService(session)
    if feature.startswith("mikrotik.system."):
        return GatewayMikrotikSystemService(session)
    # UniFi per-domain services. Mirrors MikroTik's per-domain split —
    # each prefix maps to a dedicated service so the apply dispatch is
    # vendor-uniform. New domains land here as they ship.
    if feature.startswith("unifi.clients."):
        from app.services.adapter_unifi_clients import (
            GatewayUniFiClientsService,
        )

        return GatewayUniFiClientsService(session)
    if feature.startswith("unifi.devices."):
        from app.services.adapter_unifi_devices import (
            GatewayUniFiDevicesService,
        )

        return GatewayUniFiDevicesService(session)
    if feature.startswith("unifi.wlans."):
        from app.services.adapter_unifi_wlans import (
            GatewayUniFiWlansService,
        )

        return GatewayUniFiWlansService(session)
    if feature.startswith("unifi.networks."):
        from app.services.adapter_unifi_networks import (
            GatewayUniFiNetworksService,
        )

        return GatewayUniFiNetworksService(session)
    if feature.startswith("unifi.firewall."):
        from app.services.adapter_unifi_firewall import GatewayUniFiFirewallService

        return GatewayUniFiFirewallService(session)
    if feature.startswith("unifi.traffic."):
        from app.services.adapter_unifi_traffic import GatewayUniFiTrafficService

        return GatewayUniFiTrafficService(session)
    if feature.startswith("unifi.dns."):
        from app.services.adapter_unifi_dns import GatewayUniFiDnsService

        return GatewayUniFiDnsService(session)
    if feature.startswith("unifi.routing."):
        from app.services.adapter_unifi_routing import GatewayUniFiRoutingService

        return GatewayUniFiRoutingService(session)
    if feature.startswith("unifi.vpn."):
        from app.services.adapter_unifi_vpn import GatewayUniFiVpnService

        return GatewayUniFiVpnService(session)
    if feature.startswith("unifi.portprofiles."):
        from app.services.adapter_unifi_port_profiles import GatewayUniFiPortProfilesService

        return GatewayUniFiPortProfilesService(session)
    if feature.startswith("unifi.wlangroups."):
        from app.services.adapter_unifi_wlan_groups import GatewayUniFiWlanGroupsService

        return GatewayUniFiWlanGroupsService(session)
    if feature.startswith("unifi.radios."):
        from app.services.adapter_unifi_radios import GatewayUniFiRadiosService

        return GatewayUniFiRadiosService(session)
    if feature.startswith("unifi.switch."):
        from app.services.adapter_unifi_switch import GatewayUniFiSwitchService

        return GatewayUniFiSwitchService(session)
    if feature.startswith("unifi.radius."):
        from app.services.adapter_unifi_radius import GatewayUniFiRadiusService

        return GatewayUniFiRadiusService(session)
    if feature.startswith("unifi.hotspot."):
        from app.services.adapter_unifi_hotspot import GatewayUniFiHotspotService

        return GatewayUniFiHotspotService(session)
    if feature.startswith("firewall."):
        return GatewayFirewallService(session)
    if feature.startswith("firmware."):
        return GatewayFirmwareService(session)
    if feature.startswith("profile."):
        return GatewayProfilesService(session)
    if feature.startswith("wifi."):
        return GatewayWifiService(session)
    if feature.startswith("hotspot."):
        return GatewayHotspotService(session)
    if feature.startswith("routing."):
        return GatewayRoutingService(session)
    if feature.startswith("switch."):
        return GatewaySwitchAdvancedService(session)
    if feature.startswith(("system.", "monitoring.")) or feature in (
        "site.time",
        "site.led_schedule",
        "site.reboot_schedule",
        "site.notifications",
    ):
        return GatewaySystemService(session)
    if feature.startswith("bulk.") or feature.startswith("site."):
        # Catches site.clone, site.template.*, bulk.*
        return GatewayBulkService(session)
    # FreePBX / VoIP per-domain staged-write services. ``pbx.*`` features
    # bridge a ``voip.pbx`` row into the staging pipeline via
    # FreePBXServiceBase (resolves the PBX, auto-pairs the controllers FK).
    if feature.startswith("pbx.extension."):
        from app.services.adapter_freepbx_extensions import (
            FreePBXExtensionsService,
        )

        return FreePBXExtensionsService(session)
    if feature.startswith("pbx.trunk."):
        from app.services.adapter_freepbx_trunks import FreePBXTrunksService

        return FreePBXTrunksService(session)
    if feature.startswith("pbx.ring_group."):
        from app.services.adapter_freepbx_ring_groups import (
            FreePBXRingGroupsService,
        )

        return FreePBXRingGroupsService(session)
    if feature.startswith("pbx.queue."):
        from app.services.adapter_freepbx_queues import FreePBXQueuesService

        return FreePBXQueuesService(session)
    if feature.startswith("pbx.ivr."):
        from app.services.adapter_freepbx_ivr import FreePBXIVRService

        return FreePBXIVRService(session)
    if feature.startswith("pbx.inbound_route."):
        from app.services.adapter_freepbx_inbound_routes import (
            FreePBXInboundRoutesService,
        )

        return FreePBXInboundRoutesService(session)
    # If the feature carries a known vendor prefix but no sub-domain
    # branch matched above (e.g. ``proxmox.bogus.thing`` or
    # ``mikrotik.unknown_domain.x``), refuse rather than silently
    # falling through to GatewayVPNService — that fallback was a
    # latent dispatch hazard where a typo'd feature would dispatch
    # to the wrong vendor's applier.
    from fastapi import HTTPException

    if feature.startswith(
        ("proxmox.", "opnsense.", "pfsense.", "mikrotik.", "openwrt.", "truenas.", "pbx.", "unifi.")
    ):
        raise HTTPException(
            400,
            detail=(
                f"feature {feature!r} has a known vendor prefix but no "
                "registered sub-domain service"
            ),
        )
    # Fallback to VPN service for genuinely-untyped features (no
    # vendor prefix). Preserves historical behaviour for any custom
    # feature codes a deployment may have added.
    return GatewayVPNService(session)


router = APIRouter(prefix="/gateway-vpn", tags=["gateway-vpn"])


# ──────────────────────────────────────────────────────────────────────
# Live read paths (protocol-agnostic)
# ──────────────────────────────────────────────────────────────────────


@router.get(
    "/{controller_id}/sites/{site_id}/{protocol}/config",
    response_model=GatewayVPNDetailResponse,
    summary="Read live VPN protocol-level config from the controller",
)
async def get_protocol_config(
    controller_id: UUID,
    site_id: UUID,
    protocol: str,
    user: Annotated[CurrentUser, Depends(require_permissions("vpn:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    # Per-user site grant: site_id is an explicit path param,
    # so enforce the caller's grant before the live read. No-op for
    # super_admin / org_admin / grant-less users.
    assert_can_access_site(user, site_id, detail="site not found")
    svc = GatewayVPNService(session)
    return await svc.get_protocol_config(protocol, controller_id, user.organization_id, site_id)


@router.get(
    "/{controller_id}/sites/{site_id}/{protocol}/status",
    response_model=VPNStatusResponse,
    summary="Read live VPN protocol status (active tunnels, peers, traffic)",
)
async def get_protocol_status(
    controller_id: UUID,
    site_id: UUID,
    protocol: str,
    user: Annotated[CurrentUser, Depends(require_permissions("vpn:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    assert_can_access_site(user, site_id, detail="site not found")
    svc = GatewayVPNService(session)
    payload = await svc.get_protocol_status(protocol, controller_id, user.organization_id, site_id)
    return {
        "protocol": protocol,
        "controller_id": payload["controller_id"],
        "site_id": payload["site_id"],
        "items": payload["items"],
        "fetched_at": payload["fetched_at"],
    }


@router.get(
    "/{controller_id}/sites/{site_id}/{protocol}/users",
    response_model=GatewayVPNListResponse,
    summary="Read live user list for protocols that have one (openvpn|l2tp|pptp|sslvpn)",
)
async def list_protocol_users(
    controller_id: UUID,
    site_id: UUID,
    protocol: str,
    user: Annotated[CurrentUser, Depends(require_permissions("vpn:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    assert_can_access_site(user, site_id, detail="site not found")
    svc = GatewayVPNService(session)
    return await svc.list_protocol_users(protocol, controller_id, user.organization_id, site_id)


@router.get(
    "/{controller_id}/sites/{site_id}/ipsec/policies",
    response_model=GatewayVPNListResponse,
    summary="Read live list of IPsec site-to-site / client policies",
)
async def list_ipsec_policies(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("vpn:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    assert_can_access_site(user, site_id, detail="site not found")
    svc = GatewayVPNService(session)
    return await svc.list_ipsec_policies(controller_id, user.organization_id, site_id)


@router.get(
    "/{controller_id}/sites/{site_id}/wireguard/peers",
    response_model=GatewayVPNListResponse,
    summary="Read live WireGuard peer list",
)
async def list_wireguard_peers(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("vpn:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    assert_can_access_site(user, site_id, detail="site not found")
    svc = GatewayVPNService(session)
    return await svc.list_wireguard_peers(controller_id, user.organization_id, site_id)


@router.get(
    "/{controller_id}/sites/{site_id}/gre/tunnels",
    response_model=GatewayVPNListResponse,
    summary="Read live GRE tunnel list",
)
async def list_gre_tunnels(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("vpn:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    assert_can_access_site(user, site_id, detail="site not found")
    svc = GatewayVPNService(session)
    return await svc.list_gre_tunnels(controller_id, user.organization_id, site_id)


# ──────────────────────────────────────────────────────────────────────
# Write paths — STAGE only (no live writes by default)
# ──────────────────────────────────────────────────────────────────────


@router.post(
    "/{controller_id}/sites/{site_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Stage a VPN write. Does NOT touch the controller.",
)
async def stage_vpn_change(
    controller_id: UUID,
    site_id: UUID,
    feature: str,  # e.g. "vpn.ipsec.policy", "vpn.wireguard.peer"
    operation: Annotated[
        str,
        Query(description="create | update | delete"),
    ],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("vpn:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Record a write intent. The change shows up in ``GET /changes`` and
    only touches the live controller if an operator later force-applies it
    AND ``OMADA_READ_ONLY=false`` in the environment."""
    if not feature.startswith("vpn."):
        from fastapi import HTTPException

        raise HTTPException(400, detail="vpn endpoint only accepts vpn.* features")
    assert_can_access_site(user, site_id, detail="site not found")
    svc = GatewayVPNService(session)
    change = await svc.stage_change(
        feature=feature,
        operation=operation,
        payload=body.payload,
        controller_id=controller_id,
        organization_id=user.organization_id,
        site_id=site_id,
        target_id=body.target_id,
        notes=body.notes,
        actor_id=user.id,
    )
    return PendingChangeResponse.from_model(change)


@router.get(
    "/{controller_id}/sites/{site_id}/changes",
    response_model=list[PendingChangeResponse],
    summary="List pending VPN changes for a site",
)
async def list_pending_changes(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("vpn:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    feature_prefix: Annotated[
        str,
        Query(description="e.g. 'vpn.ipsec' to filter to IPsec changes only"),
    ] = "vpn.",
    status_filter: Annotated[
        str,
        Query(alias="status", description="pending|applied|discarded|failed"),
    ] = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> Any:
    assert_can_access_site(user, site_id, detail="site not found")
    staging = AdapterStagingService(session)
    # Push the site_id filter into SQL — previously we fetched up to
    # ``limit`` rows across the whole controller and then filtered in
    # Python, which silently dropped rows when the controller had
    # heavy traffic on other sites.
    changes = await staging.list_pending(
        organization_id=user.organization_id,
        controller_id=controller_id,
        site_id=site_id,
        feature_prefix=feature_prefix,
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]


@router.get(
    "/changes/by-gateway/{gateway_id}",
    response_model=list[PendingChangeResponse],
    summary="Single-query fetch of all staged changes for a gateway",
)
async def list_pending_changes_by_gateway(
    gateway_id: UUID,
    vendor: Annotated[
        str,
        Query(
            description=(
                "Vendor short name: mikrotik | pfsense | opnsense | "
                "openwrt | unifi | proxmox. Resolves to its top-level feature "
                "prefix so one SQL query returns every domain at once."
            ),
        ),
    ],
    # Read gate: staged-change metadata (notes, feature, payload summary) is
    # sensitive, so this consolidated cross-vendor list must hold a read
    # permission like its per-domain siblings — previously it accepted any
    # authenticated org user (bare get_current_user), letting them enumerate
    # every gateway's staged changes. ``network:read`` is the baseline read
    # tier every operator-and-above role holds (directly or via ``network:*``).
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    status_filter: Annotated[
        str,
        Query(alias="status", description="pending|applied|discarded|failed|all"),
    ] = "pending",
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
) -> Any:
    """
    Drawer-fanout consolidation.

    The pending-changes drawer used to fire one HTTP request per
    vendor domain (MikroTik = 13 GETs on every drawer open). Each
    request did its own DB round-trip + auth check + middleware
    stack. This endpoint replaces all of them with a single
    feature-prefix query — ``feature LIKE '{vendor}.%'`` — that
    returns the same data in one shot.

    The frontend can opt into this fast path while the per-domain
    endpoints remain available as a fallback (helpful for vendor
    drilldown views that DO want only one domain).
    """
    # Vendor → prefix is just ``{vendor}.``; every vendor service
    # namespaces features under that root. Mismatch → 400 so a typo
    # doesn't silently return zero rows.
    # Vendor → top-level feature prefix. Almost always ``{vendor}.``; the
    # exception is FreePBX, whose staged features namespace under ``pbx.``
    # (the VoIP module owns more than just FreePBX), so map it explicitly.
    _VENDOR_PREFIX = {
        "mikrotik": "mikrotik.",
        "pfsense": "pfsense.",
        "opnsense": "opnsense.",
        "openwrt": "openwrt.",
        "unifi": "unifi.",
        "freepbx": "pbx.",
        # Proxmox stages under ``proxmox.*`` across a dozen per-domain
        # routers. It was missing here, which meant the Pending Changes
        # drawer could not list a Proxmox change at all -- so the staged
        # path the hypervisor module's own catastrophic guard tells
        # operators to use ("stage it via the staged adapter endpoints")
        # had no way to review or apply anything once staged.
        "proxmox": "proxmox.",
    }
    vendor_lower = vendor.lower()
    if vendor_lower not in _VENDOR_PREFIX:
        from fastapi import HTTPException

        raise HTTPException(
            400,
            detail=(f"unknown vendor {vendor!r}; expected one of {sorted(_VENDOR_PREFIX)}"),
        )
    # Per-user site grant: resolve the gateway/controller first so a
    # site-limited caller can't list a sibling-site gateway's staged changes by
    # supplying its id. The resolver asserts the caller's site grant (via the
    # request-scoped chokepoint) and 404s on miss. No-op for super/org admins.
    from app.services.adapter_base import GatewayServiceBase

    await GatewayServiceBase(session)._resolve_controller_or_gateway(
        gateway_id, user.organization_id
    )
    staging = AdapterStagingService(session)
    changes = await staging.list_pending(
        organization_id=user.organization_id,
        controller_id=gateway_id,
        feature_prefix=_VENDOR_PREFIX[vendor_lower],
        status_filter=None if status_filter == "all" else status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]


@router.post(
    "/changes/{change_id}/discard",
    response_model=PendingChangeResponse,
    summary="Discard a pending change without applying it",
)
async def discard_change(
    change_id: UUID,
    user: Annotated[CurrentUser, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    force: Annotated[
        bool,
        Query(description="Allow discarding a row stuck in 'applying'"),
    ] = False,
) -> Any:
    """Mark a pending change as discarded.

    Permission is dynamic: discarding a ``system.*`` change requires
    ``controller:write``, a ``vpn.*`` change requires ``vpn:write``,
    etc. — so a low-privilege operator can't sabotage another team's
    queued change. Tenant check happens BEFORE any state mutation
    (inside the staging service).
    """
    from fastapi import HTTPException

    staging = AdapterStagingService(session)

    # Look up the row first (read-only) so we can do the permission
    # check before any mutation.
    change = await staging.get(change_id)
    if change is None or change.organization_id != user.organization_id:
        raise HTTPException(404, detail="pending change not found")
    # Per-user site grant: a staged change carries the
    # site it targets; a site-limited operator may only discard changes
    # for sites they're granted. No-op for super_admin / org_admin.
    assert_can_access_site(user, change.site_id, detail="pending change not found")
    if change.site_id is None and change.controller_id is not None:
        # Controller-level change (site_id is None, so the assert above no-ops):
        # resolve the change's controller to assert the caller's grant for the
        # controller's site — blocks discarding/applying a sibling controller's
        # queued change by id. No-op for super_admin / org_admin.
        from app.services.adapter_base import GatewayServiceBase

        await GatewayServiceBase(session)._resolve_controller_or_gateway(
            change.controller_id, user.organization_id
        )
    # Controllerless overlay.* writes carry BOTH site_id and controller_id NULL, so
    # neither the site-grant assert above nor the controller-grant fallback fires —
    # they're appliance-global daemon actions (Tailscale/NetBird up/down) with no
    # real site. A SITE-LIMITED operator must not apply/discard one outside an
    # org-admin context, else the site grant that bounds them is silently bypassed
    # (audit Finding 1). 404 (not 403) to avoid an existence oracle. No-op for
    # super_admin / org_admin (is_site_limited is False for them).
    if change.site_id is None and change.controller_id is None and user.is_site_limited:
        raise HTTPException(404, detail="pending change not found")

    required = _required_apply_permission(change.feature)
    if not user.has_permission(required):
        raise HTTPException(
            403,
            detail=(f"feature {change.feature!r} requires {required} permission"),
        )
    required_role = _required_apply_role(change.feature)
    if required_role is not None and not user.has_min_role(required_role):
        raise HTTPException(
            403,
            detail=(
                f"feature {change.feature!r} is catastrophic and requires "
                f"minimum role {required_role}"
            ),
        )

    discarded = await staging.discard(
        change_id,
        organization_id=user.organization_id,
        actor_id=user.id,
        force=force,
    )
    return PendingChangeResponse.from_model(discarded)


@router.post(
    "/changes/{change_id}/apply",
    response_model=PendingChangeResponse,
    summary=("Apply a pending change — gated by OMADA_READ_ONLY + force flag"),
)
async def apply_change(
    change_id: UUID,
    body: ApplyPendingChangeRequest,
    user: Annotated[CurrentUser, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Push a staged change to the live controller.

    Refused unless ``OMADA_READ_ONLY=false`` in the environment AND the
    request body carries ``force=true``. Both must be set; the dual-gate
    is intentional so a stray Apply click cannot mutate prod.

    Permission check is dynamic: this single endpoint applies changes
    from every feature domain (vpn, firewall, system, network, ...),
    so a static ``require_permissions("vpn:write")`` would let a
    site-operator with only ``vpn:write`` apply a controller-level
    ``system.admin`` change another operator staged. We look up the
    permission required for ``change.feature`` after fetching the
    change.
    """
    from fastapi import HTTPException

    staging = AdapterStagingService(session)

    change = await staging.get(change_id)
    if change is None or change.organization_id != user.organization_id:
        raise HTTPException(404, detail="pending change not found")
    # Per-user site grant: a staged change carries the
    # site it targets; a site-limited operator may only apply changes
    # for sites they're granted. No-op for super_admin / org_admin.
    assert_can_access_site(user, change.site_id, detail="pending change not found")
    if change.site_id is None and change.controller_id is not None:
        # Controller-level change (site_id is None, so the assert above no-ops):
        # resolve the change's controller to assert the caller's grant for the
        # controller's site — blocks discarding/applying a sibling controller's
        # queued change by id. No-op for super_admin / org_admin.
        from app.services.adapter_base import GatewayServiceBase

        await GatewayServiceBase(session)._resolve_controller_or_gateway(
            change.controller_id, user.organization_id
        )
    # Controllerless overlay.* writes carry BOTH site_id and controller_id NULL, so
    # neither the site-grant assert above nor the controller-grant fallback fires —
    # they're appliance-global daemon actions (Tailscale/NetBird up/down) with no
    # real site. A SITE-LIMITED operator must not apply/discard one outside an
    # org-admin context, else the site grant that bounds them is silently bypassed
    # (audit Finding 1). 404 (not 403) to avoid an existence oracle. No-op for
    # super_admin / org_admin (is_site_limited is False for them).
    if change.site_id is None and change.controller_id is None and user.is_site_limited:
        raise HTTPException(404, detail="pending change not found")

    required = _required_apply_permission(change.feature)
    if not user.has_permission(required):
        raise HTTPException(
            403,
            detail=(f"feature {change.feature!r} requires {required} permission"),
        )
    required_role = _required_apply_role(change.feature)
    if required_role is not None and not user.has_min_role(required_role):
        raise HTTPException(
            403,
            detail=(
                f"feature {change.feature!r} is catastrophic and requires "
                f"minimum role {required_role}"
            ),
        )

    # Dispatch to the right feature service based on the change's
    # feature prefix so non-VPN changes apply correctly.
    svc = _service_for_feature(change.feature, session)
    applier = svc.build_applier(change)
    applied = await staging.apply_change(
        change_id,
        force=body.force,
        confirmed=body.confirmed,
        applier=applier,
        actor_id=user.id,
    )

    # A FreePBX config change just mutated the live PBX, so its synced view
    # is now stale. Refresh just that entity from the device so the operator
    # sees the change immediately (no manual re-sync). Best-effort: a refresh
    # failure must never fail an apply that already succeeded.
    if applied.status == "applied" and change.feature.startswith("pbx."):
        import logging

        _log = logging.getLogger(__name__)
        from app.modules.voip.service import VoIPService

        voip = VoIPService(session, organization_id=change.organization_id)
        try:
            await voip.refresh_after_apply(change.controller_id, change.feature)
        except Exception:
            _log.warning(
                "post-apply synced-cache refresh failed for %s",
                change.feature,
                exc_info=True,
            )
        # Opt-in auto-reload: the GraphQL write lands in the FreePBX DB but is
        # inert until a doreload. When the operator opts in, activate it now —
        # doreload (fwconsole reload) is FreePBX's standard config-apply and is
        # call-preserving, but we still skip it when calls are active as extra
        # caution and leave the "Apply Config" banner up. Best-effort: never
        # fails the apply that already succeeded.
        if body.auto_reload:
            try:
                active = await voip.get_pbx_active_calls(change.controller_id)
                if len(active) == 0:
                    await voip.reload_pbx_config(change.controller_id)
                    _log.info("auto-reload applied for %s", change.feature)
                else:
                    _log.info(
                        "auto-reload skipped for %s: %d active call(s); banner left up",
                        change.feature,
                        len(active),
                    )
            except Exception:
                _log.warning(
                    "auto-reload skipped for %s (reload/verify failed); banner left up",
                    change.feature,
                    exc_info=True,
                )

    return PendingChangeResponse.from_model(applied)
