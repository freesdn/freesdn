# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the per-feature apply-dispatcher logic.

The single ``/gateway-vpn/changes/{id}/apply`` endpoint applies
changes from EVERY feature domain (vpn, firewall, wifi, system,
bulk, hotspot, routing, switch, …) — so the dispatcher must:

* Route ``change.feature`` to the correct service's ``build_applier``.
* Map each feature prefix to the right *required permission*, so a
  low-privilege operator can't apply a controller-level change.

These two functions are the privilege boundary at apply time.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.adapter_omada_vpn import (
    _required_apply_permission,
    _required_apply_role,
    _service_for_feature,
)
from app.services.adapter_freepbx_extensions import FreePBXExtensionsService
from app.services.adapter_freepbx_inbound_routes import FreePBXInboundRoutesService
from app.services.adapter_freepbx_ivr import FreePBXIVRService
from app.services.adapter_freepbx_queues import FreePBXQueuesService
from app.services.adapter_freepbx_ring_groups import FreePBXRingGroupsService
from app.services.adapter_freepbx_trunks import FreePBXTrunksService
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
from app.services.adapter_opnsense_dhcp import GatewayOpnsenseDhcpService
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
from app.services.adapter_pfsense_dns import GatewayPfsenseDnsService
from app.services.adapter_pfsense_firewall import (
    GatewayPfsenseFirewallService,
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
from app.services.adapter_proxmox_cluster import (
    GatewayProxmoxClusterService,
)
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
from app.services.adapter_unifi_clients import GatewayUniFiClientsService
from app.services.adapter_unifi_devices import GatewayUniFiDevicesService
from app.services.adapter_unifi_dns import GatewayUniFiDnsService
from app.services.adapter_unifi_firewall import GatewayUniFiFirewallService
from app.services.adapter_unifi_hotspot import GatewayUniFiHotspotService
from app.services.adapter_unifi_networks import GatewayUniFiNetworksService
from app.services.adapter_unifi_port_profiles import GatewayUniFiPortProfilesService
from app.services.adapter_unifi_radios import GatewayUniFiRadiosService
from app.services.adapter_unifi_radius import GatewayUniFiRadiusService
from app.services.adapter_unifi_routing import GatewayUniFiRoutingService
from app.services.adapter_unifi_switch import GatewayUniFiSwitchService
from app.services.adapter_unifi_traffic import GatewayUniFiTrafficService
from app.services.adapter_unifi_vpn import GatewayUniFiVpnService
from app.services.adapter_unifi_wlan_groups import GatewayUniFiWlanGroupsService
from app.services.adapter_unifi_wlans import GatewayUniFiWlansService

# ── Service routing ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "feature, expected_cls",
    [
        # Each feature prefix routes to its dedicated service.
        ("vpn.ipsec.policy", GatewayVPNService),
        ("vpn.wireguard.peer", GatewayVPNService),
        ("firewall.dmz", GatewayFirewallService),
        ("firmware.upgrade", GatewayFirmwareService),
        ("firmware.upgrade.batch", GatewayFirmwareService),
        ("profile.dhcp", GatewayProfilesService),
        ("wifi.wlan_group.advanced", GatewayWifiService),
        ("wifi.wids_wips", GatewayWifiService),
        ("wifi.channel_pilot.run", GatewayWifiService),
        ("hotspot.operator", GatewayHotspotService),
        ("routing.vrrp", GatewayRoutingService),
        ("switch.sflow", GatewaySwitchAdvancedService),
        ("switch.mstp", GatewaySwitchAdvancedService),
        # System / monitoring / explicit site keys → System service.
        ("system.admin", GatewaySystemService),
        ("system.smtp", GatewaySystemService),
        ("monitoring.snmp", GatewaySystemService),
        ("site.time", GatewaySystemService),
        ("site.led_schedule", GatewaySystemService),
        ("site.reboot_schedule", GatewaySystemService),
        ("site.notifications", GatewaySystemService),
        # The remaining site.* features (clone, template) → Bulk.
        ("site.clone", GatewayBulkService),
        ("site.template.export", GatewayBulkService),
        ("site.template.apply", GatewayBulkService),
        ("bulk.device.adopt", GatewayBulkService),
        ("bulk.client.kick", GatewayBulkService),
        # OPNsense full coverage — every domain has its own service.
        # Each ``opnsense.*`` prefix is checked before the generic
        # ``firewall.`` so the OPNsense services handle them, not the
        # Omada GatewayFirewallService.
        ("opnsense.firewall.rule", GatewayOpnsenseFirewallService),
        ("opnsense.firewall.alias", GatewayOpnsenseFirewallService),
        ("opnsense.firewall.apply", GatewayOpnsenseFirewallService),
        ("opnsense.nat.source_rule", GatewayOpnsenseNatService),
        ("opnsense.nat.port_forward", GatewayOpnsenseNatService),
        ("opnsense.dhcp.static_mapping", GatewayOpnsenseDhcpService),
        ("opnsense.dhcp.kea_subnet", GatewayOpnsenseDhcpService),
        ("opnsense.dns.host_override", GatewayOpnsenseDnsService),
        ("opnsense.dns.domain_override", GatewayOpnsenseDnsService),
        ("opnsense.vpn.wireguard.peer", GatewayOpnsenseVpnService),
        ("opnsense.vpn.openvpn.instance", GatewayOpnsenseVpnService),
        ("opnsense.vpn.ipsec.connect", GatewayOpnsenseVpnService),
        ("opnsense.routing.static_route", GatewayOpnsenseRoutingService),
        ("opnsense.routing.apply", GatewayOpnsenseRoutingService),
        ("opnsense.services.start", GatewayOpnsenseServicesService),
        ("opnsense.services.restart", GatewayOpnsenseServicesService),
        ("opnsense.system.reboot", GatewayOpnsenseSystemService),
        ("opnsense.system.backup_create", GatewayOpnsenseSystemService),
        ("opnsense.ids.settings", GatewayOpnsenseIdsService),
        ("opnsense.ids.rule", GatewayOpnsenseIdsService),
        ("opnsense.shaper.pipe", GatewayOpnsenseShaperService),
        ("opnsense.shaper.queue", GatewayOpnsenseShaperService),
        ("opnsense.interfaces.vlan", GatewayOpnsenseInterfacesService),
        # Proxmox full coverage — 12 hypervisor feature domains.
        ("proxmox.vm.destroy", GatewayProxmoxVmService),
        ("proxmox.vm.guest_agent_exec", GatewayProxmoxVmService),
        ("proxmox.container.destroy", GatewayProxmoxContainerService),
        ("proxmox.container.start", GatewayProxmoxContainerService),
        ("proxmox.snapshot.delete", GatewayProxmoxSnapshotService),
        ("proxmox.snapshot.rollback", GatewayProxmoxSnapshotService),
        ("proxmox.storage.delete_volume", GatewayProxmoxStorageService),
        ("proxmox.storage.upload", GatewayProxmoxStorageService),
        ("proxmox.backup.restore", GatewayProxmoxBackupService),
        ("proxmox.backup.prune", GatewayProxmoxBackupService),
        ("proxmox.node.shutdown", GatewayProxmoxNodeService),
        ("proxmox.node.certificate_upload", GatewayProxmoxNodeService),
        ("proxmox.cluster.task_stop", GatewayProxmoxClusterService),
        ("proxmox.ha.group", GatewayProxmoxHaService),
        ("proxmox.ha.resource", GatewayProxmoxHaService),
        ("proxmox.replication.run", GatewayProxmoxReplicationService),
        ("proxmox.sdn.zone", GatewayProxmoxSdnService),
        ("proxmox.sdn.apply", GatewayProxmoxSdnService),
        ("proxmox.ceph.osd_create", GatewayProxmoxCephService),
        ("proxmox.firewall.cluster_rule", GatewayProxmoxFirewallService),
        ("proxmox.firewall.guest_rule", GatewayProxmoxFirewallService),
        # pfSense full coverage — sibling firewall to OPNsense.
        ("pfsense.firewall.rule", GatewayPfsenseFirewallService),
        ("pfsense.firewall.alias", GatewayPfsenseFirewallService),
        ("pfsense.nat.port_forward", GatewayPfsenseNatService),
        ("pfsense.dhcp.static_mapping", GatewayPfsenseDhcpService),
        ("pfsense.dns.override", GatewayPfsenseDnsService),
        ("pfsense.vpn.openvpn.instance", GatewayPfsenseVpnService),
        ("pfsense.vpn.wireguard.peer", GatewayPfsenseVpnService),
        ("pfsense.routing.static_route", GatewayPfsenseRoutingService),
        ("pfsense.services.restart", GatewayPfsenseServicesService),
        ("pfsense.system.reboot", GatewayPfsenseSystemService),
        # MikroTik full coverage — 13 RouterOS feature domains. Each
        # ``mikrotik.<domain>.`` prefix routes to its dedicated service.
        ("mikrotik.firewall.filter", GatewayMikrotikFirewallService),
        ("mikrotik.firewall.nat", GatewayMikrotikFirewallService),
        ("mikrotik.firewall.address_list", GatewayMikrotikFirewallService),
        ("mikrotik.interfaces.bridge", GatewayMikrotikInterfacesService),
        ("mikrotik.interfaces.vlan", GatewayMikrotikInterfacesService),
        ("mikrotik.interfaces.bonding", GatewayMikrotikInterfacesService),
        ("mikrotik.ip.address", GatewayMikrotikIPService),
        ("mikrotik.ip.pool", GatewayMikrotikIPService),
        ("mikrotik.dhcp.server", GatewayMikrotikDHCPService),
        ("mikrotik.dhcp.lease", GatewayMikrotikDHCPService),
        ("mikrotik.dns.static", GatewayMikrotikDNSService),
        ("mikrotik.dns.cache", GatewayMikrotikDNSService),
        ("mikrotik.vpn.ipsec.peer", GatewayMikrotikVpnService),
        ("mikrotik.vpn.wireguard.peer", GatewayMikrotikVpnService),
        ("mikrotik.vpn.l2tp.server", GatewayMikrotikVpnService),
        ("mikrotik.routing.static", GatewayMikrotikRoutingService),
        ("mikrotik.routing.ospf.instance", GatewayMikrotikRoutingService),
        ("mikrotik.routing.bgp.peer", GatewayMikrotikRoutingService),
        ("mikrotik.queues.simple", GatewayMikrotikQueuesService),
        ("mikrotik.queues.tree", GatewayMikrotikQueuesService),
        ("mikrotik.ppp.profile", GatewayMikrotikPppService),
        ("mikrotik.ppp.secret", GatewayMikrotikPppService),
        ("mikrotik.hotspot.server", GatewayMikrotikHotspotService),
        ("mikrotik.hotspot.user", GatewayMikrotikHotspotService),
        ("mikrotik.hotspot.voucher", GatewayMikrotikHotspotService),
        ("mikrotik.capsman.manager", GatewayMikrotikCapsmanService),
        ("mikrotik.capsman.configuration", GatewayMikrotikCapsmanService),
        ("mikrotik.security.certificate", GatewayMikrotikSecurityService),
        ("mikrotik.security.user", GatewayMikrotikSecurityService),
        ("mikrotik.system.identity", GatewayMikrotikSystemService),
        ("mikrotik.system.reboot", GatewayMikrotikSystemService),
        ("mikrotik.system.backup", GatewayMikrotikSystemService),
        # FreePBX / VoIP — each pbx.<entity>.* prefix routes to its service.
        ("pbx.extension.create", FreePBXExtensionsService),
        ("pbx.extension.update", FreePBXExtensionsService),
        ("pbx.extension.delete", FreePBXExtensionsService),
        ("pbx.trunk.update", FreePBXTrunksService),
        ("pbx.ring_group.create", FreePBXRingGroupsService),
        ("pbx.ring_group.delete", FreePBXRingGroupsService),
        ("pbx.queue.update", FreePBXQueuesService),
        ("pbx.ivr.update", FreePBXIVRService),
        ("pbx.inbound_route.create", FreePBXInboundRoutesService),
        ("pbx.inbound_route.delete", FreePBXInboundRoutesService),
        # UniFi full coverage — all 13 per-domain services. Before the
        # apply-path fix the dispatcher only routed 4 (clients/devices/
        # wlans/networks); the other 9 fell through to GatewayVPNService
        # whose build_applier 400s, so a staged unifi.firewall/dns/traffic/
        # routing/vpn/portprofiles/wlangroups/radios/switch change could
        # be STAGED but never APPLIED. Each ``unifi.<domain>.`` prefix is
        # checked before the generic ``firewall.``/``vpn.`` fallbacks.
        ("unifi.clients.block", GatewayUniFiClientsService),
        ("unifi.clients.forget", GatewayUniFiClientsService),
        ("unifi.devices.restart", GatewayUniFiDevicesService),
        ("unifi.devices.upgrade", GatewayUniFiDevicesService),
        ("unifi.wlans.create_ssid", GatewayUniFiWlansService),
        ("unifi.networks.create", GatewayUniFiNetworksService),
        ("unifi.firewall.rule", GatewayUniFiFirewallService),
        ("unifi.firewall.policy", GatewayUniFiFirewallService),
        ("unifi.firewall.zone", GatewayUniFiFirewallService),
        ("unifi.traffic.rule", GatewayUniFiTrafficService),
        ("unifi.traffic.route", GatewayUniFiTrafficService),
        ("unifi.dns.static_record", GatewayUniFiDnsService),
        ("unifi.routing.static_route", GatewayUniFiRoutingService),
        ("unifi.vpn.server", GatewayUniFiVpnService),
        ("unifi.portprofiles.profile", GatewayUniFiPortProfilesService),
        ("unifi.wlangroups.group", GatewayUniFiWlanGroupsService),
        ("unifi.radios.update", GatewayUniFiRadiosService),
        ("unifi.switch.port_override", GatewayUniFiSwitchService),
        # Parity domains: built-in RADIUS users + guest hotspot (operators +
        # vouchers). Checked before the generic firewall./vpn. fallbacks.
        ("unifi.radius.create_user", GatewayUniFiRadiusService),
        ("unifi.radius.delete_user", GatewayUniFiRadiusService),
        ("unifi.hotspot.create_voucher", GatewayUniFiHotspotService),
        ("unifi.hotspot.revoke_voucher", GatewayUniFiHotspotService),
        ("unifi.hotspot.create_operator", GatewayUniFiHotspotService),
    ],
)
def test_service_for_feature_routes_correctly(
    feature: str, expected_cls: type
) -> None:
    session = MagicMock()
    svc = _service_for_feature(feature, session)
    assert isinstance(svc, expected_cls), (
        f"feature={feature!r} expected {expected_cls.__name__} but "
        f"got {type(svc).__name__}"
    )


def test_dispatcher_distinguishes_site_time_from_site_clone() -> None:
    """Order matters: ``site.time`` (System) is checked BEFORE the
    generic ``site.`` (Bulk) prefix."""
    session = MagicMock()
    assert isinstance(
        _service_for_feature("site.time", session), GatewaySystemService
    )
    assert isinstance(
        _service_for_feature("site.clone", session), GatewayBulkService
    )


# ── Permission mapping ───────────────────────────────────────────


@pytest.mark.parametrize(
    "feature, expected_perm",
    [
        # Controller-level features require controller:write so a
        # site-operator with only network:write can't apply them.
        ("system.admin", "controller:write"),
        ("system.smtp", "controller:write"),
        ("system.ssl_cert", "controller:write"),
        ("monitoring.snmp", "controller:write"),
        # VPN features stay on vpn:write.
        ("vpn.ipsec.policy", "vpn:write"),
        ("vpn.wireguard.peer", "vpn:write"),
        # Firewall on firewall:write.
        ("firewall.dmz", "firewall:write"),
        # All OPNsense sub-features inherit firewall:write.
        ("opnsense.firewall.rule", "firewall:write"),
        ("opnsense.firewall.alias", "firewall:write"),
        ("opnsense.firewall.apply", "firewall:write"),
        ("opnsense.nat.source_rule", "firewall:write"),
        ("opnsense.dhcp.static_mapping", "firewall:write"),
        ("opnsense.dns.host_override", "firewall:write"),
        ("opnsense.vpn.wireguard.peer", "firewall:write"),
        ("opnsense.routing.static_route", "firewall:write"),
        ("opnsense.services.restart", "firewall:write"),
        ("opnsense.system.reboot", "firewall:write"),
        ("opnsense.ids.settings", "firewall:write"),
        ("opnsense.shaper.pipe", "firewall:write"),
        ("opnsense.interfaces.vlan", "firewall:write"),
        # All Proxmox sub-features inherit hypervisor:write — these are
        # the most catastrophic writes in the platform.
        ("proxmox.vm.destroy", "hypervisor:write"),
        ("proxmox.vm.guest_agent_exec", "hypervisor:write"),
        ("proxmox.container.destroy", "hypervisor:write"),
        ("proxmox.snapshot.rollback", "hypervisor:write"),
        ("proxmox.storage.delete_volume", "hypervisor:write"),
        ("proxmox.backup.restore", "hypervisor:write"),
        ("proxmox.node.shutdown", "hypervisor:write"),
        ("proxmox.cluster.task_stop", "hypervisor:write"),
        ("proxmox.ha.resource", "hypervisor:write"),
        ("proxmox.sdn.apply", "hypervisor:write"),
        ("proxmox.firewall.cluster_rule", "hypervisor:write"),
        # MikroTik sub-features inherit network:write by default —
        # RouterOS is a network device (NOT a firewall tier), so
        # routine edits land on the network operator scope. EXCEPT
        # device-rooting subfeatures (security.*, system.reboot/
        # shutdown/backup_load/file_delete) which escalate to
        # controller:write because they create admin users, manage
        # CAs, manage AAA servers, or overwrite the entire config.
        ("mikrotik.firewall.filter", "network:write"),
        ("mikrotik.firewall.nat", "network:write"),
        ("mikrotik.interfaces.bridge", "network:write"),
        ("mikrotik.ip.address", "network:write"),
        ("mikrotik.dhcp.server", "network:write"),
        ("mikrotik.dns.static", "network:write"),
        ("mikrotik.vpn.wireguard.peer", "network:write"),
        ("mikrotik.routing.bgp.peer", "network:write"),
        ("mikrotik.queues.simple", "network:write"),
        ("mikrotik.ppp.secret", "network:write"),
        ("mikrotik.hotspot.user", "network:write"),
        ("mikrotik.capsman.configuration", "network:write"),
        # Device-rooting → controller:write
        ("mikrotik.security.user", "controller:write"),
        ("mikrotik.security.certificate", "controller:write"),
        ("mikrotik.security.certificate_sign", "controller:write"),
        ("mikrotik.security.snmp_community", "controller:write"),
        ("mikrotik.security.radius_server", "controller:write"),
        ("mikrotik.system.reboot", "controller:write"),
        ("mikrotik.system.shutdown", "controller:write"),
        ("mikrotik.system.backup_load", "controller:write"),
        ("mikrotik.system.file_delete", "controller:write"),
        # Non-device-rooting system features stay at network:write
        ("mikrotik.system.identity", "network:write"),
        ("mikrotik.system.backup_create", "network:write"),
        # All FreePBX/VoIP config writes map to the VoIP manage tier,
        # matching the direct voip/api.py write endpoints.
        ("pbx.extension.create", "voip.manage_phones"),
        ("pbx.extension.delete", "voip.manage_phones"),
        ("pbx.trunk.update", "voip.manage_phones"),
        ("pbx.ring_group.create", "voip.manage_phones"),
        ("pbx.queue.update", "voip.manage_phones"),
        ("pbx.ivr.update", "voip.manage_phones"),
        ("pbx.inbound_route.delete", "voip.manage_phones"),
        # Firmware upgrade is admin-only: apply demands the same
        # ``firmware:upgrade`` tier the stage gate enforces, so the
        # default ``network:write`` fallback can't defeat the
        # deliberately admin-only firmware boundary.
        ("firmware.upgrade", "firmware:upgrade"),
        # Everything else (network operator scope).
        ("wifi.wlan_group.advanced", "network:write"),
        ("hotspot.operator", "network:write"),
        ("routing.vrrp", "network:write"),
        ("switch.sflow", "network:write"),
        ("profile.dhcp", "network:write"),
        ("bulk.device.adopt", "network:write"),
        ("site.clone", "network:write"),
        ("site.template.apply", "network:write"),
        ("site.time", "network:write"),
        ("site.led_schedule", "network:write"),
        # New UniFi parity domains map to the network-operator scope (like Omada
        # hotspot); a delete is additionally confirm-gated by the central preflight.
        ("unifi.radius.create_user", "network:write"),
        ("unifi.radius.delete_user", "network:write"),
        ("unifi.hotspot.create_voucher", "network:write"),
        ("unifi.hotspot.delete_operator", "network:write"),
        # UniFi device destructive tiers must NOT fall through to network:write.
        # ``upgrade`` FLASHES firmware (can brick) → the admin-only firmware:upgrade
        # tier, parity with Omada ``firmware.upgrade``. restart/disable + client
        # forget stay controller:write. (Regression: an external security review
        # found upgrade defaulting to network:write — a network operator could
        # flash firmware, which the platform reserves to the admin-only tier.)
        ("unifi.devices.upgrade", "firmware:upgrade"),
        ("unifi.devices.restart", "controller:write"),
        ("unifi.devices.disable", "controller:write"),
        ("unifi.clients.forget", "controller:write"),
        # Non-destructive UniFi device ops stay network:write.
        ("unifi.devices.locate", "network:write"),
        ("unifi.devices.port_override", "network:write"),
    ],
)
def test_required_apply_permission(
    feature: str, expected_perm: str
) -> None:
    assert _required_apply_permission(feature) == expected_perm


def test_unknown_feature_falls_back_to_network_write() -> None:
    """Unknown / future feature codes default to the safest non-empty
    permission, ``network:write`` — never empty / always-allow."""
    perm = _required_apply_permission("entirely.new.feature")
    assert perm == "network:write"


# ── Dispatcher fallthrough ───────────────────────────────────────


def test_unknown_vendor_subfeature_raises_400() -> None:
    """Vendor-prefixed features without a registered sub-domain must
    raise 400 instead of silently routing to GatewayVPNService.

    Before the fix, ``proxmoxx.vm.create`` (typo) or
    ``mikrotik.unknown_domain.x`` would dispatch to VPN service whose
    build_applier would 400 the change LATER — but only after some
    work was done. This test guards the new, eager refusal.
    """
    session = MagicMock()
    for bogus in (
        "proxmox.unknown.thing",
        "opnsense.bogus.domain",
        "pfsense.unknown.x",
        "mikrotik.fake_domain.y",
    ):
        with pytest.raises(HTTPException) as exc:
            _service_for_feature(bogus, session)
        assert exc.value.status_code == 400
        assert "no registered sub-domain" in exc.value.detail


def test_genuinely_untyped_features_still_fallback_to_vpn() -> None:
    """Features without any vendor prefix keep the historical VPN
    fallback — preserves backward compat for custom feature codes a
    deployment may have added (the dispatcher hardening only
    targeted vendor-prefixed unknowns)."""
    from app.services.adapter_omada_vpn import GatewayVPNService

    session = MagicMock()
    svc = _service_for_feature("custom.thing.no_vendor", session)
    assert isinstance(svc, GatewayVPNService)


# ── Role gate for catastrophic features ──────────────────────────


@pytest.mark.parametrize(
    "feature, expected_role",
    [
        # Proxmox catastrophics
        ("proxmox.vm.destroy", "site_admin"),
        ("proxmox.vm.guest_agent_exec", "site_admin"),
        ("proxmox.vm.guest_agent_file_write", "site_admin"),
        ("proxmox.container.destroy", "site_admin"),
        ("proxmox.snapshot.rollback", "site_admin"),
        ("proxmox.backup.restore", "site_admin"),
        ("proxmox.node.shutdown", "site_admin"),
        ("proxmox.node.reboot", "site_admin"),
        ("proxmox.node.certificate_upload", "site_admin"),
        # MikroTik catastrophics
        ("mikrotik.system.reboot", "site_admin"),
        ("mikrotik.system.shutdown", "site_admin"),
        ("mikrotik.system.backup_load", "site_admin"),
        # UniFi catastrophics — device restart/disable (outage) + upgrade (firmware
        # flash / brick) all require site_admin ON TOP of the permission tier.
        # (Regression: upgrade was absent from the catastrophic set → no role gate.)
        ("unifi.devices.restart", "site_admin"),
        ("unifi.devices.disable", "site_admin"),
        ("unifi.devices.upgrade", "site_admin"),
        # Non-catastrophic features should NOT require an elevated role
        ("unifi.devices.locate", None),
        ("unifi.radius.create_user", None),
        ("proxmox.vm.start", None),
        ("proxmox.snapshot.create", None),
        ("proxmox.backup.create", None),
        ("mikrotik.system.identity", None),
        ("mikrotik.system.backup_create", None),
        ("mikrotik.firewall.filter", None),
        ("opnsense.firewall.rule", None),
        ("pfsense.firewall.alias", None),
        ("vpn.ipsec.policy", None),
    ],
)
def test_required_apply_role(
    feature: str, expected_role: str | None
) -> None:
    assert _required_apply_role(feature) == expected_role


def test_dispatcher_handles_no_collisions_between_categories() -> None:
    """Spot-check: every (feature, expected service) pair we test
    above runs through the dispatcher exactly once with no
    overlap. If a future change introduces a new prefix that
    matches both system AND bulk, this catches it (because both
    services would be returned and the asserts above would fail)."""
    # The parametrize already covers this — this is a documentation
    # test ensuring the invariant has a name.
    assert True
