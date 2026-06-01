# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - API v1 Router
===========================

Main API router that includes all endpoint modules.
"""

from fastapi import APIRouter, Depends

from app.api.v1.endpoints import (
    access_points,
    actions,
    adapter_freepbx_extensions,
    adapter_freepbx_inbound_routes,
    adapter_freepbx_ivr,
    adapter_freepbx_queues,
    adapter_freepbx_ring_groups,
    adapter_freepbx_trunks,
    adapter_mikrotik_capsman,
    adapter_mikrotik_dhcp,
    adapter_mikrotik_dns,
    adapter_mikrotik_firewall,
    adapter_mikrotik_hotspot,
    adapter_mikrotik_interfaces,
    adapter_mikrotik_ip,
    adapter_mikrotik_ppp,
    adapter_mikrotik_queues,
    adapter_mikrotik_routing,
    adapter_mikrotik_security,
    adapter_mikrotik_system,
    adapter_mikrotik_vpn,
    adapter_omada_bulk,
    adapter_omada_diagnostics,
    adapter_omada_firewall,
    adapter_omada_firmware,
    adapter_omada_hotspot,
    adapter_omada_insights,
    adapter_omada_open_api,
    adapter_omada_profiles,
    adapter_omada_raw,
    adapter_omada_routing,
    adapter_omada_switch_advanced,
    adapter_omada_system,
    adapter_omada_vpn,
    adapter_omada_wifi,
    adapter_openwrt,
    adapter_openwrt_dhcp,
    adapter_openwrt_firewall,
    adapter_opnsense_cron,
    adapter_opnsense_dhcp,
    adapter_opnsense_diagnostics,
    adapter_opnsense_dns,
    adapter_opnsense_firewall,
    adapter_opnsense_ids,
    adapter_opnsense_interfaces,
    adapter_opnsense_nat,
    adapter_opnsense_routing,
    adapter_opnsense_services,
    adapter_opnsense_shaper,
    adapter_opnsense_system,
    adapter_opnsense_vpn,
    adapter_pfsense_dhcp,
    adapter_pfsense_diagnostics,
    adapter_pfsense_dns,
    adapter_pfsense_firewall,
    adapter_pfsense_interfaces,
    adapter_pfsense_nat,
    adapter_pfsense_routing,
    adapter_pfsense_services,
    adapter_pfsense_system,
    adapter_pfsense_vpn,
    adapter_proxmox_backup,
    adapter_proxmox_ceph,
    adapter_proxmox_cluster,
    adapter_proxmox_container,
    adapter_proxmox_firewall,
    adapter_proxmox_ha,
    adapter_proxmox_node,
    adapter_proxmox_replication,
    adapter_proxmox_sdn,
    adapter_proxmox_snapshot,
    adapter_proxmox_storage,
    adapter_proxmox_vm,
    adapter_unifi_clients,
    adapter_unifi_devices,
    adapter_unifi_dns,
    adapter_unifi_firewall,
    adapter_unifi_hotspot,
    adapter_unifi_networks,
    adapter_unifi_port_profiles,
    adapter_unifi_radios,
    adapter_unifi_radius,
    adapter_unifi_routing,
    adapter_unifi_switch,
    adapter_unifi_traffic,
    adapter_unifi_vpn,
    adapter_unifi_wlan_groups,
    adapter_unifi_wlans,
    adapters,
    agent_detail,
    agent_downloads,
    agent_release_upload,
    agent_schedules,
    agents,
    alert_rules,
    analytics,
    api_keys,
    audit,
    auth,
    automation,
    backups,
    capabilities,
    config_versions,
    controllers,
    correlation,
    credentials,
    dashboard,
    data,
    devices,
    discovery,
    dpi,
    enterprise,
    events,
    fabric,
    firmware,
    health,
    integrations,
    logs,
    marketplace,
    network,
    notifications,
    oauth2,
    organizations,
    plugins,
    poe,
    radius,
    roaming,
    roles,
    security,
    sites,
    sla,
    sla_reports,
    sso,
    switches,
    system,
    tasks,
    topology,
    unifi_clients,
    unifi_devices,
    unifi_firewall,
    unifi_networks,
    unifi_sites,
    unifi_system,
    unifi_wlans,
    users,
    vpn,
    vpn_orchestration,
    webhook_templates,
    webhooks,
    websocket,
    ztp,
)
from app.api.v1.endpoints.staging_guards import enforce_catastrophic_stage_role

api_router = APIRouter()

# WP-08: stage-time catastrophic-role gate, attached router-wide to EVERY
# adapter router whose stage endpoint can accept a catastrophic feature
# (Proxmox vm/container/node/…, Omada bulk/system/firmware, OPNsense/pfSense/
# MikroTik system, UniFi devices). It mirrors the apply-time role gate and is
# a NO-OP on read routes and on non-catastrophic features (``feature`` is None
# or maps to no required role), so it never blocks a legitimate operator — it
# only adds the site_admin minimum-role check at stage time for catastrophic
# features (factory_reset / reboot / firmware upgrade / backup-restore /
# config-restore / device forget / …), closing the queue-poison window where a
# low-tier write operator plants a catastrophic change for a higher-tier
# operator to later apply from the queue.
_catastrophic_stage_gate = [Depends(enforce_catastrophic_stage_role)]
# Back-compat alias: the Proxmox include_router calls below use this name.
_proxmox_stage_gate = _catastrophic_stage_gate

# Include endpoint routers
api_router.include_router(health.router, prefix="/health", tags=["Health"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(api_keys.router, prefix="/api-keys", tags=["API Keys"])
api_router.include_router(oauth2.router, prefix="/oauth2", tags=["OAuth2"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(organizations.router, prefix="/organizations", tags=["Organizations"])
api_router.include_router(roles.router, prefix="/roles", tags=["Roles"])
api_router.include_router(sites.router, prefix="/sites", tags=["Sites"])
api_router.include_router(controllers.router, prefix="/controllers", tags=["Controllers"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
api_router.include_router(devices.router, prefix="/devices", tags=["Devices"])
api_router.include_router(credentials.router, prefix="/credentials", tags=["Credentials"])
api_router.include_router(discovery.router, prefix="/discovery", tags=["Discovery"])
api_router.include_router(adapters.router, prefix="/adapters", tags=["Adapters"])
api_router.include_router(events.router, prefix="/events", tags=["Events"])
api_router.include_router(actions.router, prefix="/actions", tags=["Actions"])
api_router.include_router(backups.router, prefix="/backups", tags=["Backups"])
api_router.include_router(capabilities.router, prefix="/capabilities", tags=["Capabilities"])
api_router.include_router(notifications.router, prefix="/notifications", tags=["Notifications"])
api_router.include_router(audit.router, prefix="/audit", tags=["Audit"])
api_router.include_router(logs.router, prefix="/logs", tags=["Logs"])
api_router.include_router(automation.router, prefix="/automation", tags=["Automation"])
api_router.include_router(fabric.router, prefix="/fabric", tags=["Fabric"])
api_router.include_router(tasks.router, prefix="/tasks", tags=["Tasks"])
# Order matters: more-specific (literal-prefix) routers MUST register
# before the catch-all `/agents/{agent_id}` routes in agents.router so
# FastAPI's first-match-wins doesn't swallow `/agents/schedules`,
# `/agents/releases`, etc. as `agent_id="schedules"` etc.
api_router.include_router(agent_downloads.router, prefix="/agents", tags=["Agent Downloads"])
api_router.include_router(agent_release_upload.router, prefix="/agents", tags=["Agent Releases"])
api_router.include_router(agent_schedules.router, prefix="/agents", tags=["Agent Schedules"])
api_router.include_router(agents.router, prefix="/agents", tags=["Agents"])
api_router.include_router(agent_detail.router, prefix="/agents", tags=["Agent Detail"])
api_router.include_router(analytics.router, prefix="/analytics", tags=["Analytics"])
api_router.include_router(vpn.router, prefix="/vpn", tags=["VPN"])
api_router.include_router(adapter_omada_vpn.router, tags=["Gateway VPN"])
api_router.include_router(
    adapter_omada_firmware.router,
    tags=["Gateway Firmware"],
    dependencies=_catastrophic_stage_gate,
)
api_router.include_router(adapter_omada_profiles.router, tags=["Gateway Profiles"])
api_router.include_router(adapter_omada_firewall.router, tags=["Gateway Firewall"])
api_router.include_router(adapter_omada_wifi.router, tags=["Gateway WiFi"])
api_router.include_router(adapter_omada_insights.router, tags=["Gateway Insights"])
api_router.include_router(adapter_omada_open_api.router, tags=["Gateway OpenAPI"])
api_router.include_router(adapter_omada_raw.router, tags=["Gateway Raw"])
api_router.include_router(
    adapter_omada_bulk.router, tags=["Gateway Bulk"], dependencies=_catastrophic_stage_gate
)
api_router.include_router(
    adapter_omada_system.router, tags=["Gateway System"], dependencies=_catastrophic_stage_gate
)
api_router.include_router(adapter_omada_switch_advanced.router, tags=["Gateway Switch Advanced"])
api_router.include_router(adapter_omada_hotspot.router, tags=["Gateway Hotspot"])
api_router.include_router(adapter_omada_routing.router, tags=["Gateway Routing"])
api_router.include_router(adapter_omada_diagnostics.router, tags=["Gateway Diagnostics"])
api_router.include_router(adapter_opnsense_firewall.router, tags=["Gateway OPNsense Firewall"])
api_router.include_router(adapter_opnsense_nat.router, tags=["Gateway OPNsense NAT"])
api_router.include_router(adapter_opnsense_dhcp.router, tags=["Gateway OPNsense DHCP"])
api_router.include_router(adapter_opnsense_dns.router, tags=["Gateway OPNsense DNS"])
api_router.include_router(adapter_opnsense_vpn.router, tags=["Gateway OPNsense VPN"])
api_router.include_router(adapter_opnsense_routing.router, tags=["Gateway OPNsense Routing"])
api_router.include_router(adapter_opnsense_services.router, tags=["Gateway OPNsense Services"])
api_router.include_router(adapter_opnsense_ids.router, tags=["Gateway OPNsense IDS/IPS"])
api_router.include_router(adapter_opnsense_shaper.router, tags=["Gateway OPNsense Shaper"])
api_router.include_router(
    adapter_opnsense_system.router,
    tags=["Gateway OPNsense System"],
    dependencies=_catastrophic_stage_gate,
)
api_router.include_router(
    adapter_opnsense_diagnostics.router,
    tags=["Gateway OPNsense Diagnostics"],
)
api_router.include_router(
    adapter_opnsense_interfaces.router,
    tags=["Gateway OPNsense Interfaces"],
)
api_router.include_router(adapter_opnsense_cron.router, tags=["Gateway OPNsense Cron"])
# WP-08: gate ALL Proxmox stage endpoints with the stage-time catastrophic-role
# check (mirrors the apply-time gate; no-op on the read routes). Closes the
# queue-poison window where a low-tier hypervisor:write operator plants a
# catastrophic change (vm.destroy / node shutdown / storage wipe / cert upload)
# FreePBX / VoIP staged-write endpoints. Each route enforces
# ``voip.manage_phones`` (write) / ``voip.view`` (read); apply rides the
# shared /gateway-vpn apply endpoint under the ADAPTER_READ_ONLY+force gate.
api_router.include_router(adapter_freepbx_extensions.router, tags=["Gateway FreePBX Extensions"])
api_router.include_router(adapter_freepbx_trunks.router, tags=["Gateway FreePBX Trunks"])
api_router.include_router(adapter_freepbx_ring_groups.router, tags=["Gateway FreePBX Ring Groups"])
api_router.include_router(adapter_freepbx_queues.router, tags=["Gateway FreePBX Queues"])
api_router.include_router(adapter_freepbx_ivr.router, tags=["Gateway FreePBX IVR"])
api_router.include_router(
    adapter_freepbx_inbound_routes.router, tags=["Gateway FreePBX Inbound Routes"]
)

# for a site_admin to later apply.
api_router.include_router(
    adapter_proxmox_vm.router, tags=["Gateway Proxmox VM"], dependencies=_proxmox_stage_gate
)
api_router.include_router(
    adapter_proxmox_container.router,
    tags=["Gateway Proxmox Container"],
    dependencies=_proxmox_stage_gate,
)
api_router.include_router(
    adapter_proxmox_snapshot.router,
    tags=["Gateway Proxmox Snapshot"],
    dependencies=_proxmox_stage_gate,
)
api_router.include_router(
    adapter_proxmox_storage.router,
    tags=["Gateway Proxmox Storage"],
    dependencies=_proxmox_stage_gate,
)
api_router.include_router(
    adapter_proxmox_backup.router, tags=["Gateway Proxmox Backup"], dependencies=_proxmox_stage_gate
)
api_router.include_router(
    adapter_proxmox_cluster.router,
    tags=["Gateway Proxmox Cluster"],
    dependencies=_proxmox_stage_gate,
)
api_router.include_router(
    adapter_proxmox_ha.router, tags=["Gateway Proxmox HA"], dependencies=_proxmox_stage_gate
)
api_router.include_router(
    adapter_proxmox_node.router, tags=["Gateway Proxmox Node"], dependencies=_proxmox_stage_gate
)
api_router.include_router(
    adapter_proxmox_replication.router,
    tags=["Gateway Proxmox Replication"],
    dependencies=_proxmox_stage_gate,
)
api_router.include_router(
    adapter_proxmox_sdn.router, tags=["Gateway Proxmox SDN"], dependencies=_proxmox_stage_gate
)
api_router.include_router(
    adapter_proxmox_ceph.router, tags=["Gateway Proxmox Ceph"], dependencies=_proxmox_stage_gate
)
api_router.include_router(
    adapter_proxmox_firewall.router,
    tags=["Gateway Proxmox Firewall"],
    dependencies=_proxmox_stage_gate,
)
api_router.include_router(adapter_pfsense_firewall.router, tags=["Gateway pfSense Firewall"])
api_router.include_router(adapter_pfsense_nat.router, tags=["Gateway pfSense NAT"])
api_router.include_router(adapter_pfsense_dhcp.router, tags=["Gateway pfSense DHCP"])
api_router.include_router(adapter_pfsense_dns.router, tags=["Gateway pfSense DNS"])
api_router.include_router(adapter_pfsense_vpn.router, tags=["Gateway pfSense VPN"])
api_router.include_router(adapter_mikrotik_firewall.router, tags=["Gateway MikroTik Firewall"])
api_router.include_router(
    adapter_mikrotik_interfaces.router,
    tags=["Gateway MikroTik Interfaces"],
)
api_router.include_router(adapter_mikrotik_ip.router, tags=["Gateway MikroTik IP"])
api_router.include_router(adapter_mikrotik_dhcp.router, tags=["Gateway MikroTik DHCP"])
api_router.include_router(adapter_mikrotik_dns.router, tags=["Gateway MikroTik DNS"])
api_router.include_router(adapter_mikrotik_vpn.router, tags=["Gateway MikroTik VPN"])
api_router.include_router(adapter_mikrotik_routing.router, tags=["Gateway MikroTik Routing"])
api_router.include_router(adapter_mikrotik_queues.router, tags=["Gateway MikroTik QoS"])
api_router.include_router(adapter_mikrotik_ppp.router, tags=["Gateway MikroTik PPP/PPPoE"])
api_router.include_router(adapter_mikrotik_hotspot.router, tags=["Gateway MikroTik Hotspot"])
api_router.include_router(adapter_mikrotik_capsman.router, tags=["Gateway MikroTik CAPsMAN"])
api_router.include_router(adapter_mikrotik_security.router, tags=["Gateway MikroTik Security"])
api_router.include_router(
    adapter_openwrt.router,
    tags=["Gateway OpenWrt"],
)
api_router.include_router(
    adapter_openwrt_firewall.router,
    tags=["Gateway OpenWrt Firewall"],
)
api_router.include_router(
    adapter_openwrt_dhcp.router,
    tags=["Gateway OpenWrt DHCP"],
)
api_router.include_router(
    adapter_unifi_clients.router,
    tags=["Gateway UniFi Clients"],
)
api_router.include_router(
    adapter_unifi_devices.router,
    tags=["Gateway UniFi Devices"],
    dependencies=_catastrophic_stage_gate,
)
api_router.include_router(
    adapter_unifi_wlans.router,
    tags=["Gateway UniFi WLANs"],
)
api_router.include_router(
    adapter_unifi_networks.router,
    tags=["Gateway UniFi Networks"],
)
api_router.include_router(
    adapter_unifi_firewall.router,
    tags=["Gateway UniFi Firewall"],
)
api_router.include_router(
    adapter_unifi_traffic.router,
    tags=["Gateway UniFi Traffic"],
)
api_router.include_router(
    adapter_unifi_dns.router,
    tags=["Gateway UniFi DNS"],
)
api_router.include_router(
    adapter_unifi_routing.router,
    tags=["Gateway UniFi Routing"],
)
api_router.include_router(
    adapter_unifi_vpn.router,
    tags=["Gateway UniFi VPN"],
)
api_router.include_router(
    adapter_unifi_port_profiles.router,
    tags=["Gateway UniFi Port Profiles"],
)
api_router.include_router(
    adapter_unifi_wlan_groups.router,
    tags=["Gateway UniFi WLAN Groups"],
)
api_router.include_router(
    adapter_unifi_radios.router,
    tags=["Gateway UniFi Radios"],
)
api_router.include_router(
    adapter_unifi_radius.router,
    tags=["Gateway UniFi RADIUS"],
)
api_router.include_router(
    adapter_unifi_hotspot.router,
    tags=["Gateway UniFi Hotspot"],
)
api_router.include_router(
    adapter_unifi_switch.router,
    tags=["Gateway UniFi Switch"],
)
api_router.include_router(
    adapter_mikrotik_system.router,
    tags=["Gateway MikroTik System"],
    dependencies=_catastrophic_stage_gate,
)
api_router.include_router(adapter_pfsense_routing.router, tags=["Gateway pfSense Routing"])
api_router.include_router(adapter_pfsense_services.router, tags=["Gateway pfSense Services"])
api_router.include_router(
    adapter_pfsense_system.router,
    tags=["Gateway pfSense System"],
    dependencies=_catastrophic_stage_gate,
)
api_router.include_router(
    adapter_pfsense_diagnostics.router,
    tags=["Gateway pfSense Diagnostics"],
)
api_router.include_router(
    adapter_pfsense_interfaces.router,
    tags=["Gateway pfSense Interfaces"],
)
api_router.include_router(security.router, prefix="/security", tags=["Security"])
api_router.include_router(data.router, prefix="/data", tags=["Data Import/Export"])
api_router.include_router(firmware.router, prefix="/firmware", tags=["Firmware"])
api_router.include_router(webhooks.router, prefix="/webhooks", tags=["Webhooks"])
api_router.include_router(sso.router, prefix="/auth/sso", tags=["SSO"])
api_router.include_router(switches.router, prefix="/switches", tags=["Switches"])
api_router.include_router(network.router, prefix="/network", tags=["Network"])
api_router.include_router(poe.router, prefix="/poe", tags=["PoE"])
api_router.include_router(access_points.router, prefix="/access-points", tags=["Access Points"])
api_router.include_router(websocket.router, tags=["WebSocket"])
api_router.include_router(config_versions.router, prefix="/enterprise", tags=["Config Versions"])
api_router.include_router(enterprise.router, prefix="/enterprise", tags=["Enterprise Config"])
api_router.include_router(correlation.router, prefix="/correlation", tags=["Event Correlation"])
api_router.include_router(sla.router, prefix="/sla", tags=["SLA Monitoring"])
api_router.include_router(topology.router, prefix="/topology", tags=["Topology"])
api_router.include_router(alert_rules.router, prefix="/alert-rules", tags=["Alert Rules"])
api_router.include_router(plugins.router, prefix="/plugins", tags=["Plugins"])
api_router.include_router(
    webhook_templates.router, prefix="/webhooks/templates", tags=["Webhook Templates"]
)
api_router.include_router(integrations.router, prefix="/integrations", tags=["Integrations"])
api_router.include_router(marketplace.router, prefix="/marketplace/plugins", tags=["Marketplace"])
api_router.include_router(ztp.router, prefix="/ztp", tags=["ZTP & Provisioning"])
api_router.include_router(dpi.router, prefix="/dpi", tags=["DPI / Traffic Analytics"])
api_router.include_router(radius.router, prefix="/radius", tags=["RADIUS / 802.1X"])
api_router.include_router(roaming.router, prefix="/roaming", tags=["Client Roaming"])
api_router.include_router(vpn_orchestration.router, prefix="/vpn", tags=["VPN Orchestration"])
api_router.include_router(sla_reports.router, prefix="/sla", tags=["SLA Reports"])
api_router.include_router(system.router, prefix="/system", tags=["System"])

# ── UniFi adapter REST surface ─────────────────────────────────────
# Seven feature-area routers, each with its own ``prefix="/unifi"`` so
# they share the ``/api/v1/unifi/...`` namespace but stay cleanly
# split by surface area (sites / devices / clients / networks /
# wlans / firewall / system).
api_router.include_router(unifi_sites.router, tags=["UniFi Sites"])
api_router.include_router(unifi_devices.router, tags=["UniFi Devices"])
api_router.include_router(unifi_clients.router, tags=["UniFi Clients"])
api_router.include_router(unifi_networks.router, tags=["UniFi Networks"])
api_router.include_router(unifi_wlans.router, tags=["UniFi WLANs"])
api_router.include_router(unifi_firewall.router, tags=["UniFi Firewall"])
api_router.include_router(unifi_system.router, tags=["UniFi System"])
