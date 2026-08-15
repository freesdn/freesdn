# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Adapter Capabilities
==================================

Standard capabilities that adapters can provide.
Used for feature detection and capability-based operations.
"""

from enum import StrEnum


class Capability(StrEnum):
    """
    Standard capabilities that adapters can provide.
    Grouped by category for organization.
    """

    # ═══════════════════════════════════════════════════════════════════════════
    # NETWORK - Switch
    # ═══════════════════════════════════════════════════════════════════════════
    SWITCH_PORT_CONFIG = "switch.port.config"
    SWITCH_PORT_ENABLE = "switch.port.enable"
    SWITCH_PORT_STATUS = "switch.port.status"
    VLAN_MANAGEMENT = "switch.vlan.management"
    VLAN_CREATE = "switch.vlan.create"
    VLAN_DELETE = "switch.vlan.delete"
    POE_CONTROL = "switch.poe.control"
    POE_SCHEDULE = "switch.poe.schedule"
    POE_STATUS = "switch.poe.status"
    PORT_STATISTICS = "switch.port.statistics"
    SPANNING_TREE = "switch.spanning_tree"
    LINK_AGGREGATION = "switch.lag"
    PORT_MIRRORING = "switch.port_mirroring"
    STORM_CONTROL = "switch.storm_control"
    MAC_TABLE = "switch.mac_table"
    LLDP_NEIGHBORS = "switch.lldp.neighbors"

    # ═══════════════════════════════════════════════════════════════════════════
    # NETWORK - WiFi
    # ═══════════════════════════════════════════════════════════════════════════
    WIFI_SSID_MANAGEMENT = "wifi.ssid.management"
    WIFI_SSID_CREATE = "wifi.ssid.create"
    WIFI_SSID_DELETE = "wifi.ssid.delete"
    WIFI_CLIENT_LIST = "wifi.client.list"
    WIFI_CLIENT_KICK = "wifi.client.kick"
    WIFI_CLIENT_BLOCK = "wifi.client.block"
    WIFI_RADIO_CONFIG = "wifi.radio.config"
    BAND_STEERING = "wifi.band_steering"
    CLIENT_ISOLATION = "wifi.client_isolation"
    GUEST_PORTAL = "wifi.guest_portal"
    WIFI_STATISTICS = "wifi.statistics"
    MESH_NETWORKING = "wifi.mesh"
    WIFI_ROAMING = "wifi.roaming"

    # ═══════════════════════════════════════════════════════════════════════════
    # NETWORK - Routing
    # ═══════════════════════════════════════════════════════════════════════════
    ROUTING_STATIC = "routing.static"
    ROUTING_DYNAMIC = "routing.dynamic"
    NAT = "routing.nat"
    WAN_FAILOVER = "routing.wan_failover"
    LOAD_BALANCING = "routing.load_balancing"
    QOS = "routing.qos"
    TRAFFIC_SHAPING = "routing.traffic_shaping"
    DHCP_SERVER = "routing.dhcp"
    DNS = "routing.dns"

    # ═══════════════════════════════════════════════════════════════════════════
    # FIREWALL
    # ═══════════════════════════════════════════════════════════════════════════
    FIREWALL_BASIC = "firewall.rules.basic"
    FIREWALL_ADVANCED = "firewall.rules.advanced"
    FIREWALL_LOGGING = "firewall.logging"
    IDS_IPS = "firewall.ids_ips"
    GEO_BLOCKING = "firewall.geo_blocking"
    APPLICATION_FILTER = "firewall.app_filter"
    CONTENT_FILTER = "firewall.content_filter"

    # ═══════════════════════════════════════════════════════════════════════════
    # VPN
    # ═══════════════════════════════════════════════════════════════════════════
    VPN_CLIENT = "vpn.client"
    VPN_SERVER = "vpn.server"
    VPN_IPSEC = "vpn.ipsec"
    VPN_OPENVPN = "vpn.openvpn"
    VPN_WIREGUARD = "vpn.wireguard"
    VPN_L2TP = "vpn.l2tp"
    VPN_PPTP = "vpn.pptp"

    # ═══════════════════════════════════════════════════════════════════════════
    # CAMERA
    # ═══════════════════════════════════════════════════════════════════════════
    CAMERA_SNAPSHOT = "camera.snapshot"
    CAMERA_STREAM_RTSP = "camera.stream.rtsp"
    CAMERA_STREAM_HLS = "camera.stream.hls"
    CAMERA_STREAM_WEBRTC = "camera.stream.webrtc"
    CAMERA_PTZ = "camera.ptz"
    CAMERA_PTZ_PRESETS = "camera.ptz.presets"
    CAMERA_RECORDING = "camera.recording"
    CAMERA_PLAYBACK = "camera.playback"
    CAMERA_MOTION_DETECTION = "camera.motion"
    CAMERA_AI_PERSON = "camera.ai.person"
    CAMERA_AI_VEHICLE = "camera.ai.vehicle"
    CAMERA_AI_FACE = "camera.ai.face"
    CAMERA_AI_LINE_CROSSING = "camera.ai.line_crossing"
    CAMERA_AUDIO = "camera.audio"
    CAMERA_TWO_WAY_AUDIO = "camera.audio.two_way"
    CAMERA_PRIVACY_MASK = "camera.privacy_mask"
    CAMERA_OSD = "camera.osd"

    # ═══════════════════════════════════════════════════════════════════════════
    # NVR
    # ═══════════════════════════════════════════════════════════════════════════
    NVR_RECORDING = "nvr.recording"
    NVR_PLAYBACK = "nvr.playback"
    NVR_SEARCH = "nvr.search"
    NVR_EXPORT = "nvr.export"
    NVR_STORAGE = "nvr.storage"
    NVR_CHANNEL_MANAGEMENT = "nvr.channels"

    # ═══════════════════════════════════════════════════════════════════════════
    # VOIP - Phone
    # ═══════════════════════════════════════════════════════════════════════════
    PHONE_PROVISIONING = "phone.provisioning"
    PHONE_CONFIG = "phone.config"
    PHONE_REBOOT = "phone.reboot"
    PHONE_STATUS = "phone.status"
    PHONE_LINE_CONFIG = "phone.line"
    PHONE_BLF = "phone.blf"
    PHONE_DIRECTORY = "phone.directory"

    # ═══════════════════════════════════════════════════════════════════════════
    # VOIP - PBX
    # ═══════════════════════════════════════════════════════════════════════════
    PBX_EXTENSIONS = "pbx.extensions"
    PBX_TRUNKS = "pbx.trunks"
    PBX_ROUTES = "pbx.routes"
    PBX_IVR = "pbx.ivr"
    PBX_QUEUES = "pbx.queues"
    PBX_RING_GROUPS = "pbx.ring_groups"
    PBX_VOICEMAIL = "pbx.voicemail"
    PBX_CALL_LOGS = "pbx.call_logs"
    PBX_RECORDINGS = "pbx.recordings"
    PBX_CONFERENCE = "pbx.conference"

    # ═══════════════════════════════════════════════════════════════════════════
    # ACCESS CONTROL
    # ═══════════════════════════════════════════════════════════════════════════
    ACCESS_DOOR_OPEN = "access.door.open"
    ACCESS_DOOR_LOCK = "access.door.lock"
    ACCESS_DOOR_STATUS = "access.door.status"
    ACCESS_USERS = "access.users"
    ACCESS_CARDS = "access.cards"
    ACCESS_SCHEDULES = "access.schedules"
    ACCESS_LOGS = "access.logs"
    ACCESS_INTERCOM = "access.intercom"
    ACCESS_ZONES = "access.zones"

    # ═══════════════════════════════════════════════════════════════════════════
    # GENERAL / DEVICE
    # ═══════════════════════════════════════════════════════════════════════════
    DEVICE_INFO = "device.info"
    DEVICE_REBOOT = "device.reboot"
    DEVICE_FIRMWARE_CHECK = "device.firmware.check"
    DEVICE_FIRMWARE_UPGRADE = "device.firmware.upgrade"
    DEVICE_BACKUP = "device.backup"
    DEVICE_RESTORE = "device.restore"
    DEVICE_FACTORY_RESET = "device.factory_reset"
    DEVICE_LOCATE = "device.locate"
    DEVICE_LOGS = "device.logs"
    DEVICE_METRICS = "device.metrics"

    # ═══════════════════════════════════════════════════════════════════════════
    # ENTERPRISE NETWORK (Added for deep Omada integration)
    # ═══════════════════════════════════════════════════════════════════════════
    ROGUE_AP_DETECTION = "wifi.rogue_ap"
    CHANNEL_UTILIZATION = "wifi.channel_util"
    CAPTIVE_PORTAL = "wifi.captive_portal"
    HOTSPOT_VOUCHERS = "wifi.hotspot.vouchers"
    SITE_RADIO_SETTINGS = "wifi.site_radio"
    DOT1X_AUTH = "switch.dot1x"
    DHCP_SNOOPING = "switch.dhcp_snooping"
    SWITCH_ACL = "switch.acl"
    DHCP_RESERVATIONS = "routing.dhcp.reservations"
    IP_GROUPS = "firewall.ip_groups"
    URL_FILTERING = "firewall.url_filter"
    STATIC_ROUTES = "routing.static_routes"
    IP_MAC_BINDING = "routing.ip_mac_binding"
    DDNS = "routing.ddns"
    FIRMWARE_BATCH = "device.firmware.batch"
    CONTROLLER_BACKUP = "controller.backup"
    EVENTS_ALERTS = "controller.events"
    SITE_SETTINGS = "controller.site_settings"

    # Capabilities added for v26.05 Omada deepening (each backed by a
    # gateway-* endpoint module + service + UI page). Future adapters
    # advertise these so the UI can decide which tabs to render.
    CONTROLLER_SMTP = "controller.smtp"
    CONTROLLER_SSL_CERT = "controller.ssl_cert"
    CONTROLLER_ADMINS = "controller.admins"
    CONTROLLER_NOTIFICATIONS = "controller.notifications"
    CONTROLLER_GLOBAL_SETTINGS = "controller.global"
    CONTROLLER_MAINTENANCE = "controller.maintenance"
    CONTROLLER_CLOUD_ACCESS = "controller.cloud_access"
    SITE_TIME_NTP = "site.time"
    SITE_LED_SCHEDULE = "site.led_schedule"
    SITE_REBOOT_SCHEDULE = "site.reboot_schedule"
    SITE_NOTIFICATIONS = "site.notifications"
    MONITORING_SNMP = "monitoring.snmp"
    MONITORING_SYSLOG = "monitoring.syslog"
    SITE_TEMPLATES = "site.templates"
    SITE_CLONE = "site.clone"
    BULK_DEVICE_OPS = "bulk.device"
    BULK_CLIENT_OPS = "bulk.client"
    BULK_SSID_OPS = "bulk.ssid"
    HOTSPOT_OPERATORS = "hotspot.operators"
    HOTSPOT_SMS_GATEWAY = "hotspot.sms_gateway"
    HOTSPOT_FREE_AUTH = "hotspot.free_auth"
    ROUTING_VRRP = "routing.vrrp"
    ROUTING_BGP = "routing.bgp"
    ROUTING_IPV6_STATIC = "routing.ipv6_static"
    ROUTING_TABLE_VIEW = "routing.table"
    SWITCH_SFLOW = "switch.sflow"
    SWITCH_LLDP_MED = "switch.lldp_med"
    SWITCH_QINQ = "switch.qinq"
    SWITCH_MSTP = "switch.mstp"
    SWITCH_VOICE_VLAN = "switch.voice_vlan"
    SWITCH_POE_BUDGET = "switch.poe_budget"
    SWITCH_PORT_JUMBO = "switch.port_jumbo"
    WIFI_WIDS_WIPS = "wifi.wids_wips"
    WIFI_MESH_DETAIL = "wifi.mesh_detail"
    WIFI_REGULATORY = "wifi.regulatory"
    WIFI_DFS = "wifi.dfs"
    WIFI_CHANNEL_PILOT = "wifi.channel_pilot"
    WIFI_LOCATE_AP = "wifi.locate_ap"
    GATEWAY_SPEED_TEST = "gateway.speed_test"
    GATEWAY_SESSION_STATS = "gateway.session_stats"

    # ═══════════════════════════════════════════════════════════════════════════
    # GATEWAY ORCHESTRATION
    # ═══════════════════════════════════════════════════════════════════════════
    GATEWAY_VLAN_INTERFACE = "gateway.vlan_interface.manage"
    GATEWAY_DHCP_MANAGE = "gateway.dhcp.manage"
    GATEWAY_DNS_MANAGE = "gateway.dns.manage"
    GATEWAY_ALIAS_MANAGE = "gateway.alias.manage"
    GATEWAY_PING = "gateway.diagnostics.ping"
    GATEWAY_TRACEROUTE = "gateway.diagnostics.traceroute"
    GATEWAY_DNS_LOOKUP = "gateway.diagnostics.dns_lookup"
    GATEWAY_BACKUP = "gateway.backup"
    GATEWAY_FIRMWARE_STATUS = "gateway.firmware.status"
    GATEWAY_SERVICE_RESTART = "gateway.service.restart"

    # ═══════════════════════════════════════════════════════════════════════════
    # OPNsense-specific feature surfaces (each backed by a
    # adapter_opnsense_* service + endpoint module). The frontend
    # checks these so it can hide tabs / buttons for features the
    # adapter doesn't advertise.
    # ═══════════════════════════════════════════════════════════════════════════
    OPNSENSE_FIREWALL_RULES = "opnsense.firewall.rules"
    OPNSENSE_FIREWALL_ALIASES = "opnsense.firewall.aliases"
    OPNSENSE_NAT_SOURCE = "opnsense.nat.source"
    OPNSENSE_NAT_PORT_FORWARD = "opnsense.nat.port_forward"
    OPNSENSE_DHCP_LEASES = "opnsense.dhcp.leases"
    OPNSENSE_DHCP_STATIC_MAPPINGS = "opnsense.dhcp.static_mappings"
    OPNSENSE_DHCP_KEA = "opnsense.dhcp.kea"
    OPNSENSE_DNS_HOST_OVERRIDES = "opnsense.dns.host_overrides"
    OPNSENSE_DNS_DOMAIN_OVERRIDES = "opnsense.dns.domain_overrides"
    OPNSENSE_VPN_WIREGUARD = "opnsense.vpn.wireguard"
    OPNSENSE_VPN_OPENVPN = "opnsense.vpn.openvpn"
    OPNSENSE_VPN_IPSEC = "opnsense.vpn.ipsec"
    OPNSENSE_ROUTING_STATIC = "opnsense.routing.static"
    OPNSENSE_ROUTING_TABLE = "opnsense.routing.table"
    OPNSENSE_GATEWAY_STATUS = "opnsense.gateway.status"
    OPNSENSE_SERVICES_CONTROL = "opnsense.services.control"
    OPNSENSE_SYSTEM_INFO = "opnsense.system.info"
    OPNSENSE_SYSTEM_REBOOT = "opnsense.system.reboot"
    OPNSENSE_SYSTEM_BACKUP = "opnsense.system.backup"
    OPNSENSE_SYSTEM_FIRMWARE = "opnsense.system.firmware"
    OPNSENSE_DIAG_LOGS = "opnsense.diagnostics.logs"
    OPNSENSE_DIAG_TRAFFIC = "opnsense.diagnostics.traffic"
    OPNSENSE_DIAG_PING = "opnsense.diagnostics.ping"
    OPNSENSE_DIAG_TRACEROUTE = "opnsense.diagnostics.traceroute"
    OPNSENSE_DIAG_DNS_LOOKUP = "opnsense.diagnostics.dns_lookup"
    OPNSENSE_IDS_SETTINGS = "opnsense.ids.settings"
    OPNSENSE_IDS_RULES = "opnsense.ids.rules"
    OPNSENSE_IDS_ALERTS = "opnsense.ids.alerts"
    OPNSENSE_SHAPER_PIPES = "opnsense.shaper.pipes"
    OPNSENSE_SHAPER_QUEUES = "opnsense.shaper.queues"
    OPNSENSE_SHAPER_RULES = "opnsense.shaper.rules"
    OPNSENSE_INTERFACES_LIST = "opnsense.interfaces.list"
    OPNSENSE_INTERFACES_VLAN = "opnsense.interfaces.vlan"
    OPNSENSE_INTERFACES_ARP = "opnsense.interfaces.arp"
    OPNSENSE_INTERFACES_NDP = "opnsense.interfaces.ndp"
    OPNSENSE_CRON_JOBS = "opnsense.cron.jobs"

    # ═══════════════════════════════════════════════════════════════════════════
    # Proxmox-specific feature surfaces (each backed by a
    # adapter_proxmox_* service + endpoint module). Frontend hides
    # tabs the cluster doesn't advertise.
    # ═══════════════════════════════════════════════════════════════════════════
    PROXMOX_VM_LIFECYCLE = "proxmox.vm.lifecycle"
    PROXMOX_VM_CONFIG = "proxmox.vm.config"
    PROXMOX_VM_CLONE = "proxmox.vm.clone"
    PROXMOX_VM_MIGRATE = "proxmox.vm.migrate"
    PROXMOX_VM_GUEST_AGENT = "proxmox.vm.guest_agent"
    PROXMOX_VM_CLOUDINIT = "proxmox.vm.cloudinit"
    PROXMOX_CONTAINER_LIFECYCLE = "proxmox.container.lifecycle"
    PROXMOX_CONTAINER_CONFIG = "proxmox.container.config"
    PROXMOX_CONTAINER_CLONE = "proxmox.container.clone"
    PROXMOX_CONTAINER_MIGRATE = "proxmox.container.migrate"
    PROXMOX_SNAPSHOT_CREATE = "proxmox.snapshot.create"
    PROXMOX_SNAPSHOT_ROLLBACK = "proxmox.snapshot.rollback"
    PROXMOX_SNAPSHOT_DELETE = "proxmox.snapshot.delete"
    PROXMOX_STORAGE_VOLUME = "proxmox.storage.volume"
    PROXMOX_STORAGE_UPLOAD = "proxmox.storage.upload"
    PROXMOX_BACKUP_JOBS = "proxmox.backup.jobs"
    PROXMOX_BACKUP_RUN = "proxmox.backup.run"
    PROXMOX_BACKUP_RESTORE = "proxmox.backup.restore"
    PROXMOX_BACKUP_PRUNE = "proxmox.backup.prune"
    PROXMOX_NODE_CONTROL = "proxmox.node.control"
    PROXMOX_NODE_CERTIFICATE = "proxmox.node.certificate"
    PROXMOX_NODE_APT = "proxmox.node.apt"
    PROXMOX_NODE_SERVICE = "proxmox.node.service"
    PROXMOX_CLUSTER_TASKS = "proxmox.cluster.tasks"
    PROXMOX_CLUSTER_FIREWALL = "proxmox.cluster.firewall"
    PROXMOX_HA_GROUPS = "proxmox.ha.groups"
    PROXMOX_HA_RESOURCES = "proxmox.ha.resources"
    PROXMOX_REPLICATION = "proxmox.replication"
    PROXMOX_SDN_ZONE = "proxmox.sdn.zone"
    PROXMOX_SDN_VNET = "proxmox.sdn.vnet"
    PROXMOX_SDN_APPLY = "proxmox.sdn.apply"
    PROXMOX_CEPH_STATUS = "proxmox.ceph.status"
    PROXMOX_CEPH_MON = "proxmox.ceph.mon"
    PROXMOX_CEPH_OSD = "proxmox.ceph.osd"
    PROXMOX_CEPH_POOLS = "proxmox.ceph.pools"
    PROXMOX_FIREWALL_CLUSTER = "proxmox.firewall.cluster"
    PROXMOX_FIREWALL_GUEST = "proxmox.firewall.guest"

    # ═══════════════════════════════════════════════════════════════════════════
    # pfSense-specific feature surfaces (each backed by a
    # adapter_pfsense_* service + endpoint module). pfSense is a
    # sibling firewall to OPNsense — same dual-gate, same staging.
    # ═══════════════════════════════════════════════════════════════════════════
    PFSENSE_FIREWALL_RULES = "pfsense.firewall.rules"
    PFSENSE_FIREWALL_ALIASES = "pfsense.firewall.aliases"
    PFSENSE_NAT_PORT_FORWARD = "pfsense.nat.port_forward"
    PFSENSE_NAT_OUTBOUND = "pfsense.nat.outbound"
    PFSENSE_DHCP_LEASES = "pfsense.dhcp.leases"
    PFSENSE_DHCP_STATIC_MAPPINGS = "pfsense.dhcp.static_mappings"
    PFSENSE_DNS_OVERRIDES = "pfsense.dns.overrides"
    PFSENSE_VPN_OPENVPN = "pfsense.vpn.openvpn"
    PFSENSE_VPN_WIREGUARD = "pfsense.vpn.wireguard"
    PFSENSE_VPN_IPSEC = "pfsense.vpn.ipsec"
    PFSENSE_ROUTING_GATEWAYS = "pfsense.routing.gateways"
    PFSENSE_ROUTING_STATIC = "pfsense.routing.static"
    PFSENSE_SERVICES_CONTROL = "pfsense.services.control"
    PFSENSE_SYSTEM_INFO = "pfsense.system.info"
    PFSENSE_SYSTEM_REBOOT = "pfsense.system.reboot"
    PFSENSE_DIAG_LOGS = "pfsense.diagnostics.logs"
    PFSENSE_DIAG_PING = "pfsense.diagnostics.ping"
    PFSENSE_DIAG_TRACEROUTE = "pfsense.diagnostics.traceroute"
    PFSENSE_DIAG_DNS_LOOKUP = "pfsense.diagnostics.dns_lookup"
    PFSENSE_INTERFACES_LIST = "pfsense.interfaces.list"
    PFSENSE_INTERFACES_VLAN = "pfsense.interfaces.vlan"
    PFSENSE_INTERFACES_ARP = "pfsense.interfaces.arp"

    # ═══════════════════════════════════════════════════════════════════════════
    # MikroTik RouterOS-specific feature surfaces (each backed by a
    # adapter_mikrotik_* service + endpoint module). MikroTik is a
    # network-tier device — uses ``network:write`` permission tier.
    # ═══════════════════════════════════════════════════════════════════════════
    MIKROTIK_FIREWALL_FILTER = "mikrotik.firewall.filter"
    MIKROTIK_FIREWALL_NAT = "mikrotik.firewall.nat"
    MIKROTIK_FIREWALL_MANGLE = "mikrotik.firewall.mangle"
    MIKROTIK_FIREWALL_ADDRESS_LIST = "mikrotik.firewall.address_list"
    MIKROTIK_INTERFACES_LIST = "mikrotik.interfaces.list"
    MIKROTIK_INTERFACES_VLAN = "mikrotik.interfaces.vlan"
    MIKROTIK_INTERFACES_BRIDGE = "mikrotik.interfaces.bridge"
    MIKROTIK_INTERFACES_ETHERNET = "mikrotik.interfaces.ethernet"
    MIKROTIK_IP_ADDRESS = "mikrotik.ip.address"
    MIKROTIK_IP_POOL = "mikrotik.ip.pool"
    MIKROTIK_IP_ARP = "mikrotik.ip.arp"
    MIKROTIK_DHCP_SERVER = "mikrotik.dhcp.server"
    MIKROTIK_DHCP_LEASES = "mikrotik.dhcp.leases"
    MIKROTIK_DNS_SETTINGS = "mikrotik.dns.settings"
    MIKROTIK_DNS_STATIC = "mikrotik.dns.static"
    MIKROTIK_VPN_IPSEC = "mikrotik.vpn.ipsec"
    MIKROTIK_VPN_WIREGUARD = "mikrotik.vpn.wireguard"
    MIKROTIK_VPN_L2TP = "mikrotik.vpn.l2tp"
    MIKROTIK_VPN_PPTP = "mikrotik.vpn.pptp"
    MIKROTIK_ROUTING_STATIC = "mikrotik.routing.static"
    MIKROTIK_ROUTING_OSPF = "mikrotik.routing.ospf"
    MIKROTIK_ROUTING_BGP = "mikrotik.routing.bgp"
    MIKROTIK_QUEUES_SIMPLE = "mikrotik.queues.simple"
    MIKROTIK_QUEUES_TREE = "mikrotik.queues.tree"
    MIKROTIK_PPP_PPPOE_SERVER = "mikrotik.ppp.pppoe_server"
    MIKROTIK_PPP_PPPOE_CLIENT = "mikrotik.ppp.pppoe_client"
    MIKROTIK_PPP_SECRETS = "mikrotik.ppp.secrets"
    MIKROTIK_HOTSPOT_SERVER = "mikrotik.hotspot.server"
    MIKROTIK_HOTSPOT_USERS = "mikrotik.hotspot.users"
    MIKROTIK_HOTSPOT_WALLED_GARDEN = "mikrotik.hotspot.walled_garden"
    MIKROTIK_CAPSMAN_CONFIG = "mikrotik.capsman.config"
    MIKROTIK_CAPSMAN_DATAPATH = "mikrotik.capsman.datapath"
    MIKROTIK_CAPSMAN_SECURITY = "mikrotik.capsman.security"
    MIKROTIK_CAPSMAN_REGISTRATIONS = "mikrotik.capsman.registrations"
    MIKROTIK_SECURITY_USERS = "mikrotik.security.users"
    MIKROTIK_SECURITY_CERTIFICATES = "mikrotik.security.certificates"
    MIKROTIK_SECURITY_SNMP = "mikrotik.security.snmp"
    MIKROTIK_SECURITY_RADIUS = "mikrotik.security.radius"
    MIKROTIK_SYSTEM_REBOOT = "mikrotik.system.reboot"
    MIKROTIK_SYSTEM_BACKUP = "mikrotik.system.backup"
    MIKROTIK_SYSTEM_EXPORT = "mikrotik.system.export"
    MIKROTIK_SYSTEM_SERVICES = "mikrotik.system.services"
    MIKROTIK_SYSTEM_SWITCH = "mikrotik.system.switch"
    MIKROTIK_SYSTEM_TOOLS = "mikrotik.system.tools"
    MIKROTIK_SYSTEM_LOGS = "mikrotik.system.logs"

    # ═══════════════════════════════════════════════════════════════════════════
    # HYPERVISOR (Proxmox VE)
    # ═══════════════════════════════════════════════════════════════════════════
    COMPUTE_CLUSTER_STATUS = "hypervisor.cluster.status"
    COMPUTE_NODE_LIST = "hypervisor.node.list"
    COMPUTE_NODE_STATUS = "hypervisor.node.status"
    COMPUTE_VM_LIST = "hypervisor.vm.list"
    COMPUTE_VM_CONTROL = "hypervisor.vm.control"
    COMPUTE_VM_SNAPSHOT = "hypervisor.vm.snapshot"
    COMPUTE_VM_CONSOLE = "hypervisor.vm.console"
    COMPUTE_VM_CONFIG = "hypervisor.vm.config"
    COMPUTE_CONTAINER_LIST = "hypervisor.container.list"
    COMPUTE_CONTAINER_CONTROL = "hypervisor.container.control"
    COMPUTE_STORAGE_LIST = "hypervisor.storage.list"
    COMPUTE_STORAGE_CONTENT = "hypervisor.storage.content"
    COMPUTE_BACKUP_MANAGE = "hypervisor.backup.manage"
    COMPUTE_MONITORING = "hypervisor.monitoring"
    COMPUTE_NETWORK = "hypervisor.network"
    COMPUTE_TASKS = "hypervisor.tasks"


class CapabilityCategory(StrEnum):
    """Category groupings for capabilities."""

    NETWORK_SWITCH = "network.switch"
    NETWORK_WIFI = "network.wifi"
    NETWORK_ROUTING = "network.routing"
    FIREWALL = "firewall"
    VPN = "vpn"
    CAMERA = "camera"
    NVR = "nvr"
    VOIP_PHONE = "voip.phone"
    VOIP_PBX = "voip.pbx"
    ACCESS_CONTROL = "access"
    GENERAL = "general"
    GATEWAY = "gateway"
    COMPUTE = "hypervisor"


# Mapping of capabilities to their categories
CAPABILITY_CATEGORIES: dict[Capability, CapabilityCategory] = {
    # Switch capabilities
    Capability.SWITCH_PORT_CONFIG: CapabilityCategory.NETWORK_SWITCH,
    Capability.SWITCH_PORT_ENABLE: CapabilityCategory.NETWORK_SWITCH,
    Capability.SWITCH_PORT_STATUS: CapabilityCategory.NETWORK_SWITCH,
    Capability.VLAN_MANAGEMENT: CapabilityCategory.NETWORK_SWITCH,
    Capability.VLAN_CREATE: CapabilityCategory.NETWORK_SWITCH,
    Capability.VLAN_DELETE: CapabilityCategory.NETWORK_SWITCH,
    Capability.POE_CONTROL: CapabilityCategory.NETWORK_SWITCH,
    Capability.POE_SCHEDULE: CapabilityCategory.NETWORK_SWITCH,
    Capability.POE_STATUS: CapabilityCategory.NETWORK_SWITCH,
    Capability.PORT_STATISTICS: CapabilityCategory.NETWORK_SWITCH,
    Capability.SPANNING_TREE: CapabilityCategory.NETWORK_SWITCH,
    Capability.LINK_AGGREGATION: CapabilityCategory.NETWORK_SWITCH,
    Capability.PORT_MIRRORING: CapabilityCategory.NETWORK_SWITCH,
    Capability.STORM_CONTROL: CapabilityCategory.NETWORK_SWITCH,
    Capability.MAC_TABLE: CapabilityCategory.NETWORK_SWITCH,
    Capability.LLDP_NEIGHBORS: CapabilityCategory.NETWORK_SWITCH,
    # WiFi capabilities
    Capability.WIFI_SSID_MANAGEMENT: CapabilityCategory.NETWORK_WIFI,
    Capability.WIFI_SSID_CREATE: CapabilityCategory.NETWORK_WIFI,
    Capability.WIFI_SSID_DELETE: CapabilityCategory.NETWORK_WIFI,
    Capability.WIFI_CLIENT_LIST: CapabilityCategory.NETWORK_WIFI,
    Capability.WIFI_CLIENT_KICK: CapabilityCategory.NETWORK_WIFI,
    Capability.WIFI_CLIENT_BLOCK: CapabilityCategory.NETWORK_WIFI,
    Capability.WIFI_RADIO_CONFIG: CapabilityCategory.NETWORK_WIFI,
    Capability.BAND_STEERING: CapabilityCategory.NETWORK_WIFI,
    Capability.CLIENT_ISOLATION: CapabilityCategory.NETWORK_WIFI,
    Capability.GUEST_PORTAL: CapabilityCategory.NETWORK_WIFI,
    Capability.WIFI_STATISTICS: CapabilityCategory.NETWORK_WIFI,
    Capability.MESH_NETWORKING: CapabilityCategory.NETWORK_WIFI,
    Capability.WIFI_ROAMING: CapabilityCategory.NETWORK_WIFI,
    # Routing capabilities
    Capability.ROUTING_STATIC: CapabilityCategory.NETWORK_ROUTING,
    Capability.ROUTING_DYNAMIC: CapabilityCategory.NETWORK_ROUTING,
    Capability.NAT: CapabilityCategory.NETWORK_ROUTING,
    Capability.WAN_FAILOVER: CapabilityCategory.NETWORK_ROUTING,
    Capability.LOAD_BALANCING: CapabilityCategory.NETWORK_ROUTING,
    Capability.QOS: CapabilityCategory.NETWORK_ROUTING,
    Capability.TRAFFIC_SHAPING: CapabilityCategory.NETWORK_ROUTING,
    Capability.DHCP_SERVER: CapabilityCategory.NETWORK_ROUTING,
    Capability.DNS: CapabilityCategory.NETWORK_ROUTING,
    # Firewall capabilities
    Capability.FIREWALL_BASIC: CapabilityCategory.FIREWALL,
    Capability.FIREWALL_ADVANCED: CapabilityCategory.FIREWALL,
    Capability.FIREWALL_LOGGING: CapabilityCategory.FIREWALL,
    Capability.IDS_IPS: CapabilityCategory.FIREWALL,
    Capability.GEO_BLOCKING: CapabilityCategory.FIREWALL,
    Capability.APPLICATION_FILTER: CapabilityCategory.FIREWALL,
    Capability.CONTENT_FILTER: CapabilityCategory.FIREWALL,
    # VPN capabilities
    Capability.VPN_CLIENT: CapabilityCategory.VPN,
    Capability.VPN_SERVER: CapabilityCategory.VPN,
    Capability.VPN_IPSEC: CapabilityCategory.VPN,
    Capability.VPN_OPENVPN: CapabilityCategory.VPN,
    Capability.VPN_WIREGUARD: CapabilityCategory.VPN,
    Capability.VPN_L2TP: CapabilityCategory.VPN,
    Capability.VPN_PPTP: CapabilityCategory.VPN,
    # Camera capabilities
    Capability.CAMERA_SNAPSHOT: CapabilityCategory.CAMERA,
    Capability.CAMERA_STREAM_RTSP: CapabilityCategory.CAMERA,
    Capability.CAMERA_STREAM_HLS: CapabilityCategory.CAMERA,
    Capability.CAMERA_STREAM_WEBRTC: CapabilityCategory.CAMERA,
    Capability.CAMERA_PTZ: CapabilityCategory.CAMERA,
    Capability.CAMERA_PTZ_PRESETS: CapabilityCategory.CAMERA,
    Capability.CAMERA_RECORDING: CapabilityCategory.CAMERA,
    Capability.CAMERA_PLAYBACK: CapabilityCategory.CAMERA,
    Capability.CAMERA_MOTION_DETECTION: CapabilityCategory.CAMERA,
    Capability.CAMERA_AI_PERSON: CapabilityCategory.CAMERA,
    Capability.CAMERA_AI_VEHICLE: CapabilityCategory.CAMERA,
    Capability.CAMERA_AI_FACE: CapabilityCategory.CAMERA,
    Capability.CAMERA_AI_LINE_CROSSING: CapabilityCategory.CAMERA,
    Capability.CAMERA_AUDIO: CapabilityCategory.CAMERA,
    Capability.CAMERA_TWO_WAY_AUDIO: CapabilityCategory.CAMERA,
    Capability.CAMERA_PRIVACY_MASK: CapabilityCategory.CAMERA,
    Capability.CAMERA_OSD: CapabilityCategory.CAMERA,
    # NVR capabilities
    Capability.NVR_RECORDING: CapabilityCategory.NVR,
    Capability.NVR_PLAYBACK: CapabilityCategory.NVR,
    Capability.NVR_SEARCH: CapabilityCategory.NVR,
    Capability.NVR_EXPORT: CapabilityCategory.NVR,
    Capability.NVR_STORAGE: CapabilityCategory.NVR,
    Capability.NVR_CHANNEL_MANAGEMENT: CapabilityCategory.NVR,
    # VoIP Phone capabilities
    Capability.PHONE_PROVISIONING: CapabilityCategory.VOIP_PHONE,
    Capability.PHONE_CONFIG: CapabilityCategory.VOIP_PHONE,
    Capability.PHONE_REBOOT: CapabilityCategory.VOIP_PHONE,
    Capability.PHONE_STATUS: CapabilityCategory.VOIP_PHONE,
    Capability.PHONE_LINE_CONFIG: CapabilityCategory.VOIP_PHONE,
    Capability.PHONE_BLF: CapabilityCategory.VOIP_PHONE,
    Capability.PHONE_DIRECTORY: CapabilityCategory.VOIP_PHONE,
    # VoIP PBX capabilities
    Capability.PBX_EXTENSIONS: CapabilityCategory.VOIP_PBX,
    Capability.PBX_TRUNKS: CapabilityCategory.VOIP_PBX,
    Capability.PBX_ROUTES: CapabilityCategory.VOIP_PBX,
    Capability.PBX_IVR: CapabilityCategory.VOIP_PBX,
    Capability.PBX_QUEUES: CapabilityCategory.VOIP_PBX,
    Capability.PBX_RING_GROUPS: CapabilityCategory.VOIP_PBX,
    Capability.PBX_VOICEMAIL: CapabilityCategory.VOIP_PBX,
    Capability.PBX_CALL_LOGS: CapabilityCategory.VOIP_PBX,
    Capability.PBX_RECORDINGS: CapabilityCategory.VOIP_PBX,
    Capability.PBX_CONFERENCE: CapabilityCategory.VOIP_PBX,
    # Access Control capabilities
    Capability.ACCESS_DOOR_OPEN: CapabilityCategory.ACCESS_CONTROL,
    Capability.ACCESS_DOOR_LOCK: CapabilityCategory.ACCESS_CONTROL,
    Capability.ACCESS_DOOR_STATUS: CapabilityCategory.ACCESS_CONTROL,
    Capability.ACCESS_USERS: CapabilityCategory.ACCESS_CONTROL,
    Capability.ACCESS_CARDS: CapabilityCategory.ACCESS_CONTROL,
    Capability.ACCESS_SCHEDULES: CapabilityCategory.ACCESS_CONTROL,
    Capability.ACCESS_LOGS: CapabilityCategory.ACCESS_CONTROL,
    Capability.ACCESS_INTERCOM: CapabilityCategory.ACCESS_CONTROL,
    Capability.ACCESS_ZONES: CapabilityCategory.ACCESS_CONTROL,
    # General capabilities
    Capability.DEVICE_INFO: CapabilityCategory.GENERAL,
    Capability.DEVICE_REBOOT: CapabilityCategory.GENERAL,
    Capability.DEVICE_FIRMWARE_CHECK: CapabilityCategory.GENERAL,
    Capability.DEVICE_FIRMWARE_UPGRADE: CapabilityCategory.GENERAL,
    Capability.DEVICE_BACKUP: CapabilityCategory.GENERAL,
    Capability.DEVICE_RESTORE: CapabilityCategory.GENERAL,
    Capability.DEVICE_FACTORY_RESET: CapabilityCategory.GENERAL,
    Capability.DEVICE_LOCATE: CapabilityCategory.GENERAL,
    Capability.DEVICE_LOGS: CapabilityCategory.GENERAL,
    Capability.DEVICE_METRICS: CapabilityCategory.GENERAL,
    # Gateway Orchestration capabilities
    Capability.GATEWAY_VLAN_INTERFACE: CapabilityCategory.GATEWAY,
    Capability.GATEWAY_DHCP_MANAGE: CapabilityCategory.GATEWAY,
    Capability.GATEWAY_DNS_MANAGE: CapabilityCategory.GATEWAY,
    Capability.GATEWAY_ALIAS_MANAGE: CapabilityCategory.GATEWAY,
    Capability.GATEWAY_PING: CapabilityCategory.GATEWAY,
    Capability.GATEWAY_TRACEROUTE: CapabilityCategory.GATEWAY,
    Capability.GATEWAY_DNS_LOOKUP: CapabilityCategory.GATEWAY,
    Capability.GATEWAY_BACKUP: CapabilityCategory.GATEWAY,
    Capability.GATEWAY_FIRMWARE_STATUS: CapabilityCategory.GATEWAY,
    Capability.GATEWAY_SERVICE_RESTART: CapabilityCategory.GATEWAY,
    # Hypervisor capabilities
    Capability.COMPUTE_CLUSTER_STATUS: CapabilityCategory.COMPUTE,
    Capability.COMPUTE_NODE_LIST: CapabilityCategory.COMPUTE,
    Capability.COMPUTE_NODE_STATUS: CapabilityCategory.COMPUTE,
    Capability.COMPUTE_VM_LIST: CapabilityCategory.COMPUTE,
    Capability.COMPUTE_VM_CONTROL: CapabilityCategory.COMPUTE,
    Capability.COMPUTE_VM_SNAPSHOT: CapabilityCategory.COMPUTE,
    Capability.COMPUTE_VM_CONSOLE: CapabilityCategory.COMPUTE,
    Capability.COMPUTE_VM_CONFIG: CapabilityCategory.COMPUTE,
    Capability.COMPUTE_CONTAINER_LIST: CapabilityCategory.COMPUTE,
    Capability.COMPUTE_CONTAINER_CONTROL: CapabilityCategory.COMPUTE,
    Capability.COMPUTE_STORAGE_LIST: CapabilityCategory.COMPUTE,
    Capability.COMPUTE_STORAGE_CONTENT: CapabilityCategory.COMPUTE,
    Capability.COMPUTE_BACKUP_MANAGE: CapabilityCategory.COMPUTE,
    Capability.COMPUTE_MONITORING: CapabilityCategory.COMPUTE,
    Capability.COMPUTE_NETWORK: CapabilityCategory.COMPUTE,
    Capability.COMPUTE_TASKS: CapabilityCategory.COMPUTE,
}


def get_capabilities_by_category(category: CapabilityCategory) -> list[Capability]:
    """Get all capabilities for a category."""
    return [cap for cap, cat in CAPABILITY_CATEGORIES.items() if cat == category]


def get_capability_category(capability: Capability) -> CapabilityCategory | None:
    """Get the category for a capability."""
    return CAPABILITY_CATEGORIES.get(capability)
