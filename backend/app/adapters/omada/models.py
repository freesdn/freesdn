# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Omada API Pydantic models.

Typed models for every Omada API response entity so that the adapter
layer returns structured, documented data instead of raw dicts.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator

# ============================================================================
# Enumerations
# ============================================================================


class OmadaDeviceType(StrEnum):
    """Omada API device type identifiers."""

    ACCESS_POINT = "ap"
    SWITCH = "switch"
    GATEWAY = "gateway"


class OmadaDeviceStatus(StrEnum):
    """Mapped device status labels."""

    OFFLINE = "offline"
    ONLINE = "online"
    PENDING = "pending"
    ADOPTING = "adopting"
    PROVISIONING = "provisioning"
    UPGRADING = "upgrading"
    UNKNOWN = "unknown"


class OmadaLinkStatus(StrEnum):
    """Switch port link state."""

    UP = "up"
    DOWN = "down"


class OmadaSecurityMode(StrEnum):
    """WiFi security modes."""

    OPEN = "open"
    WPA_PERSONAL = "wpa_personal"
    WPA_ENTERPRISE = "wpa_enterprise"
    WPA2_PERSONAL = "wpa2_personal"
    WPA2_ENTERPRISE = "wpa2_enterprise"
    WPA3_PERSONAL = "wpa3_personal"
    WPA3_ENTERPRISE = "wpa3_enterprise"
    WPA_WPA2_PERSONAL = "wpa_wpa2_personal"
    WPA2_WPA3_PERSONAL = "wpa2_wpa3_personal"


class OmadaClientConnectionType(StrEnum):
    """How a client connects to the network."""

    WIRED = "wired"
    WIRELESS = "wireless"


class OmadaFirewallAction(StrEnum):
    """Firewall rule actions."""

    ACCEPT = "accept"
    DROP = "drop"
    REJECT = "reject"


class OmadaPortType(StrEnum):
    """Switch port physical type."""

    UNKNOWN = "unknown"
    COPPER = "copper"
    COMBO = "combo"
    SFP = "sfp"


class OmadaPortOperation(StrEnum):
    """Switch port operation mode — critical for LAGG/mirror detection."""

    SWITCHING = "switching"
    MIRRORING = "mirroring"
    AGGREGATING = "aggregating"


class OmadaGatewayPortType(StrEnum):
    """Gateway port hardware type."""

    WAN = "wan"
    WAN_LAN = "wan_lan"
    LAN = "lan"
    SFP_WAN = "sfp_wan"


class OmadaGatewayPortMode(StrEnum):
    """Gateway port operating mode."""

    DISABLED = "disabled"
    WAN = "wan"
    LAN = "lan"


class OmadaPoEMode(StrEnum):
    """Port PoE mode."""

    NONE = "none"
    DISABLED = "disabled"
    ENABLED = "enabled"
    USE_DEVICE_SETTINGS = "use_device_settings"


class OmadaLinkSpeed(StrEnum):
    """Link speed enum matching Omada values."""

    UNKNOWN = "unknown"
    AUTO = "auto"
    SPEED_10_MBPS = "10Mbps"
    SPEED_100_MBPS = "100Mbps"
    SPEED_1_GBPS = "1Gbps"
    SPEED_2_5_GBPS = "2.5Gbps"
    SPEED_10_GBPS = "10Gbps"


class OmadaLinkDuplex(StrEnum):
    """Link duplex enum."""

    UNKNOWN = "unknown"
    AUTO = "auto"
    HALF = "half"
    FULL = "full"


# ============================================================================
# API Envelope & Pagination
# ============================================================================


class OmadaApiEnvelope(BaseModel):
    """Base Omada API response envelope."""

    errorCode: int = Field(default=0)
    msg: str | None = None
    result: Any = None


class OmadaPaginatedData(BaseModel):
    """Common paginated response payload.

    Handles both internal API (``totalRows`` / ``currentPage``) and
    OpenAPI (``totalRows`` / ``page``) field names.
    """

    totalRows: int = 0
    currentPage: int = Field(default=1, alias=None)
    currentSize: int = Field(default=0, alias=None)
    data: list[dict[str, Any]] = Field(default_factory=list)

    model_config = {"populate_by_name": True}

    @field_validator("currentPage", mode="before")
    @classmethod
    def _coerce_page(cls, v: Any) -> int:
        if v is None:
            return 1
        return int(v)

    @field_validator("currentSize", mode="before")
    @classmethod
    def _coerce_size(cls, v: Any) -> int:
        if v is None:
            return 0
        return int(v)


# ============================================================================
# Controller & Site
# ============================================================================


class OmadaControllerInfo(BaseModel):
    """Controller metadata from /api/info."""

    omadacId: str | None = None
    controllerVer: str | None = None
    type: int | None = None
    siteName: str | None = None
    apiVer: int | None = None


class OmadaControllerStatus(BaseModel):
    """Controller system health metrics."""

    cpuUtil: float | None = None
    memUtil: float | None = None
    diskUtil: float | None = None
    uptime: int | None = None
    version: str | None = None
    model: str | None = None
    deviceCount: int | None = None
    siteCount: int | None = None
    clientCount: int | None = None


class OmadaSite(BaseModel):
    """Site model with all available fields."""

    siteId: str | None = None
    id: str | None = None
    name: str | None = None
    region: str | None = None
    timeZone: str | None = None
    scenario: str | None = None
    deviceCount: int | None = None
    gatewayNum: int | None = None
    switchNum: int | None = None
    apNum: int | None = None


# ============================================================================
# Network Device (base for all device types)
# ============================================================================


class OmadaDevice(BaseModel):
    """Full device model used by adapter normalization."""

    type: str | None = None
    mac: str | None = None
    name: str | None = None
    model: str | None = None
    firmwareVersion: str | None = None
    ip: str | None = None
    status: int | None = None
    statusCategory: int | None = None
    uptimeLong: int | None = None
    lastSeen: int | None = None
    cpuUtil: float | int | None = None
    memUtil: float | int | None = None
    clientNum: int | None = None
    download: int | None = None
    upload: int | None = None
    needUpgrade: bool | None = None
    fwDownload: str | None = None
    hardwareVersion: str | None = None
    modelVersion: str | None = None
    serialNumber: str | None = None
    site: str | None = None
    siteId: str | None = None
    portNum: int | None = None
    poe: bool | None = None
    poeRemaining: float | None = None
    temperature: float | None = None
    compoundModel: str | None = None
    showModel: str | None = None

    @field_validator("cpuUtil", "memUtil", mode="before")
    @classmethod
    def _coerce_float(cls, v: Any) -> float | None:
        if v is None:
            return None
        try:
            return float(v)
        except (TypeError, ValueError):
            return None


# ============================================================================
# Switch Port & PoE
# ============================================================================


class OmadaPortPoe(BaseModel):
    """PoE configuration nested inside a port."""

    enable: bool = False
    power: float | None = None
    maxPower: float | None = None
    standard: str | None = None


class OmadaSwitchPort(BaseModel):
    """Individual switch port status and configuration — FULL detail from Omada API."""

    port: int
    portId: str | None = Field(None, alias="id")
    name: str | None = None
    enabled: bool = Field(True, alias="enable")
    disable: bool | None = None  # Omada uses "disable" field
    linkStatus: bool | None = None
    linkSpeed: int | None = None
    duplex: str | None = None
    type: int | None = None  # 1=copper, 2=combo, 3=sfp
    operation: str | None = None  # "switching" | "mirroring" | "aggregating"
    profileId: str | None = None
    profileName: str | None = None
    profileOverrideEnable: bool | None = None
    nativeVlan: int | None = Field(None, alias="pvid")
    taggedVlans: list[int] = Field(default_factory=list)
    nativeNetworkId: str | None = None
    tagNetworkIds: list[str] = Field(default_factory=list)
    untagNetworkIds: list[str] = Field(default_factory=list)
    networkTagsSetting: int | None = None  # 0=ALLOW_ALL, 1=BLOCK_ALL, 2=CUSTOM
    poe: OmadaPortPoe | None = None
    supportPoe: bool | None = None
    poeMode: int | None = None  # mapped from poe field: -1=none, 0=disabled, 1=enabled
    rx: int | None = None
    tx: int | None = None
    rxBytes: int | None = None
    txBytes: int | None = None
    # L2 features
    spanningTreeEnable: bool | None = None
    stpDiscarding: bool | None = None  # from portStatus
    lldpMedEnable: bool | None = None
    topoNotifyEnable: bool | None = None
    loopbackDetectEnable: bool | None = None
    loopbackDetectVlanBasedEnable: bool | None = None
    portIsolationEnable: bool | None = None
    dot1x: int | None = None  # 0=force_unauth, 1=force_auth, 2=auto
    flowControlEnable: bool | None = None
    eeeEnable: bool | None = None
    # Bandwidth/storm control
    bandWidthCtrlType: int | None = None  # 0=off, 1=rate_limit, 2=storm_control
    bandCtrl: dict[str, Any] | None = None
    stormCtrl: dict[str, Any] | None = None
    # Voice VLAN
    voiceNetworkEnable: bool | None = None
    voiceNetworkId: str | None = None
    # Realtime status nested object
    portStatus: dict[str, Any] | None = None
    # Max speed
    maxSpeed: int | None = None
    # Tag IDs
    tagIds: list[str] = Field(default_factory=list)

    model_config = {"populate_by_name": True}

    @property
    def link_status(self) -> OmadaLinkStatus:
        return OmadaLinkStatus.UP if self.linkStatus else OmadaLinkStatus.DOWN

    @property
    def poe_enabled(self) -> bool:
        return self.poe.enable if self.poe else False

    @property
    def poe_power(self) -> float:
        return self.poe.power or 0.0 if self.poe else 0.0

    @property
    def is_lag_member(self) -> bool:
        """Port is participating in a Link Aggregation Group."""
        return (self.operation or "").lower() == "aggregating"

    @property
    def is_mirror_port(self) -> bool:
        """Port is configured as a mirror source/destination."""
        return (self.operation or "").lower() == "mirroring"

    @property
    def port_type_name(self) -> str:
        """Human-readable port type."""
        return {1: "copper", 2: "combo", 3: "sfp"}.get(self.type or 0, "unknown")

    @property
    def stp_enabled(self) -> bool:
        return self.spanningTreeEnable or False

    @property
    def stp_blocking(self) -> bool:
        """Port is in STP discarding/blocking state."""
        if self.stpDiscarding is not None:
            return self.stpDiscarding
        if self.portStatus and isinstance(self.portStatus, dict):
            return self.portStatus.get("stpDiscarding", False)
        return False


class OmadaPortStatistics(BaseModel):
    """Detailed counters for a single switch port."""

    port: int
    rxBytes: int = 0
    txBytes: int = 0
    rxPkts: int = 0
    txPkts: int = 0
    rxErrors: int = 0
    txErrors: int = 0
    rxDropped: int = 0
    txDropped: int = 0
    rxRate: float = 0.0
    txRate: float = 0.0


# ============================================================================
# VLAN / Network
# ============================================================================


class OmadaNetwork(BaseModel):
    """Omada LAN network / VLAN definition."""

    id: str | None = None
    networkId: str | None = None
    name: str | None = None
    vlanId: int | None = None
    subnet: str | None = None
    gateway: str | None = None
    subnetMask: str | None = None
    domain: str | None = None
    purpose: str | None = None
    dhcpEnable: bool | None = Field(None, alias="dhcpEnabled")
    dhcpRange: str | None = None
    igmpSnooping: bool | None = None

    model_config = {"populate_by_name": True}

    @property
    def effective_id(self) -> str | None:
        """Return the best available unique identifier."""
        return self.id or self.networkId


# ============================================================================
# WiFi / SSID
# ============================================================================


class OmadaSsid(BaseModel):
    """WiFi SSID / WLAN configuration."""

    id: str | None = None
    wlanId: str | None = None
    name: str | None = None
    enabled: bool = Field(True, alias="enable")
    ssid: str | None = None
    band: str | None = None
    security: str | None = None
    securityMode: str | None = None
    vlanId: int | None = None
    guestNetwork: bool | None = None
    rateLimit: dict[str, Any] | None = None
    schedule: dict[str, Any] | None = None
    clientIsolation: bool | None = None
    bandSteering: bool | None = None
    broadcast: bool | None = Field(None, description="SSID broadcast/hidden")
    macFilter: dict[str, Any] | None = None

    model_config = {"populate_by_name": True}

    @property
    def display_name(self) -> str:
        """Human-readable name (ssid takes precedence over name)."""
        return self.ssid or self.name or "Unnamed"


# ============================================================================
# Clients
# ============================================================================


class OmadaClient(BaseModel):
    """Connected or known client on the network."""

    mac: str
    name: str | None = None
    hostName: str | None = None
    ip: str | None = None
    osType: str | None = None
    connected: bool = True
    wireless: bool | None = None
    ssid: str | None = None
    apMac: str | None = None
    apName: str | None = None
    switchMac: str | None = None
    switchPort: int | None = None
    vlanId: int | None = None
    rxRate: float | None = None
    txRate: float | None = None
    signalLevel: int | None = None
    signalRank: int | None = None
    rssi: int | None = None
    activity: int | None = None
    uptime: int | None = None
    blocked: bool = False
    guest: bool = False
    manager: bool = False
    download: int | None = None
    upload: int | None = None
    lastSeen: int | None = None

    @property
    def display_name(self) -> str:
        return self.name or self.hostName or self.mac

    @property
    def connection_type(self) -> OmadaClientConnectionType:
        if self.wireless is not None:
            return (
                OmadaClientConnectionType.WIRELESS
                if self.wireless
                else OmadaClientConnectionType.WIRED
            )
        return (
            OmadaClientConnectionType.WIRED
            if self.switchMac
            else OmadaClientConnectionType.WIRELESS
        )


# ============================================================================
# Access Points
# ============================================================================


class OmadaRadioBand(BaseModel):
    """Radio band configuration on an AP."""

    band: str | None = None  # "2g" | "5g" | "6g"
    channel: int | None = None
    channelWidth: str | None = None
    txPower: int | None = None
    txPowerMode: str | None = None
    clients: int = 0


class OmadaAccessPoint(BaseModel):
    """Access point specifics (extends device data)."""

    mac: str
    name: str | None = None
    model: str | None = None
    ip: str | None = None
    status: int | None = None
    firmwareVersion: str | None = None
    clients: int = 0
    radioConfig: list[OmadaRadioBand] = Field(default_factory=list)
    meshEnabled: bool | None = None
    ledEnabled: bool | None = None
    lanPort: dict[str, Any] | None = None
    uptimeLong: int | None = None
    cpuUtil: float | None = None
    memUtil: float | None = None
    lastSeen: int | None = None


# ============================================================================
# Gateway
# ============================================================================


class OmadaWanPort(BaseModel):
    """A single WAN interface on a gateway."""

    portName: str | None = None
    wanType: str | None = None
    ip: str | None = None
    gateway: str | None = None
    dns: list[str] = Field(default_factory=list)
    proto: str | None = None
    mtu: int | None = None
    vlanId: int | None = None
    status: str | None = None  # "online" | "offline" | "standby"
    onlineDetect: bool | None = None


class OmadaGateway(BaseModel):
    """Gateway / router specifics."""

    mac: str
    name: str | None = None
    model: str | None = None
    ip: str | None = None
    status: int | None = None
    firmwareVersion: str | None = None
    wanPorts: list[OmadaWanPort] = Field(default_factory=list)
    lanPorts: list[dict[str, Any]] = Field(default_factory=list)
    portStats: list[dict[str, Any]] = Field(default_factory=list)
    portConfigs: list[dict[str, Any]] = Field(default_factory=list)
    poeSettings: list[dict[str, Any]] = Field(default_factory=list)
    portNum: int | None = None
    supportPoe: bool | None = None
    combinedGateway: bool | None = None
    lldpEnable: bool | None = None
    echoServer: str | None = None
    cpuUtil: float | None = None
    memUtil: float | None = None
    uptimeLong: int | None = None
    lastSeen: int | None = None
    serialNumber: str | None = None
    hardwareVersion: str | None = None
    ledSetting: int | None = None  # 0=off, 1=on, 2=site_settings


class OmadaGatewayPortStatus(BaseModel):
    """Full status for a single gateway port — mirrors the tplink-omada-client data model."""

    port: int = Field(alias="port")
    name: str | None = None
    portDesc: str | None = None  # display_name
    type: int | None = None  # 0=WAN, 1=WAN_LAN, 2=LAN, 3=SFP_WAN
    mode: int | None = None  # 0=WAN, 1=LAN
    status: int | None = None  # link_status: 0=down, 1=up
    speed: int | None = None  # link speed enum
    duplex: int | None = None
    tx: int | None = None  # bytes_tx
    rx: int | None = None  # bytes_rx
    txPkt: int | None = None
    rxPkt: int | None = None
    txRate: float | None = None
    rxRate: float | None = None
    txPktRate: float | None = None
    rxPktRate: float | None = None
    poe: bool | None = None  # poe_active
    ip: str | None = None  # WAN IP
    gateway_ip: str | None = Field(None, alias="gateway")  # WAN gateway
    proto: str | None = None  # "static" | "dhcp" | "pppoe" | "l2tp" | "pptp"
    internetState: int | None = None  # 1=connected, 0=disconnected
    onlineDetection: int | None = None  # online detection passing
    mirroredPorts: list[int] = Field(default_factory=list)
    # IPv6
    wanPortIpv6Config: dict[str, Any] | None = None

    model_config = {"populate_by_name": True}

    @property
    def display_name(self) -> str:
        return self.portDesc or self.name or f"Port {self.port}"

    @property
    def port_type_name(self) -> str:
        return {0: "wan", 1: "wan_lan", 2: "lan", 3: "sfp_wan"}.get(self.type or -1, "unknown")

    @property
    def port_mode_name(self) -> str:
        return {0: "wan", 1: "lan"}.get(self.mode if self.mode is not None else -1, "unknown")

    @property
    def link_up(self) -> bool:
        return self.status == 1

    @property
    def wan_connected(self) -> bool:
        return self.internetState == 1

    @property
    def ipv6_wan_connected(self) -> bool:
        cfg = self.wanPortIpv6Config or {}
        return cfg.get("internetState", 0) == 1

    @property
    def ipv6_enabled(self) -> bool:
        cfg = self.wanPortIpv6Config or {}
        return cfg.get("enable", False)

    @property
    def ipv6_address(self) -> str | None:
        cfg = self.wanPortIpv6Config or {}
        return cfg.get("addr")


class OmadaGatewayPortConfig(BaseModel):
    """Configuration for a single gateway port (PoE, duplex, speed, mirror)."""

    port: int
    duplex: int | None = None
    linkSpeed: int | None = None
    mirrorEnable: bool | None = None
    poeMode: int | None = None  # -1=none, 0=disabled, 1=enabled
    portStat: dict[str, Any] | None = None  # nested OmadaGatewayPortStatus

    @property
    def poe_enabled(self) -> bool:
        return self.poeMode == 1

    @property
    def mirror_enabled(self) -> bool:
        return self.mirrorEnable or False


class OmadaAPLanPortSettings(BaseModel):
    """Access Point LAN port configuration."""

    portName: str | None = None
    supportsVlan: bool | None = None
    localVlanEnable: bool | None = None
    localVlanId: int | None = None
    supportsPoe: bool | None = None
    poeEnable: bool | None = None


class OmadaWanConfig(BaseModel):
    """WAN configuration for a site."""

    wanPortSettings: list[dict[str, Any]] = Field(default_factory=list)
    loadBalancing: dict[str, Any] | None = None
    failover: dict[str, Any] | None = None


class OmadaDhcpPool(BaseModel):
    """DHCP pool extracted from network config."""

    networkId: str | None = None
    networkName: str | None = None
    vlanId: int | None = None
    enabled: bool = False
    startIp: str | None = None
    endIp: str | None = None
    gateway: str | None = None
    subnet: str | None = None
    leaseTime: int | None = None
    dns: list[str] = Field(default_factory=list)


class OmadaFirewallRule(BaseModel):
    """Firewall rule definition."""

    id: str | None = None
    name: str | None = None
    enabled: bool = True
    index: int | None = None
    action: str | None = None  # accept | drop | reject
    protocol: str | None = None
    srcIp: str | None = None
    srcPort: str | None = None
    dstIp: str | None = None
    dstPort: str | None = None
    direction: str | None = None
    srcType: str | None = None
    dstType: str | None = None
    ipGroup: dict[str, Any] | None = None


class OmadaVpnConfig(BaseModel):
    """VPN configuration for a site."""

    ipsec: list[dict[str, Any]] = Field(default_factory=list)
    l2tp: dict[str, Any] | None = None
    pptp: dict[str, Any] | None = None
    openVpn: dict[str, Any] | None = None
    wireGuard: list[dict[str, Any]] = Field(default_factory=list)


# ============================================================================
# Port Profiles
# ============================================================================


class OmadaPortProfile(BaseModel):
    """Switch port profile definition."""

    id: str | None = None
    profileId: str | None = None
    name: str | None = None
    nativeVlan: int | None = None
    taggedVlans: list[int] = Field(default_factory=list)
    untaggedVlans: list[int] = Field(default_factory=list)
    pvid: int | None = None
    type: str | None = None  # "access" | "trunk" | "general"

    @property
    def effective_id(self) -> str | None:
        return self.id or self.profileId


# ============================================================================
# Firmware
# ============================================================================


class OmadaFirmwareInfo(BaseModel):
    """Firmware information for a device."""

    currentVersion: str | None = None
    latestVersion: str | None = None
    needUpgrade: bool = False
    releaseNotes: str | None = None
    downloadUrl: str | None = None
    releaseDate: str | None = None
    fileSize: int | None = None


# ============================================================================
# Metrics
# ============================================================================


class OmadaDeviceMetrics(BaseModel):
    """Device resource metrics snapshot."""

    mac: str | None = None
    cpu: float | None = None
    memory: float | None = None
    uptime: int | None = None
    clients: int | None = None
    download: int | None = None
    upload: int | None = None
    temperature: float | None = None
    timestamp: datetime | None = None

    @property
    def cpu_percent(self) -> float:
        return self.cpu or 0.0

    @property
    def memory_percent(self) -> float:
        return self.memory or 0.0


# ============================================================================
# Normalized FreeSDN models (adapter output layer)
# ============================================================================


class NormalizedPort(BaseModel):
    """Adapter-output port representation for cross-vendor consistency."""

    port_number: int
    port_id: str | None = None
    name: str | None = None
    enabled: bool = True
    status: str = "down"  # "up" | "down"
    speed: int | str | None = None
    duplex: str | int | None = None
    port_type: str = "copper"  # "copper" | "combo" | "sfp"
    operation: str = "switching"  # "switching" | "mirroring" | "aggregating"
    is_lag_member: bool = False
    is_mirror_port: bool = False
    # PoE
    poe_supported: bool = False
    poe_enabled: bool = False
    poe_power: float = 0.0
    poe_max_power: float | None = None
    # VLAN assignment
    native_vlan: int | None = None
    tagged_vlans: list[int] = Field(default_factory=list)
    native_network_id: str | None = None
    tagged_network_ids: list[str] = Field(default_factory=list)
    untagged_network_ids: list[str] = Field(default_factory=list)
    # Profile
    profile_id: str | None = None
    profile_name: str | None = None
    profile_override_enabled: bool = False
    # L2 features
    stp_enabled: bool = False
    stp_discarding: bool = False
    lldp_med_enabled: bool = False
    loopback_detect_enabled: bool = False
    port_isolation_enabled: bool = False
    flow_control_enabled: bool = False
    eee_enabled: bool = False
    dot1x_mode: int | None = None  # 0=force_unauth, 1=force_auth, 2=auto
    # Voice VLAN
    voice_vlan_enabled: bool = False
    voice_vlan_id: str | None = None
    # Bandwidth / storm control
    bandwidth_limit_mode: int | None = None
    bandwidth_ctrl: dict[str, Any] | None = None
    storm_ctrl: dict[str, Any] | None = None
    # SFP module info (populated for SFP ports when module is inserted)
    sfp_vendor: str | None = None
    sfp_part_number: str | None = None
    sfp_serial: str | None = None
    sfp_type: str | None = None  # e.g. "10GBASE-SR", "1000BASE-LX"
    sfp_temperature: float | None = None  # Celsius
    sfp_tx_power: float | None = None  # dBm
    sfp_rx_power: float | None = None  # dBm
    sfp_wavelength: int | None = None  # nm
    # Traffic counters
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_packets: int | None = None
    tx_packets: int | None = None


class NormalizedVlan(BaseModel):
    """Adapter-output VLAN representation for cross-vendor consistency."""

    id: str | None = None
    vlan_id: int | None = None
    name: str | None = None
    gateway: str | None = None
    subnet: str | None = None
    cidr: str | None = None  # e.g. "192.168.1.0/24"
    dhcp_enabled: bool | None = None
    dhcp_range: str | None = None
    dhcp_lease_time: int | None = None  # seconds
    dhcp_dns_servers: list[str] | None = Field(default_factory=list)
    dhcp_pool_start: str | None = None
    dhcp_pool_end: str | None = None
    igmp_snooping: bool | None = None
    domain: str | None = None
    purpose: str | None = None
    internet_access: bool | None = None


class NormalizedSsid(BaseModel):
    """Adapter-output SSID representation for cross-vendor consistency."""

    id: str | None = None
    name: str | None = None
    enabled: bool = True
    vlan_id: int | None = None
    security: str | None = None
    band: str | None = None
    guest_network: bool = False
    client_isolation: bool = False
    band_steering: bool = False
    broadcast: bool = True


class NormalizedClient(BaseModel):
    """Adapter-output client representation for cross-vendor consistency."""

    mac_address: str
    name: str | None = None
    hostname: str | None = None
    ip_address: str | None = None
    connection_type: str = "unknown"  # "wired" | "wireless"
    ssid: str | None = None
    ap_mac: str | None = None
    ap_name: str | None = None
    switch_mac: str | None = None
    switch_port: int | None = None
    vlan_id: int | None = None
    uptime: int | None = None
    signal: int | None = None
    rssi: int | None = None
    snr: int | None = None
    rx_rate: float | None = None
    tx_rate: float | None = None
    download: int | None = None
    upload: int | None = None
    activity: float | None = None  # bytes/sec
    blocked: bool = False
    guest: bool = False
    os_type: str | None = None  # e.g. "Windows", "iOS", "Android"
    device_category: str | None = None  # e.g. "phone", "laptop", "iot"
    channel: int | None = None
    band: str | None = None  # "2.4ghz" | "5ghz" | "6ghz"
    wifi_mode: str | None = None  # "11ax", "11ac", etc.
    last_seen: str | None = None  # ISO timestamp
    first_seen: str | None = None


class NormalizedFirewallRule(BaseModel):
    """Adapter-output firewall rule for cross-vendor consistency."""

    id: str | None = None
    name: str | None = None
    enabled: bool = True
    index: int | None = None
    action: str | None = None  # "accept" | "drop" | "reject"
    protocol: str | None = None
    src_type: str | None = None  # "ip" | "ipGroup" | "network"
    src_ip: str | None = None
    src_port: str | None = None
    src_ip_group_id: str | None = None
    dst_type: str | None = None
    dst_ip: str | None = None
    dst_port: str | None = None
    dst_ip_group_id: str | None = None
    direction: str | None = None
    log: bool = False
    schedule: str | None = None
    comment: str | None = None


class NormalizedPortProfile(BaseModel):
    """Adapter-output port profile for cross-vendor consistency."""

    id: str | None = None
    name: str | None = None
    native_vlan: int | None = None
    tagged_vlans: list[int] = Field(default_factory=list)
    untagged_vlans: list[int] = Field(default_factory=list)
    type: str | None = None  # "access" | "trunk" | "general"
    poe_enabled: bool | None = None
    stp_enabled: bool | None = None
    lldp_enabled: bool | None = None
    bandwidth_limit: dict[str, Any] | None = None


class NormalizedGatewayPort(BaseModel):
    """Adapter-output gateway port for cross-vendor WAN/LAN status."""

    port_number: int
    name: str | None = None
    display_name: str | None = None
    port_type: str = "lan"  # "wan" | "wan_lan" | "lan" | "sfp_wan"
    mode: str = "lan"  # "wan" | "lan"
    link_status: str = "down"  # "up" | "down"
    speed: int | None = None
    duplex: str | None = None
    # PoE
    poe_active: bool = False
    poe_mode: str | None = None  # "none" | "disabled" | "enabled"
    # WAN-specific
    wan_connected: bool = False
    ipv6_wan_connected: bool = False
    online_detection: bool = False
    ip_address: str | None = None
    ipv6_enabled: bool = False
    ipv6_address: str | None = None
    wan_protocol: str | None = None  # "static" | "dhcp" | "pppoe" | "l2tp" | "pptp"
    gateway_ip: str | None = None
    # Mirroring
    mirror_enabled: bool = False
    mirrored_ports: list[int] = Field(default_factory=list)
    # Traffic counters
    bytes_tx: int = 0
    bytes_rx: int = 0
    packets_tx: int | None = None
    packets_rx: int | None = None
    tx_rate: float | None = None
    rx_rate: float | None = None


class NormalizedAPDetail(BaseModel):
    """Adapter-output AP detail with radio config and LAN port settings."""

    mac: str
    name: str | None = None
    model: str | None = None
    ip: str | None = None
    status: str = "unknown"
    firmware_version: str | None = None
    clients: int = 0
    radios: list[dict[str, Any]] = Field(default_factory=list)
    mesh_enabled: bool = False
    led_enabled: bool | None = None
    lan_port_vlan_enabled: bool = False
    lan_port_vlan_id: int | None = None
    lan_port_poe_enabled: bool | None = None
    uptime: int | None = None
    cpu_usage: float | None = None
    memory_usage: float | None = None


class NormalizedSwitchDetail(BaseModel):
    """Adapter-output detailed switch info (ports, capabilities, links)."""

    mac: str
    name: str | None = None
    model: str | None = None
    ip: str | None = None
    status: str = "unknown"
    firmware_version: str | None = None
    hardware_version: str | None = None
    serial_number: str | None = None
    number_of_ports: int = 0
    poe_ports: int = 0
    supports_poe: bool = False
    poe_budget_watts: float | None = None
    poe_consumed_watts: float | None = None
    poe_remaining_watts: float | None = None
    uplink_device_mac: str | None = None
    uplink_device_name: str | None = None
    uplink_port: int | None = None
    downlinks: list[dict[str, Any]] = Field(default_factory=list)
    uptime: int | None = None
    cpu_usage: float | None = None
    memory_usage: float | None = None
    led_setting: int | None = None
    fan_status: list[dict[str, Any]] = Field(default_factory=list)
    psu_status: list[dict[str, Any]] = Field(default_factory=list)
    temperature: float | None = None


class NormalizedGatewayDetail(BaseModel):
    """Adapter-output detailed gateway info — normalized from raw passthrough."""

    mac: str
    name: str | None = None
    model: str | None = None
    ip: str | None = None
    status: str = "unknown"
    firmware_version: str | None = None
    hardware_version: str | None = None
    serial_number: str | None = None
    # Port counts
    number_of_ports: int = 0
    wan_port_count: int = 0
    lan_port_count: int = 0
    supports_poe: bool = False
    # PoE (if gateway supports PoE output)
    poe_budget_watts: float | None = None
    poe_consumed_watts: float | None = None
    # Network
    uplink_ip: str | None = None
    wan_ipv4: str | None = None
    wan_ipv6: str | None = None
    public_ip: str | None = None
    # Link
    uplink_device_mac: str | None = None
    uplink_device_name: str | None = None
    # Features
    combined_gateway: bool = False  # multi-WAN combined mode
    lldp_enabled: bool = False
    echo_server: str | None = None  # online detection target
    led_setting: int | None = None
    # Metrics
    uptime: int | None = None
    cpu_usage: float | None = None
    memory_usage: float | None = None
    # WAN summary
    wan_ports: list[dict[str, Any]] = Field(default_factory=list)
    lan_ports: list[dict[str, Any]] = Field(default_factory=list)


# ============================================================================
# Enterprise Extension Models
# ============================================================================


class NormalizedFirmwareStatus(BaseModel):
    """Per-device firmware status with upgrade availability."""

    mac: str
    device_name: str | None = None
    device_type: str | None = None
    model: str | None = None
    current_version: str | None = None
    latest_version: str | None = None
    needs_upgrade: bool = False
    auto_upgrade: bool = False
    release_notes: str | None = None
    release_date: str | None = None
    download_url: str | None = None
    file_size: int | None = None
    is_upgrading: bool = False
    upgrade_progress: int | None = None
    last_upgrade_time: int | None = None


class NormalizedFirmwareOverview(BaseModel):
    """Fleet-wide firmware compliance summary."""

    total_devices: int = 0
    up_to_date: int = 0
    needs_upgrade: int = 0
    upgrading: int = 0
    unknown: int = 0
    compliance_percent: float = 0.0
    devices: list[NormalizedFirmwareStatus] = Field(default_factory=list)


class NormalizedDHCPReservation(BaseModel):
    """A DHCP static reservation."""

    id: str | None = None
    mac_address: str | None = None
    ip_address: str | None = None
    hostname: str | None = None
    description: str | None = None
    enabled: bool = True
    network_id: str | None = None


class NormalizedIPGroup(BaseModel):
    """An IP group (used in ACLs, firewall rules)."""

    id: str | None = None
    name: str | None = None
    type: str | None = None  # "ip_subnet" | "ip_range" | "ip_list"
    ip_list: list[str] = Field(default_factory=list)
    subnet: str | None = None


class NormalizedStaticRoute(BaseModel):
    """A static route entry."""

    id: str | None = None
    name: str | None = None
    enabled: bool = True
    destination: str | None = None
    subnet_mask: str | None = None
    gateway: str | None = None
    interface: str | None = None
    metric: int | None = None


class NormalizedIPMACBinding(BaseModel):
    """IP-MAC address binding entry."""

    id: str | None = None
    mac_address: str | None = None
    ip_address: str | None = None
    hostname: str | None = None
    enabled: bool = True


class NormalizedRogueAP(BaseModel):
    """Detected rogue access point."""

    mac_address: str | None = None
    ssid: str | None = None
    channel: int | None = None
    band: str | None = None
    signal: int | None = None
    security: str | None = None
    first_seen: int | None = None
    last_seen: int | None = None
    detecting_ap_mac: str | None = None
    detecting_ap_name: str | None = None
    classification: str = "unknown"  # "rogue" | "neighbor" | "known"


class NormalizedChannelUtil(BaseModel):
    """Channel utilization data for RF planning."""

    ap_mac: str
    ap_name: str | None = None
    band: str | None = None  # "2g" | "5g" | "6g"
    channel: int | None = None
    channel_width: str | None = None
    utilization_percent: float = 0.0
    interference_percent: float = 0.0
    noise_floor_dbm: int | None = None
    client_count: int = 0
    tx_utilization: float = 0.0
    rx_utilization: float = 0.0
    timestamp: int | None = None


class NormalizedMACTableEntry(BaseModel):
    """MAC address table entry from a switch."""

    mac_address: str
    vlan_id: int | None = None
    port: int | None = None
    type: str = "dynamic"  # "dynamic" | "static" | "filter"


class NormalizedACLRule(BaseModel):
    """Switch/device ACL rule."""

    id: str | None = None
    name: str | None = None
    enabled: bool = True
    index: int | None = None
    action: str | None = None  # "permit" | "deny"
    protocol: str | None = None
    src_ip: str | None = None
    src_mask: str | None = None
    dst_ip: str | None = None
    dst_mask: str | None = None
    src_port: str | None = None
    dst_port: str | None = None
    direction: str | None = None  # "in" | "out"


class NormalizedEvent(BaseModel):
    """Controller event / alert entry."""

    id: str | None = None
    timestamp: int | None = None
    level: str | None = None  # "info" | "warning" | "error" | "critical"
    category: str | None = None  # "device" | "client" | "system" | "security"
    message: str | None = None
    device_mac: str | None = None
    device_name: str | None = None
    client_mac: str | None = None


class NormalizedPoESchedule(BaseModel):
    """PoE time-based schedule."""

    id: str | None = None
    name: str | None = None
    enabled: bool = True
    ports: list[int] = Field(default_factory=list)
    days: list[str] = Field(default_factory=list)  # ["mon", "tue", ...]
    start_time: str | None = None  # "08:00"
    end_time: str | None = None  # "18:00"
    action: str = "disable"  # "enable" | "disable"


class NormalizedHotspotConfig(BaseModel):
    """Captive portal / hotspot configuration."""

    id: str | None = None
    portal_enabled: bool = False
    portal_type: str | None = None  # "local_password" | "voucher" | "radius" | "external"
    redirect_url: str | None = None
    authentication_timeout: int | None = None
    idle_timeout: int | None = None


class NormalizedVoucher(BaseModel):
    """Hotspot voucher entry."""

    id: str | None = None
    code: str | None = None
    type: str | None = None  # "single" | "multi"
    duration_minutes: int | None = None
    data_limit_mb: int | None = None
    download_limit_kbps: int | None = None
    upload_limit_kbps: int | None = None
    used: bool = False
    used_by: str | None = None
    created_at: str | None = None
    expires_at: str | None = None


class NormalizedSiteSettings(BaseModel):
    """Site-level settings summary."""

    site_id: str | None = None
    site_name: str | None = None
    country: str | None = None
    timezone: str | None = None
    scenario: str | None = None
    led_setting: int | None = None  # 0=off, 1=on, 2=schedule


class NormalizedTopologyDevice(BaseModel):
    """Device entry enriched for topology map with connection info."""

    mac: str
    name: str | None = None
    model: str | None = None
    device_type: str | None = None
    ip: str | None = None
    status: str = "unknown"
    uplink_mac: str | None = None
    uplink_port: int | str | None = None
    uplink_name: str | None = None
    downlinks: list[dict[str, Any]] = Field(default_factory=list)
    connected_clients: int = 0
    layer: int = 0  # 0=gateway, 1=switch, 2=ap/endpoint
