# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Omada adapter constants.

All magic numbers, endpoint paths, error code mappings, device type/status
translations, rate-limit defaults, and cache TTLs live here.
"""

from __future__ import annotations

from typing import Final

# ============================================================================
# Connection Modes
# ============================================================================

CONNECTION_MODE_LOCAL: Final[str] = "local"
CONNECTION_MODE_CLOUD: Final[str] = "cloud"

# ============================================================================
# Default Connection Parameters
# ============================================================================

DEFAULT_OMADA_PORT: Final[int] = 8043
DEFAULT_TIMEOUT: Final[float] = 30.0
DEFAULT_CONNECT_TIMEOUT: Final[float] = 10.0

# ============================================================================
# Rate Limiting & Idempotency Defaults
# ============================================================================

DEFAULT_RATE_LIMIT_RPM: Final[int] = 60
DEFAULT_RATE_LIMIT_CONCURRENT: Final[int] = 5
DEFAULT_MAX_RETRIES: Final[int] = 3
DEFAULT_RETRY_BACKOFF: Final[float] = 1.0
REBOOT_COOLDOWN_SECONDS: Final[int] = 60

# ============================================================================
# Session / Auth
# ============================================================================

SESSION_COOKIE_NEW: Final[str] = "TPOMADA_SESSIONID"
SESSION_COOKIE_LEGACY: Final[str] = "TPEAP_SESSIONID"

# ============================================================================
# Cloud / OpenAPI
# ============================================================================

# Regional cloud controller base URLs (northbound OpenAPI)
CLOUD_REGION_URLS: Final[dict[str, str]] = {
    "use1": "https://use1-omada-northbound.tplinkcloud.com",
    "euw1": "https://euw1-omada-northbound.tplinkcloud.com",
    "aps1": "https://aps1-omada-northbound.tplinkcloud.com",
    # Aliases for convenience
    "us": "https://use1-omada-northbound.tplinkcloud.com",
    "eu": "https://euw1-omada-northbound.tplinkcloud.com",
    "asia": "https://aps1-omada-northbound.tplinkcloud.com",
}

# OAuth2 token endpoints (cloud)
PATH_CLOUD_TOKEN: Final[str] = "/openapi/authorize/token"
PATH_CLOUD_CODE_LOGIN: Final[str] = "/openapi/authorize/login"

# OpenAPI prefix (used for both local-openapi and cloud)
PATH_OPENAPI_PREFIX_TEMPLATE: Final[str] = "/openapi/v1/{controller_id}"

# Cloud OAuth2 defaults
CLOUD_ACCESS_TOKEN_LIFETIME: Final[int] = 7200  # 2 hours
CLOUD_REFRESH_TOKEN_LIFETIME: Final[int] = 1209600  # 14 days
CLOUD_RATE_LIMIT_RPS: Final[int] = 10  # 10 req/sec per controller
CLOUD_DEFAULT_RPM: Final[int] = 300  # conservative: 5 req/sec

# Cloud-specific Omada error codes
OMDADA_ERROR_AUTH_CODE_ONLY: Final[int] = -44118  # endpoint requires authorization_code mode

# ============================================================================
# Omada API Error Codes
# ============================================================================

OMADA_SUCCESS: Final[int] = 0
OMADA_ERROR_GENERIC: Final[int] = -1
OMADA_ERROR_SESSION_EXPIRED: Final[int] = -1001
OMADA_ERROR_CSRF_INVALID: Final[int] = -1002
OMADA_ERROR_PERMISSION_DENIED: Final[int] = -1003
OMADA_ERROR_LOGIN_FAILED: Final[int] = -30101
OMADA_ERROR_ACCOUNT_LOCKED: Final[int] = -30109
OMADA_ERROR_INVALID_PARAMS: Final[int] = -40001
OMADA_ERROR_NOT_FOUND: Final[int] = -40002
OMADA_ERROR_DUPLICATE: Final[int] = -40003
OMADA_ERROR_DEVICE_BUSY: Final[int] = -40004
OMADA_ERROR_DEVICE_OFFLINE: Final[int] = -40005

# Mapping from Omada error codes to domain exception class names.
# Used by OmadaApiClient._handle_error_code() for structured translation.
OMADA_ERROR_TO_DOMAIN: Final[dict[int, str]] = {
    OMADA_ERROR_SESSION_EXPIRED: "OmadaSessionExpiredError",
    OMADA_ERROR_CSRF_INVALID: "OmadaSessionExpiredError",
    OMADA_ERROR_PERMISSION_DENIED: "OmadaAuthorizationError",
    OMADA_ERROR_LOGIN_FAILED: "OmadaAuthError",
    OMADA_ERROR_ACCOUNT_LOCKED: "OmadaAuthError",
    OMADA_ERROR_INVALID_PARAMS: "OmadaValidationError",
    OMADA_ERROR_NOT_FOUND: "OmadaNotFoundError",
    OMADA_ERROR_DUPLICATE: "OmadaValidationError",
    OMADA_ERROR_DEVICE_BUSY: "OmadaApiError",
    OMADA_ERROR_DEVICE_OFFLINE: "OmadaDeviceOfflineError",
}

# Retryable HTTP status codes (gateway/server errors)
RETRYABLE_HTTP_STATUS: Final[set[int]] = {429, 502, 503, 504}

# Omada error codes that trigger automatic session refresh
SESSION_EXPIRED_CODES: Final[set[int]] = {
    OMADA_ERROR_SESSION_EXPIRED,
    OMADA_ERROR_CSRF_INVALID,
}

# ============================================================================
# Device Type & Status Maps
# ============================================================================

# Omada API type strings → FreeSDN canonical type IDs
DEVICE_TYPE_MAP: Final[dict[str, str]] = {
    "ap": "access_point",
    "switch": "switch",
    "gateway": "gateway",
}

# Reverse mapping: FreeSDN type → Omada API type
FREESDN_TO_OMADA_TYPE: Final[dict[str, str]] = {
    "access_point": "ap",
    "switch": "switch",
    "gateway": "gateway",
}

# Omada numeric device status → human-readable label
# Newer Omada firmware uses statusCategory (0=offline, 1=online) for high-level,
# while status field has fine-grained values (0-5 for legacy, 14=connected for v5+).
DEVICE_STATUS_MAP: Final[dict[int, str]] = {
    0: "offline",
    1: "online",
    2: "provisioning",  # Omada "pending" → closest valid DeviceStatus
    3: "adopting",
    4: "provisioning",
    5: "online",  # Omada "upgrading" → treat as online (still reachable)
    14: "online",  # Omada v5+ "connected/running"
}

# statusCategory is a simpler/more reliable indicator on newer firmware
DEVICE_STATUS_CATEGORY_MAP: Final[dict[int, str]] = {
    0: "offline",
    1: "online",
    2: "degraded",
}

# Omada device-type → API endpoint prefix (for type-specific endpoints)
DEVICE_TYPE_ENDPOINT: Final[dict[str, str]] = {
    "ap": "eaps",
    "switch": "switches",
    "gateway": "gateways",
    "access_point": "eaps",
}

# ============================================================================
# Endpoint Path Templates
# ============================================================================

# Controller-level paths (no site context) — local internal API
PATH_INFO: Final[str] = "/api/info"
PATH_LOGIN_TEMPLATE: Final[str] = "/{controller_id}/api/v2/login"
PATH_LOGOUT_TEMPLATE: Final[str] = "/{controller_id}/api/v2/logout"
PATH_API_PREFIX_TEMPLATE: Final[str] = "/{controller_id}/api/v2"

# Controller maintenance endpoints
PATH_CONTROLLER_STATUS: Final[str] = "/maintenance/controllerStatus"
PATH_SYSTEM_INFO: Final[str] = "/maintenance/sysInfo"

# Site-scoped path templates  (/sites/{site_id}/...)
PATH_SITES: Final[str] = "/sites"
PATH_SITE: Final[str] = "/sites/{site_id}"
PATH_DEVICES: Final[str] = "/sites/{site_id}/devices"
PATH_DEVICE: Final[str] = "/sites/{site_id}/devices/{mac}"

# Switch endpoints
PATH_SWITCH_PORTS: Final[str] = "/sites/{site_id}/switches/{mac}/ports"
PATH_SWITCH_PORT: Final[str] = "/sites/{site_id}/switches/{mac}/ports/{port_id}"
PATH_SWITCH_PORT_STATS: Final[str] = "/sites/{site_id}/switches/{mac}/ports/{port_id}/stats"

# AP endpoints
PATH_APS: Final[str] = "/sites/{site_id}/eaps"
PATH_AP: Final[str] = "/sites/{site_id}/eaps/{mac}"
PATH_AP_LED: Final[str] = "/sites/{site_id}/eaps/{mac}/led"

# Gateway endpoints
PATH_GATEWAYS: Final[str] = "/sites/{site_id}/gateways"
PATH_GATEWAY: Final[str] = "/sites/{site_id}/gateways/{mac}"

# Network / VLAN endpoints
PATH_NETWORKS: Final[str] = "/sites/{site_id}/setting/lan/networks"
PATH_NETWORK: Final[str] = "/sites/{site_id}/setting/lan/networks/{network_id}"

# WiFi / SSID endpoints
PATH_SSIDS: Final[str] = "/sites/{site_id}/setting/wlans"
PATH_SSID: Final[str] = "/sites/{site_id}/setting/wlans/{ssid_id}"

# Client endpoints
PATH_CLIENTS: Final[str] = "/sites/{site_id}/clients"
PATH_CLIENT_HISTORY: Final[str] = "/sites/{site_id}/insight/clients"
PATH_CLIENT_CMD: Final[str] = "/sites/{site_id}/cmd/clients/{mac}"

# Port profile endpoints
PATH_PORT_PROFILES: Final[str] = "/sites/{site_id}/setting/lan/profileOverrides"
PATH_PORT_PROFILE: Final[str] = "/sites/{site_id}/setting/lan/profileOverrides/{profile_id}"

# Gateway config endpoints
PATH_WAN_CONFIG: Final[str] = "/sites/{site_id}/setting/wan"
PATH_FIREWALL_RULES: Final[str] = "/sites/{site_id}/setting/firewall/rules"
PATH_VPN_CONFIG: Final[str] = "/sites/{site_id}/setting/vpn"

# Device command endpoints (fallback paths for version compatibility)
PATH_DEVICE_REBOOT: Final[str] = "/sites/{site_id}/cmd/devices/{mac}/reboot"
PATH_DEVICE_ADOPT: Final[str] = "/sites/{site_id}/cmd/devices/{mac}/adopt"
PATH_DEVICE_FORGET: Final[str] = "/sites/{site_id}/cmd/devices/{mac}/forget"

# Firmware endpoints (with fallback paths)
PATH_FIRMWARE_INFO: Final[str] = "/sites/{site_id}/devices/{mac}/firmware"
PATH_FIRMWARE_INFO_ALT: Final[str] = "/sites/{site_id}/firmware/devices/{mac}"
PATH_FIRMWARE_UPGRADE: Final[str] = "/sites/{site_id}/cmd/devices/{mac}/upgrade"
PATH_FIRMWARE_UPGRADE_ALT: Final[str] = "/sites/{site_id}/devices/{mac}/firmware/upgrade"
PATH_FIRMWARE_LIST: Final[str] = "/sites/{site_id}/firmware"
PATH_FIRMWARE_LOG: Final[str] = "/sites/{site_id}/firmware/upgradeLog"

# Diagnostic endpoints
PATH_DEVICE_CABLE_TEST: Final[str] = "/sites/{site_id}/cmd/devices/{mac}/cableTest"
PATH_DEVICE_PING: Final[str] = "/sites/{site_id}/cmd/devices/{mac}/ping"
PATH_DEVICE_TRACEROUTE: Final[str] = "/sites/{site_id}/cmd/devices/{mac}/traceroute"

# Switch advanced endpoints
PATH_SWITCH_IGMP: Final[str] = "/sites/{site_id}/switches/{mac}/igmpSnooping"
PATH_SWITCH_ACL: Final[str] = "/sites/{site_id}/switches/{mac}/acl"
PATH_SWITCH_LAGS: Final[str] = "/sites/{site_id}/switches/{mac}/lags"
PATH_SWITCH_MIRROR: Final[str] = "/sites/{site_id}/switches/{mac}/mirror"
PATH_SWITCH_MAC_TABLE: Final[str] = "/sites/{site_id}/switches/{mac}/macTable"
PATH_SWITCH_DOT1X: Final[str] = "/sites/{site_id}/setting/lan/dot1x"

# Site-level switch settings
PATH_STP_CONFIG: Final[str] = "/sites/{site_id}/setting/lan/stp"
PATH_QOS_CONFIG: Final[str] = "/sites/{site_id}/setting/lan/qos"
PATH_DHCP_SNOOPING: Final[str] = "/sites/{site_id}/setting/lan/dhcpSnooping"
PATH_JUMBO_FRAME: Final[str] = "/sites/{site_id}/setting/lan/jumboFrame"

# AP advanced endpoints
PATH_AP_RADIOS: Final[str] = "/sites/{site_id}/eaps/{mac}/radios"
PATH_AP_RF_SCAN: Final[str] = "/sites/{site_id}/eaps/{mac}/rfscan"
PATH_AP_ROGUE: Final[str] = "/sites/{site_id}/insight/rogueAps"
PATH_AP_CHANNEL_UTIL: Final[str] = "/sites/{site_id}/stat/channelUtilization"

# Site-level radio settings
PATH_SITE_RADIO_SETTINGS: Final[str] = "/sites/{site_id}/setting/wlans/radioSetting"
PATH_SITE_RADIO_2G: Final[str] = "/sites/{site_id}/setting/wlans/radioSetting/2g"
PATH_SITE_RADIO_5G: Final[str] = "/sites/{site_id}/setting/wlans/radioSetting/5g"
PATH_SITE_RADIO_6G: Final[str] = "/sites/{site_id}/setting/wlans/radioSetting/6g"

# Hotspot / captive portal
PATH_HOTSPOT: Final[str] = "/sites/{site_id}/setting/hotspot"
PATH_PORTAL: Final[str] = "/sites/{site_id}/setting/captivePortal"
PATH_PORTAL_VOUCHERS: Final[str] = "/sites/{site_id}/hotspot/vouchers"

# IP group / network group
PATH_IP_GROUPS: Final[str] = "/sites/{site_id}/setting/firewall/ipGroups"
PATH_IP_GROUP: Final[str] = "/sites/{site_id}/setting/firewall/ipGroups/{group_id}"

# URL filtering
PATH_URL_FILTER: Final[str] = "/sites/{site_id}/setting/firewall/urlFilter"

# DHCP reservations
PATH_DHCP_RESERVATIONS: Final[str] = (
    "/sites/{site_id}/setting/lan/networks/{network_id}/dhcpReservations"
)

# Static routes
PATH_STATIC_ROUTES: Final[str] = "/sites/{site_id}/setting/routing/static"
PATH_STATIC_ROUTE: Final[str] = "/sites/{site_id}/setting/routing/static/{route_id}"

# IP-MAC binding
PATH_IP_MAC_BINDINGS: Final[str] = "/sites/{site_id}/setting/lan/ipMacBinding"

# DDNS
PATH_DDNS_CONFIG: Final[str] = "/sites/{site_id}/setting/wan/ddns"

# Gateway advanced endpoints
PATH_GATEWAY_WAN_FAILOVER: Final[str] = "/sites/{site_id}/setting/wan/failover"
PATH_GATEWAY_LOAD_BALANCE: Final[str] = "/sites/{site_id}/setting/wan/loadBalance"

# Controller maintenance
PATH_CONTROLLER_BACKUP: Final[str] = "/maintenance/backup"
PATH_CONTROLLER_RESTORE: Final[str] = "/maintenance/restore"
PATH_CONTROLLER_LOGS: Final[str] = "/maintenance/logs"

# Site settings
PATH_SITE_SETTINGS: Final[str] = "/sites/{site_id}/setting"
PATH_SITE_COUNTRY: Final[str] = "/sites/{site_id}/setting/country"
PATH_SITE_TIME: Final[str] = "/sites/{site_id}/setting/time"

# Events / alerts
PATH_EVENTS: Final[str] = "/sites/{site_id}/events"
PATH_ALERTS: Final[str] = "/sites/{site_id}/alerts"
PATH_NOTIFICATIONS: Final[str] = "/sites/{site_id}/setting/notification"

# PoE schedule
PATH_POE_SCHEDULE: Final[str] = "/sites/{site_id}/setting/lan/poeSchedule"

# ============================================================================
# Cache TTL Defaults (seconds)
# ============================================================================

CACHE_TTL_SITES: Final[int] = 60
CACHE_TTL_DEVICES: Final[int] = 30
CACHE_TTL_PORTS: Final[int] = 15
CACHE_TTL_CLIENTS: Final[int] = 30
CACHE_TTL_CONFIG: Final[int] = 60
CACHE_TTL_CONTROLLER: Final[int] = 15
CACHE_TTL_FIRMWARE: Final[int] = 300
CACHE_TTL_EVENTS: Final[int] = 15
CACHE_TTL_ROGUE_APS: Final[int] = 60
CACHE_TTL_CHANNEL_UTIL: Final[int] = 30
CACHE_TTL_MAC_TABLE: Final[int] = 15

# ============================================================================
# Minimum Supported Controller Versions
# ============================================================================

MIN_SUPPORTED_MAJOR: Final[int] = 5
FULLY_SUPPORTED_MINOR_MIN: Final[int] = 9

# ============================================================================
# Pagination Defaults
# ============================================================================

DEFAULT_PAGE_SIZE_DEVICES: Final[int] = 200
DEFAULT_PAGE_SIZE_CLIENTS: Final[int] = 500
DEFAULT_PAGE_SIZE_SSIDS: Final[int] = 100
DEFAULT_PAGE_SIZE_SITES: Final[int] = 100

# OpenAPI uses different pagination param names
OPENAPI_PAGE_PARAM: Final[str] = "page"
OPENAPI_PAGE_SIZE_PARAM: Final[str] = "pageSize"
LOCAL_PAGE_PARAM: Final[str] = "currentPage"
LOCAL_PAGE_SIZE_PARAM: Final[str] = "currentPageSize"
