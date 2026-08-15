# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Grandstream Adapter Constants
=============================================

P-value configuration keys, API endpoints, model families, etc.
Reference: Grandstream GXP/GRP/GXV/DP phone admin guides.
"""

from typing import Any

ModelFamily = dict[str, Any]

# ═══════════════════════════════════════════════════════════════════════════════
# Phone API endpoints (HTTP on phone's web interface)
# ═══════════════════════════════════════════════════════════════════════════════
#
# All paths reverse-engineered from a live GXP2170 (firmware 1.0.11.106).
# The OLD
# constants (``/cgi-bin/api-send_request``, ``/cgi-bin/api-get_cfg``, etc.)
# were from a much older firmware family and silently 404'd on every GXP we
# tested against a lab fleet of GXP2170 phones. The full endpoint catalog was
# extracted from the GWT permutation bundle ``4FA19191A40777C152A6F77FF1743AF9.cache.js``.
#
# Auth flow (challenge-response, SHA-256 via sjcl.js):
#   1. POST /cgi-bin/access     body: access=sha256_hex(username)        → token
#   2. POST /cgi-bin/dologin    body: username=&password=sha256_hex(pw + token) → sid
#   3. Every subsequent request: append ``&sid=<sid>`` as a query param
#   4. POST /cgi-bin/dorefresh every ~30 s to keep the session alive
#
# Required headers on EVERY request:
#   Origin:  http://<phone-ip>
#   Referer: http://<phone-ip>/

# ── Auth lifecycle ──────────────────────────────────────────────────
PHONE_API_ACCESS = "/cgi-bin/access"  # Step 1: get nonce/token
PHONE_API_DOLOGIN = "/cgi-bin/dologin"  # Step 2: submit hashed password
PHONE_API_DOREFRESH = "/cgi-bin/dorefresh"  # Keep-alive (every ~30 s)
PHONE_API_DOLOGOUT = "/cgi-bin/dologout"  # Tear down session
PHONE_API_GET_LOCKOUT = "/cgi-bin/api-get_lockout"  # "ok" or "lockout"

# ── Config read / write ────────────────────────────────────────────
PHONE_API_CONFIG_GET = "/cgi-bin/config_get"  # GET ?pvalues=K1,K2,…&sid=
PHONE_API_CONFIG_UPDATE = (
    "/cgi-bin/config_update"  # POST [{"alias":"","pvalue":"P35","value":"203"}, …]
)
PHONE_API_METACONFIG = "/cgi-bin/metaconfig_get"  # Meta/UI config

# ── System operations ──────────────────────────────────────────────
# api-sys_operation handles reboot/factory_reset/etc. via "request"
# JSON body. Anti-replay stamp is bound to the request and tracked
# server-side.
PHONE_API_SYS_OPERATION = "/cgi-bin/api-sys_operation"
PHONE_API_GET_SYSTEM_STATUS = "/cgi-bin/api-get_system_status"
PHONE_API_GET_DATABASE = "/cgi-bin/api-get_database_status"
PHONE_API_GET_SECURITY_VER = "/cgi-bin/api-get_security_version"
PHONE_API_GET_USER_SPACE = "/cgi-bin/api-get_user_space_info"
PHONE_API_GET_TIME = "/cgi-bin/api-get_time"
PHONE_API_CHECK_PROCESS = "/cgi-bin/api-check_process_running"

# ── Phone control + presence ───────────────────────────────────────
PHONE_API_GET_PHONE_STATUS = "/cgi-bin/api-get_phone_status"
PHONE_API_GET_LINE_STATUS = "/cgi-bin/api-get_line_status"
PHONE_API_GET_ACCOUNTS = "/cgi-bin/api-get_accounts"
PHONE_API_PHONE_OPERATION = "/cgi-bin/api-phone_operation"  # answer/hangup/hold/transfer
PHONE_API_MAKE_CALL = "/cgi-bin/api-make_call"
PHONE_API_SWAP_ACCOUNT = "/cgi-bin/api-swap_account"
PHONE_API_SEND_IM = "/cgi-bin/api-send_instant_message"

# ── Multi-Purpose Keys (BLF, speed-dial, side-keys) ─────────────────
# Types 1-5 map to: 1=Line Key, 2=Programmable Key, 3=Side Key (ext),
# 4=Softkey, 5=Idle Key. Paged in chunks of 6 (GXP2170 has 48 line keys).
PHONE_API_MPK_DOWNLOAD = "/cgi-bin/api-mpk_download"  # GET ?type=N&page=N[&status=1]
PHONE_API_MPK_SAVE = "/cgi-bin/api-save_mpk"  # POST write

# ── Contacts / phonebook ───────────────────────────────────────────
PHONE_API_PHONEBOOK_DOWNLOAD = "/cgi-bin/phonebook_download"
PHONE_API_SAVE_CONTACT = "/cgi-bin/api-save_contact"
PHONE_API_DELETE_CONTACT = "/cgi-bin/api-delete_contact"
PHONE_API_DELETE_ALL_CONTACT = "/cgi-bin/api-delete_all_contact"
PHONE_API_CONTACT_GROUP = "/cgi-bin/api-add_group"
PHONE_API_CONTACT_GROUP_EDIT = "/cgi-bin/api-edit_delete_group"

# ── Call history / dialplan / ringtone ─────────────────────────────
PHONE_API_CALL_HISTORIES = "/cgi-bin/callhistories"
PHONE_API_DIALPLAN = "/cgi-bin/dialplan"
PHONE_API_RINGTONE = "/cgi-bin/ringtone"

# ── Diagnostics ────────────────────────────────────────────────────
PHONE_API_GET_RTP_INFO = "/cgi-bin/api-get_rtp_info"
PHONE_API_GET_PCAP_LIST = "/cgi-bin/api-get_pcap_list"
PHONE_API_GET_PACKET_STATUS = "/cgi-bin/api-get_packet_status"
PHONE_API_PCAP_CONTROL = "/cgi-bin/api-pcap"
PHONE_API_GET_RECORD_LIST = "/cgi-bin/api-get_record_list"
PHONE_API_GET_DUMP_LIST = "/cgi-bin/api-get_dump_list"
PHONE_API_DELETE_DUMPS = "/cgi-bin/api-delete_core_dumps"
PHONE_API_GET_SCREENSHOT = "/cgi-bin/api-get_screenshot"
PHONE_API_DELETE_SCREENS = "/cgi-bin/api-delete_screens"
PHONE_API_TRACEROUTE_PING = "/cgi-bin/api-traceroute_and_ping"
PHONE_API_PRINT_LOG = "/cgi-bin/printlog"

# ── Firmware + certificates ────────────────────────────────────────
PHONE_API_FIRMWARE_UPGRADE = "/cgi-bin/firmware-upgrade"
PHONE_API_FIRMWARE_UPGRADE_SETUP = "/cgi-bin/setup-firmware-upgrade"
PHONE_API_UPLOAD_CA = "/cgi-bin/upload_CA"
PHONE_API_DELETE_CA = "/cgi-bin/delete_CA"

# ── Password management ────────────────────────────────────────────
PHONE_API_CHANGE_PASSWORD = "/cgi-bin/api-change_password"
PHONE_API_CHANGE_DEFAULT_PASSWORD = "/cgi-bin/api-change_default_password"

# ── Defaults ───────────────────────────────────────────────────────
PHONE_DEFAULT_PORT = 80  # HTTP
PHONE_DEFAULT_HTTPS_PORT = 443
PHONE_DEFAULT_ADMIN_PASSWORD = "admin"
PHONE_DEFAULT_USERNAME = "admin"
PHONE_REQUEST_TIMEOUT = 10.0
PHONE_MAX_RETRIES = 2
PHONE_KEEPALIVE_INTERVAL = 30.0  # seconds — dorefresh cadence (browser uses ~30 s)
PHONE_LOGIN_LOCKOUT_LIMIT = 5  # phone locks user after 5 failed dologins

# ── Legacy aliases (kept so older code paths keep importing) ───────
# These were the old endpoint constants. We keep the names but point
# them at the correct paths — anything importing the OLD names now
# transparently uses the right endpoint.
PHONE_API_LOGIN = PHONE_API_DOLOGIN  # was /cgi-bin/api-send_request
PHONE_API_GET_CONFIG = PHONE_API_CONFIG_GET  # was /cgi-bin/api-get_cfg
PHONE_API_SET_CONFIG = PHONE_API_CONFIG_UPDATE  # was /cgi-bin/api-set_cfg
PHONE_API_REBOOT = PHONE_API_SYS_OPERATION  # unchanged path, different semantics
PHONE_API_GET_STATUS = PHONE_API_GET_PHONE_STATUS  # was /cgi-bin/api-get_status
PHONE_API_PHONEBOOK = PHONE_API_PHONEBOOK_DOWNLOAD


# ═══════════════════════════════════════════════════════════════════════════════
# P-value mapping: SIP Account 1  (prefix P for Account 1)
#
# Multi-account phones use P-value ranges:
#   Account 1: P-values as listed
#   Account 2: typically offset by a known delta (varies by model)
#
# These are the most common P-values across GXP/GRP series.
# ═══════════════════════════════════════════════════════════════════════════════

# ── Account / SIP registration ───────────────────────────────────────

P_ACCOUNT_ACTIVE = "P271"  # 0=No, 1=Yes
P_ACCOUNT_NAME = "P270"  # Account Name (display label)
P_SIP_SERVER = "P47"  # SIP Server / Proxy
P_SIP_SERVER_PORT = "P48"  # SIP Server Port (default 5060)
P_OUTBOUND_PROXY = "P2327"  # Outbound Proxy (Account 1)
P_SIP_USER_ID = "P35"  # SIP User ID (extension number)
P_AUTH_ID = "P36"  # Authenticate ID
P_AUTH_PASSWORD = "P34"  # Authenticate Password
P_DISPLAY_NAME = "P3"  # Display Name (caller ID)
P_SIP_TRANSPORT = "P130"  # 0=UDP, 1=TCP, 2=TLS
P_REGISTER_EXPIRY = "P32"  # Registration Expiration (seconds)

# ── Audio / Codec ────────────────────────────────────────────────────

P_PREFERRED_CODEC_1 = "P57"  # Preferred Vocoder
P_PREFERRED_CODEC_2 = "P58"
P_PREFERRED_CODEC_3 = "P59"
P_PREFERRED_CODEC_4 = "P60"
P_PREFERRED_CODEC_5 = "P61"

# Codec values: 0=PCMU, 2=G726-32, 4=G723, 8=PCMA, 9=G722, 18=G729, 98=iLBC

P_DTMF_MODE = "P73"  # 0=In-audio, 1=RFC2833, 2=SIP INFO
P_JITTER_BUFFER_TYPE = "P380"  # 0=Fixed, 1=Adaptive
P_JITTER_BUFFER_MAX = "P381"  # Max jitter buffer (ms)

# ── Network ──────────────────────────────────────────────────────────

P_IP_MODE = "P8"  # 0=DHCP, 1=Static, 2=PPPoE
P_STATIC_IP = "P9"  # Static IP
P_SUBNET_MASK = "P10"  # Subnet Mask
P_DEFAULT_GATEWAY = "P11"  # Default Gateway
P_DNS_1 = "P12"  # Primary DNS
P_DNS_2 = "P13"  # Secondary DNS
P_VLAN_TAG = "P51"  # PC VLAN Tag (data VLAN)
P_VLAN_PRIORITY = "P87"  # VLAN Priority
P_LAN_VLAN_TAG = "P22"  # LAN/Phone VLAN Tag (voice VLAN)
P_LAN_VLAN_PRIORITY = "P23"  # LAN VLAN Priority

# ── Provisioning ─────────────────────────────────────────────────────

P_CONFIG_SERVER_PATH = "P237"  # Config Server Path (TFTP/HTTP/HTTPS)
P_FIRMWARE_SERVER_PATH = "P192"  # Firmware Server Path
P_PROVISION_PROTOCOL = "P212"  # 0=TFTP, 1=HTTP, 2=HTTPS, 4=FTP
P_PROVISION_SERVER = "P237"  # Provisioning Server Address
P_CONFIG_FILE_PREFIX = "P7019"  # Config file prefix (default: cfg)
P_XML_CONFIG_PASSWORD = "P1359"  # XML Config File Download Password
P_AUTO_PROVISION = "P8465"  # Auto Provision: 0=No, 1=Yes
P_PROVISION_INTERVAL = "P193"  # Auto Provision Interval (minutes, 0=disabled)
P_RANDOMIZED_PROVISION = "P8458"  # Randomized Auto Provisioning: 0=No, 1=Yes

# ── Phone behavior ──────────────────────────────────────────────────

P_ADMIN_PASSWORD = "P2"  # Admin Password
P_USER_PASSWORD = "P196"  # User Password
P_PHONE_LANGUAGE = "P1362"  # Language (0=English, etc.)
P_TIME_ZONE = "P64"  # Time Zone (e.g., "GMT-5")
P_NTP_SERVER = "P30"  # NTP Server
P_SCREEN_SAVER_TIMEOUT = "P2916"  # Screensaver timeout (seconds)
P_LCD_BRIGHTNESS = "P726"  # LCD Brightness (0-100)
P_RING_VOLUME = "P145"  # Ring volume (0-7)
P_SPEAKER_VOLUME = "P154"  # Speaker volume (0-7)
P_CALL_LOG_ENABLE = "P1592"  # Enable call log: 0=No, 1=Yes

# ── BLF / Line Keys ─────────────────────────────────────────────────

# BLF keys start at different P-values per model.
# GRP2601:   P323 (mode), P301 (ext), P302 (name) for key1
# GRP2615:   P323 (mode), P301 (ext), P302 (name) for key1
# Mode: 0=None, 1=SpeedDial, 2=BLF, 3=Presence, 10=SpeedDial+BLF, 16=DialDTMF
P_LINE_KEY_1_MODE = "P323"
P_LINE_KEY_1_VALUE = "P301"
P_LINE_KEY_1_NAME = "P302"
P_LINE_KEY_1_ACCOUNT = "P305"

# Additional keys offset by model-specific increments
# Key N: P323+(N-1)*stride, P301+(N-1)*stride, etc.
LINE_KEY_STRIDE = 6  # Stride between consecutive MPK settings


# ═══════════════════════════════════════════════════════════════════════════════
# Model families and their characteristics
# ═══════════════════════════════════════════════════════════════════════════════

GRANDSTREAM_MODEL_FAMILIES: dict[str, ModelFamily] = {
    "GRP26xx": {
        "models": [
            "GRP2601",
            "GRP2602",
            "GRP2603",
            "GRP2604",
            "GRP2612",
            "GRP2613",
            "GRP2614",
            "GRP2615",
            "GRP2616",
            "GRP2624",
        ],
        "type": "ip_phone",
        "max_accounts": 4,
        "max_line_keys": 24,
        "has_color_lcd": True,
        "has_bluetooth": False,
        "has_wifi": False,
        "poe": True,
    },
    "GXP21xx": {
        "models": ["GXP2135", "GXP2140", "GXP2160", "GXP2170"],
        "type": "ip_phone",
        "max_accounts": 4,
        "max_line_keys": 48,
        "has_color_lcd": True,
        "has_bluetooth": True,
        "has_wifi": False,
        "poe": True,
    },
    "GXP16xx": {
        "models": ["GXP1610", "GXP1615", "GXP1620", "GXP1625", "GXP1628", "GXP1630"],
        "type": "ip_phone",
        "max_accounts": 2,
        "max_line_keys": 8,
        "has_color_lcd": False,
        "has_bluetooth": False,
        "has_wifi": False,
        "poe": True,
    },
    "DP7xx": {
        "models": ["DP720", "DP722", "DP730", "DP750", "DP752", "DP760"],
        "type": "dect",
        "max_accounts": 10,
        "max_line_keys": 0,
        "has_color_lcd": True,
        "has_bluetooth": False,
        "has_wifi": False,
        "poe": False,
    },
    "GXV34xx": {
        "models": ["GXV3450", "GXV3470", "GXV3480"],
        "type": "video_phone",
        "max_accounts": 16,
        "max_line_keys": 0,
        "has_color_lcd": True,
        "has_bluetooth": True,
        "has_wifi": True,
        "poe": True,
    },
    "HT8xx": {
        "models": ["HT801", "HT802", "HT812", "HT813", "HT814", "HT818"],
        "type": "ata",
        "max_accounts": 8,
        "max_line_keys": 0,
        "has_color_lcd": False,
        "has_bluetooth": False,
        "has_wifi": False,
        "poe": False,
    },
    "GWN70xx": {
        "models": ["GWN7000", "GWN7001", "GWN7002", "GWN7003"],
        "type": "gateway",
        "max_accounts": 0,
        "max_line_keys": 0,
        "has_color_lcd": False,
        "has_bluetooth": False,
        "has_wifi": False,
        "poe": True,
    },
}


def get_model_family(model: str) -> ModelFamily | None:
    """Look up the family info for a given model string."""
    model_upper = model.upper()
    for _family_name, family_info in GRANDSTREAM_MODEL_FAMILIES.items():
        models = family_info.get("models")
        if isinstance(models, list) and model_upper in [str(m).upper() for m in models]:
            return family_info
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# XML provisioning constants
# ═══════════════════════════════════════════════════════════════════════════════

# Default config file naming: cfg{MAC}.xml  (MAC lowercase, no colons)
XML_CONFIG_PREFIX = "cfg"
XML_CONFIG_EXTENSION = ".xml"

# Provisioning protocols
PROVISION_PROTOCOL_TFTP = 0
PROVISION_PROTOCOL_HTTP = 1
PROVISION_PROTOCOL_HTTPS = 2
PROVISION_PROTOCOL_FTP = 4

# Directory endpoints
PHONEBOOK_XML_PATH = "/gs_phonebook.xml"

# Codecs
CODEC_MAP = {
    "PCMU": 0,
    "ulaw": 0,
    "G726-32": 2,
    "g726": 2,
    "G723": 4,
    "g723": 4,
    "PCMA": 8,
    "alaw": 8,
    "G722": 9,
    "g722": 9,
    "G729": 18,
    "g729": 18,
    "iLBC": 98,
    "ilbc": 98,
    "opus": 123,
}
