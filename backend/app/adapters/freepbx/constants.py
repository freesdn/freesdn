# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - FreePBX Adapter Constants
========================================

AMI event types, ARI resource paths, FreePBX API endpoints, and mappings.
"""

# ═══════════════════════════════════════════════════════════════════════════════
# AMI Constants
# ═══════════════════════════════════════════════════════════════════════════════

AMI_DEFAULT_PORT = 5038

# AMI Event types we subscribe to
AMI_CALL_EVENTS = frozenset(
    {
        "Newchannel",
        "Newstate",
        "Hangup",
        "Bridge",
        "BridgeEnter",
        "BridgeLeave",
        "DialBegin",
        "DialEnd",
        "Cdr",
        "Hold",
        "Unhold",
        "Transfer",
        "AttendedTransfer",
        "BlindTransfer",
        "ParkedCall",
        "UnParkedCall",
        "MusicOnHoldStart",
        "MusicOnHoldStop",
    }
)

AMI_EXTENSION_EVENTS = frozenset(
    {
        "ExtensionStatus",
        "PeerStatus",
        "DeviceStateChange",
        "ContactStatus",
        "Registry",
    }
)

AMI_QUEUE_EVENTS = frozenset(
    {
        "QueueCallerJoin",
        "QueueCallerLeave",
        "QueueCallerAbandon",
        "QueueMemberAdded",
        "QueueMemberRemoved",
        "QueueMemberStatus",
        "QueueMemberPaused",
        "QueueMemberPenalty",
        "QueueMemberRinginuse",
        "AgentConnect",
        "AgentComplete",
    }
)

AMI_VOICEMAIL_EVENTS = frozenset(
    {
        "MessageWaiting",
    }
)

AMI_CONFERENCE_EVENTS = frozenset(
    {
        "ConfbridgeJoin",
        "ConfbridgeLeave",
        "ConfbridgeStart",
        "ConfbridgeEnd",
        "ConfbridgeMute",
        "ConfbridgeUnmute",
        "ConfbridgeTalking",
    }
)

ALL_AMI_EVENTS = (
    AMI_CALL_EVENTS
    | AMI_EXTENSION_EVENTS
    | AMI_QUEUE_EVENTS
    | AMI_VOICEMAIL_EVENTS
    | AMI_CONFERENCE_EVENTS
)

# AMI Extension state codes → human-readable
EXTENSION_STATE_MAP = {
    -1: "not_found",
    0: "idle",
    1: "in_use",
    2: "busy",
    4: "unavailable",
    8: "ringing",
    9: "ringing_in_use",
    16: "on_hold",
}

# AMI Peer status values
PEER_STATUS_MAP = {
    "Registered": "online",
    "Unregistered": "offline",
    "Reachable": "online",
    "Lagged": "degraded",
    "Unreachable": "offline",
    "Rejected": "error",
}

# AMI Channel state values
CHANNEL_STATE_MAP = {
    0: "down",
    1: "reserved",
    2: "offhook",
    3: "dialing",
    4: "ring",  # ringing (outbound)
    5: "ringing",  # ringing (inbound)
    6: "up",  # answered
    7: "busy",
    8: "dialing_offhook",
    9: "prering",
    10: "unknown",
}


# ═══════════════════════════════════════════════════════════════════════════════
# ARI Constants
# ═══════════════════════════════════════════════════════════════════════════════

ARI_DEFAULT_PORT = 8088

ARI_ENDPOINTS = {
    "channels": "/ari/channels",
    "bridges": "/ari/bridges",
    "endpoints": "/ari/endpoints",
    "deviceStates": "/ari/deviceStates",
    "mailboxes": "/ari/mailboxes",
    "recordings_stored": "/ari/recordings/stored",
    "recordings_live": "/ari/recordings/live",
    "sounds": "/ari/sounds",
    "playbacks": "/ari/playbacks",
    "applications": "/ari/applications",
    "asterisk": "/ari/asterisk",
    "events": "/ari/events",
}

# ARI WebSocket event types
ARI_CHANNEL_EVENTS = frozenset(
    {
        "StasisStart",
        "StasisEnd",
        "ChannelCreated",
        "ChannelDestroyed",
        "ChannelStateChange",
        "ChannelDtmfReceived",
        "ChannelDialplan",
        "ChannelHangupRequest",
        "ChannelVarset",
        "ChannelConnectedLine",
        "ChannelHold",
        "ChannelUnhold",
        "ChannelTalkingStarted",
        "ChannelTalkingFinished",
    }
)

ARI_BRIDGE_EVENTS = frozenset(
    {
        "BridgeCreated",
        "BridgeDestroyed",
        "BridgeMerged",
        "ChannelEnteredBridge",
        "ChannelLeftBridge",
    }
)

ARI_HANGUP_REASONS = {
    "normal": "normal",
    "busy": "busy",
    "congestion": "congestion",
    "no_answer": "no_answer",
    "timeout": "timeout",
    "rejected": "rejected",
    "answered_elsewhere": "answered_elsewhere",
}


# ═══════════════════════════════════════════════════════════════════════════════
# FreePBX AJAX Endpoints (session-based auth)
# ═══════════════════════════════════════════════════════════════════════════════
#
# These use the admin AJAX API (``/admin/ajax.php?…``) which works with a
# standard PHPSESSID cookie obtained by logging into the web UI.
# The values below are the *query-string* portion only.

FREEPBX_AJAX_ENDPOINTS = {
    # ── Core PBX objects ──
    "extensions": "module=core&command=getExtensionGrid&type=all",
    "trunks": "module=core&command=getJSON&jdata=allTrunks",
    "ring_groups": "module=ringgroups&command=getJSON&jdata=grid",
    "queues": "module=queues&command=getJSON&jdata=grid",
    "ivr": "module=ivr&command=getJSON&jdata=grid",
    "dids": "module=core&command=getJSON&jdata=allDID",
    # ── Routing & call-flow ──
    "outbound_routes": "module=core&command=getJSON&jdata=allRoutes",
    "followme": "module=findmefollow&command=getJSON&jdata=grid",
    "announcements": "module=announcement&command=getJSON&jdata=grid",
    "daynight": "module=daynight&command=getJSON&jdata=grid",
    # ── Ancillary PBX objects ──
    "paging": "module=paging&command=getJSON&jdata=grid",
    "blacklist": "module=blacklist&command=getJSON&jdata=grid",
    "pinsets": "module=pinsets&command=getJSON&jdata=grid",
    "misc_destinations": "module=miscdests&command=getJSON&jdata=grid",
    # ── System / admin ──
    "admin_users": "module=core&command=getJSON&jdata=ampusers",
    "certificates": "module=certman&command=getJSON&jdata=grid",
    # ── Discovered additional endpoints ──
    "time_conditions": "module=timeconditions&command=getJSON&jdata=tcgrid",
    "contacts": "module=contactmanager&command=grid&group=1",
    "system_recordings": "module=recordings&command=grid",
    "music_on_hold": "module=music&command=getJSON&jdata=categories",
    "ami_managers": "module=manager&command=list",
    "backup_jobs": "module=backup&command=backupGrid",
    "callback": "module=callback&command=getJSON&jdata=grid",
    "disa": "module=disa&command=getJSON&jdata=grid",
    "call_recording_modes": "module=callrecording&command=getJSON&jdata=grid",
}

# Legacy OAuth2 REST endpoint paths (kept for reference / future OAuth2 mode)
FREEPBX_API_ENDPOINTS = {
    "extensions": "/admin/api/api/rest/core/users",
    "trunks": "/admin/api/api/rest/trunks/trunks",
    "ring_groups": "/admin/api/api/rest/ringgroups/ringgroups",
    "queues": "/admin/api/api/rest/queues/queues",
    "ivr": "/admin/api/api/rest/ivr/ivrs",
    "cdr": "/admin/api/api/rest/cdr/cdr",
    "voicemail": "/admin/api/api/rest/voicemail/voicemail",
    "token": "/admin/api/api/token",
}

# FreePBX GQL endpoint (v17+)
FREEPBX_GQL_ENDPOINT = "/admin/api/api/gql"

# Default ports
FREEPBX_WEB_PORT = 443


# ═══════════════════════════════════════════════════════════════════════════════
# Connection retry / timing
# ═══════════════════════════════════════════════════════════════════════════════

AMI_RECONNECT_DELAY_BASE = 2.0  # seconds
AMI_RECONNECT_DELAY_MAX = 60.0  # seconds
AMI_KEEPALIVE_INTERVAL = 30.0  # Ping every 30 seconds
AMI_ACTION_TIMEOUT = 10.0  # Default action timeout
AMI_LOGIN_TIMEOUT = 5.0  # Login timeout
AMI_READ_TIMEOUT = 30.0  # Read loop idle timeout (seconds)

ARI_REQUEST_TIMEOUT = 15.0  # HTTP request timeout
ARI_WS_PING_INTERVAL = 20.0  # WebSocket ping interval
ARI_WS_RECONNECT_DELAY = 5.0  # WS reconnect delay

REST_REQUEST_TIMEOUT = 15.0
REST_MAX_RETRIES = 3
REST_RETRY_DELAY = 1.0


# ═══════════════════════════════════════════════════════════════════════════════
# Default app name for ARI Stasis application
# ═══════════════════════════════════════════════════════════════════════════════

FREESDN_ARI_APP = "freesdn"
