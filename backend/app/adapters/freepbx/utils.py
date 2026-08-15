# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - FreePBX Adapter Utilities
=========================================

Helper functions for normalizing AMI data, parsing channels, etc.
"""

from __future__ import annotations

import re

from .constants import CHANNEL_STATE_MAP, EXTENSION_STATE_MAP, PEER_STATUS_MAP
from .models import (
    AMIChannel,
    AMIExtensionState,
    AMIPeer,
    AMIQueueMember,
    CallDirection,
    ChannelState,
    ExtensionState,
    PeerState,
)


def normalize_extension_state(state_code: int | str) -> ExtensionState:
    """Convert an AMI extension state code to our enum."""
    if isinstance(state_code, str):
        state_code = int(state_code) if state_code.lstrip("-").isdigit() else -1
    label = EXTENSION_STATE_MAP.get(state_code, "not_found")
    try:
        return ExtensionState(label)
    except ValueError:
        return ExtensionState.NOT_FOUND


def normalize_channel_state(state_code: int | str) -> ChannelState:
    """Convert an AMI channel state code to our enum."""
    if isinstance(state_code, str):
        state_code = int(state_code) if state_code.isdigit() else 10
    label = CHANNEL_STATE_MAP.get(state_code, "unknown")
    try:
        return ChannelState(label)
    except ValueError:
        return ChannelState.UNKNOWN


def normalize_peer_status(raw_status: str) -> PeerState:
    """Convert AMI PeerStatus to our enum."""
    label = PEER_STATUS_MAP.get(raw_status, "offline")
    try:
        return PeerState(label)
    except ValueError:
        return PeerState.OFFLINE


def parse_channel_name(channel_name: str) -> tuple[str, str]:
    """
    Parse a channel name like ``PJSIP/1001-0000003a`` into (tech, endpoint).

    Returns:
        (technology, endpoint/resource) tuple.
    """
    match = re.match(r"^([^/]+)/(.+?)(?:-[0-9a-f]+)?$", channel_name, re.IGNORECASE)
    if match:
        return match.group(1), match.group(2)
    return channel_name, ""


def detect_call_direction(
    src: str, dst: str, internal_pattern: str = r"^\d{3,5}$"
) -> CallDirection:
    """
    Detect call direction based on source/destination patterns.

    Default internal pattern matches 3-5 digit extensions.
    """
    src_internal = bool(re.match(internal_pattern, src))
    dst_internal = bool(re.match(internal_pattern, dst))

    if src_internal and dst_internal:
        return CallDirection.INTERNAL
    if src_internal and not dst_internal:
        return CallDirection.OUTBOUND
    return CallDirection.INBOUND


def ami_headers_to_peer(headers: dict[str, str]) -> AMIPeer:
    """Convert raw AMI PeerEntry/EndpointList headers to an AMIPeer model."""
    # SIP/chan_sip format
    if "ObjectName" in headers:
        raw_status = headers.get("Status", "")
        response_time = None
        if "OK" in raw_status:
            # e.g. "OK (15 ms)"
            match = re.search(r"\((\d+)\s*ms\)", raw_status)
            if match:
                response_time = int(match.group(1))

        return AMIPeer(
            peer_name=headers["ObjectName"],
            ip_address=headers.get("IPaddress") if headers.get("IPaddress") != "-none-" else None,
            port=int(headers["IPport"]) if headers.get("IPport", "0").isdigit() else None,
            status=PeerState.ONLINE if raw_status.startswith("OK") else PeerState.OFFLINE,
            response_time=response_time,
            user_agent=headers.get("UserAgent"),
        )

    # PJSIP EndpointList format
    endpoint = headers.get("Endpoint", headers.get("ObjectName", "unknown"))
    return AMIPeer(
        peer_name=endpoint,
        ip_address=None,  # PJSIP EndpointList doesn't include IP by default
        status=(
            PeerState.ONLINE
            if headers.get("DeviceState", "").lower() in ("not_inuse", "inuse", "ringing")
            else PeerState.OFFLINE
        ),
    )


def ami_headers_to_channel(headers: dict[str, str]) -> AMIChannel:
    """Convert raw AMI CoreShowChannel headers to an AMIChannel model."""
    state_code = headers.get("ChannelState", "10")
    return AMIChannel(
        channel_id=headers.get("Uniqueid", headers.get("UniqueID", "")),
        channel_name=headers.get("Channel", ""),
        state=normalize_channel_state(state_code),
        caller_id_num=headers.get("CallerIDNum", ""),
        caller_id_name=headers.get("CallerIDName", ""),
        connected_line_num=headers.get("ConnectedLineNum", ""),
        connected_line_name=headers.get("ConnectedLineName", ""),
        context=headers.get("Context", ""),
        extension=headers.get("Exten", headers.get("Extension", "")),
        priority=headers.get("Priority", ""),
        account_code=headers.get("AccountCode", ""),
        unique_id=headers.get("Uniqueid", headers.get("UniqueID", "")),
        linked_id=headers.get("Linkedid", headers.get("LinkedID", "")),
        duration=int(headers["Duration"]) if headers.get("Duration", "").isdigit() else 0,
        bridged_channel=headers.get("BridgedChannel"),
    )


def ami_headers_to_extension_state(headers: dict[str, str]) -> AMIExtensionState:
    """Convert raw AMI ExtensionStatus headers to an AMIExtensionState."""
    state_code = headers.get("Status", "-1")
    return AMIExtensionState(
        extension=headers.get("Exten", headers.get("Extension", "")),
        context=headers.get("Context", "default"),
        state=normalize_extension_state(state_code),
        status_text=headers.get("StatusText", ""),
    )


def ami_headers_to_queue_member(headers: dict[str, str]) -> AMIQueueMember:
    """Convert raw AMI QueueMember headers to model."""
    return AMIQueueMember(
        queue=headers.get("Queue", ""),
        member_name=headers.get("MemberName", headers.get("Name", "")),
        interface=headers.get("Interface", headers.get("Location", "")),
        state_interface=headers.get("StateInterface", ""),
        membership=headers.get("Membership", "dynamic"),
        penalty=int(headers["Penalty"]) if headers.get("Penalty", "").isdigit() else 0,
        calls_taken=int(headers["CallsTaken"]) if headers.get("CallsTaken", "").isdigit() else 0,
        paused=headers.get("Paused", "0") == "1",
        last_call=int(headers["LastCall"]) if headers.get("LastCall", "").isdigit() else 0,
        last_pause=int(headers["LastPause"]) if headers.get("LastPause", "").isdigit() else 0,
        in_call=headers.get("InCall", "0") == "1",
        status=int(headers["Status"]) if headers.get("Status", "").isdigit() else 0,
    )


def format_sip_channel(tech: str, extension: str) -> str:
    """Format a SIP channel string for AMI Originate."""
    return f"{tech}/{extension}"


def clean_mac_address(mac: str) -> str:
    """Normalize a MAC address to lowercase colon-separated."""
    mac = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(mac) != 12:
        return mac
    return ":".join(mac[i : i + 2] for i in range(0, 12, 2)).lower()
