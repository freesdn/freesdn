# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - FreePBX Adapter Models
=====================================

Pydantic models for AMI messages, ARI responses, and FreePBX API data.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ═══════════════════════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════════════════════


class ChannelState(StrEnum):
    DOWN = "down"
    RESERVED = "reserved"
    OFFHOOK = "offhook"
    DIALING = "dialing"
    RING = "ring"
    RINGING = "ringing"
    UP = "up"
    BUSY = "busy"
    UNKNOWN = "unknown"


class CallDirection(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    INTERNAL = "internal"


class ExtensionState(StrEnum):
    IDLE = "idle"
    IN_USE = "in_use"
    BUSY = "busy"
    UNAVAILABLE = "unavailable"
    RINGING = "ringing"
    RINGING_IN_USE = "ringing_in_use"
    ON_HOLD = "on_hold"
    NOT_FOUND = "not_found"


class PeerState(StrEnum):
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    ERROR = "error"


class QueueStrategy(StrEnum):
    RINGALL = "ringall"
    LEASTRECENT = "leastrecent"
    FEWESTCALLS = "fewestcalls"
    RANDOM = "random"
    RRMEMORY = "rrmemory"
    LINEAR = "linear"
    WRANDOM = "wrandom"


# ═══════════════════════════════════════════════════════════════════════════════
# AMI Models
# ═══════════════════════════════════════════════════════════════════════════════


class AMIChannel(BaseModel):
    """Parsed AMI channel information."""

    channel_id: str
    channel_name: str
    state: ChannelState = ChannelState.UNKNOWN
    caller_id_num: str = ""
    caller_id_name: str = ""
    connected_line_num: str = ""
    connected_line_name: str = ""
    context: str = ""
    extension: str = ""
    priority: str = ""
    account_code: str = ""
    unique_id: str = ""
    linked_id: str = ""
    duration: int = 0
    bridged_channel: str | None = None


class AMIPeer(BaseModel):
    """Parsed AMI SIP peer status."""

    peer_name: str
    ip_address: str | None = None
    port: int | None = None
    status: PeerState = PeerState.OFFLINE
    response_time: int | None = None  # ms
    user_agent: str | None = None


class AMIExtensionState(BaseModel):
    """Parsed AMI extension state."""

    extension: str
    context: str = "default"
    state: ExtensionState = ExtensionState.IDLE
    status_text: str = ""


class AMIQueueMember(BaseModel):
    """Queue member info from AMI."""

    queue: str
    member_name: str
    interface: str
    state_interface: str = ""
    membership: str = "dynamic"
    penalty: int = 0
    calls_taken: int = 0
    paused: bool = False
    last_call: int = 0
    last_pause: int = 0
    in_call: bool = False
    status: int = 0  # AST_DEVICE_*


class AMIQueueEntry(BaseModel):
    """Caller waiting in queue from AMI."""

    queue: str
    position: int
    channel: str
    caller_id_num: str = ""
    caller_id_name: str = ""
    connected_line_num: str = ""
    connected_line_name: str = ""
    wait: int = 0  # seconds waiting


class AMICdr(BaseModel):
    """Call Detail Record from AMI CDR event."""

    unique_id: str
    source: str = ""
    destination: str = ""
    dest_context: str = ""
    caller_id: str = ""
    channel: str = ""
    dest_channel: str = ""
    start_time: str = ""
    answer_time: str = ""
    end_time: str = ""
    duration: int = 0
    billable_seconds: int = 0
    disposition: str = ""  # ANSWERED, NO ANSWER, BUSY, FAILED
    ama_flags: str = ""
    account_code: str = ""
    user_field: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# ARI Models
# ═══════════════════════════════════════════════════════════════════════════════


class ARIChannel(BaseModel):
    """ARI channel resource."""

    id: str
    name: str
    state: str = "Down"
    caller: dict[str, str] = Field(default_factory=dict)
    connected: dict[str, str] = Field(default_factory=dict)
    accountcode: str = ""
    dialplan: dict[str, Any] = Field(default_factory=dict)
    creationtime: str = ""
    language: str = "en"


class ARIBridge(BaseModel):
    """ARI bridge resource."""

    id: str
    technology: str = "simple_bridge"
    bridge_type: str = "mixing"
    bridge_class: str = ""
    creator: str = ""
    name: str = ""
    channels: list[str] = Field(default_factory=list)


class ARIEndpoint(BaseModel):
    """ARI endpoint resource."""

    technology: str
    resource: str
    state: str | None = None
    channel_ids: list[str] = Field(default_factory=list)


class ARIPlayback(BaseModel):
    """ARI playback resource."""

    id: str
    media_uri: str = ""
    target_uri: str = ""
    language: str = "en"
    state: str = "queued"


class ARIRecording(BaseModel):
    """ARI live recording resource."""

    name: str
    format: str = "wav"
    state: str = ""
    target_uri: str = ""
    duration: int | None = None
    silence_duration: int | None = None
    talking_duration: int | None = None


class ARIRtpStats(BaseModel):
    """ARI RTP statistics for a channel."""

    channel_uniqueid: str = ""
    local_ssrc: int = 0
    remote_ssrc: int = 0
    txcount: int = 0
    rxcount: int = 0
    txjitter: float = 0.0
    rxjitter: float = 0.0
    rxploss: int = 0
    txploss: int = 0
    rtt: float = 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# FreePBX REST API Models
# ═══════════════════════════════════════════════════════════════════════════════


class FreePBXExtension(BaseModel):
    """FreePBX extension/user resource."""

    extension: str
    name: str = ""
    voicemail: str = ""  # "enabled" / "disabled" / "novm"
    ring_time: int = 0
    call_waiting: str = ""
    call_forward_all: str = ""
    call_forward_busy: str = ""
    call_forward_no_answer: str = ""
    context: str = "from-internal"
    tech: str = "pjsip"  # pjsip or sip
    secret: str = ""  # SIP password
    raw_data: dict[str, Any] = Field(default_factory=dict)


class FreePBXTrunk(BaseModel):
    """FreePBX SIP trunk resource."""

    trunk_id: int | str = ""
    name: str = ""
    tech: str = "pjsip"
    host: str = ""
    port: int = 5060
    username: str = ""
    context: str = ""
    max_channels: int = 0
    disabled: bool = False
    raw_data: dict[str, Any] = Field(default_factory=dict)


class FreePBXRingGroup(BaseModel):
    """FreePBX ring group resource."""

    grpnum: str = ""
    description: str = ""
    strategy: str = "ringall"
    grptime: int = 20
    grplist: str = ""  # comma-separated extensions
    postdest: str = ""  # failover destination
    raw_data: dict[str, Any] = Field(default_factory=dict)


class FreePBXQueue(BaseModel):
    """FreePBX call queue resource."""

    extension: str = ""
    name: str = ""
    strategy: str = "ringall"
    timeout: int = 15
    retry: int = 5
    maxlen: int = 0
    service_level: int = 60
    weight: int = 0
    members: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class FreePBXIVR(BaseModel):
    """FreePBX IVR menu resource."""

    ivr_id: int | str = ""
    name: str = ""
    description: str = ""
    announcement: str = ""
    timeout: int = 10
    loops: int = 3
    entries: list[dict[str, Any]] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class FreePBXCdrRecord(BaseModel):
    """FreePBX CDR record from REST API."""

    unique_id: str = ""
    call_date: str = ""
    src: str = ""
    dst: str = ""
    dst_channel: str = ""
    duration: int = 0
    billsec: int = 0
    disposition: str = ""
    recording_file: str = ""
    did: str = ""
    raw_data: dict[str, Any] = Field(default_factory=dict)
