# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Grandstream Adapter Models
==========================================

Pydantic models for Grandstream phone configuration and status.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PhoneType(StrEnum):
    IP_PHONE = "ip_phone"
    VIDEO_PHONE = "video_phone"
    DECT = "dect"
    ATA = "ata"
    GATEWAY = "gateway"
    UNKNOWN = "unknown"


class RegistrationStatus(StrEnum):
    REGISTERED = "registered"
    UNREGISTERED = "unregistered"
    TRYING = "trying"
    FAILED = "failed"
    UNKNOWN = "unknown"


class LineKeyMode(StrEnum):
    NONE = "none"
    SPEED_DIAL = "speed_dial"
    BLF = "blf"
    PRESENCE = "presence"
    SPEED_DIAL_BLF = "speed_dial_blf"
    DIAL_DTMF = "dial_dtmf"
    LINE = "line"


class PhoneInfo(BaseModel):
    """Basic phone identification info returned by the phone API."""

    mac_address: str = ""
    model: str = ""
    firmware_version: str = ""
    hardware_version: str = ""
    ip_address: str = ""
    serial_number: str = ""
    uptime: int = 0  # seconds


class SIPAccountStatus(BaseModel):
    """Status of a single SIP account on the phone."""

    account_index: int = 0
    active: bool = False
    sip_server: str = ""
    sip_user_id: str = ""
    display_name: str = ""
    registration_status: RegistrationStatus = RegistrationStatus.UNKNOWN
    transport: str = "UDP"


class PhoneStatus(BaseModel):
    """Full phone status including all accounts."""

    info: PhoneInfo = Field(default_factory=PhoneInfo)
    accounts: list[SIPAccountStatus] = Field(default_factory=list)
    network: dict[str, Any] = Field(default_factory=dict)
    active_calls: int = 0


class SIPAccountConfig(BaseModel):
    """Configuration for a single SIP account."""

    account_index: int = 0
    active: bool = True
    account_name: str = ""
    sip_server: str = ""
    sip_server_port: int = 5060
    outbound_proxy: str = ""
    sip_user_id: str = ""
    auth_id: str = ""
    auth_password: str = ""
    display_name: str = ""
    transport: str = "UDP"  # UDP, TCP, TLS
    register_expiry: int = 3600
    preferred_codecs: list[str] = Field(default_factory=lambda: ["PCMU", "PCMA", "G722"])


class LineKeyConfig(BaseModel):
    """Configuration for a single line/BLF key."""

    key_index: int
    mode: LineKeyMode = LineKeyMode.NONE
    value: str = ""  # Extension number or URL
    label: str = ""  # Display label
    account_index: int = 0  # SIP account (0-based)


class PhoneNetworkConfig(BaseModel):
    """Network configuration for the phone."""

    ip_mode: str = "DHCP"  # DHCP, Static, PPPoE
    static_ip: str = ""
    subnet_mask: str = ""
    gateway: str = ""
    dns1: str = ""
    dns2: str = ""
    voice_vlan_id: int | None = None
    voice_vlan_priority: int | None = None
    data_vlan_id: int | None = None
    data_vlan_priority: int | None = None


class PhoneProvisioningConfig(BaseModel):
    """Provisioning settings for a phone."""

    server_address: str = ""
    protocol: str = "HTTP"  # TFTP, HTTP, HTTPS, FTP
    config_file_prefix: str = "cfg"
    auto_provision: bool = True
    provision_interval: int = 60  # minutes
    xml_password: str = ""


class PhoneConfig(BaseModel):
    """Complete phone configuration (used for provisioning)."""

    accounts: list[SIPAccountConfig] = Field(default_factory=list)
    line_keys: list[LineKeyConfig] = Field(default_factory=list)
    network: PhoneNetworkConfig = Field(default_factory=PhoneNetworkConfig)
    provisioning: PhoneProvisioningConfig = Field(default_factory=PhoneProvisioningConfig)

    # General settings
    admin_password: str = ""
    user_password: str = ""
    language: str = "en"
    timezone: str = ""
    ntp_server: str = ""
    ring_volume: int = 5
    speaker_volume: int = 5
    lcd_brightness: int = 50

    # Raw P-values override (for anything not modeled above)
    raw_p_values: dict[str, str] = Field(default_factory=dict)


class PhonebookEntry(BaseModel):
    """A phone directory entry."""

    first_name: str = ""
    last_name: str = ""
    phone_number: str = ""
    account_index: int = 0
    group: str = ""
    speed_dial: str = ""
