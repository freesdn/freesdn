# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Grandstream Adapter Utilities
=============================================

Helper functions for MAC normalization, P-value parsing, model detection, etc.
"""

from __future__ import annotations

import re
from typing import Any

from .constants import get_model_family
from .models import PhoneType


def normalize_mac(mac: str) -> str:
    """Normalize MAC to lowercase colon-separated format."""
    mac_clean = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(mac_clean) != 12:
        return mac.lower()
    return ":".join(mac_clean[i : i + 2] for i in range(0, 12, 2)).lower()


def mac_to_filename(mac: str) -> str:
    """Convert MAC to Grandstream config filename (no separators, lowercase)."""
    return re.sub(r"[^0-9a-fA-F]", "", mac).lower()


def is_grandstream_mac(mac: str) -> bool:
    """
    Check if a MAC address belongs to a Grandstream device.

    Known Grandstream OUIs:
    - 00:0B:82
    - C0:74:AD
    - 7C:2F:80
    """
    mac_clean = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    if len(mac_clean) < 6:
        return False
    oui = mac_clean[:6]
    return oui in {"000B82", "C074AD", "7C2F80"}


def detect_phone_type(model: str) -> PhoneType:
    """Detect phone type from model string."""
    family = get_model_family(model)
    if family:
        type_str = family.get("type", "unknown")
        try:
            return PhoneType(type_str)
        except ValueError:
            pass

    model_upper = model.upper()
    if model_upper.startswith("GRP") or model_upper.startswith("GXP"):
        return PhoneType.IP_PHONE
    if model_upper.startswith("GXV"):
        return PhoneType.VIDEO_PHONE
    if model_upper.startswith("DP"):
        return PhoneType.DECT
    if model_upper.startswith("HT"):
        return PhoneType.ATA
    if model_upper.startswith("GWN"):
        return PhoneType.GATEWAY
    return PhoneType.UNKNOWN


def parse_p_value_int(raw: dict[str, Any], key: str, default: int = 0) -> int:
    """Safely parse an integer P-value."""
    val = raw.get(key, "")
    if isinstance(val, int):
        return val
    if isinstance(val, str) and val.isdigit():
        return int(val)
    return default


def parse_p_value_bool(raw: dict[str, Any], key: str, default: bool = False) -> bool:
    """Safely parse a boolean P-value (0/1)."""
    val = raw.get(key, "")
    if isinstance(val, bool):
        return val
    return str(val) == "1"


def build_blf_value(extension: str, sip_server: str = "") -> str:
    """Build BLF subscription value for a line key."""
    if sip_server:
        return f"{extension}@{sip_server}"
    return extension


def build_speed_dial_value(number: str) -> str:
    """Build speed dial value for a line key."""
    return number
