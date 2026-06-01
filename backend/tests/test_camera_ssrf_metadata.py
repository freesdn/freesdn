# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Camera IP SSRF guard — cloud-metadata blocking (security review finding).

_is_address_allowed must reject cloud-metadata IPs unconditionally — including
the ones outside 169.254/16 (Alibaba 100.100.100.200 in CGNAT, AWS IPv6
fd00:ec2::254 in ULA) that were previously only blocked when the opt-in
BLOCK_PRIVATE_CAMERA_SUBNETS flag was set — so a camera/NVR can never be pointed
at a metadata endpoint, and the snapshot fetch (which re-validates resolved IPs)
can't be DNS-rebound onto one.
"""
from __future__ import annotations

import ipaddress

import pytest

from app.modules.cameras.schemas import _is_address_allowed


@pytest.mark.parametrize(
    "ip",
    [
        "169.254.169.254",  # AWS/Azure/GCP IMDS (link-local)
        "100.100.100.200",  # Alibaba Cloud metadata (CGNAT 100.64/10)
        "fd00:ec2::254",    # AWS IMDS over IPv6 (ULA fc00::/7)
    ],
)
def test_cloud_metadata_ips_always_blocked(ip: str) -> None:
    assert _is_address_allowed(ipaddress.ip_address(ip)) is False


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "0.0.0.0", "fe80::1"])
def test_loopback_and_linklocal_blocked(ip: str) -> None:
    assert _is_address_allowed(ipaddress.ip_address(ip)) is False


def test_onprem_private_camera_allowed_by_default() -> None:
    # Default deployment (BLOCK_PRIVATE_CAMERA_SUBNETS unset) must still allow a
    # normal on-prem camera — the metadata fix must not break legitimate use.
    assert _is_address_allowed(ipaddress.ip_address("192.168.1.50")) is True
    assert _is_address_allowed(ipaddress.ip_address("10.20.30.40")) is True
