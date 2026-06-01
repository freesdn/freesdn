# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Test discovery scan CIDR size limits.

A user must not be able to request a scan of ``0.0.0.0/0`` (4 billion hosts)
or any other CIDR that would OOM the backend while materializing the target
list. The validator lives in :mod:`app.schemas.discovery`.
"""

import pytest
from pydantic import ValidationError

from app.schemas.discovery import DiscoveryScanRequest, ScanRequestSchema


class TestCIDRSizeLimits:
    """Single-CIDR validator (DiscoveryScanRequest)."""

    def test_rejects_ipv4_any(self):
        """0.0.0.0/0 must be rejected."""
        with pytest.raises(ValidationError, match="too large"):
            DiscoveryScanRequest(cidr="0.0.0.0/0")

    def test_rejects_ipv4_slash_8(self):
        """/8 (16M hosts) must be rejected."""
        with pytest.raises(ValidationError, match="too large"):
            DiscoveryScanRequest(cidr="10.0.0.0/8")

    def test_rejects_ipv4_slash_15(self):
        """/15 (131K hosts) must be rejected — just over the cap."""
        with pytest.raises(ValidationError, match="too large"):
            DiscoveryScanRequest(cidr="10.0.0.0/15")

    def test_rejects_ipv6_any(self):
        """::/0 must be rejected."""
        with pytest.raises(ValidationError):
            DiscoveryScanRequest(cidr="::/0")

    def test_rejects_ipv6_slash_64(self):
        """A /64 is 2**64 hosts — must be rejected."""
        with pytest.raises(ValidationError, match="too large"):
            DiscoveryScanRequest(cidr="2001:db8::/64")

    def test_allows_slash_24(self):
        """/24 (256 hosts) is the common case and must be allowed."""
        req = DiscoveryScanRequest(cidr="192.168.1.0/24")
        assert req.cidr == "192.168.1.0/24"

    def test_allows_slash_16(self):
        """/16 (65k hosts) is the max allowed."""
        req = DiscoveryScanRequest(cidr="10.0.0.0/16")
        assert req.cidr == "10.0.0.0/16"

    def test_allows_single_ipv4(self):
        """A bare IP (==/32) must be allowed."""
        req = DiscoveryScanRequest(cidr="192.168.1.105")
        assert req.cidr.startswith("192.168.1.105")

    def test_allows_ipv6_slash_112(self):
        """/112 (65k IPv6 hosts) is the max allowed."""
        req = DiscoveryScanRequest(cidr="2001:db8::/112")
        assert "2001:db8" in req.cidr

    def test_rejects_malformed(self):
        """Invalid CIDR string is rejected."""
        with pytest.raises(ValidationError):
            DiscoveryScanRequest(cidr="not-a-cidr")

    def test_rejects_multicast(self):
        """Multicast ranges should not be scan targets."""
        with pytest.raises(ValidationError):
            DiscoveryScanRequest(cidr="224.0.0.0/24")

    def test_allows_hyphen_range(self):
        """Short hyphen ranges (192.168.1.10-20) are accepted."""
        req = DiscoveryScanRequest(cidr="192.168.1.10-20")
        assert req.cidr == "192.168.1.10-20"

    def test_rejects_oversized_hyphen_range(self):
        """A hyphen range spanning >65k hosts is rejected."""
        with pytest.raises(ValidationError, match="too large"):
            DiscoveryScanRequest(cidr="10.0.0.0-10.2.0.0")


class TestScanRequestSchemaTargets:
    """List-based validator on the real ScanRequestSchema."""

    def test_rejects_any_target_in_list_over_limit(self):
        """If *any* target in the list is too large, the whole request fails."""
        with pytest.raises(ValidationError, match="too large"):
            ScanRequestSchema(targets=["192.168.1.0/24", "0.0.0.0/0"])

    def test_rejects_oversized_exclude_target(self):
        """Exclude list is validated the same way."""
        with pytest.raises(ValidationError, match="too large"):
            ScanRequestSchema(
                targets=["192.168.1.0/24"],
                exclude_targets=["10.0.0.0/8"],
            )

    def test_allows_normal_scan(self):
        """The common case (/24 + small exclude) must work."""
        req = ScanRequestSchema(
            targets=["192.168.1.0/24", "10.0.5.0/28"],
            exclude_targets=["192.168.1.1"],
        )
        assert len(req.targets) == 2

    def test_requires_at_least_one_target(self):
        """Empty target list is rejected."""
        with pytest.raises(ValidationError):
            ScanRequestSchema(targets=[])

    def test_rejects_too_many_targets(self):
        """More than 256 targets is rejected (DoS prevention)."""
        with pytest.raises(ValidationError):
            ScanRequestSchema(targets=[f"192.168.{i // 256}.{i % 256}" for i in range(300)])
