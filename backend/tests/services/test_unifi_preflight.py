# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""UniFi pre-flight gate — catastrophic staged ops require confirmed=true.

Regression for the convergence-sweep finding: UniFi was the only adapter in
_CATASTROPHIC_EVENT_PREFIXES without a central enforce_* gate, so the devices
applier (unifi.devices.restart/.disable) could be applied with force=True and no
confirmation, unlike every other vendor.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.services.adapter_unifi_preflight import enforce_unifi_preflight


class TestUnifiPreflightBlocksUnconfirmedCatastrophic:
    @pytest.mark.parametrize(
        "feature,operation",
        [
            ("unifi.devices.restart", "update"),
            ("unifi.devices.disable", "update"),
            ("unifi.devices.upgrade", "update"),  # firmware flash + reboot
            ("unifi.clients.forget", "delete"),
            ("unifi.firewall.rule", "delete"),  # ANY delete is catastrophic
        ],
    )
    def test_blocks_without_confirmed(self, feature: str, operation: str) -> None:
        with pytest.raises(HTTPException) as exc:
            enforce_unifi_preflight(feature, operation, {})
        assert exc.value.status_code == 409
        assert "confirmed=true" in exc.value.detail

    @pytest.mark.parametrize(
        "feature,operation",
        [
            ("unifi.devices.restart", "update"),
            ("unifi.devices.disable", "update"),
            ("unifi.devices.upgrade", "update"),
            ("unifi.firewall.rule", "delete"),
        ],
    )
    def test_allows_with_confirmed(self, feature: str, operation: str) -> None:
        # confirmed=true → no raise
        enforce_unifi_preflight(feature, operation, {"confirmed": True})


class TestUnifiPreflightPassthrough:
    def test_safe_unifi_op_not_blocked(self) -> None:
        # A non-catastrophic, non-delete UniFi op needs no confirmation.
        enforce_unifi_preflight("unifi.devices.port_override", "update", {})

    @pytest.mark.parametrize(
        "feature",
        ["opnsense.system.reboot", "proxmox.node.reboot", "bulk.device.forget", None],
    )
    def test_noop_for_non_unifi_features(self, feature) -> None:
        # The gate is prefix-scoped — other vendors are handled by their own gates.
        enforce_unifi_preflight(feature, "delete", {})
