# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Dry-run preview for OPNsense firewall staged writes.

``GatewayService.preflight_preview`` classifies a prospective staged change's
destructiveness (and whether it will need confirmed=true at apply time) without
staging anything or touching the device. The preview must MATCH the runtime gate:
catastrophic for opnsense system-ops + ALL deletes; destructive (warn-only) for
service stop/restart; and a strict no-op (safe) for non-opnsense features, since
the gate (enforce_opnsense_preflight) only acts on opnsense.* features.
"""
from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest

from app.modules.firewall.gateway_service import GatewayService


def _svc() -> GatewayService:
    svc = GatewayService(MagicMock())

    async def _get_gw(gw_id, org_id):  # tenant-scope stub
        return MagicMock()

    svc._get_gw = _get_gw  # type: ignore[assignment]
    return svc


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "feature,operation,risk,confirm",
    [
        ("opnsense.firewall.rule", "delete", "catastrophic", True),
        ("opnsense.nat.port_forward", "delete", "catastrophic", True),
        ("opnsense.system.reboot", "create", "catastrophic", True),
        ("opnsense.system.backup_restore", "create", "catastrophic", True),
        ("opnsense.system.backup_delete", "create", "catastrophic", True),
        ("opnsense.firewall.rule", "create", "safe", False),
        ("opnsense.firewall.apply", "create", "safe", False),
        ("opnsense.services.restart", "create", "destructive", False),
        # Non-opnsense feature → the opnsense gate doesn't apply → previews safe.
        ("mikrotik.firewall.rule", "delete", "safe", False),
        ("pfsense.firewall.rule", "delete", "safe", False),
    ],
)
async def test_preflight_preview_matches_gate(feature, operation, risk, confirm) -> None:
    out = await _svc().preflight_preview(uuid.uuid4(), uuid.uuid4(), feature, operation, {})
    assert out["feature"] == feature
    assert out["risk"] == risk
    assert out["requires_confirmation"] is confirm
