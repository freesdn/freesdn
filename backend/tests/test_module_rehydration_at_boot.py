# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Regression: enabled modules must be re-hydrated (re-started) at process boot.

A capability audit found that modules — unlike plugins — were never restarted at
startup, so the collector's UDP listeners (and any module on_start side effect)
silently stopped after every redeploy until an admin re-toggled the module. This
locks the boot-time re-hydration helper: it starts enabled modules for active
orgs and skips disabled/inactive/unknown ones.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app import main as main_mod


@pytest.mark.asyncio
async def test_rehydrate_starts_enabled_active_known_modules_only(monkeypatch):
    org_active_a = uuid4()
    org_active_b = uuid4()
    org_inactive = uuid4()

    fake_registry = MagicMock()
    fake_registry.modules = {"collector": object(), "cameras": object()}
    fake_registry.start_module_for_org = AsyncMock()
    monkeypatch.setattr(main_mod, "module_registry", fake_registry)

    active_rows = MagicMock()
    active_rows.all.return_value = [(org_active_a,), (org_active_b,)]  # org_inactive absent
    enabled_rows = MagicMock()
    enabled_rows.all.return_value = [
        ("collector", org_active_a),  # enabled + active + known  -> start
        ("cameras", org_active_b),  # enabled + active + known  -> start
        ("collector", org_inactive),  # org not active            -> skip
        ("ghost_module", org_active_a),  # not in registry           -> skip
    ]
    db = MagicMock()
    db.execute = AsyncMock(side_effect=[active_rows, enabled_rows])

    started = await main_mod._rehydrate_enabled_modules(db)

    assert started == 2
    actual = {(c.args[0], c.args[1]) for c in fake_registry.start_module_for_org.await_args_list}
    assert actual == {("collector", org_active_a), ("cameras", org_active_b)}


@pytest.mark.asyncio
async def test_rehydrate_survives_a_module_start_failure(monkeypatch):
    org = uuid4()
    fake_registry = MagicMock()
    fake_registry.modules = {"collector": object(), "cameras": object()}

    async def _start(module_id, organization_id, db):
        if module_id == "collector":
            raise RuntimeError("UDP bind failed")

    fake_registry.start_module_for_org = AsyncMock(side_effect=_start)
    monkeypatch.setattr(main_mod, "module_registry", fake_registry)

    active_rows = MagicMock()
    active_rows.all.return_value = [(org,)]
    enabled_rows = MagicMock()
    enabled_rows.all.return_value = [("collector", org), ("cameras", org)]
    db = MagicMock()
    db.execute = AsyncMock(side_effect=[active_rows, enabled_rows])

    # collector raises but must not abort the loop — cameras still starts.
    started = await main_mod._rehydrate_enabled_modules(db)
    assert started == 1
