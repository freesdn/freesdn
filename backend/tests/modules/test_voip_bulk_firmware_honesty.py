# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
"Bulk firmware upgrade" records a target; it does not upgrade a phone.

``bulk_update_firmware`` writes ``firmware_target`` and
``firmware_upgrade_scheduled`` and nothing reads either column to push firmware.
The endpoint was documented as scheduling an upgrade and answered only with
counts, so a caller saw "succeeded: N". The answer now says what happened.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.modules.voip import api


async def test_bulk_firmware_says_no_firmware_is_pushed(monkeypatch: pytest.MonkeyPatch) -> None:
    service = SimpleNamespace(
        bulk_update_firmware=AsyncMock(
            return_value={"total": 2, "succeeded": 2, "failed": 0, "skipped": 0, "errors": []}
        )
    )
    monkeypatch.setattr(api, "_set_org", lambda *_a, **_k: None)
    data = api.BulkFirmwareRequest(phone_ids=[uuid4(), uuid4()], target_version="1.0.11.23")
    out = await api.bulk_firmware_upgrade(data, current_user=SimpleNamespace(), service=service)
    assert out["succeeded"] == 2
    assert "recorded for 2 phone(s)" in out["message"]
    assert "does not push firmware" in out["message"]


def test_nothing_reads_the_firmware_target_to_push_it() -> None:
    """If something starts pushing firmware from these columns, this message
    becomes false: update the endpoint, the README and this test together."""
    from pathlib import Path

    app_dir = Path(api.__file__).resolve().parents[2]
    allowed = {"modules/voip/models.py", "modules/voip/schemas.py", "modules/voip/service.py"}
    readers = sorted(
        p.relative_to(app_dir).as_posix()
        for p in app_dir.rglob("*.py")
        if "firmware_target" in p.read_text(encoding="utf-8")
        and p.relative_to(app_dir).as_posix() not in allowed
    )
    assert readers == [], readers
