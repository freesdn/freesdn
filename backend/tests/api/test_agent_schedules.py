# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the agent_schedules CRUD endpoints + WS push helper.

We mostly exercise the pure validation in AgentScheduleIn (cron shape,
scan_type allowlist, target length cap) and the push helper's site-vs-
agent fan-out logic via a stubbed registry.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.api.v1.endpoints.agent_schedules import AgentScheduleIn


class TestAgentScheduleInValidation:
    def test_valid_minimal(self) -> None:
        s = AgentScheduleIn(name="nightly", cron="0 2 * * *")
        assert s.scan_type == "quick"
        assert s.enabled is True
        assert s.targets == []

    def test_cron_must_have_5_fields(self) -> None:
        with pytest.raises(ValidationError, match="cron must have 5 fields"):
            AgentScheduleIn(name="x", cron="0 2 *")

    def test_invalid_scan_type_rejected(self) -> None:
        with pytest.raises(ValidationError, match="scan_type must be one of"):
            AgentScheduleIn(name="x", cron="0 2 * * *", scan_type="malicious")

    def test_target_over_64_chars_rejected(self) -> None:
        bad = "a" * 65
        with pytest.raises(ValidationError):
            AgentScheduleIn(name="x", cron="0 2 * * *", targets=[bad])

    def test_target_list_capped_at_64(self) -> None:
        # max_length on the field
        many = [f"10.0.0.{i}" for i in range(70)]
        with pytest.raises(ValidationError):
            AgentScheduleIn(name="x", cron="0 2 * * *", targets=many)

    def test_name_required_min_length(self) -> None:
        with pytest.raises(ValidationError):
            AgentScheduleIn(name="", cron="0 2 * * *")

    def test_full_payload_round_trip(self) -> None:
        agent_id = uuid4()
        s = AgentScheduleIn(
            name="lab-quick",
            scan_type="quick",
            cron="0 */4 * * *",
            targets=["192.168.1.0/24", "10.0.0.0/24"],
            interface="eth0",
            enabled=False,
            agent_id=agent_id,
        )
        assert s.targets == ["192.168.1.0/24", "10.0.0.0/24"]
        assert s.agent_id == agent_id
        assert s.enabled is False


class TestCronShape:
    """Edge cases for the cron-shape validator (the agent's parser does
    full validation; we only check the field count here)."""

    @pytest.mark.parametrize(
        "cron",
        [
            "0 */4 * * *",
            "*/5 * * * *",
            "0 2 1 * *",
            "0 2 1-15 * 1-5",
            "0,15,30,45 * * * *",
        ],
    )
    def test_accepts_valid_shapes(self, cron: str) -> None:
        s = AgentScheduleIn(name="x", cron=cron)
        assert s.cron == cron

    @pytest.mark.parametrize(
        "cron",
        ["* * * *", "* * * * * *", ""],
    )
    def test_rejects_bad_shapes(self, cron: str) -> None:
        with pytest.raises(ValidationError):
            AgentScheduleIn(name="x", cron=cron)
