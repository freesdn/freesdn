# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the schedule-run notification dispatch logic.

The chapter's invariants:
- notify_on_failure=True + run_status="failed" → dispatch
- notify_on_new_devices=N + new_host_count>=N + completed → dispatch
- notification_channels={} → never dispatch (short-circuit)
- Both conditions false → never dispatch
- Failed run with notify_on_new_devices set but notify_on_failure=False → skip
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest


def _make_schedule(**overrides):
    """Build a SimpleNamespace that quacks like AgentSchedule for the helper."""
    base = dict(
        id=uuid4(),
        name="test-sched",
        cron="0 * * * *",
        site_id=uuid4(),
        organization_id=uuid4(),
        notification_channels={"email": {"to": ["op@example.test"]}},
        notify_on_failure=False,
        notify_on_new_devices=0,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.mark.asyncio
@patch("app.services.notification_helpers.dispatch_notifications", new_callable=AsyncMock)
async def test_short_circuits_when_no_channels(mock_dispatch):
    """notification_channels={} → no dispatch, no title work wasted."""
    from app.services.remote_agent import _maybe_notify_schedule_run

    sched = _make_schedule(
        notification_channels={},
        notify_on_failure=True,  # would normally trigger
    )
    await _maybe_notify_schedule_run(
        db=None,
        schedule=sched,
        run_status="failed",
        new_host_count=0,
        total_device_count=0,
        duration_seconds=1.0,
        error_message="boom",
    )
    mock_dispatch.assert_not_called()


@pytest.mark.asyncio
@patch("app.services.notification_helpers.dispatch_notifications", new_callable=AsyncMock)
async def test_dispatches_on_failure(mock_dispatch):
    """notify_on_failure=True + run_status='failed' triggers."""
    from app.services.remote_agent import _maybe_notify_schedule_run

    sched = _make_schedule(notify_on_failure=True)
    await _maybe_notify_schedule_run(
        db=None,
        schedule=sched,
        run_status="failed",
        new_host_count=0,
        total_device_count=0,
        duration_seconds=2.5,
        error_message="scan timeout",
    )
    mock_dispatch.assert_called_once()
    call = mock_dispatch.call_args
    assert "FAILED" in call.kwargs["title"]
    assert "scan timeout" in call.kwargs["body"]


@pytest.mark.asyncio
@patch("app.services.notification_helpers.dispatch_notifications", new_callable=AsyncMock)
async def test_dispatches_on_new_devices_threshold(mock_dispatch):
    """notify_on_new_devices=5 + new_host_count=7 + completed triggers."""
    from app.services.remote_agent import _maybe_notify_schedule_run

    sched = _make_schedule(notify_on_new_devices=5)
    await _maybe_notify_schedule_run(
        db=None,
        schedule=sched,
        run_status="completed",
        new_host_count=7,
        total_device_count=20,
        duration_seconds=10.0,
        error_message=None,
    )
    mock_dispatch.assert_called_once()
    call = mock_dispatch.call_args
    assert "7" in call.kwargs["title"]
    assert "new device" in call.kwargs["title"].lower()


@pytest.mark.asyncio
@patch("app.services.notification_helpers.dispatch_notifications", new_callable=AsyncMock)
async def test_no_dispatch_below_threshold(mock_dispatch):
    """new_host_count=3 < notify_on_new_devices=5 → no dispatch."""
    from app.services.remote_agent import _maybe_notify_schedule_run

    sched = _make_schedule(notify_on_new_devices=5)
    await _maybe_notify_schedule_run(
        db=None,
        schedule=sched,
        run_status="completed",
        new_host_count=3,
        total_device_count=20,
        duration_seconds=10.0,
        error_message=None,
    )
    mock_dispatch.assert_not_called()


@pytest.mark.asyncio
@patch("app.services.notification_helpers.dispatch_notifications", new_callable=AsyncMock)
async def test_failed_run_does_not_trigger_new_devices_path(mock_dispatch):
    """A failed run never goes through the new-devices branch even if
    new_host_count happened to be set — failures route via failure path
    only (and only if notify_on_failure=True)."""
    from app.services.remote_agent import _maybe_notify_schedule_run

    sched = _make_schedule(
        notify_on_failure=False,
        notify_on_new_devices=1,  # set, but should be ignored for failed
    )
    await _maybe_notify_schedule_run(
        db=None,
        schedule=sched,
        run_status="failed",
        new_host_count=99,  # would trigger if path applied
        total_device_count=0,
        duration_seconds=1.0,
        error_message="x",
    )
    mock_dispatch.assert_not_called()


@pytest.mark.asyncio
@patch("app.services.notification_helpers.dispatch_notifications", new_callable=AsyncMock)
async def test_zero_threshold_disables_new_devices_path(mock_dispatch):
    """notify_on_new_devices=0 is the documented disabled value."""
    from app.services.remote_agent import _maybe_notify_schedule_run

    sched = _make_schedule(notify_on_new_devices=0)
    await _maybe_notify_schedule_run(
        db=None,
        schedule=sched,
        run_status="completed",
        new_host_count=999,
        total_device_count=999,
        duration_seconds=10.0,
        error_message=None,
    )
    mock_dispatch.assert_not_called()
