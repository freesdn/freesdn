# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Tests for notification dispatch helpers and NotificationService integration.
"""

import uuid
from unittest.mock import AsyncMock, patch

import pytest

from app.services.notification import (
    DeliveryResult,
    DeliveryStatus,
    NotificationChannel,
)
from app.services.notification_helpers import (
    _extract_recipients,
    dispatch_notifications,
)


@pytest.fixture
def mock_db():
    """Create a mock async DB session."""
    db = AsyncMock()
    db.execute = AsyncMock()
    return db


def _ok_result(channel: NotificationChannel) -> DeliveryResult:
    return DeliveryResult(
        success=True,
        channel=channel,
        status=DeliveryStatus.SENT,
        message_id=str(uuid.uuid4()),
    )


def _fail_result(channel: NotificationChannel, error: str) -> DeliveryResult:
    return DeliveryResult(
        success=False,
        channel=channel,
        status=DeliveryStatus.FAILED,
        error=error,
    )


# =========================================================================
# dispatch_notifications
# =========================================================================


class TestDispatchNotifications:
    """Tests for the dispatch_notifications helper."""

    @pytest.mark.asyncio
    async def test_empty_channels_returns_empty_list(self, mock_db):
        """When channels_config is None or empty, return []."""
        assert await dispatch_notifications(mock_db, None, "t", "b") == []
        assert await dispatch_notifications(mock_db, {}, "t", "b") == []

    @pytest.mark.asyncio
    async def test_unknown_channel_is_skipped(self, mock_db):
        """Unknown channel names should be silently skipped."""
        config = {"carrier_pigeon": {"to": "nest"}}
        with patch("app.services.notification_helpers.NotificationService") as MockSvc:
            MockSvc.return_value.load_providers_from_db = AsyncMock()
            result = await dispatch_notifications(mock_db, config, "t", "b")
        assert result == []
        MockSvc.return_value.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_email_channel_dispatches_to_all_recipients(self, mock_db):
        """Email config with multiple 'to' addresses dispatches one send per address."""
        config = {"email": {"to": ["a@example.com", "b@example.com"]}}
        expected = _ok_result(NotificationChannel.EMAIL)

        with patch("app.services.notification_helpers.NotificationService") as MockSvc:
            MockSvc.return_value.load_providers_from_db = AsyncMock()
            mock_send = AsyncMock(return_value=expected)
            MockSvc.return_value.send = mock_send

            results = await dispatch_notifications(mock_db, config, "Alert", "Something happened")

        assert len(results) == 2
        assert mock_send.call_count == 2
        # Verify both recipients were targeted
        recipients_called = {call.kwargs["recipient"] for call in mock_send.call_args_list}
        assert recipients_called == {"a@example.com", "b@example.com"}

    @pytest.mark.asyncio
    async def test_slack_channel_dispatches(self, mock_db):
        """Slack config dispatches to the configured channel."""
        config = {"slack": {"channel": "#ops-alerts"}}
        expected = _ok_result(NotificationChannel.SLACK)

        with patch("app.services.notification_helpers.NotificationService") as MockSvc:
            MockSvc.return_value.load_providers_from_db = AsyncMock()
            MockSvc.return_value.send = AsyncMock(return_value=expected)
            results = await dispatch_notifications(mock_db, config, "t", "b")

        assert len(results) == 1
        assert results[0].channel == NotificationChannel.SLACK

    @pytest.mark.asyncio
    async def test_webhook_channel_dispatches(self, mock_db):
        """Webhook config dispatches to the configured URL."""
        config = {"webhook": {"url": "https://hooks.example.com/incoming"}}
        expected = _ok_result(NotificationChannel.WEBHOOK)

        with patch("app.services.notification_helpers.NotificationService") as MockSvc:
            MockSvc.return_value.load_providers_from_db = AsyncMock()
            MockSvc.return_value.send = AsyncMock(return_value=expected)
            results = await dispatch_notifications(mock_db, config, "t", "b")

        assert len(results) == 1
        call_kwargs = MockSvc.return_value.send.call_args.kwargs
        assert call_kwargs["recipient"] == "https://hooks.example.com/incoming"
        assert call_kwargs["channel"] == NotificationChannel.WEBHOOK

    @pytest.mark.asyncio
    async def test_teams_channel_dispatches(self, mock_db):
        """Teams config dispatches to the configured webhook_url."""
        config = {"teams": {"webhook_url": "https://teams.example.com/hook"}}
        expected = _ok_result(NotificationChannel.TEAMS)

        with patch("app.services.notification_helpers.NotificationService") as MockSvc:
            MockSvc.return_value.load_providers_from_db = AsyncMock()
            MockSvc.return_value.send = AsyncMock(return_value=expected)
            results = await dispatch_notifications(mock_db, config, "t", "b")

        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_multiple_channels_dispatched_concurrently(self, mock_db):
        """Multiple channels in config all get dispatched."""
        config = {
            "email": {"to": ["admin@ex.com"]},
            "slack": {"channel": "#alerts"},
            "webhook": {"url": "https://hooks.ex.com/in"},
        }

        with patch("app.services.notification_helpers.NotificationService") as MockSvc:
            MockSvc.return_value.load_providers_from_db = AsyncMock()

            async def _fake_send(**kwargs):
                return _ok_result(kwargs["channel"])

            MockSvc.return_value.send = AsyncMock(side_effect=_fake_send)
            results = await dispatch_notifications(mock_db, config, "t", "b")

        assert len(results) == 3
        channels = {r.channel for r in results}
        assert channels == {
            NotificationChannel.EMAIL,
            NotificationChannel.SLACK,
            NotificationChannel.WEBHOOK,
        }

    @pytest.mark.asyncio
    async def test_failed_send_still_returns_result(self, mock_db):
        """A send that returns success=False is still included in results."""
        config = {"email": {"to": ["x@ex.com"]}}
        fail = _fail_result(NotificationChannel.EMAIL, "SMTP down")

        with patch("app.services.notification_helpers.NotificationService") as MockSvc:
            MockSvc.return_value.load_providers_from_db = AsyncMock()
            MockSvc.return_value.send = AsyncMock(return_value=fail)
            results = await dispatch_notifications(mock_db, config, "t", "b")

        assert len(results) == 1
        assert results[0].success is False
        assert results[0].error == "SMTP down"

    @pytest.mark.asyncio
    async def test_exception_in_send_returns_none_filtered_out(self, mock_db):
        """If send() raises, the result is filtered out (returns None)."""
        config = {"email": {"to": ["x@ex.com"]}}

        with patch("app.services.notification_helpers.NotificationService") as MockSvc:
            MockSvc.return_value.load_providers_from_db = AsyncMock()
            MockSvc.return_value.send = AsyncMock(side_effect=RuntimeError("connection reset"))
            results = await dispatch_notifications(mock_db, config, "t", "b")

        # The exception is caught inside _send_one; None is returned and filtered
        assert results == []

    @pytest.mark.asyncio
    async def test_organization_id_passed_through(self, mock_db):
        """organization_id kwarg is forwarded to NotificationService.send."""
        org_id = uuid.uuid4()
        config = {"email": {"to": ["a@ex.com"]}}

        with patch("app.services.notification_helpers.NotificationService") as MockSvc:
            MockSvc.return_value.load_providers_from_db = AsyncMock()
            MockSvc.return_value.send = AsyncMock(
                return_value=_ok_result(NotificationChannel.EMAIL)
            )
            await dispatch_notifications(mock_db, config, "t", "b", organization_id=org_id)

        call_kwargs = MockSvc.return_value.send.call_args.kwargs
        assert call_kwargs["organization_id"] == org_id

    @pytest.mark.asyncio
    async def test_body_html_passed_through(self, mock_db):
        """body_html kwarg is forwarded to NotificationService.send."""
        config = {"email": {"to": ["a@ex.com"]}}

        with patch("app.services.notification_helpers.NotificationService") as MockSvc:
            MockSvc.return_value.load_providers_from_db = AsyncMock()
            MockSvc.return_value.send = AsyncMock(
                return_value=_ok_result(NotificationChannel.EMAIL)
            )
            await dispatch_notifications(mock_db, config, "t", "b", body_html="<b>bold</b>")

        call_kwargs = MockSvc.return_value.send.call_args.kwargs
        assert call_kwargs["body_html"] == "<b>bold</b>"


# =========================================================================
# _extract_recipients
# =========================================================================


class TestExtractRecipients:
    """Tests for the _extract_recipients helper."""

    def test_email_list(self):
        assert _extract_recipients("email", {"to": ["a@b.com", "c@d.com"]}) == [
            "a@b.com",
            "c@d.com",
        ]

    def test_email_single_string(self):
        """A single string 'to' value is wrapped in a list."""
        assert _extract_recipients("email", {"to": "solo@b.com"}) == ["solo@b.com"]

    def test_email_missing_to(self):
        assert _extract_recipients("email", {}) == []

    def test_slack_channel(self):
        assert _extract_recipients("slack", {"channel": "#ops"}) == ["#ops"]

    def test_slack_missing_channel(self):
        assert _extract_recipients("slack", {}) == []

    def test_teams_webhook_url(self):
        assert _extract_recipients("teams", {"webhook_url": "https://t"}) == ["https://t"]

    def test_webhook_url(self):
        assert _extract_recipients("webhook", {"url": "https://w"}) == ["https://w"]

    def test_sms_list(self):
        assert _extract_recipients("sms", {"to": ["+1234", "+5678"]}) == [
            "+1234",
            "+5678",
        ]

    def test_sms_single(self):
        assert _extract_recipients("sms", {"to": "+111"}) == ["+111"]

    def test_in_app_user_ids(self):
        assert _extract_recipients("in_app", {"user_ids": ["u1", "u2"]}) == [
            "u1",
            "u2",
        ]

    def test_in_app_single_user_id(self):
        assert _extract_recipients("in_app", {"user_ids": "u1"}) == ["u1"]

    def test_unknown_channel_returns_empty(self):
        assert _extract_recipients("fax", {"number": "555"}) == []

    def test_non_dict_config_returns_empty(self):
        assert _extract_recipients("email", "not_a_dict") == []
