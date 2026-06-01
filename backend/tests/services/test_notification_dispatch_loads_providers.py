# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Regression: notification dispatch must LOAD the org's providers before send().

The alert/notification dispatch path used to create ``NotificationService`` and
call ``send()`` WITHOUT ever calling ``load_providers_from_db()``, so ``send()``
found no provider for email/slack/teams/webhook/sms and every network-channel
alert was silently dropped ("No provider configured") — only ``in_app`` ever
delivered. A capability audit proved this at runtime. These tests lock the fix.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from app.services.notification import (
    DeliveryResult,
    DeliveryStatus,
    NotificationChannel,
    NotificationService,
)
from app.services.notification_helpers import dispatch_notifications


@pytest.mark.asyncio
async def test_dispatch_loads_providers_before_sending_network_channels(monkeypatch):
    loaded_orgs: list = []

    async def _fake_load(self, organization_id=None):
        loaded_orgs.append(organization_id)
        # Simulate a webhook provider being registered from the DB.
        self._providers[NotificationChannel.WEBHOOK] = SimpleNamespace()

    monkeypatch.setattr(NotificationService, "load_providers_from_db", _fake_load)

    provider_present_at_send: list = []

    async def _fake_send(
        self, *, channel, recipient, title, body, body_html=None, organization_id=None, **_
    ):
        provider = self._providers.get(channel)
        provider_present_at_send.append((channel, provider is not None))
        return DeliveryResult(
            success=provider is not None,
            channel=channel,
            status=DeliveryStatus.SENT if provider else DeliveryStatus.FAILED,
            error=None if provider else f"No provider configured for channel: {channel.value}",
        )

    monkeypatch.setattr(NotificationService, "send", _fake_send)

    org = uuid4()
    results = await dispatch_notifications(
        MagicMock(),
        {"webhook": {"url": "https://hook.example/x"}},
        "Alert",
        "body",
        organization_id=org,
    )

    # providers were loaded for the org BEFORE the send happened...
    assert loaded_orgs == [org]
    # ...so the webhook provider was registered at send time → delivery succeeds.
    assert provider_present_at_send == [(NotificationChannel.WEBHOOK, True)]
    assert results and results[0].success is True


@pytest.mark.asyncio
async def test_dispatch_skips_provider_load_for_in_app_only(monkeypatch):
    """in_app is delivered directly via create_in_app, so the DB provider load is
    skipped when no network channel is configured (no wasted query)."""
    loaded: list = []

    async def _fake_load(self, organization_id=None):
        loaded.append(organization_id)

    monkeypatch.setattr(NotificationService, "load_providers_from_db", _fake_load)

    created: list = []

    async def _fake_create_in_app(self, *, user_id, title, body, organization_id=None, commit=True):
        created.append(user_id)

    monkeypatch.setattr(NotificationService, "create_in_app", _fake_create_in_app)

    uid = uuid4()
    results = await dispatch_notifications(
        MagicMock(),
        {"in_app": {"user_ids": [str(uid)]}},
        "Alert",
        "body",
        organization_id=uuid4(),
    )

    assert loaded == []  # no network channel → no provider load
    assert created == [uid]
    assert results and results[0].success is True
