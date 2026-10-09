# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Personal notification content must reach only its addressed connection."""

from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from app.api.v1.endpoints.websocket import ConnectionInfo, ConnectionManager
from app.core.events import Event, EventCategory

ORG, OTHER_ORG, USER, PEER, SITE, OTHER_SITE = [str(uuid4()) for _ in range(6)]


def connection(user=USER, limited=False, **changes):
    values = {
        "websocket": AsyncMock(),
        "user_id": user,
        "organization_id": ORG,
        "subscriptions": {"*"},
        "is_site_limited": limited,
        "accessible_site_ids": [SITE] if limited else [],
    }
    values.update(changes)
    return ConnectionInfo(**values)


def notification(payload=None, event_type="notification.created", **changes):
    values = {
        "event_type": event_type,
        "category": EventCategory.USER,
        "organization_id": ORG,
        "payload": payload if payload is not None else {"user_id": USER},
    }
    values.update(changes)
    return Event(**values)


@pytest.mark.parametrize(
    "event_type",
    ["notification.created", "notification.updated", "notification.read", "notification.dismissed"],
)
@pytest.mark.parametrize(
    ("user", "limited"), [(USER, False), (USER, True), (PEER, False), (PEER, True)]
)
def test_all_notification_events_require_recipient_even_for_unrestricted_users(
    event_type, user, limited
):
    event = notification(
        {"user_id": USER, "notification": {"user_id": USER, "body": "private"}}, event_type
    )
    assert ConnectionManager()._should_receive(connection(user, limited), event) is (user == USER)


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        "invalid",
        {},
        {"user_id": None},
        {"user_id": PEER},
        {"notification": {"user_id": USER}},
        {"user_id": USER, "notification": "invalid"},
        {"user_id": USER, "notification": None},
        {"user_id": USER, "notification": {}},
        {"user_id": USER, "notification": {"user_id": PEER}},
        {"user_id": USER, "notification": {"user_id": None}},
    ],
)
@pytest.mark.parametrize("limited", [False, True])
def test_missing_or_conflicting_recipient_fails_closed(payload, limited):
    event = notification()
    event.payload = payload
    assert ConnectionManager()._should_receive(connection(limited=limited), event) is False


@pytest.mark.parametrize("limited", [False, True])
@pytest.mark.parametrize(
    "condition",
    [
        "missing_event_org",
        "missing_connection_org",
        "other_org",
        "unsubscribed",
        "opt_in_site_filter",
        "owned_site",
        "uuid_target",
        "matching_nested",
    ],
)
def test_recipient_check_preserves_existing_filters_and_valid_shapes(condition, limited):
    info, event = connection(limited=limited), notification()
    allowed = condition in {"owned_site", "uuid_target", "matching_nested"}
    if condition == "missing_event_org":
        event.organization_id = None
    elif condition == "missing_connection_org":
        info.organization_id = None
    elif condition == "other_org":
        event.organization_id = OTHER_ORG
    elif condition == "unsubscribed":
        info.subscriptions = {"device.*"}
    elif condition == "opt_in_site_filter":
        info.site_ids = [OTHER_SITE]
        event.payload["site_id"] = SITE
    elif condition == "owned_site":
        event.payload["site_id"] = SITE
    elif condition == "uuid_target":
        event.payload["user_id"] = UUID(USER)
    elif condition == "matching_nested":
        event.payload["notification"] = {"user_id": UUID(USER)}
    assert ConnectionManager()._should_receive(info, event) is allowed


@pytest.mark.parametrize(
    "event_type", ["device.updated", "alert.fired", "task.started", "automation.executed"]
)
@pytest.mark.parametrize("limited", [False, True])
def test_unrelated_events_can_carry_an_actor_user_without_becoming_personal(event_type, limited):
    event = notification({"user_id": PEER, "site_id": SITE}, event_type)
    assert ConnectionManager()._should_receive(connection(limited=limited), event) is True


@pytest.mark.asyncio
@pytest.mark.parametrize("event_type", ["notification.created", "notification.read"])
async def test_actual_broadcast_fans_out_only_to_addressed_users_multiple_connections(event_type):
    manager = ConnectionManager()
    manager._connections = {
        "target-first": connection(),
        "target-second": connection(limited=True),
        "peer-unrestricted": connection(PEER),
        "peer-restricted": connection(PEER, True),
        "other-tenant": connection(organization_id=OTHER_ORG),
    }
    event = notification(
        {"user_id": USER, "notification": {"user_id": USER, "body": "owned-private-body"}},
        event_type,
    )
    await manager.broadcast_event(event)
    for name, info in manager._connections.items():
        if name.startswith("target-"):
            info.websocket.send_json.assert_awaited_once()
            assert (
                info.websocket.send_json.call_args.args[0]["event"]["payload"]["notification"][
                    "body"
                ]
                == "owned-private-body"
            )
        else:
            info.websocket.send_json.assert_not_awaited()


def test_recipient_does_not_bypass_server_site_grant():
    event = notification({"user_id": USER, "site_id": OTHER_SITE})
    assert ConnectionManager()._should_receive(connection(limited=True), event) is False
