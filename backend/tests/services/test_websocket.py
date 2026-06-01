# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Tests for WebSocket ConnectionManager.
"""

from unittest.mock import AsyncMock

import pytest

from app.services.websocket import ConnectionManager


def _make_ws(*, accept_ok: bool = True, send_ok: bool = True) -> AsyncMock:
    """Create a mock WebSocket that optionally fails on send."""
    ws = AsyncMock()
    ws.accept = AsyncMock()
    if send_ok:
        ws.send_json = AsyncMock()
    else:
        ws.send_json = AsyncMock(side_effect=RuntimeError("connection closed"))
    return ws


@pytest.fixture
def manager():
    return ConnectionManager()


# =========================================================================
# Connect / Disconnect
# =========================================================================


class TestConnectDisconnect:
    """Tests for connection lifecycle tracking."""

    @pytest.mark.asyncio
    async def test_connect_accepts_and_tracks(self, manager):
        ws = _make_ws()
        await manager.connect(ws, user_id="u1", organization_id="org1")

        assert manager.connection_count == 1
        ws.accept.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_connect_multiple(self, manager):
        ws1, ws2 = _make_ws(), _make_ws()
        await manager.connect(ws1, user_id="u1")
        await manager.connect(ws2, user_id="u2")

        assert manager.connection_count == 2

    @pytest.mark.asyncio
    async def test_disconnect_removes_connection(self, manager):
        ws = _make_ws()
        await manager.connect(ws, user_id="u1", organization_id="org1")
        manager.disconnect(ws)

        assert manager.connection_count == 0

    @pytest.mark.asyncio
    async def test_disconnect_cleans_user_tracking(self, manager):
        ws = _make_ws()
        await manager.connect(ws, user_id="u1")
        assert manager.is_user_connected("u1")

        manager.disconnect(ws)
        assert not manager.is_user_connected("u1")

    @pytest.mark.asyncio
    async def test_disconnect_cleans_org_tracking(self, manager):
        ws = _make_ws()
        await manager.connect(ws, user_id="u1", organization_id="org1")
        manager.disconnect(ws)

        assert manager._org_connections.get("org1") is None

    @pytest.mark.asyncio
    async def test_disconnect_unknown_ws_is_noop(self, manager):
        ws = _make_ws()
        manager.disconnect(ws)  # should not raise
        assert manager.connection_count == 0

    @pytest.mark.asyncio
    async def test_multiple_connections_same_user(self, manager):
        ws1, ws2 = _make_ws(), _make_ws()
        await manager.connect(ws1, user_id="u1")
        await manager.connect(ws2, user_id="u1")

        assert manager.get_user_connection_count("u1") == 2

        manager.disconnect(ws1)
        assert manager.get_user_connection_count("u1") == 1
        assert manager.is_user_connected("u1")

        manager.disconnect(ws2)
        assert not manager.is_user_connected("u1")


# =========================================================================
# Broadcast
# =========================================================================


class TestBroadcast:
    """Tests for broadcast to all connected clients."""

    @pytest.mark.asyncio
    async def test_broadcast_sends_to_all(self, manager):
        ws1, ws2 = _make_ws(), _make_ws()
        await manager.connect(ws1)
        await manager.connect(ws2)

        count = await manager.broadcast("test_event", {"key": "val"})

        assert count == 2
        ws1.send_json.assert_awaited_once()
        ws2.send_json.assert_awaited_once()

        # Verify message structure
        msg = ws1.send_json.call_args[0][0]
        assert msg["type"] == "test_event"
        assert msg["data"] == {"key": "val"}
        assert "timestamp" in msg

    @pytest.mark.asyncio
    async def test_broadcast_no_clients(self, manager):
        count = await manager.broadcast("test_event")
        assert count == 0

    @pytest.mark.asyncio
    async def test_broadcast_to_user(self, manager):
        ws1, ws2 = _make_ws(), _make_ws()
        await manager.connect(ws1, user_id="u1")
        await manager.connect(ws2, user_id="u2")

        count = await manager.broadcast_to_user("u1", "evt", {"x": 1})

        assert count == 1
        ws1.send_json.assert_awaited_once()
        ws2.send_json.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_broadcast_to_organization(self, manager):
        ws1, ws2 = _make_ws(), _make_ws()
        await manager.connect(ws1, user_id="u1", organization_id="org1")
        await manager.connect(ws2, user_id="u2", organization_id="org2")

        count = await manager.broadcast_to_organization("org1", "evt")

        assert count == 1
        ws1.send_json.assert_awaited_once()
        ws2.send_json.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_broadcast_to_nonexistent_user(self, manager):
        count = await manager.broadcast_to_user("ghost", "evt")
        assert count == 0


# =========================================================================
# Room-based messaging
# =========================================================================


class TestRooms:
    """Tests for room join/leave/broadcast."""

    @pytest.mark.asyncio
    async def test_join_and_broadcast_to_room(self, manager):
        ws1, ws2, ws3 = _make_ws(), _make_ws(), _make_ws()
        await manager.connect(ws1, user_id="u1")
        await manager.connect(ws2, user_id="u2")
        await manager.connect(ws3, user_id="u3")

        manager.join_room(ws1, "room-a")
        manager.join_room(ws2, "room-a")
        # ws3 is NOT in room-a

        count = await manager.broadcast_to_room("room-a", "room_event", {"r": 1})

        assert count == 2
        ws1.send_json.assert_awaited_once()
        ws2.send_json.assert_awaited_once()
        ws3.send_json.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_leave_room(self, manager):
        ws = _make_ws()
        await manager.connect(ws, user_id="u1")
        manager.join_room(ws, "room-b")
        manager.leave_room(ws, "room-b")

        count = await manager.broadcast_to_room("room-b", "evt")
        assert count == 0

    @pytest.mark.asyncio
    async def test_join_room_unconnected_ws_is_noop(self, manager):
        ws = _make_ws()
        # Not connected, join should be silently ignored
        manager.join_room(ws, "room-x")
        assert "room-x" not in manager._rooms

    @pytest.mark.asyncio
    async def test_disconnect_removes_from_rooms(self, manager):
        ws = _make_ws()
        await manager.connect(ws, user_id="u1")
        manager.join_room(ws, "room-c")
        manager.disconnect(ws)

        # Room entry may still exist as empty set; broadcast should send to nobody
        count = await manager.broadcast_to_room("room-c", "evt")
        assert count == 0

    @pytest.mark.asyncio
    async def test_broadcast_to_nonexistent_room(self, manager):
        count = await manager.broadcast_to_room("no-such-room", "evt")
        assert count == 0


# =========================================================================
# Failed client cleanup
# =========================================================================


class TestFailedClientCleanup:
    """Tests that broken WebSocket connections are cleaned up."""

    @pytest.mark.asyncio
    async def test_broadcast_disconnects_failed_client(self, manager):
        ws_ok = _make_ws(send_ok=True)
        ws_bad = _make_ws(send_ok=False)
        await manager.connect(ws_ok, user_id="good")
        await manager.connect(ws_bad, user_id="bad")

        count = await manager.broadcast("evt")

        # Only the working client should have succeeded
        assert count == 1
        # The bad client should have been disconnected
        assert manager.connection_count == 1
        assert not manager.is_user_connected("bad")
        assert manager.is_user_connected("good")

    @pytest.mark.asyncio
    async def test_send_message_disconnects_on_failure(self, manager):
        ws = _make_ws(send_ok=False)
        await manager.connect(ws, user_id="u1")

        ok = await manager.send_message(ws, "evt", {"x": 1})

        assert ok is False
        assert manager.connection_count == 0

    @pytest.mark.asyncio
    async def test_send_message_succeeds(self, manager):
        ws = _make_ws()
        await manager.connect(ws, user_id="u1")

        ok = await manager.send_message(ws, "evt", {"x": 1})

        assert ok is True
        assert manager.connection_count == 1
        msg = ws.send_json.call_args[0][0]
        assert msg["type"] == "evt"
        assert msg["data"] == {"x": 1}


# =========================================================================
# Status helpers
# =========================================================================


class TestStatusHelpers:
    """Tests for status query methods."""

    @pytest.mark.asyncio
    async def test_get_connected_users(self, manager):
        ws1, ws2 = _make_ws(), _make_ws()
        await manager.connect(ws1, user_id="alice")
        await manager.connect(ws2, user_id="bob")

        users = manager.get_connected_users()
        assert set(users) == {"alice", "bob"}

    @pytest.mark.asyncio
    async def test_connection_count(self, manager):
        assert manager.connection_count == 0

        ws = _make_ws()
        await manager.connect(ws)
        assert manager.connection_count == 1

    @pytest.mark.asyncio
    async def test_connect_without_user_or_org(self, manager):
        """Connection without user_id or org_id still tracked."""
        ws = _make_ws()
        await manager.connect(ws)

        assert manager.connection_count == 1
        assert manager.get_connected_users() == []
