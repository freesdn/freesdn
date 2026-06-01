# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Regression tests pinning the canonical RouterOS REST wire format.

These tests would have caught the bug where the MikroTik
client used PATCH for updates and DELETE for removes — a pattern that
mocks accept but real RouterOS 7.21.3 rejects with HTTP 400.

Empirical findings against CHR 7.21.3 (logged in commit message of
the fix):
* ``PATCH /<menu>``      → 400 "missing or invalid resource identifier"
* ``PATCH /<menu>/<id>`` → 400 "missing or invalid resource identifier"
* ``DELETE /<menu>/<id>``→ 400 "missing or invalid resource identifier"
* ``POST /<menu>``       → 400 "no such command"
* ``PUT /<menu>``        → 200 (creates the item)
* ``POST /<menu>/set``   → 200 (updates singleton OR item-by-id when
                                 ``.id`` is in the body)
* ``POST /<menu>/remove``→ 200 (deletes when ``.id`` is in the body)

Any future refactor of the verb helpers must preserve this contract.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.adapters.mikrotik.client import MikroTikClient


def _client_with_mocked_http() -> tuple[MikroTikClient, AsyncMock]:
    c = MikroTikClient(
        host="10.0.0.1",
        username="admin",
        password="x",
        port=80,
        use_ssl=False,
        verify_ssl=False,
        timeout=5,
    )
    resp = MagicMock(status_code=200, text="[]")
    resp.json.return_value = []
    http = AsyncMock()
    http.is_closed = False
    http.request = AsyncMock(return_value=resp)
    c._client = http
    return c, http


@patch("app.adapters.mikrotik.client._is_adapter_read_only", lambda: False)
class TestRouterOSWireFormat:
    """Pin the wire format the MikroTik client uses.

    Each test asserts the EXACT HTTP method + path + body shape that
    real RouterOS REST accepts. A test failure means the helper has
    regressed away from what real CHR will accept.
    """

    # ── post() — action verbs (POST /menu/<action>)
    # ── put() — adds (PUT /menu)
    # NOTE: fix. Previously post() did PUT for
    # "/menu/add" semantics, which broke every action-verb call
    # (/save, /move, /run, /flush, etc.) because RouterOS rejected
    # PUT-to-action with "no such command". Reverted: post() is now
    # literal POST (for action verbs), put() is literal PUT (for adds).
    # The 41 add call sites in client.py were swept to use put().

    @pytest.mark.asyncio
    async def test_put_adds_to_menu(self) -> None:
        c, http = _client_with_mocked_http()
        await c.put("/ip/firewall/filter", {"chain": "forward", "action": "accept"})
        call = http.request.await_args
        assert call.args[0] == "PUT"
        assert call.args[1].endswith("/rest/ip/firewall/filter")
        assert call.kwargs["json"] == {"chain": "forward", "action": "accept"}

    @pytest.mark.asyncio
    async def test_post_is_action_verb_post(self) -> None:
        # /system/backup/save is an action — RouterOS expects POST
        c, http = _client_with_mocked_http()
        await c.post("/system/backup/save", {"name": "test"})
        call = http.request.await_args
        assert call.args[0] == "POST"
        assert call.args[1].endswith("/rest/system/backup/save")
        assert call.kwargs["json"] == {"name": "test"}

    # ── patch() — singleton updates use POST /<path>/set, no .id

    @pytest.mark.asyncio
    async def test_patch_singleton_uses_post_set_no_id(self) -> None:
        c, http = _client_with_mocked_http()
        await c.patch("/system/identity", {"name": "router01"})
        call = http.request.await_args
        assert call.args[0] == "POST"
        assert call.args[1].endswith("/rest/system/identity/set")
        assert call.kwargs["json"] == {"name": "router01"}

    @pytest.mark.asyncio
    async def test_patch_singleton_ntp_client(self) -> None:
        c, http = _client_with_mocked_http()
        await c.patch(
            "/system/ntp/client",
            {"primary-ntp": "10.0.0.2", "enabled": "true"},
        )
        call = http.request.await_args
        assert call.args[0] == "POST"
        assert call.args[1].endswith("/rest/system/ntp/client/set")
        assert call.kwargs["json"] == {
            "primary-ntp": "10.0.0.2",
            "enabled": "true",
        }

    # ── patch() — item-by-id updates split .id from URL into body

    @pytest.mark.asyncio
    async def test_patch_item_by_id_splits_id_into_body(self) -> None:
        c, http = _client_with_mocked_http()
        await c.patch("/ip/firewall/filter/*1", {"action": "drop"})
        call = http.request.await_args
        assert call.args[0] == "POST"
        # ID must be removed from the URL — POST goes to the menu's /set
        assert call.args[1].endswith("/rest/ip/firewall/filter/set")
        # ID lives in the body as ".id"
        assert call.kwargs["json"] == {".id": "*1", "action": "drop"}

    @pytest.mark.asyncio
    async def test_patch_item_by_id_hex_id(self) -> None:
        # RouterOS IDs are *<hex> — must work for multi-char hex.
        c, http = _client_with_mocked_http()
        await c.patch("/ip/route/*1f", {"distance": "10"})
        call = http.request.await_args
        assert call.args[0] == "POST"
        assert call.args[1].endswith("/rest/ip/route/set")
        assert call.kwargs["json"] == {".id": "*1f", "distance": "10"}

    # ── delete() — POST /<path>/remove with .id in body

    @pytest.mark.asyncio
    async def test_delete_uses_post_remove_with_id_in_body(self) -> None:
        c, http = _client_with_mocked_http()
        await c.delete("/ip/firewall/filter", "*5")
        call = http.request.await_args
        assert call.args[0] == "POST"
        assert call.args[1].endswith("/rest/ip/firewall/filter/remove")
        assert call.kwargs["json"] == {".id": "*5"}

    @pytest.mark.asyncio
    async def test_delete_without_id_still_uses_post_remove(self) -> None:
        # Edge case: empty .id — still issues POST /remove but with
        # an empty body. RouterOS will 400; that's the caller's problem
        # (they shouldn't be calling delete() without an ID).
        c, http = _client_with_mocked_http()
        await c.delete("/ip/route")
        call = http.request.await_args
        assert call.args[0] == "POST"
        assert call.args[1].endswith("/rest/ip/route/remove")
        assert call.kwargs["json"] == {}

    # ── put() and post() are now distinct verbs after fix
    # (put → PUT for adds; post → POST for action verbs)

    @pytest.mark.asyncio
    async def test_put_is_now_separate_from_post(self) -> None:
        c, http = _client_with_mocked_http()
        await c.put("/queue/simple", {"name": "guest", "target": "192.168.1.0/24"})
        call = http.request.await_args
        assert call.args[0] == "PUT"
        assert call.args[1].endswith("/rest/queue/simple")

    # ── get() unchanged — GET /menu

    @pytest.mark.asyncio
    async def test_get_unchanged(self) -> None:
        c, http = _client_with_mocked_http()
        await c.get("/system/identity")
        call = http.request.await_args
        assert call.args[0] == "GET"
        assert call.args[1].endswith("/rest/system/identity")
