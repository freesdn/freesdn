# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Regression: AMI login must not wait on a reader that has not started.

``_login()`` registers a future in ``self._pending`` and awaits it, but the only
code that ever resolves those futures is ``_read_loop``. ``connect()`` created
the read task AFTER ``_login()`` returned, so during the handshake nothing was
draining the socket: Asterisk sent ``Response: Success`` with the matching
ActionID, nobody read it, and the login timed out on a healthy connection. The
FreePBX AMI transport could never authenticate.

These tests drive the real ``connect()`` against a local fake AMI server, so
they exercise the actual ordering rather than a mock of it.
"""

from __future__ import annotations

import asyncio

import pytest

from app.adapters.freepbx.ami_client import AMIClient
from app.adapters.freepbx.exceptions import AMIConnectionError


class FakeAMIServer:
    """Minimal AMI server: greeting, then answer Login with Success."""

    def __init__(self, *, answer_login: bool = True) -> None:
        self.answer_login = answer_login
        self.received_login = False
        self.sent_success = False
        self._server: asyncio.AbstractServer | None = None
        self.port = 0

    async def __aenter__(self) -> FakeAMIServer:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *_exc) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"Asterisk Call Manager/7.0.0\r\n")
        await writer.drain()

        action_id = None
        try:
            while True:
                line = await reader.readline()
                if not line:
                    return
                text = line.decode(errors="replace").strip()
                if text.lower().startswith("action: login"):
                    self.received_login = True
                elif text.lower().startswith("actionid:"):
                    action_id = text.split(":", 1)[1].strip()
                elif text == "" and self.received_login:
                    break
        except (ConnectionResetError, asyncio.IncompleteReadError):
            return

        if not self.answer_login:
            return  # simulate a server that never answers

        writer.write(
            f"Response: Success\r\nActionID: {action_id}\r\nMessage: Authentication accepted\r\n\r\n".encode()
        )
        await writer.drain()
        self.sent_success = True

        # Hold the connection open so the client's reader has something to read.
        try:
            await reader.read()
        except Exception:
            return


def _client(port: int) -> AMIClient:
    return AMIClient(host="127.0.0.1", port=port, username="admin", secret="secret")


@pytest.mark.asyncio
async def test_login_succeeds_against_a_server_that_answers() -> None:
    """The core regression.

    Fails before the fix with ``AMIConnectionError: AMI login timed out`` even
    though the server sent ``Response: Success``.
    """
    async with FakeAMIServer() as server:
        client = _client(server.port)
        try:
            await asyncio.wait_for(client.connect(), timeout=10)
            assert server.received_login, "server never saw the Login action"
            assert server.sent_success, "server never answered"
            assert client._authenticated is True, "client did not record authentication"
            assert client._read_task is not None, "reader must be running after connect"
        finally:
            await client.disconnect()


@pytest.mark.asyncio
async def test_failed_login_does_not_leak_the_reader_task() -> None:
    """A server that never answers must leave no reader behind.

    Starting the reader earlier means a failed handshake now has a task to clean
    up; without the cancel it would keep running against a closed transport for
    every failed connection attempt.
    """
    async with FakeAMIServer(answer_login=False) as server:
        client = _client(server.port)
        with pytest.raises(AMIConnectionError):
            await asyncio.wait_for(client.connect(), timeout=15)

        assert client._read_task is None, "the reader task must be cleaned up on login failure"
