# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreePBX OAuth2 GraphQL write-transport contract tests.

These lock the *shape* of the GraphQL mutations the FreePBX adapter sends —
the layer a live verification against pbx.example.test proved is easy to break
silently (the addExtension mutation rejected creates until ``email``/``name``
were defaulted, because those fields are NON_NULL).

No network: ``_graphql`` is replaced with a recorder that captures
``(query, variables)`` and returns a success block, so each write method's
mutation field, variable structure, and required-field defaults are asserted
offline. A second group locks in the FreePBX *limitation* — trunks, queues,
and IVRs have no GraphQL/REST write path, so their adapter methods must raise
rather than silently no-op.
"""
from __future__ import annotations

import asyncio

import aiohttp
import pytest

from app.adapters.freepbx.constants import REST_MAX_RETRIES
from app.adapters.freepbx.exceptions import FreePBXApiError, FreePBXConnectionError
from app.adapters.freepbx.rest_client import FreePBXRestClient


class _GqlRecorder:
    """Replaces ``_graphql``; records calls, returns an always-ok data block."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict | None]] = []

    async def __call__(self, query, variables=None, *, operation_name=None, idempotent=False):
        self.calls.append((query, variables))
        return _AlwaysOk()

    @property
    def last_query(self) -> str:
        return self.calls[-1][0]

    @property
    def last_vars(self) -> dict:
        return self.calls[-1][1] or {}


class _AlwaysOk(dict):
    """Truthy data block whose ``.get(field)`` is always a success payload."""

    def __bool__(self) -> bool:  # keep ``data_block or {}`` from discarding us
        return True

    def get(self, key, default=None):  # noqa: D102
        return {"status": True, "message": "ok"}


def _oauth_client() -> tuple[FreePBXRestClient, _GqlRecorder]:
    client = FreePBXRestClient(
        host="pbx.example.test",
        username="admin",
        password="x",
        api_client_id="cid",
        api_client_secret="csec",
    )
    client._auth_mode = "oauth2"  # bypass the live OAuth2 handshake
    rec = _GqlRecorder()
    client._graphql = rec  # type: ignore[assignment]
    return client, rec


# ── Extensions ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_extension_defaults_required_nonnull_fields():
    """Regression for the live-caught bug: addExtension's name/email are
    NON_NULL, so create must default them (and tech) or FreePBX 400s."""
    client, rec = _oauth_client()
    await client.create_extension("8000", {})
    assert "addExtension(input:$input)" in rec.last_query
    inp = rec.last_vars["input"]
    assert inp["extensionId"] == "8000"
    assert inp["tech"] == "pjsip"
    assert inp["name"] == "8000"  # defaults to the number
    assert inp["email"] == ""  # required-but-empty is allowed


@pytest.mark.asyncio
async def test_create_extension_uses_variables_not_interpolation():
    """Operator data rides GraphQL variables, never string-interpolated."""
    client, rec = _oauth_client()
    await client.create_extension("8000", {"name": "Front Desk"})
    assert "$input" in rec.last_query
    assert rec.last_vars["input"]["name"] == "Front Desk"
    # the operator value must NOT appear baked into the query text
    assert "Front Desk" not in rec.last_query


@pytest.mark.asyncio
async def test_update_extension_mutation_and_input():
    client, rec = _oauth_client()
    await client.update_extension("8000", {"name": "X"})
    assert "updateExtension(input:$input)" in rec.last_query
    assert rec.last_vars["input"]["extensionId"] == "8000"


@pytest.mark.asyncio
async def test_delete_extension_mutation():
    client, rec = _oauth_client()
    await client.delete_extension("8000")
    assert "deleteExtension(input:$input)" in rec.last_query


# ── Inbound routes (DIDs) ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_did_mutation_and_destination():
    client, rec = _oauth_client()
    await client.create_did(
        {"extension": "15551234", "description": "d", "destination": "app-blackhole,hangup,1"}
    )
    assert "addInboundRoute(input:$input)" in rec.last_query
    inp = rec.last_vars["input"]
    assert inp["extension"] == "15551234"
    assert inp["destination"] == "app-blackhole,hangup,1"


@pytest.mark.asyncio
async def test_update_did_threads_old_keys():
    """Inbound routes are keyed by (extension, cidnum); update must thread the
    old key so FreePBX can locate the row."""
    client, rec = _oauth_client()
    await client.update_did("15551234/8005551212", {"description": "new"})
    assert "updateInboundRoute(input:$input)" in rec.last_query
    inp = rec.last_vars["input"]
    assert inp["oldExtension"] == "15551234"
    assert inp["oldCidnum"] == "8005551212"


@pytest.mark.asyncio
async def test_delete_did_by_id():
    client, rec = _oauth_client()
    await client.delete_did("15551234/")
    assert "removeInboundRoute(input:$input)" in rec.last_query
    assert rec.last_vars["input"] == {"id": "15551234/"}


# ── Ring groups ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_ring_group_mutation():
    client, rec = _oauth_client()
    await client.create_ring_group({"groupNumber": "600", "description": "Sales"})
    assert "addRingGroup(input:$input)" in rec.last_query


@pytest.mark.asyncio
async def test_update_ring_group_sets_group_number():
    client, rec = _oauth_client()
    await client.update_ring_group("600", {"description": "Sales"})
    assert "updateRingGroup(input:$input)" in rec.last_query
    assert rec.last_vars["input"]["groupNumber"] == "600"


@pytest.mark.asyncio
async def test_delete_ring_group_mutation():
    client, rec = _oauth_client()
    await client.delete_ring_group("600")
    assert "deleteRingGroup(input:$input)" in rec.last_query
    assert rec.last_vars["input"] == {"groupNumber": "600"}


# ── Write-result unwrapping ─────────────────────────────────────────────


def test_gql_write_result_raises_on_status_false():
    with pytest.raises(FreePBXApiError, match="boom"):
        FreePBXRestClient._gql_write_result({"addExtension": {"status": False, "message": "boom"}}, "addExtension")


def test_gql_write_result_returns_payload_on_success():
    out = FreePBXRestClient._gql_write_result(
        {"addExtension": {"status": True, "message": "created"}}, "addExtension"
    )
    assert out == {"status": True, "message": "created"}


# ── OAuth2 requirement ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_writes_require_oauth2_mode():
    """In session (non-OAuth2) mode, GraphQL writes refuse up front."""
    client = FreePBXRestClient(host="pbx.example.test", username="admin", password="x")
    assert client._auth_mode == "session"
    for coro in (
        client.create_extension("8000", {}),
        client.create_did({"destination": "x"}),
        client.create_ring_group({"groupNumber": "600"}),
    ):
        with pytest.raises(FreePBXApiError, match="OAuth2"):
            await coro


# ── FreePBX limitation: trunks / queues / IVR have no write transport ────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method,args",
    [
        ("create_trunk", ({},)),
        ("update_trunk", ("1", {})),
        ("delete_trunk", ("1",)),
        ("create_queue", ({},)),
        ("update_queue", ("700", {})),
        ("delete_queue", ("700",)),
        ("create_ivr", ({},)),
        ("update_ivr", ("1", {})),
        ("delete_ivr", ("1",)),
    ],
)
async def test_unsupported_writes_raise(method, args):
    """Trunks, queues, and IVRs have no GraphQL/REST write path on FreePBX —
    the adapter must raise (so the staged apply surfaces a clear error)
    rather than silently succeed. Locks the documented limitation."""
    client, _ = _oauth_client()
    with pytest.raises(FreePBXApiError):
        await getattr(client, method)(*args)


# ── Response PARSING (FreeSDN correctly reads a real FreePBX response) ────
#
# The write-shape tests above assert what FreeSDN SENDS; these assert that the
# read methods correctly PARSE the shapes FreePBX returns. A _DataStub returns
# a fixed GraphQL ``data`` block so the parse/normalize path is exercised.


def _client_returning(data: dict):
    client, _ = _oauth_client()

    async def _fake_graphql(query, variables=None, *, operation_name=None, idempotent=False):
        return data

    client._graphql = _fake_graphql  # type: ignore[assignment]
    return client


@pytest.mark.asyncio
async def test_list_dids_parses_inbound_routes_envelope():
    client = _client_returning(
        {
            "allInboundRoutes": {
                "inboundRoutes": [
                    {"id": "15551234/", "extension": "15551234", "description": "Main"},
                    {"id": "18005551212/", "extension": "18005551212", "description": "TF"},
                ],
                "totalCount": 2,
            }
        }
    )
    rows = await client.list_dids()
    assert [r["extension"] for r in rows] == ["15551234", "18005551212"]


@pytest.mark.asyncio
async def test_get_system_status_parses_need_reload():
    client = _client_returning(
        {"fetchAsteriskDetails": {"needReload": True, "version": "20.5.0", "status": "running"}}
    )
    status = await client.get_system_status()
    assert status["needReload"] is True
    assert status["version"] == "20.5.0"


@pytest.mark.asyncio
async def test_list_dids_empty_envelope_is_safe():
    """A missing/empty envelope must normalize to [] (not raise)."""
    client = _client_returning({"allInboundRoutes": {"inboundRoutes": None}})
    assert await client.list_dids() == []


# ── Transport resilience: idempotent reads retry transient blips ─────────


class _Resp:
    def __init__(self, status, text):
        self.status = status
        self._text = text

    async def text(self):
        return self._text


class _FlakyCtx:
    def __init__(self, session, call_n):
        self._session = session
        self._call_n = call_n

    async def __aenter__(self):
        if self._call_n <= self._session.fail_times:
            raise aiohttp.ClientError("transient blip")
        return _Resp(200, '{"data": {"ok": 1}}')

    async def __aexit__(self, *a):
        return False


class _FlakySession:
    def __init__(self, fail_times: int):
        self.fail_times = fail_times
        self.calls = 0

    def post(self, *a, **k):
        self.calls += 1
        return _FlakyCtx(self, self.calls)


def _client_with_session(session) -> FreePBXRestClient:
    # Build directly (not via _oauth_client, which stubs out _graphql) so the
    # REAL _graphql runs against the fake session.
    client = FreePBXRestClient(
        host="pbx.example.test",
        username="admin",
        password="x",
        api_client_id="cid",
        api_client_secret="csec",
    )
    client._auth_mode = "oauth2"
    client._session = session

    async def _tok():
        return "tok"

    client._ensure_oauth2_token = _tok  # type: ignore[assignment]
    return client


async def _no_sleep(*_a, **_k):
    return None


@pytest.mark.asyncio
async def test_graphql_idempotent_read_retries_transient(monkeypatch):
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    # All but the last allowed attempt blip, so the read still succeeds.
    session = _FlakySession(fail_times=REST_MAX_RETRIES - 1)
    client = _client_with_session(session)
    data = await client._graphql("{ ok }", idempotent=True)
    assert data == {"ok": 1}
    assert session.calls == REST_MAX_RETRIES  # retried up to the cap


@pytest.mark.asyncio
async def test_graphql_write_does_not_retry(monkeypatch):
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    session = _FlakySession(fail_times=1)  # single blip
    client = _client_with_session(session)
    with pytest.raises(FreePBXConnectionError):
        await client._graphql("mutation { x }")  # idempotent defaults False
    assert session.calls == 1  # writes are NOT auto-retried (no double-write)
