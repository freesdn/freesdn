"""SSE response/revocation regressions with synthetic identity and vendor data."""

import asyncio
import inspect
import json
from contextlib import asynccontextmanager
from copy import deepcopy
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException, Request

from app.core import dependencies
from app.core.dependencies import CurrentUser
from app.db import session as sessions
from app.modules.firewall.gateway_api import stream_firewall_logs
from app.modules.firewall.gateway_service import GatewayNotFoundError, GatewayService


@pytest.fixture
def stream_fixture(monkeypatch):
    org, site, actor, gateway_id = (uuid4() for _ in range(4))
    user = SimpleNamespace(id=actor, organization_id=org, role="viewer", email="owned@example.test")
    principal = CurrentUser(
        user,
        ["firewall.view"],
        {"jti": "owned-stream-jti", "tv": 0},
        accessible_site_ids={site},
    )
    gateway = SimpleNamespace(
        id=gateway_id,
        org_id=org,
        site_id=site,
        vendor="opnsense",
        host="192.0.2.1",
        port=443,
        verify_ssl=True,
        credentials={"owned": "synthetic"},
        settings={},
    )
    f = SimpleNamespace(
        principal=principal,
        current=deepcopy(principal),
        gateway=gateway,
        calls=0,
        active_sessions=0,
        original_closed=False,
        disconnected=False,
        data={"logs": [{"message": "owned-private-stream-entry"}]},
        during=None,
        unavailable=False,
        missing=False,
        authority_error=False,
    )

    class Session:
        async def close(self):
            f.original_closed = True

    @asynccontextmanager
    async def factory():
        f.active_sessions += 1
        try:
            yield Session()
        finally:
            f.active_sessions -= 1

    async def authenticate(*args, **kwargs):
        if f.authority_error:
            raise RuntimeError("private authority storage failure")
        return f.current

    async def gateway_read(service, gateway_id, org_id):
        if (
            f.missing
            or org_id != f.gateway.org_id
            or (
                service.accessible_site_ids is not None
                and f.gateway.site_id not in service.accessible_site_ids
            )
        ):
            raise GatewayNotFoundError(gateway_id)
        return f.gateway

    async def logs(service, gateway_id, org_id, limit=50):
        f.calls += 1
        if f.during:
            f.during()
        if f.unavailable:
            raise RuntimeError("private vendor credentials in failure")
        return deepcopy(f.data)

    async def disconnected(_):
        return f.disconnected

    monkeypatch.setattr(sessions, "security_session_factory", factory)
    monkeypatch.setattr(dependencies, "get_current_user_optional", authenticate)
    monkeypatch.setattr(GatewayService, "get_gateway", gateway_read)
    monkeypatch.setattr(GatewayService, "get_live_firewall_log", logs)
    monkeypatch.setattr(Request, "is_disconnected", disconnected)
    f.service = GatewayService(db=Session(), accessible_site_ids={site})
    f.request = Request({"type": "http", "headers": [(b"authorization", b"Bearer owned")]})
    return f


async def response(f, limit=50):
    kwargs = {
        "gateway_id": f.gateway.id,
        "current_user": f.principal,
        "svc": f.service,
        "limit": limit,
        "interval": 0,
    }
    # Both versions exercise the real route/body iterator. Request was added to
    # the repaired handler; it is not a synthetic alternate production path.
    if "request" in inspect.signature(stream_firewall_logs).parameters:
        kwargs["request"] = f.request
    return await stream_firewall_logs(**kwargs)


async def next_event(r):
    return await asyncio.wait_for(anext(r.body_iterator), timeout=2)


@pytest.mark.parametrize("envelope", ["flat", "logs", "rows"])
async def test_real_service_log_envelopes_are_delivered_and_deduplicated(stream_fixture, envelope):
    f = stream_fixture
    rows = [{"message": "owned-private-stream-entry"}]
    f.data = {"logs": rows if envelope == "flat" else {envelope: rows}}
    r = await response(f)
    try:
        assert json.loads((await next_event(r)).removeprefix("data: ")) == rows
        assert await next_event(r) == ": keepalive\n\n"
    finally:
        await r.body_iterator.aclose()


def revoke(f, reason):
    if reason == "revoked":
        f.current = None
    elif reason == "role":
        f.current.permissions = []
    elif reason == "actor":
        f.current.user.id = uuid4()
    elif reason == "organization":
        f.current.user.organization_id = uuid4()
    elif reason == "credential":
        f.current.token_claims["jti"] = "other-credential"
    elif reason == "site-last-grant":
        f.current._accessible_site_ids = set()
    elif reason == "site-other-grant":
        f.current._accessible_site_ids = {uuid4()}
    elif reason == "site-level":
        f.current._site_access_levels = {f.gateway.site_id: "invalid"}
    elif reason == "target":
        f.gateway.host = "192.0.2.2"
    elif reason == "parents":
        f.missing = True
    elif reason == "authority-store":
        f.authority_error = True
    else:
        raise AssertionError(reason)


@pytest.mark.parametrize(
    "reason",
    [
        "revoked",
        "role",
        "actor",
        "organization",
        "credential",
        "site-last-grant",
        "site-other-grant",
        "site-level",
        "target",
        "parents",
        "authority-store",
    ],
)
@pytest.mark.parametrize("timing", ["between-polls", "during-io"])
async def test_revocation_ends_stream_without_releasing_inflight_logs(
    stream_fixture, reason, timing
):
    f = stream_fixture
    r = await response(f)
    try:
        await next_event(r)
        if timing == "between-polls":
            revoke(f, reason)
        else:
            f.during = lambda: revoke(f, reason)
        before = f.calls
        event = await next_event(r)
        assert event.startswith("event: close\n")
        assert "owned-private-stream-entry" not in event and "private authority" not in event
        assert f.calls == before + (timing == "during-io")
        with pytest.raises(StopAsyncIteration):
            await next_event(r)
        assert f.active_sessions == 0
    finally:
        await r.body_iterator.aclose()


async def test_no_database_session_is_held_while_stream_is_idle(stream_fixture):
    f = stream_fixture
    r = await response(f)
    try:
        assert f.original_closed and f.active_sessions == 0
        await next_event(r)
        assert f.active_sessions == 0
    finally:
        await r.body_iterator.aclose()


async def test_missing_gateway_is_404_before_stream_headers(stream_fixture):
    f = stream_fixture
    f.missing = True
    with pytest.raises(HTTPException) as exc:
        await response(f)
    assert exc.value.status_code == 404 and f.calls == 0


async def test_disconnect_stops_polling(stream_fixture):
    f = stream_fixture
    r = await response(f)
    f.disconnected = True
    try:
        with pytest.raises(StopAsyncIteration):
            await next_event(r)
        assert f.calls == 0
    finally:
        await r.body_iterator.aclose()


async def test_vendor_failure_is_generic_terminal_event(stream_fixture):
    f = stream_fixture
    r = await response(f)
    f.unavailable = True
    try:
        event = await next_event(r)
        assert event.startswith("event: close\n") and "private vendor" not in event
        with pytest.raises(StopAsyncIteration):
            await next_event(r)
    finally:
        await r.body_iterator.aclose()


async def test_existing_limit_bounds_emitted_rows(stream_fixture):
    f = stream_fixture
    f.data = {"logs": [{"message": str(n)} for n in range(5)]}
    r = await response(f, limit=2)
    try:
        assert len(json.loads((await next_event(r)).removeprefix("data: "))) == 2
    finally:
        await r.body_iterator.aclose()


@pytest.mark.parametrize("rows", [[], {"rows": []}, {"logs": []}])
async def test_empty_valid_log_response_remains_keepalive(stream_fixture, rows):
    f = stream_fixture
    f.data = {"logs": rows}
    r = await response(f)
    try:
        assert await next_event(r) == ": keepalive\n\n"
    finally:
        await r.body_iterator.aclose()


async def test_stream_without_organization_fails_closed(stream_fixture):
    f = stream_fixture
    f.principal.user.organization_id = None
    f.current.user.organization_id = None
    with pytest.raises(HTTPException) as exc:
        await response(f)
    assert exc.value.status_code == 404 and f.calls == 0
