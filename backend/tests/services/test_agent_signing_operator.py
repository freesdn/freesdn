"""Private actual-router/PG contracts; planned, never runtime-qualified yet.

The limiter uses its actual implementation with a deterministic owned Redis
protocol double. This does not qualify a real Redis outage or distributed quota.
Authentication, factors, journal phases, storage and migrations are not bypassed.
Browser-cookie/CSRF and full application registration remain separate gates.
"""

import asyncio
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import replace
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI, HTTPException
from sqlalchemy import text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints import agent_signing as endpoint
from app.core import redis_client
from app.db.session import get_session
from app.main import app as product_app
from app.models.agent_signing import AgentSigningIdentity
from app.models.api_keys import APIKey
from app.models.core import User
from app.models.sso import SSOProvider
from app.services import agent_signing_lifecycle as lifecycle
from app.services import agent_signing_status as inspection
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_signing_lifecycle as lifecycle_probes

PREFIX = "/api/v1/auth/agent-signing"


@pytest_asyncio.fixture
async def operator(maintenance_engine, monkeypatch, tmp_path):
    context = asynccontextmanager(lifecycle_probes.owned_lifecycle.__wrapped__)
    async with context(maintenance_engine, monkeypatch, tmp_path) as f:
        app = FastAPI(exception_handlers=product_app.exception_handlers)
        app.include_router(endpoint.router, prefix=PREFIX)

        async def request_session():
            async with AsyncSession(f.engine, expire_on_commit=False, autoflush=False) as db:
                yield db

        app.dependency_overrides[get_session] = request_session
        f.redis_count, f.redis_unavailable, f.redis_closed = 0, False, 0

        class OwnedRedis:
            async def incr(self, key):
                assert key.startswith("auth:ratelimit:")
                if f.redis_unavailable:
                    raise ConnectionError("Owned Redis unavailable control")
                f.redis_count += 1
                return f.redis_count

            async def expire(self, key, seconds):
                assert key.startswith("auth:ratelimit:") and seconds > 0

            async def aclose(self):
                f.redis_closed += 1

        monkeypatch.setattr(redis_client, "get_async_redis", lambda **_kwargs: OwnedRedis())
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                                     base_url="http://test") as client:
            f.operator_client = client
            yield f


def command_body(f, **changes):
    command = replace(f.command, **changes)
    return {"action": command.action, "operation_id": str(command.operation_id),
            "installation_id": str(command.installation_id), "identity_epoch": command.identity_epoch,
            "expected_public_sha256": command.expected_public_sha256}


def execute_body(f, **changes):
    return {**command_body(f, **changes), "password": f.password, "acknowledge_identity_risk": True,
            "acknowledge_no_prior_identity": True, "acknowledge_independent_fingerprint": True}


async def change_account(f, **values):
    async with AsyncSession(f.engine) as db, db.begin():
        await db.execute(update(User).where(User.id == f.user).values(**values))


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("null_org", [False, True])
@pytest.mark.parametrize("resource", ["status", "missing_operation"])
async def test_inspection_does_not_initialize_or_touch_key_storage(operator, kind, null_org, resource):
    f = operator
    if null_org:
        await change_account(f, organization_id=None)
    headers = await lifecycle_probes.headers(f, kind)
    before = await lifecycle_probes.snapshot(f)
    path = "/status" if resource == "status" else "/operations/" + str(uuid4())
    result = await f.operator_client.get(PREFIX + path, headers=headers)
    after = await lifecycle_probes.snapshot(f)
    assert after == before and not f.root.exists() and f.redis_count == 0
    assert result.status_code == (200 if resource == "status" else 404)
    if result.status_code == 200:
        body = result.json()
        assert body["state"] == "unconfigured" and body["active"] is None
        assert body["storage_checked"] is body["authorization_granted"] is body["empty_state_proves_new_installation"] is False
        assert result.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("action", ["initialize", "adopt", "resume", "cancel", "recover"])
async def test_preflight_is_read_only_and_not_an_authorization_grant(operator, kind, action):
    f = operator
    headers = await lifecycle_probes.headers(f, kind)
    body = command_body(f, action=action, expected_public_sha256="a"*64 if action in ("adopt", "recover") else None)
    before = await lifecycle_probes.snapshot(f)
    result = await f.operator_client.post(PREFIX + "/preflight", headers=headers, json=body)
    after = await lifecycle_probes.snapshot(f)
    assert result.status_code == 200 and before == after and not f.root.exists()
    reply = result.json()
    assert reply["database_eligible"] is (action in ("initialize", "adopt"))
    assert reply["authorization_granted"] is reply["storage_checked"] is False
    assert reply["fresh_confirmation_required"] is True and f.redis_count == 0


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("null_org", [False, True])
async def test_actual_local_route_activates_and_status_exposes_only_public_metadata(operator, kind, null_org):
    f = operator
    if null_org:
        await change_account(f, organization_id=None)
    headers = await lifecycle_probes.headers(f, kind)
    result = await f.operator_client.post(PREFIX + "/execute-local", headers=headers, json=execute_body(f))
    durable = await lifecycle_probes.snapshot(f)
    assert result.status_code == 200 and result.json()["state"] == "activated"
    assert len(durable[0]) == len(durable[1]) == 1 and durable[2]
    status = await f.operator_client.get(PREFIX + "/operations/" + str(f.command.operation_id), headers=headers)
    assert status.status_code == 200 and status.json()["operation"]["state"] == "activated"
    body = status.json()
    assert body["active"]["public_key_sha256"] == durable[2][".public-key.pem"]
    assert set(body["active"]) == {"operation_id", "installation_id", "identity_epoch", "public_key_sha256", "activated_at"}
    assert set(body["operation"]) == set(inspection._PUBLIC_OPERATION_FIELDS)
    assert f.password not in status.text and "BEGIN " not in status.text
    assert "password" not in status.text and "confirmation_id" not in status.text
    assert f.redis_count == f.redis_closed == 1


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("phase", ["pending", "prepared", "activated"])
async def test_lost_response_has_inspectable_retained_phase_without_automatic_retry(operator, monkeypatch, kind, phase):
    f = operator
    headers = await lifecycle_probes.headers(f, kind)
    original = lifecycle._phase

    async def lost_after_committed_phase(*args, **kwargs):
        result = await original(*args, **kwargs)
        row = result[0] if isinstance(result, tuple) else result
        if row["state"] == phase:
            raise HTTPException(503, "Owned lost response after real committed phase")
        return result

    monkeypatch.setattr(lifecycle, "_phase", lost_after_committed_phase)
    result = await f.operator_client.post(PREFIX + "/execute-local", headers=headers, json=execute_body(f))
    retained = await lifecycle_probes.snapshot(f)
    assert result.status_code == 503 and retained[0][0]["state"] == phase
    status = await f.operator_client.get(PREFIX + "/operations/" + str(f.command.operation_id), headers=headers)
    assert status.status_code == 200 and status.json()["operation"]["state"] == phase
    assert await lifecycle_probes.snapshot(f) == retained
    assert f.redis_count == 1


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("change", ["disabled", "role", "version", "credential"])
async def test_current_authority_rechecked_after_owned_snapshot_before_disclosure(operator, monkeypatch, kind, change):
    f = operator
    headers = await lifecycle_probes.headers(f, kind)
    original = inspection._read_snapshot
    captured, proceed = asyncio.Event(), asyncio.Event()

    async def pause_after_real_snapshot(operation_id):
        value = await original(operation_id)
        captured.set()
        await proceed.wait()
        return value

    monkeypatch.setattr(inspection, "_read_snapshot", pause_after_real_snapshot)
    request = asyncio.create_task(f.operator_client.get(PREFIX + "/status", headers=headers))
    try:
        async with asyncio.timeout(10):
            await captured.wait()
            if change == "credential" and kind == "key":
                async with AsyncSession(f.engine) as db, db.begin():
                    await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(is_active=False))
            else:
                values = {"disabled": {"is_active": False}, "role": {"role": "viewer"},
                          "version": {"token_version": 18}, "credential": {"token_version": 18}}[change]
                await change_account(f, **values)
            proceed.set()
            result = await request
        assert result.status_code == 401 and "retained_installation_id" not in result.text
        assert not f.root.exists()
    finally:
        proceed.set()
        if not request.done():
            request.cancel()
        await asyncio.gather(request, return_exceptions=True)


@pytest.mark.parametrize("mode", ["wrong_password", "redis_unavailable", "rate_exhausted", "scoped_key", "org_admin"])
async def test_refused_confirmation_has_no_signing_journal_or_key_side_effect(operator, mode):
    f = operator
    body = execute_body(f)
    if mode == "wrong_password":
        body["password"] += "-wrong"
    elif mode == "redis_unavailable":
        f.redis_unavailable = True
    elif mode == "rate_exhausted":
        f.redis_count = 5
    elif mode == "scoped_key":
        async with AsyncSession(f.engine) as db, db.begin():
            await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(scopes=["agent:admin"]))
    else:
        await change_account(f, role="org_admin")
    before = await lifecycle_probes.snapshot(f)
    result = await f.operator_client.post(PREFIX + "/execute-local", headers=await lifecycle_probes.headers(f), json=body)
    assert await lifecycle_probes.snapshot(f) == before and not f.root.exists()
    assert result.status_code == {"wrong_password": 401, "redis_unavailable": 503,
                                  "rate_exhausted": 429, "scoped_key": 403, "org_admin": 403}[mode]


@pytest.mark.parametrize("change", [
    ("action", "inspect"), ("action", "rotate"), ("identity_epoch", True), ("identity_epoch", "1"),
    ("operation_id", "not-a-uuid"), ("password", ""), ("code", "x"*11),
    ("acknowledge_identity_risk", False), ("acknowledge_no_prior_identity", False),
    ("confirmation_id", "untrusted"), ("secret_key", "untrusted"), ("private_key", "untrusted"),
])
async def test_wire_intent_refuses_coercion_missing_acknowledgment_and_forged_receipts(operator, change):
    f = operator
    body = execute_body(f)
    body[change[0]] = change[1]
    result = await f.operator_client.post(PREFIX + "/execute-local", headers=await lifecycle_probes.headers(f), json=body)
    assert result.status_code == 422 and not f.root.exists()
    assert f.redis_count == 0 and f.password not in result.text
    assert (await lifecycle_probes.snapshot(f))[:2] == ([], [])


async def test_repeatable_status_snapshot_during_actual_activation_has_no_mixed_phases(operator, monkeypatch, record_property):
    f = operator
    headers = await lifecycle_probes.headers(f)
    phase = lifecycle._phase

    async def stop_prepared(*args, **kwargs):
        result = await phase(*args, **kwargs)
        if not isinstance(result, tuple) and result["state"] == "prepared":
            raise HTTPException(503, "Owned response loss after committed preparation")
        return result

    monkeypatch.setattr(lifecycle, "_phase", stop_prepared)
    initial = await f.operator_client.post(PREFIX + "/execute-local", headers=headers, json=execute_body(f))
    assert initial.status_code == 503 and (await lifecycle_probes.snapshot(f))[0][0]["state"] == "prepared"
    monkeypatch.setattr(lifecycle, "_phase", phase)
    execute = AsyncSession.execute
    observed, proceed = asyncio.Event(), asyncio.Event()
    reader = None
    # A request can enter owned child tasks; tag its context instead of one task.
    reader_context = ContextVar("signing_snapshot_reader", default=False)
    pids = {}

    async def after_identity_read(db, statement, *args, **kwargs):
        result = await execute(db, statement, *args, **kwargs)
        if (reader_context.get() and getattr(statement, "is_select", False)
                and any(table is AgentSigningIdentity.__table__ for table in statement.get_final_froms())
                and statement._for_update_arg is None and not observed.is_set()):
            pids["read"] = (await execute(db, text("SELECT pg_backend_pid()"))).scalar_one()
            assert (await execute(db, text("SHOW transaction_isolation"))).scalar_one() == "repeatable read"
            assert (await execute(db, text("SHOW transaction_read_only"))).scalar_one() == "on"
            pids["owned_child"] = asyncio.current_task() is not reader
            observed.set()
            await proceed.wait()
        return result

    async def observed_phase(db, *args, **kwargs):
        assert not reader_context.get()
        # Capture the actual writer's dedicated physical connection without
        # leaving an extra caller transaction open before the original phase.
        pids["write"] = await db.scalar(text("SELECT pg_backend_pid()"))
        await db.rollback()
        return await phase(db, *args, **kwargs)

    monkeypatch.setattr(AsyncSession, "execute", after_identity_read)
    monkeypatch.setattr(lifecycle, "_phase", observed_phase)
    async def read_status():
        token = reader_context.set(True)
        try:
            return await f.operator_client.get(PREFIX + "/status", headers=headers)
        finally:
            reader_context.reset(token)

    reader = asyncio.create_task(read_status())
    try:
        async with asyncio.timeout(15):
            await observed.wait()
            resumed = await f.operator_client.post(PREFIX + "/execute-local", headers=headers,
                                                   json=execute_body(f, action="resume"))
            assert resumed.status_code == 200 and resumed.json()["state"] == "activated"
            proceed.set()
            status = await reader
        assert status.status_code == 200 and status.json()["state"] == "incomplete"
        assert status.json()["active"] is None and status.json()["open_operation"]["state"] == "prepared"
        assert pids["read"] != pids["write"]
        latest = await f.operator_client.get(PREFIX + "/status", headers=headers)
        assert latest.status_code == 200 and latest.json()["state"] == "active"
        record_property("request_context_crossed_owned_task", pids["owned_child"])
        record_property("actual_repeatable_read_read_only_transaction", True)
        record_property("consistent_snapshot_across_actual_activation", True)
        record_property("distinct_physical_connections", True)
    finally:
        proceed.set()
        if not reader.done():
            reader.cancel()
        await asyncio.gather(reader, return_exceptions=True)


@pytest.mark.parametrize("route", ["status", "preflight", "execute-local"])
async def test_missing_authentication_discloses_no_signing_state(operator, route):
    f = operator
    if route == "status":
        result = await f.operator_client.get(PREFIX + "/status")
    else:
        body = execute_body(f) if route == "execute-local" else command_body(f)
        result = await f.operator_client.post(PREFIX + "/" + route, json=body)
    assert result.status_code == 401 and "retained_installation_id" not in result.text
    assert not f.root.exists() and f.redis_count == 0


async def test_inspection_command_cannot_obtain_or_execute_a_fresh_mutation_factor(operator):
    from app.services.agent_signing_authority import FreshSigningFactor

    f = operator
    invalid = [
        ("inspect", uuid4(), UUID(int=0), 1),
        ("inspect", UUID(int=0), uuid4(), 1),
        ("inspect", UUID(int=0), UUID(int=0), 2),
    ]
    for args in invalid:
        with pytest.raises(ValueError):
            type(inspection.INSPECTION_COMMAND)(*args)
    f.command = inspection.INSPECTION_COMMAND
    refused_local = await f.lifecycle_client.post("/owned/signing-lifecycle", headers=await lifecycle_probes.headers(f))
    assert refused_local.status_code == 403 and not f.root.exists()
    # Internal boundary probe: no forged HTTP receipt is accepted by the schema.
    from unittest.mock import Mock

    from app.services.agent_signing_authority import SigningLifecycleAuthority

    authority = Mock(spec=SigningLifecycleAuthority)
    factor = FreshSigningFactor(authority, 1, 2)
    with pytest.raises(HTTPException) as refused:
        await lifecycle.execute_signing_lifecycle(factor=factor, command=inspection.INSPECTION_COMMAND)
    assert refused.value.status_code == 403
    authority.check.assert_not_called()


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("protocol", ["oidc", "ldap"])
async def test_external_account_inspection_never_substitutes_a_local_factor(operator, kind, protocol):
    f = operator
    async with AsyncSession(f.engine) as db, db.begin():
        await db.execute(update(SSOProvider).where(SSOProvider.id == f.provider).values(protocol=protocol))
        await db.execute(update(User).where(User.id == f.user).values(
            auth_provider=protocol, sso_provider_id=f.provider, external_id="owned-external-subject"
        ))
    headers = await lifecycle_probes.headers(f, kind)
    preflight = await f.operator_client.post(PREFIX + "/preflight", headers=headers, json=command_body(f))
    assert preflight.status_code == 200 and preflight.json()["confirmation_method"] == protocol
    assert preflight.json()["local_confirmation_available"] is False
    before = await lifecycle_probes.snapshot(f)
    executed = await f.operator_client.post(PREFIX + "/execute-local", headers=headers, json=execute_body(f))
    assert executed.status_code == 409 and await lifecycle_probes.snapshot(f) == before
    assert f.redis_count == 0 and not f.root.exists()
