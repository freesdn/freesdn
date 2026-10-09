"""Explicit operation busy/refusal and same-intent authorization on retry.

This replaces the obsolete DELETE target-row-wait contract. The supported
operation protocol refuses conflicting table locks with NOWAIT; it does not
queue that request. Observe the real PostgreSQL refusal without replacing auth,
SQL, commit, cancellation or filesystem behavior. No actual wait is claimed.
"""

import hashlib
from contextlib import asynccontextmanager
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from sqlalchemy import event, insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import api_router
from app.api.v1.endpoints.agent_release_operations import (
    ReleaseOperationPolicy,
    create_release_operation_router,
)
from app.core.security import verify_token
from app.db.session import get_session
from app.main import app as product_app
from app.models.agent_release_operations import AgentReleaseOperation
from app.models.agents import AgentRelease
from app.models.api_keys import APIKey
from app.models.core import User, UserSession
from app.schemas.agent_release_operation_contract import IntentReviewResponse, OperationResponse
from app.schemas.agent_release_operations import encode_release_command
from app.services.agent_release_delete_request import ReleaseDeletionRequest
from app.services.agent_release_request import ReleaseReservationBudget
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_release_cleanup_coordinator as cleanup_probes
from tests.services import test_agent_release_reservation as reservation_probes
from tests.services import test_agent_signing_lifecycle as lifecycle_probes


@pytest_asyncio.fixture
async def public_deletion_wait(maintenance_engine, monkeypatch, tmp_path):
    context = asynccontextmanager(cleanup_probes.cleaner.__wrapped__)
    async with context(maintenance_engine, monkeypatch, tmp_path) as f:
        f.legacy_root = tmp_path / 'owned-legacy-release'
        f.legacy_root.mkdir(mode=0o700)
        monkeypatch.setenv('FREESDN_AGENT_RELEASE_DIR', str(f.legacy_root))
        f.request_pids = []
        app = FastAPI(exception_handlers=product_app.exception_handlers)
        app.include_router(api_router, prefix='/api/v1')
        app.include_router(create_release_operation_router(ReleaseOperationPolicy(
            root=str(f.artifacts), budget=ReleaseReservationBudget(100, 100, 1073741824, 1073741824),
        )), prefix='/api/v1/agents')

        async def request_session():
            # Pin the authentication connection independently of any commit.
            # The coordinator owns a different physical security connection.
            async with f.engine.connect() as connection:
                f.request_pids.append(await connection.scalar(text('SELECT pg_backend_pid()')))
                await connection.rollback()
                async with AsyncSession(bind=connection, expire_on_commit=False, autoflush=False) as db:
                    yield db

        app.dependency_overrides[get_session] = request_session
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url='http://test',
        ) as client:
            f.public_routes = client
            yield f


async def _state(f, release_id, operation_id):
    async with AsyncSession(f.engine) as db:
        release = (await db.execute(select(AgentRelease.__table__).where(
            AgentRelease.id == release_id,
        ))).mappings().one_or_none()
        operation = (await db.execute(select(AgentReleaseOperation.__table__).where(
            AgentReleaseOperation.operation_id == operation_id,
        ))).mappings().one_or_none()
    return dict(release) if release is not None else None, dict(operation) if operation is not None else None


@pytest.mark.parametrize('kind', ['jwt', 'key'])
@pytest.mark.parametrize('transition', ['disabled', 'role', 'credential', 'target-owner', 'valid-control'])
async def test_public_delete_busy_retry_revalidates_current_authority(
    public_deletion_wait, kind, transition, record_property,
):
    f = public_deletion_wait
    release_id = uuid4()
    content = b'owned target whose authority must survive a database wait'
    payload = f.legacy_root / f'{release_id}-owned-agent.bin'
    payload.write_bytes(content)
    unrelated = f.legacy_root / 'unrelated-evidence'
    unrelated.write_bytes(b'preserve')
    async with f.engine.begin() as db:
        await db.execute(update(User).where(User.id == f.user).values(role='org_admin'))
        await db.execute(insert(AgentRelease).values(
            id=release_id, organization_id=f.org, version='owned-wait-' + release_id.hex[:12],
            platform='linux', agent_type='daemon',
            download_url=f'/api/v1/agents/releases/{release_id}/binary',
            checksum_sha256=hashlib.sha256(content).hexdigest(), file_size=len(content), filename='owned-agent.bin',
            signature=None, is_latest=False, is_prerelease=False,
            release_notes='Owned authority wait', min_backend_version='', download_count=0,
        ))
    credential = await lifecycle_probes.headers(f, kind)
    claims = await verify_token(credential['Authorization'].split(' ', 1)[1]) if kind == 'jwt' else None
    original, absent = await _state(f, release_id, uuid4())
    assert original is not None and absent is None
    intent = ReleaseDeletionRequest.capture(operation_id=uuid4(), release=original)
    body = encode_release_command(intent)
    headers = {**credential, 'Content-Type': 'application/json'}
    path = f'/api/v1/agents/release-operations/{intent.operation_id}'
    reviewed = await f.public_routes.get(
        f'/api/v1/agents/releases/{release_id}/deletion-intent/{intent.operation_id}', headers=credential,
    )
    assert reviewed.status_code == 200
    assert IntentReviewResponse.model_validate_json(reviewed.content).intent_sha256 == intent.request_sha256()
    reserved = await f.public_routes.post(path + '/reserve', content=body, headers=headers)
    assert reserved.status_code == 200
    assert OperationResponse.model_validate_json(reserved.content).result.phase == 'reserved'
    before, journal = await _state(f, release_id, intent.operation_id)
    assert before == original
    assert journal['phase'] == 'reserved' and journal['decision'] is None and journal['transition_sequence'] == 0
    assert journal['request_bytes'] == intent.request_bytes() and journal['request_sha256'] == intent.request_sha256()
    retired = await f.public_routes.delete(f'/api/v1/agents/releases/{release_id}', headers=credential)
    record_property('retired_delete_status', retired.status_code)
    assert retired.status_code == 410 and await _state(f, release_id, intent.operation_id) == (before, journal)
    actual_refusals = []

    def observe_database_error(context):
        # Read driver metadata only. Do not consume a cursor, issue another SQL
        # statement, return an exception or alter the failing transaction.
        error = context.original_exception
        statement = ' '.join((context.statement or '').split())
        if getattr(error, 'sqlstate', None) == '55P03':
            driver = context.connection.connection.driver_connection
            actual_refusals.append({'sqlstate': error.sqlstate, 'statement': statement,
                                    'owner_pid': driver.get_server_pid()})

    event.listen(f.engine.sync_engine, 'handle_error', observe_database_error)
    try:
        async with AsyncSession(f.engine) as holder:
            holder_pid = await holder.scalar(text('SELECT pg_backend_pid()'))
            # This conflicts with the real phase's SHARE NOWAIT table lock.
            # It neither takes account locks nor fabricates an awaited row lock.
            await holder.execute(text('LOCK TABLE agents.agent_releases IN ROW EXCLUSIVE MODE'))
            granted = await holder.scalar(text(
                "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid() "
                "AND relation='agents.agent_releases'::regclass AND mode='RowExclusiveLock' AND granted)"
            ))
            assert granted is True
            first = await f.public_routes.post(path + '/delete', content=body, headers=headers)
            busy_state = await _state(f, release_id, intent.operation_id)
            first_files = payload.read_bytes() == content and unrelated.read_bytes() == b'preserve'
            record_property('actual_busy_http_status', first.status_code)
            record_property('actual_postgres_lock_refusals', len(actual_refusals))
            record_property('actual_busy_state_unchanged', busy_state == (before, journal))
            record_property('actual_busy_files_preserved', first_files)
            assert first.status_code == 503 and busy_state == (before, journal) and first_files
            assert len(actual_refusals) == 1
            refusal = actual_refusals[0]
            assert refusal['statement'] == 'LOCK TABLE agents.agent_releases IN SHARE MODE NOWAIT'
            assert refusal['owner_pid'] != holder_pid and refusal['owner_pid'] not in f.request_pids
            record_property('native_nowait_55P03_observed', True)
            record_property('operation_owner_connection_distinct_from_authentication_and_holder', True)
            record_property('actual_table_lock_was_granted', granted)
            if transition == 'disabled':
                await holder.execute(update(User).where(User.id == f.user).values(is_active=False))
            elif transition == 'role':
                await holder.execute(update(User).where(User.id == f.user).values(role='viewer'))
            elif transition == 'credential':
                if kind == 'jwt':
                    await holder.execute(update(UserSession).where(
                        UserSession.access_jti == claims['jti'],
                    ).values(is_revoked=True))
                else:
                    await holder.execute(update(APIKey).where(APIKey.id == f.key_id).values(is_active=False))
            elif transition == 'target-owner':
                await holder.execute(update(AgentRelease).where(
                    AgentRelease.id == release_id,
                ).values(organization_id=f.other_org))
            expected = dict((await holder.execute(select(AgentRelease.__table__).where(
                AgentRelease.id == release_id,
            ))).mappings().one())
            await holder.commit()
    finally:
        event.remove(f.engine.sync_engine, 'handle_error', observe_database_error)
    committed, retained = await _state(f, release_id, intent.operation_id)
    assert committed == expected and retained == journal
    response = await f.public_routes.post(path + '/delete', content=body, headers=headers)
    row, decision = await _state(f, release_id, intent.operation_id)
    preserved = payload.exists() and payload.read_bytes() == content
    unchanged = row is not None and row == expected
    untouched = unrelated.read_bytes() == b'preserve'
    record_property('actual_retry_http_status', response.status_code)
    record_property('actual_committed_release_present', row is not None)
    record_property('actual_release_matches_committed_holder_state', unchanged)
    record_property('actual_original_payload_preserved', preserved)
    record_property('actual_unrelated_payload_preserved', untouched)
    record_property('actual_retained_operation_phase', decision['phase'])
    record_property('actual_retained_operation_decision', str(decision['decision']))
    assert decision['request_bytes'] == intent.request_bytes() and decision['request_sha256'] == intent.request_sha256()
    if transition == 'valid-control':
        assert response.status_code == 200 and row is None
        result = OperationResponse.model_validate_json(response.content).result
        assert result.decision == 'deleted' and result.cleanup_disposition == 'retain-unverified'
        assert decision['phase'] == 'decided' and decision['decision'] == 'deleted' and decision['transition_sequence'] == 2
        # A successful legacy unpublication never grants filesystem cleanup.
        assert preserved
        replay = await f.public_routes.post(path + '/delete', content=body, headers=headers)
        record_property('actual_decided_replay_status', replay.status_code)
        assert replay.status_code == 200
        assert await _state(f, release_id, intent.operation_id) == (None, decision)
        assert OperationResponse.model_validate_json(replay.content).result.newly_changed is False
    else:
        assert response.status_code in {401, 403, 404, 409}
        assert unchanged and preserved and decision == journal
    assert untouched and payload.read_bytes() == content and unrelated.read_bytes() == b'preserve'
    await reservation_probes.assert_leases_free(f, intent)
