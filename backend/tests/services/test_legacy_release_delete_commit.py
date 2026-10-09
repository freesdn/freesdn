"""Actual retained-operation commit-failure contract; private fixture correction.

Use the real operation router, authentication, permission and database commit path.
Only an owned database row, payload and deferred PostgreSQL rejection trigger
are involved. No authentication, commit method or filesystem call is replaced.
This harness does not qualify main-app middleware, startup or deployment.
"""

import hashlib
from contextlib import asynccontextmanager
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from sqlalchemy import event, insert, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import api_router
from app.api.v1.endpoints.agent_release_operations import (
    ReleaseOperationPolicy,
    create_release_operation_router,
)
from app.db.session import get_session
from app.main import app as product_app
from app.models.agent_release_operations import AgentReleaseOperation
from app.models.agents import AgentRelease
from app.schemas.agent_release_operation_contract import IntentReviewResponse, OperationResponse
from app.schemas.agent_release_operations import encode_release_command
from app.services.agent_release_delete_request import ReleaseDeletionRequest
from app.services.agent_release_request import ReleaseReservationBudget
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_release_cleanup_coordinator as cleanup_probes
from tests.services import test_agent_signing_lifecycle as lifecycle_probes


@pytest_asyncio.fixture
async def legacy_public_route(maintenance_engine, monkeypatch, tmp_path):
    context = asynccontextmanager(cleanup_probes.cleaner.__wrapped__)
    async with context(maintenance_engine, monkeypatch, tmp_path) as f:
        f.legacy_root = tmp_path / 'legacy-public-binaries'
        f.legacy_root.mkdir(mode=0o700)
        monkeypatch.setenv('FREESDN_AGENT_RELEASE_DIR', str(f.legacy_root))
        app = FastAPI(exception_handlers=product_app.exception_handlers)
        app.include_router(api_router, prefix='/api/v1')
        # Production creates this same router from its captured server policy.
        # Use only the owned fixture root and explicit unchanged-size budgets.
        app.include_router(create_release_operation_router(ReleaseOperationPolicy(
            root=str(f.artifacts), budget=ReleaseReservationBudget(100, 100, 1073741824, 1073741824),
        )), prefix='/api/v1/agents')

        async def request_session():
            async with AsyncSession(f.engine, expire_on_commit=False, autoflush=False) as db:
                yield db

        app.dependency_overrides[get_session] = request_session
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url='http://test',
        ) as client:
            f.public_routes = client
            yield f


@pytest.mark.parametrize('kind', ['jwt', 'key'])
@pytest.mark.parametrize('reject_at_commit', [True, False], ids=['deferred-commit-refusal', 'valid-control'])
async def test_public_legacy_delete_preserves_payload_when_database_commit_refuses(
    legacy_public_route, kind, reject_at_commit, record_property,
):
    f = legacy_public_route
    release_id = uuid4()
    content = b'owned legacy payload retained until a database decision'
    filename = 'owned-agent.bin'
    payload = f.legacy_root / f'{release_id}-{filename}'
    payload.write_bytes(content)
    unrelated = f.legacy_root / 'unrelated-owned-evidence'
    unrelated.write_bytes(b'unchanged')
    async with f.engine.begin() as db:
        await db.execute(insert(AgentRelease).values(
            id=release_id, organization_id=f.org, version='owned-legacy-' + release_id.hex[:12],
            platform='linux', agent_type='daemon',
            download_url=f'/api/v1/agents/releases/{release_id}/binary',
            checksum_sha256=hashlib.sha256(content).hexdigest(), file_size=len(content),
            filename=filename, signature=None, is_latest=False, is_prerelease=False,
            release_notes='Owned rollback qualification', min_backend_version='', download_count=0,
        ))
    credential = await lifecycle_probes.headers(f, kind)
    async with AsyncSession(f.engine) as db:
        original_row = dict((await db.execute(select(AgentRelease.__table__).where(
            AgentRelease.id == release_id,
        ))).mappings().one())
    intent = ReleaseDeletionRequest.capture(operation_id=uuid4(), release=original_row)
    reviewed = await f.public_routes.get(
        f'/api/v1/agents/releases/{release_id}/deletion-intent/{intent.operation_id}', headers=credential,
    )
    assert reviewed.status_code == 200
    assert IntentReviewResponse.model_validate_json(reviewed.content).intent_sha256 == intent.request_sha256()
    # Retired DELETE must refuse rather than forwarding or consuming intent.
    retired = await f.public_routes.delete(f'/api/v1/agents/releases/{release_id}', headers=credential)
    record_property('retired_delete_status', retired.status_code)
    assert retired.status_code == 410
    async with AsyncSession(f.engine) as db:
        assert dict((await db.execute(select(AgentRelease.__table__).where(
            AgentRelease.id == release_id,
        ))).mappings().one()) == original_row
    assert payload.read_bytes() == content and unrelated.read_bytes() == b'unchanged'
    function = 'owned_legacy_refusal_' + uuid4().hex
    trigger = 'owned_legacy_commit_' + uuid4().hex
    refusal_marker = 'Owned release deletion commit refusal ' + release_id.hex
    actual_refusals = []

    def observe_database_error(context):
        # Observe only: never return a replacement exception or alter rollback.
        error = context.original_exception
        if getattr(error, 'sqlstate', None) == '23514' and refusal_marker in str(error):
            actual_refusals.append(True)

    event.listen(f.engine.sync_engine, 'handle_error', observe_database_error)
    installed = False
    try:
        if reject_at_commit:
            # Generated names and the owned UUID are local fixture data. This
            # is a deferred PostgreSQL failure, not a mocked Python commit.
            async with f.engine.begin() as db:
                await db.execute(text(f"""
                    CREATE FUNCTION agents.{function}() RETURNS trigger
                    LANGUAGE plpgsql AS $$
                    BEGIN
                        RAISE EXCEPTION '{refusal_marker}'
                            USING ERRCODE = '23514';
                    END $$
                """))
                await db.execute(text(f"""
                    CREATE CONSTRAINT TRIGGER {trigger}
                    AFTER DELETE ON agents.agent_releases
                    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
                    WHEN (OLD.id = '{release_id}'::uuid)
                    EXECUTE FUNCTION agents.{function}()
                """))
            installed = True
        response = await f.public_routes.post(
            f'/api/v1/agents/release-operations/{intent.operation_id}/delete',
            content=encode_release_command(intent), headers={**credential, 'Content-Type': 'application/json'},
        )
        # Observe committed SQL and file state independently before assertions;
        # the first failed assertion must not hide the other observed effects.
        async with AsyncSession(f.engine) as db:
            row = (await db.execute(select(AgentRelease.__table__).where(
                AgentRelease.id == release_id,
            ))).mappings().one_or_none()
        async with AsyncSession(f.engine) as db:
            retained = dict((await db.execute(select(AgentReleaseOperation.__table__).where(
                AgentReleaseOperation.operation_id == intent.operation_id,
            ))).mappings().one())
        record_property('actual_retained_operation_phase', retained['phase'])
        record_property('actual_retained_operation_decision', str(retained['decision']))
        present = payload.exists()
        exact = present and payload.read_bytes() == content
        untouched = unrelated.read_bytes() == b'unchanged'
        record_property('actual_http_status', response.status_code)
        record_property('actual_committed_release_present', row is not None)
        record_property('actual_original_payload_present', present)
        record_property('actual_original_payload_bytes_preserved', exact)
        record_property('actual_unrelated_payload_preserved', untouched)
        record_property('deferred_database_refusal_installed', installed)
        record_property('actual_owned_deferred_database_refusal_observed', bool(actual_refusals))
        if reject_at_commit:
            assert actual_refusals == [True], 'The intended real database refusal must actually execute'
            assert response.status_code >= 400
            assert row is not None
            assert exact, 'A refused database deletion must retain the original release payload'
            assert dict(row) == original_row
            assert retained['phase'] == 'reserved' and retained['decision'] is None
            assert retained['transition_sequence'] == 0
        else:
            assert actual_refusals == []
            assert response.status_code == 200
            assert row is None
            result = OperationResponse.model_validate_json(response.content).result
            assert result.decision == 'deleted' and result.cleanup_disposition == 'retain-unverified'
            assert retained['phase'] == 'decided' and retained['decision'] == 'deleted'
            # The new deletion decision never grants unlink of unverified legacy bytes.
            assert exact
        assert retained['request_bytes'] == intent.request_bytes()
        assert retained['request_sha256'] == intent.request_sha256()
        assert untouched
    finally:
        event.remove(f.engine.sync_engine, 'handle_error', observe_database_error)
        if installed:
            async with f.engine.begin() as db:
                await db.execute(text(f'DROP TRIGGER {trigger} ON agents.agent_releases'))
                await db.execute(text(f'DROP FUNCTION agents.{function}()'))
