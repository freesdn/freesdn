"""Owned PostgreSQL and actual HTTP catalogue; no lifespan or browser proof.

These probes are private/unqualified until source freeze and first runtime.
A page is an observation, never a grant or signature verification result.
"""
import asyncio
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.models.agents import AgentRelease
from app.models.api_keys import APIKey
from app.models.core import User
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_signing_lifecycle as lifecycle
from tests.services.test_public_release_binary import public_reader as public_reader

PAGE = '/api/v1/agents/release-catalogue'
LEGACY = '/api/v1/agents/releases'
STAMP = datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)


async def seed_rows(f, owners, **overrides):
    rows = [{'id': uuid4(), 'organization_id': owner, 'version': '26.1', 'platform': 'linux', 'agent_type': 'daemon',
             'download_url': 'https://artifact.invalid/unverified', 'checksum_sha256': 'a'*64,
             'file_size': 10, 'release_notes': 'original', 'min_backend_version': '', 'is_latest': False,
             'is_prerelease': False, 'published_at': STAMP, 'download_count': 0, 'signature': None, 'filename': None}
            for owner in owners]
    for row in rows:
        row.update(overrides)
    async with f.engine.begin() as db:
        await db.execute(insert(AgentRelease), rows)
    return rows


async def snapshot(f):
    async with f.engine.connect() as db:
        return [dict(row) for row in (await db.execute(select(AgentRelease.__table__).order_by(AgentRelease.id))).mappings()]


@pytest.mark.parametrize('credential', ('jwt', 'key'))
async def test_pagination_retains_all_equal_timestamp_ids_without_duplicates(public_reader, credential):
    f = public_reader
    rows = await seed_rows(f, [f.org]*5)
    original = await snapshot(f)
    headers = await lifecycle.headers(f, credential)
    params = {'limit': 2}
    seen = []
    for index in range(3):
        response = await f.public_client.get(PAGE, headers=headers, params=params)
        assert response.status_code == 200, response.text
        data = response.json()
        assert set(data) == {'items', 'limit', 'has_more', 'next_published_at', 'next_id'}
        assert data['limit'] == 2 and data['has_more'] is (index < 2)
        assert len(data['items']) == (2 if index < 2 else 1)
        assert all(row['organization_id'] == str(f.org) and row['signature'] is None for row in data['items'])
        assert 'no-store' in response.headers['cache-control']
        seen.extend(row['id'] for row in data['items'])
        if index < 2:
            assert data['next_id'] == data['items'][-1]['id']
            assert data['next_published_at'] == data['items'][-1]['published_at']
            params.update(before_id=data['next_id'], before_published_at=data['next_published_at'])
        else:
            assert data['next_id'] is data['next_published_at'] is None
    assert seen == sorted([str(row['id']) for row in rows], reverse=True)
    assert len(set(seen)) == 5 and await snapshot(f) == original


@pytest.mark.parametrize('profile', ('org-jwt', 'org-key', 'super-jwt', 'super-scoped-key', 'no-org-scoped-key'))
async def test_page_preserves_actual_role_and_scoped_key_tenant_ceiling(public_reader, profile):
    f = public_reader
    rows = await seed_rows(f, [f.org, f.other_org, None])
    async with f.engine.begin() as db:
        if profile.startswith('org-'):
            await db.execute(update(User).where(User.id == f.user).values(role='org_admin'))
        if 'scoped' in profile:
            await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(scopes=['agent:admin']))
        if profile.startswith('no-org'):
            await db.execute(update(User).where(User.id == f.user).values(organization_id=None))
    headers = await lifecycle.headers(f, 'jwt' if profile.endswith('jwt') else 'key')
    response = await f.public_client.get(PAGE, headers=headers)
    assert response.status_code == 200, response.text
    expected = [] if profile.startswith('no-org') else rows if profile == 'super-jwt' else [rows[0], rows[2]]
    assert {row['id'] for row in response.json()['items']} == {str(row['id']) for row in expected}
    assert response.json()['has_more'] is False


@pytest.mark.parametrize('params,status', (
    ({'limit': 0}, 422), ({'limit': 101}, 422), ({'limit': 'true'}, 422),
    ({'before_id': 'not-a-uuid'}, 422), ({'before_published_at': '2026-01-01T00:00:00'}, 422),
    ({'before_id': '11111111-1111-4111-8111-111111111111'}, 400),
    ({'before_published_at': '2026-01-01T00:00:00Z'}, 400), ({'platform': 'x'*51}, 422),
))
async def test_invalid_page_input_is_explicit_and_has_no_database_mutation(public_reader, params, status):
    f = public_reader
    await seed_rows(f, [f.org])
    before = await snapshot(f)
    response = await f.public_client.get(PAGE, headers=await lifecycle.headers(f), params=params)
    assert response.status_code == status
    assert 'items' not in response.json() and await snapshot(f) == before


@pytest.mark.parametrize('count', (100, 101))
async def test_legacy_response_never_silently_omits_excess_rows(public_reader, count):
    f = public_reader
    rows = await seed_rows(f, [f.org]*count)
    before = await snapshot(f)
    response = await f.public_client.get(LEGACY, headers=await lifecycle.headers(f))
    assert response.status_code == (200 if count == 100 else 413)
    if count == 100:
        assert {row['id'] for row in response.json()} == {str(row['id']) for row in rows}
        assert all('organization_id' not in row for row in response.json())
    else:
        assert PAGE in response.json()['error']['message'] and not isinstance(response.json(), list)
    assert await snapshot(f) == before


@pytest.mark.parametrize('field,value', (
    ('release_notes', 'x'*20001), ('signature', 'x'*4097), ('release_notes', '\U0001f680'*20000),
    ('file_size', -1), ('download_count', -1),
))
async def test_stored_metadata_bounds_preserve_original_rows(public_reader, field, value):
    f = public_reader
    await seed_rows(f, [f.org], **{field: value})
    before = await snapshot(f)
    response = await f.public_client.get(PAGE, headers=await lifecycle.headers(f))
    valid_unicode = field == 'release_notes' and value.startswith('\U0001f680')
    assert response.status_code == (200 if valid_unicode else 409), response.text
    if valid_unicode:
        assert response.json()['items'][0]['release_notes'] == value
    else:
        assert 'items' not in response.json() and 'No rows were altered' in response.json()['error']['message']
    assert await snapshot(f) == before


@pytest.mark.parametrize('filter_name,raw', (('platform', 'LiNuX'), ('agent_type', 'DaEmOn')))
async def test_public_page_normalizes_filters_and_reports_empty_continuation(public_reader, filter_name, raw):
    f = public_reader
    rows = await seed_rows(f, [f.org])
    headers = await lifecycle.headers(f)
    response = await f.public_client.get(PAGE, headers=headers, params={filter_name: raw})
    assert response.status_code == 200 and [r['id'] for r in response.json()['items']] == [str(rows[0]['id'])]
    empty = await f.public_client.get(PAGE, headers=headers, params={filter_name: 'not-present'})
    assert empty.status_code == 200
    assert empty.json()['items'] == [] and empty.json()['has_more'] is False
    assert empty.json()['next_id'] is empty.json()['next_published_at'] is None


@pytest.mark.parametrize('mode', ('timeout', 'cancel', 'valid-wait', 'revoked-after-wait'))
async def test_real_page_query_wait_is_bounded_and_releases_request_resources(public_reader, mode, record_property):
    f = public_reader
    await seed_rows(f, [f.org])
    headers = await lifecycle.headers(f)
    app = f.public_client._transport.app
    original = app.dependency_overrides[get_session]
    pids = []

    async def pinned_request():
        async with f.engine.connect() as connection:
            pids.append(await connection.scalar(text('SELECT pg_backend_pid()')))
            await connection.rollback()
            async with AsyncSession(bind=connection, expire_on_commit=False, autoflush=False) as db:
                yield db

    app.dependency_overrides[get_session] = pinned_request
    task = None
    try:
        # Establish the independent observer before starting the measured wait.
        # The connection and command limits remain the original fixture limits.
        async with f.engine.connect() as observer, f.engine.connect() as holder:
            tx = await holder.begin()
            holder_pid = await holder.scalar(text('SELECT pg_backend_pid()'))
            await holder.execute(text('LOCK TABLE agents.agent_releases IN ACCESS EXCLUSIVE MODE'))
            try:
                task = asyncio.create_task(f.public_client.get(PAGE, headers=headers))
                genuine = False
                async with asyncio.timeout(3):
                    while not genuine:
                        assert not task.done(), 'Request completed before actual catalogue wait'
                        for pid in pids:
                            genuine |= holder_pid in await observer.scalar(text('SELECT pg_blocking_pids(:pid)'), {'pid': pid})
                        if not genuine:
                            await asyncio.sleep(.01)
                record_property('genuine_catalogue_query_wait', genuine)
                if mode == 'revoked-after-wait':
                    async with f.engine.begin() as db:
                        await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(is_active=False))
                if mode in ('valid-wait', 'revoked-after-wait'):
                    await tx.rollback()
                elif mode == 'cancel':
                    task.cancel()
                if mode == 'cancel':
                    with pytest.raises(asyncio.CancelledError):
                        await asyncio.wait_for(task, 8)
                else:
                    response = await asyncio.wait_for(task, 8)
                    expected = {'timeout': 503, 'valid-wait': 200, 'revoked-after-wait': 401}[mode]
                    assert response.status_code == expected, response.text
                    assert ('items' in response.json()) is (mode == 'valid-wait')
                async with asyncio.timeout(3):
                    while True:
                        # pg_stat_activity is cached within this observer's
                        # transaction. Poll live state without changing the
                        # request transaction, deadline or closure predicate.
                        await observer.execute(text('SELECT pg_stat_clear_snapshot()'))
                        present = any([await observer.scalar(text('SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=:pid)'), {'pid': pid}) for pid in pids])
                        if not present:
                            break
                        await asyncio.sleep(.01)
                record_property('request_physical_connections_closed', True)
            finally:
                if tx.is_active:
                    await tx.rollback()
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        app.dependency_overrides[get_session] = original
    assert len(await snapshot(f)) == 1
    if mode != 'revoked-after-wait':
        retry = await f.public_client.get(PAGE, headers=headers)
        assert retry.status_code == 200 and len(retry.json()['items']) == 1


async def test_observer_cached_activity_requires_fresh_snapshot(public_reader, record_property):
    """Prove snapshot staleness with actual close and a separate live observer."""
    f = public_reader
    query = text('SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=:pid)')
    async with f.engine.connect() as observer, f.engine.connect() as target:
        observer_pid = await observer.scalar(text('SELECT pg_backend_pid()'))
        target_pid = await target.scalar(text('SELECT pg_backend_pid()'))
        assert observer_pid != target_pid
        assert await observer.scalar(query, {'pid': target_pid}) is True
        await target.close()
        # A separately connected observer establishes actual disappearance.
        # It refreshes statistics on each poll under the same3second bound.
        async with f.engine.connect() as independent:
            independent_pid = await independent.scalar(text('SELECT pg_backend_pid()'))
            assert independent_pid not in (observer_pid, target_pid)
            async with asyncio.timeout(3):
                while True:
                    await independent.execute(text('SELECT pg_stat_clear_snapshot()'))
                    if not await independent.scalar(query, {'pid': target_pid}):
                        break
                    await asyncio.sleep(.01)
        cached = await observer.scalar(query, {'pid': target_pid})
        await observer.execute(text('SELECT pg_stat_clear_snapshot()'))
        fresh = await observer.scalar(query, {'pid': target_pid})
        record_property('actual_target_connection_closed', True)
        record_property('cached_observer_still_reported_present', cached)
        record_property('fresh_observer_reported_present', fresh)
        record_property('three_distinct_physical_connections', True)
        assert cached is True and fresh is False
