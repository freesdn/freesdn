"""Proposed catalogue authorization continuity after a genuine PostgreSQL wait.

The public factory/authentication are real; only the owned database dependency
is pinned so pg_blocking_pids can prove the request was waiting on a table lock.
No outcome is qualified until this draft is frozen, run and independently reviewed.
"""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_password_hash
from app.db.session import get_session
from app.models.api_keys import APIKey
from app.models.core import User, UserSession
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_signing_lifecycle as lifecycle
from tests.services import test_public_release_binary as binary
from tests.services.test_public_release_binary import public_reader as public_reader

CASES = [(credential, change) for credential in ('jwt', 'key') for change in
         ('disabled', 'deleted', 'organization', 'role', 'counter', 'password', 'unchanged')]
CASES += [('key', change) for change in ('key-revoked', 'key-scopes', 'key-expired')]
CASES += [('jwt', 'session-revoked')]


async def mutate(f, change):
    async with f.engine.begin() as db:
        if change == 'unchanged':
            return
        if change.startswith('key-'):
            values = {'key-revoked': {'is_active': False}, 'key-scopes': {'scopes': ['agent:read']},
                      'key-expired': {'expires_at': datetime.now(UTC) - timedelta(seconds=1)}}[change]
            result = await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(**values))
            assert result.rowcount == 1
        elif change == 'session-revoked':
            result = await db.execute(update(UserSession).where(UserSession.user_id == f.user).values(is_revoked=True))
            assert result.rowcount >= 1
        else:
            values = {'disabled': {'is_active': False}, 'deleted': {'deleted_at': datetime.now(UTC)},
                      'organization': {'organization_id': f.other_org}, 'role': {'role': 'viewer'},
                      'counter': {'token_version': User.token_version + 1},
                      'password': {'hashed_password': get_password_hash('Owned!Changed-Aa7-Password')}}[change]
            result = await db.execute(update(User).where(User.id == f.user).values(**values))
            assert result.rowcount == 1


@pytest.mark.parametrize(('credential', 'change'), CASES)
async def test_catalogue_refuses_authority_changed_during_real_query_wait(public_reader, credential, change, record_property):
    f = public_reader
    await binary.seed(f, 'legacy-explicit', f.org)
    headers = await lifecycle.headers(f, credential)
    headers.update({'X-FreeSDN-Release-Actor': str(f.user), 'X-FreeSDN-Release-Organization': str(f.org)})
    before = dict(await binary.row(f))
    app = f.public_client._transport.app
    original = app.dependency_overrides[get_session]
    pids = []

    async def pinned_request():
        # A committing API-key authentication routine cannot release the owned
        # physical connection; no outer transaction masks its real commit.
        async with f.engine.connect() as connection:
            pids.append(await connection.scalar(text('SELECT pg_backend_pid()')))
            await connection.rollback()
            async with AsyncSession(bind=connection, expire_on_commit=False, autoflush=False) as db:
                yield db

    app.dependency_overrides[get_session] = pinned_request
    task = None
    response = None
    genuine = False
    try:
        async with f.engine.connect() as holder:
            transaction = await holder.begin()
            holder_pid = await holder.scalar(text('SELECT pg_backend_pid()'))
            await holder.execute(text('LOCK TABLE agents.agent_releases IN ACCESS EXCLUSIVE MODE'))
            try:
                task = asyncio.create_task(f.public_client.get('/api/v1/agents/releases', headers=headers))
                async with f.engine.connect() as observer, asyncio.timeout(3):
                    while not genuine:
                        assert not task.done(), 'Request completed before the required catalogue wait'
                        for pid in pids:
                            if holder_pid in await observer.scalar(text('SELECT pg_blocking_pids(:pid)'), {'pid': pid}):
                                assert pid != holder_pid
                                genuine = True
                        if not genuine:
                            await asyncio.sleep(.01)
                record_property('genuine_catalogue_query_wait', genuine)
                await mutate(f, change)
            finally:
                await transaction.rollback()
            response = await asyncio.wait_for(task, 8)
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        app.dependency_overrides[get_session] = original
    assert response is not None
    after = dict(await binary.row(f))
    data = response.json()
    disclosed = isinstance(data, list) and any(item.get('id') == str(f.release_id) for item in data)
    record_property('observed_status', response.status_code)
    record_property('disclosed_owned_release', disclosed)
    record_property('entire_release_row_unchanged', before == after)
    record_property('transition_committed_before_query_release', True)
    assert genuine
    assert response.status_code == 200 if change == 'unchanged' else response.status_code in (401, 403)
    assert before == after
    assert disclosed is (change == 'unchanged')
