"""Owned PostgreSQL and actual HTTP catalogue; no lifespan or browser proof.

These probes are private/unqualified until source freeze and first runtime.
A page is an observation, never a grant or signature verification result.
"""
import asyncio
import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.models.agents import AgentRelease
from app.models.api_keys import APIKey
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.harness_wait import HARNESS_WAIT_SECONDS
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














@pytest.mark.parametrize('mode', ('timeout', 'cancel', 'valid-wait', 'revoked-after-wait'))
async def test_diagnostic_catalogue_query_cleanup(public_reader, mode, record_property):
    f = public_reader
    await seed_rows(f, [f.org])
    headers = await lifecycle.headers(f)
    app = f.public_client._transport.app
    original = app.dependency_overrides[get_session]
    pids = []
    driver_connections = []
    cleanup_steps = []

    async def pinned_request():
        async with f.engine.connect() as connection:
            pids.append(await connection.scalar(text('SELECT pg_backend_pid()')))
            raw = await connection.get_raw_connection()
            driver_connections.append(raw.driver_connection)
            await connection.rollback()
            try:
                async with AsyncSession(bind=connection, expire_on_commit=False, autoflush=False) as db:
                    try:
                        yield db
                    finally:
                        cleanup_steps.append('session-yield-finally')
                cleanup_steps.append('session-context-exited')
            finally:
                cleanup_steps.append('connection-finally')
        cleanup_steps.append('connection-context-exited')

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
                async with asyncio.timeout(HARNESS_WAIT_SECONDS):
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
                try:
                    async with asyncio.timeout(HARNESS_WAIT_SECONDS):
                        while True:
                            # pg_stat_activity is cached within this observer's
                            # transaction. Poll live state without changing the
                            # request transaction, deadline or closure predicate.
                            await observer.execute(text('SELECT pg_stat_clear_snapshot()'))
                            present = any([await observer.scalar(text('SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=:pid)'), {'pid': pid}) for pid in pids])
                            if not present:
                                break
                            await asyncio.sleep(.01)
                finally:
                    await observer.execute(text('SELECT pg_stat_clear_snapshot()'))
                    observed = (await observer.execute(text(
                        'SELECT pid, state, wait_event_type, wait_event '
                        'FROM pg_stat_activity WHERE pid = ANY(:pids) ORDER BY pid'
                    ), {'pids': pids})).mappings().all()
                    record_property('diagnostic_backend_states', json.dumps([dict(row) for row in observed]))
                    record_property('diagnostic_driver_closed', json.dumps([c.is_closed() for c in driver_connections]))
                    record_property('diagnostic_dependency_cleanup_steps', json.dumps(cleanup_steps))
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
