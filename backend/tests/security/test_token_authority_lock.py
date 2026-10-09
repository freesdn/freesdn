"""AFTER-only owned PostgreSQL credential-fence contracts, currently unrun."""

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import token_blacklist as tokens
from app.core.token_authority_lock import (
    lock_token_authority,
    token_authority_lock_key,
    try_share_token_authority,
)
from app.db.session import create_test_engine
from app.models.core import TokenRevocation


@pytest_asyncio.fixture
async def token_fence(monkeypatch):
    engine = create_test_engine()
    f = SimpleNamespace(engine=engine, jti=uuid4().hex, other=uuid4().hex, pids=[])

    @asynccontextmanager
    async def factory():
        async with engine.connect() as connection:
            f.pids.append(await connection.scalar(text("SELECT pg_backend_pid()")))
            await connection.rollback()
            async with AsyncSession(bind=connection, expire_on_commit=False) as db:
                yield db

    monkeypatch.setattr(tokens, "security_session_factory", factory)
    try:
        yield f
    finally:
        async with AsyncSession(engine) as db, db.begin():
            await db.execute(delete(TokenRevocation).where(TokenRevocation.jti_hash.in_(
                [tokens._identity(f.jti), tokens._identity(f.other)]
            )))
        await engine.dispose()
        engine = None


async def real_token_wait(f, task, holder):
    async with AsyncSession(f.engine) as observer, asyncio.timeout(5):
        while True:
            assert not task.done(), "Writer acknowledged before its genuine PostgreSQL wait"
            for pid in set(f.pids):
                if holder in await observer.scalar(text("SELECT pg_blocking_pids(:p)"), {"p": pid}):
                    return pid
            await asyncio.sleep(0.01)


@pytest.mark.parametrize("writer", ["blacklist", "claim"])
@pytest.mark.parametrize("release", ["commit", "rollback"])
async def test_revocation_writer_waits_for_current_authority_reader(token_fence, writer, release):
    f = token_fence
    fn = tokens.blacklist_token if writer == "blacklist" else tokens.claim_token_jti
    async with AsyncSession(f.engine) as holder:
        await holder.begin()
        holder_pid = await holder.scalar(text("SELECT pg_backend_pid()"))
        assert await try_share_token_authority(holder, f.jti)
        task = asyncio.create_task(fn(f.jti, datetime.now(UTC) + timedelta(minutes=1)))
        try:
            await real_token_wait(f, task, holder_pid)
            assert not await tokens.is_token_blacklisted(f.jti)
            await getattr(holder, release)()
            result = await asyncio.wait_for(task, 5)
            assert (result is None if writer == "blacklist" else result is True)
            assert await tokens.is_token_blacklisted(f.jti)
        finally:
            await holder.rollback()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("writer", ["blacklist", "claim"])
async def test_actual_lock_wait_past_expiry_never_grants_expired_claim(token_fence, writer):
    f = token_fence
    expiry = datetime.now(UTC) + timedelta(seconds=1.5)
    fn = tokens.blacklist_token if writer == "blacklist" else tokens.claim_token_jti
    async with AsyncSession(f.engine) as holder:
        await holder.begin()
        holder_pid = await holder.scalar(text("SELECT pg_backend_pid()"))
        assert await try_share_token_authority(holder, f.jti)
        task = asyncio.create_task(fn(f.jti, expiry))
        try:
            await real_token_wait(f, task, holder_pid)
            await asyncio.sleep(max(0, (expiry - datetime.now(UTC)).total_seconds()) + 0.05)
            await holder.commit()
            result = await asyncio.wait_for(task, 5)
            assert (result is None if writer == "blacklist" else result is False)
            # Keep the original post-wait tombstone contract, including expiry.
            async with AsyncSession(f.engine) as db:
                row = await db.get(TokenRevocation, tokens._identity(f.jti))
                assert row is not None and row.expires_at == expiry
        finally:
            await holder.rollback()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("release", ["commit", "rollback"])
async def test_reader_refuses_inflight_writer_without_inverse_wait(token_fence, release):
    f = token_fence
    async with AsyncSession(f.engine) as holder, AsyncSession(f.engine) as reader:
        await holder.begin()
        await lock_token_authority(holder, f.jti)
        await reader.begin()
        async with asyncio.timeout(1):
            assert not await try_share_token_authority(reader, f.jti)
        await reader.rollback()
        await getattr(holder, release)()
        await reader.begin()
        assert await try_share_token_authority(reader, f.jti)
        assert not await tokens.is_token_blacklisted(f.jti)


@pytest.mark.parametrize("writer", ["blacklist", "claim"])
async def test_another_jti_is_not_blocked_by_owned_reader(token_fence, writer):
    f = token_fence
    fn = tokens.blacklist_token if writer == "blacklist" else tokens.claim_token_jti
    assert token_authority_lock_key(f.jti) != token_authority_lock_key(f.other)
    async with AsyncSession(f.engine) as holder, holder.begin():
        assert await try_share_token_authority(holder, f.jti)
        result = await asyncio.wait_for(fn(f.other, datetime.now(UTC) + timedelta(minutes=1)), 2)
        assert (result is None if writer == "blacklist" else result is True)
        assert await tokens.is_token_blacklisted(f.other)
        assert not await tokens.is_token_blacklisted(f.jti)


async def test_coordinated_refresh_still_has_one_committed_winner(token_fence):
    f = token_fence
    results = await asyncio.gather(*[
        tokens.claim_token_jti(f.jti, datetime.now(UTC) + timedelta(minutes=1)) for _ in range(16)
    ])
    assert results.count(True) == 1 and results.count(False) == 15
    assert await tokens.is_token_blacklisted(f.jti)


@pytest.mark.parametrize("value", [None, b"bytes", "", "a" * 1025, 123, "\ud800"])
def test_invalid_identity_has_no_coordination_key(value):
    with pytest.raises((ValueError, UnicodeError)):
        token_authority_lock_key(value)


@pytest.mark.parametrize("jti", ["a", "a" * 1024, "caf\u00e9", "token-\u2603"])
def test_key_is_stable_domain_bound_signed_bigint(jti):
    value = token_authority_lock_key(jti)
    assert type(value) is int and -(2**63) <= value < 2**63
    assert value == token_authority_lock_key(jti)
    # The revocation row digest is a different domain from its lock identity.
    assert value != int.from_bytes(bytes.fromhex(tokens._identity(jti))[:8], "big", signed=True)


@pytest.mark.parametrize("helper", ["exclusive", "shared"])
async def test_no_implicit_transaction_or_caller_commit(token_fence, helper):
    fn = lock_token_authority if helper == "exclusive" else try_share_token_authority
    async with AsyncSession(token_fence.engine) as db:
        with pytest.raises(RuntimeError, match="owned transaction"):
            await fn(db, token_fence.jti)
        assert not db.in_transaction()


async def test_cancellation_releases_shared_transaction_and_waiting_writer(token_fence):
    f = token_fence
    acquired = asyncio.Event()
    never = asyncio.Event()
    state = {}

    async def reader():
        async with AsyncSession(f.engine) as db, db.begin():
            state["pid"] = await db.scalar(text("SELECT pg_backend_pid()"))
            assert await try_share_token_authority(db, f.jti)
            acquired.set()
            await never.wait()

    holder = asyncio.create_task(reader())
    await asyncio.wait_for(acquired.wait(), 3)
    task = asyncio.create_task(tokens.blacklist_token(f.jti, datetime.now(UTC) + timedelta(minutes=1)))
    try:
        await real_token_wait(f, task, state["pid"])
        holder.cancel()
        result = await asyncio.gather(holder, return_exceptions=True)
        assert isinstance(result[0], asyncio.CancelledError)
        await asyncio.wait_for(task, 5)
        assert await tokens.is_token_blacklisted(f.jti)
    finally:
        holder.cancel()
        await asyncio.gather(holder, task, return_exceptions=True)
