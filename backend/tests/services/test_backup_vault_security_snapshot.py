# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real independent PostgreSQL writers must not produce a mixed security graph.

These cover the account/provider/grant SELECT, not every module's collection.
They do not serialize destination restore writers or qualify packaged services.
"""

import asyncio

import pytest
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security_utils import encrypt_field
from app.models.core import Site, User, UserSiteAccess
from app.models.sso import SSOProvider
from app.services.backup_contributors.account_security import collect_snapshot
from tests.services.test_backup_vault_security_roundtrip import source_fixture
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db


@pytest.mark.parametrize("reads", [100])
async def test_security_graph_is_consistent_during_real_committed_rotations(vault_db, tmp_path, monkeypatch, request, reads):
    from uuid import uuid4

    import pyotp

    f = await source_fixture(vault_db, tmp_path, monkeypatch, protocol="oidc")
    seeds = [f.seed, pyotp.random_base32()]
    site = Site(organization_id=f.org.id, name="Owned snapshot site", slug=uuid4().hex)
    f.db.add(site)
    await f.db.flush()
    grant = UserSiteAccess(user_id=f.user.id, site_id=site.id, access_level="read")
    f.db.add(grant)
    f.user.preferences = {"owned_epoch": 0}
    f.user.external_id = "owned-epoch-0"
    f.provider.extra_settings = {"owned_epoch": 0}
    await f.db.commit()
    org_id, user_id, provider_id, grant_id = f.org.id, f.user.id, f.provider.id, grant.id
    ready, finished = asyncio.Event(), asyncio.Event()
    observed, writes, pids = [], [], {}

    async def writer():
        # Hold an independent physical connection through all commits.
        async with f.db.bind.connect() as connection:
            async with AsyncSession(bind=connection, expire_on_commit=False, autoflush=False) as pinned:
                pids["writer"] = await pinned.scalar(text("select pg_backend_pid()"))
                await pinned.commit()
                ready.set()
                epoch = 1
                while not finished.is_set():
                    await pinned.execute(update(User).where(User.id == user_id).values(
                        preferences={"owned_epoch": epoch}, external_id=f"owned-epoch-{epoch}",
                        mfa_secret=encrypt_field(seeds[epoch % 2]),
                    ))
                    await pinned.execute(update(SSOProvider).where(SSOProvider.id == provider_id)
                                         .values(extra_settings={"owned_epoch": epoch}))
                    await pinned.execute(update(UserSiteAccess).where(UserSiteAccess.id == grant_id)
                                         .values(access_level="write" if epoch % 2 else "read"))
                    await pinned.commit()
                    writes.append(epoch)
                    epoch += 1
                    await asyncio.sleep(0)

    async def reader():
        await ready.wait()
        try:
            pids["reader"] = await f.db.scalar(text("select pg_backend_pid()"))
            assert await f.db.scalar(text("show transaction_isolation")) == "read committed"
            for _ in range(reads):
                snapshot = await collect_snapshot(f.db, org_id)
                user, provider, access = snapshot["users"][0], snapshot["sso_providers"][0], snapshot["user_site_access"][0]
                epoch = user["preferences"]["owned_epoch"]
                assert provider["extra_settings"]["owned_epoch"] == epoch
                assert user["external_id"] == f"owned-epoch-{epoch}"
                assert user["mfa_secret"] == seeds[epoch % 2]
                assert access["access_level"] == ("write" if epoch % 2 else "read")
                observed.append(epoch)
                await asyncio.sleep(0)
        finally:
            finished.set()

    await asyncio.wait_for(asyncio.gather(writer(), reader()), timeout=30)
    assert pids["writer"] != pids["reader"], "Independent sessions must actually use distinct server connections"
    assert len(writes) >= 2 and len(set(observed)) >= 2
    assert len(observed) == reads
    assert f.user.preferences == {"owned_epoch": 0}, "The collector must not trust this deliberately stale ORM object"
    request.node.user_properties.extend([
        ("actual_committed_rotations", len(writes)), ("security_snapshots", len(observed)),
        ("distinct_observed_epochs", len(set(observed))), ("distinct_postgres_connections", True),
    ])


async def test_security_snapshot_reads_own_flushed_state_without_committing_caller(vault_db, tmp_path, monkeypatch):
    f = await source_fixture(vault_db, tmp_path, monkeypatch, protocol="oidc")
    user_id, org_id = f.user.id, f.org.id
    before = dict(f.user.preferences)
    f.user.preferences = {"owned_uncommitted": True}
    await f.db.flush()
    snapshot = await collect_snapshot(f.db, org_id)
    assert snapshot["users"][0]["preferences"] == {"owned_uncommitted": True}
    assert f.db.in_transaction()
    async with AsyncSession(f.db.bind) as observer:
        assert await observer.scalar(select(User.preferences).where(User.id == user_id)) == before
    await f.db.rollback()
    async with AsyncSession(f.db.bind) as observer:
        assert await observer.scalar(select(User.preferences).where(User.id == user_id)) == before
