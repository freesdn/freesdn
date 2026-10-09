"""Real journal waits must not preserve a revoked initiating probe authority."""

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, insert, text, update

from app.core.security import verify_token
from app.models.api_keys import APIKey
from app.models.core import TokenRevocation, User
from tests.services.test_backup_artifact_integrity_contract import owned_actor
from tests.services.test_backup_transport_sftp import sftp_peer as sftp_peer
from tests.services.test_backup_transport_tls import ftps_peer as ftps_peer
from tests.services.test_remote_publication_acknowledgment import fixture
from tests.services.test_remote_write_coordination import configure, history

CASES = [
    (credential, transition)
    for credential in ("jwt", "key")
    for transition in ("unchanged", "disabled", "soft-deleted", "demoted", "org-removed")
] + [("jwt", transition) for transition in ("counter", "revoked-jti")] + [
    ("key", transition)
    for transition in ("key-disabled", "key-scoped", "key-wildcard", "key-expired", "key-replaced", "key-deleted")
]


async def mutate(actor, transition):
    now = datetime.now(UTC)
    async with actor.engine.begin() as db:
        if transition == "unchanged":
            return
        values = {
            "disabled": {"is_active": False},
            "soft-deleted": {"deleted_at": now},
            "demoted": {"role": "viewer"},
            "org-removed": {"organization_id": None},
            "counter": {"token_version": 18},
        }
        if transition in values:
            result = await db.execute(update(User).where(User.id == actor.actor_id).values(**values[transition]))
        elif transition == "revoked-jti":
            token = actor.client.headers["Authorization"].removeprefix("Bearer ")
            claims = await verify_token(token)
            assert claims is not None and claims.get("jti"), "Owned real access token prerequisite"
            digest = hashlib.sha256(claims["jti"].encode()).hexdigest()
            actor.claim_hashes.add(digest)
            result = await db.execute(insert(TokenRevocation).values(
                jti_hash=digest, expires_at=datetime.fromtimestamp(claims["exp"], UTC),
            ))
        elif transition == "key-deleted":
            result = await db.execute(delete(APIKey).where(APIKey.user_id == actor.actor_id))
        else:
            values = {
                "key-disabled": {"is_active": False},
                "key-scoped": {"scopes": ["network:read"]},
                "key-wildcard": {"scopes": ["*"]},
                "key-expired": {"expires_at": now - timedelta(seconds=1)},
                "key-replaced": {"key_hash": "a" * 64},
            }
            result = await db.execute(update(APIKey).where(APIKey.user_id == actor.actor_id).values(**values[transition]))
        assert result.rowcount == 1, "Exactly one owned account or credential must change"


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
@pytest.mark.parametrize("credential,transition", CASES)
async def test_probe_wait_rechecks_current_authority(
    request, monkeypatch, tmp_path, protocol, credential, transition,
):
    remote = fixture(request, monkeypatch, protocol)
    async with owned_actor(monkeypatch, tmp_path, credential) as actor:
        await configure(actor, remote, protocol)
        async with actor.engine.connect() as blocker:
            transaction = await blocker.begin()
            holder = await blocker.scalar(text("SELECT pg_backend_pid()"))
            await blocker.execute(text("LOCK TABLE backup.remote_write_operations IN ACCESS EXCLUSIVE MODE"))
            task = asyncio.create_task(actor.client.post(f"/api/v1/backups/storage-locations/{actor.storage_id}/test"))
            waited = False
            try:
                for _ in range(300):
                    async with actor.engine.connect() as observer:
                        waiters = await observer.scalar(text(
                            "SELECT count(*) FROM pg_stat_activity WHERE :holder = ANY(pg_blocking_pids(pid))"),
                            {"holder": holder},
                        )
                    if waiters:
                        waited = True
                        break
                    if task.done():
                        break
                    await asyncio.sleep(.01)
                assert waited and not task.done(), "Actual PostgreSQL journal wait prerequisite"
                assert remote.auths() == 0 and not remote.state.events and not remote.files()
                await mutate(actor, transition)
            finally:
                await transaction.rollback()
                answer = await asyncio.wait_for(asyncio.shield(task), 12)
                await asyncio.gather(task, return_exceptions=True)
        # Save durable and wire observations before any response assertion.
        rows = await history(actor)
        body = answer.json()
        renames = [entry for entry in remote.state.events if entry[0] == "rename"]
        deletes = [entry for entry in remote.state.events if entry[0] == "delete"]
        observed = {
            "credential": credential, "transition": transition, "protocol": protocol,
            "genuine_journal_wait": waited, "HTTP": answer.status_code,
            "response_success": body.get("success"),
            "remote_authentications_after_change": remote.auths(),
            "remote_renames_after_change": len(renames), "remote_deletes_after_change": len(deletes),
            "remaining_remote_objects": len(remote.files()),
            "history_rows": len(rows), "history_phases": ",".join(row.phase for row in rows),
            "response_contains_recovery_candidates": "possible_storage_paths" in answer.text,
        }
        request.node.user_properties.extend(observed.items())
        assert len(rows) == 1, "The released real reservation remains independently committed"
        if transition == "unchanged":
            assert answer.status_code == 200 and body["success"] is True
            assert remote.auths() == 4 and len(renames) == len(deletes) == 1 and not remote.files()
            assert rows[0].phase == "acknowledged"
        else:
            assert answer.status_code in {401, 403}, "Revoked probe authority survived the real journal wait"
            assert remote.auths() == 0 and not remote.state.events and not remote.files()
            assert rows[0].phase == "reserved"
            assert not observed["response_contains_recovery_candidates"]
