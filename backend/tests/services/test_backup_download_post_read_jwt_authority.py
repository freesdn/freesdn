# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private unrun JWT/session post-copy probes with real expiry and commits."""

import asyncio
import hashlib
import threading
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.backup_download_response import LocalDownloadSource as ConfigurationDownloadSource
from app.core.security import create_access_token, verify_token
from app.core.token_blacklist import blacklist_token
from app.models.core import TokenRevocation, UserSession
from app.services.vault_snapshot_response import LocalDownloadSource as VaultDownloadSource
from tests.services.test_backup_artifact_integrity_contract import (
    create_archive,
    owned_actor,
    recorded_download_headers,
)

TRANSITIONS = [
    "jwt_expired", "jti_revoked", "session_flag", "session_timestamp",
    "unchanged", "session_metadata", "legacy_untracked", "unrelated_jti",
]
REFUSALS = {"jwt_expired", "jti_revoked", "session_flag", "session_timestamp"}


@pytest.mark.parametrize("secrets", [False, True])
@pytest.mark.parametrize("transition", TRANSITIONS)
async def test_prepared_download_checks_current_jwt_before_first_response(
    tmp_path, monkeypatch, request, secrets, transition
):
    async with owned_actor(monkeypatch, tmp_path) as f:
        backup, _path, raw = await create_archive(f, secrets)
        source_type = VaultDownloadSource if secrets else ConfigurationDownloadSource
        expected_digest, expected_bytes = hashlib.sha256(raw).hexdigest(), len(raw)
        del raw
        token = create_access_token(str(f.actor_id), token_version=17,
                                    expires_delta=timedelta(seconds=8 if transition == "jwt_expired" else 120))
        claims = await verify_token(token)
        assert claims is not None and claims["sub"] == str(f.actor_id) and claims["tv"] == 17
        other = create_access_token(str(f.actor_id), token_version=17)
        other_claims = await verify_token(other)
        assert other_claims is not None and other_claims["jti"] != claims["jti"]
        owned_hashes = [hashlib.sha256(c["jti"].encode()).hexdigest() for c in (claims, other_claims)]
        session_id = uuid4()
        headers = {"Authorization": "Bearer " + token}
        if transition != "legacy_untracked":
            async with AsyncSession(f.engine) as db:
                db.add(UserSession(id=session_id, user_id=f.actor_id, access_jti=claims["jti"],
                                   created_at=datetime.now(UTC), expires_at=datetime.now(UTC) + timedelta(minutes=5)))
                await db.commit()
        assert (await f.client.get("/api/v1/backups/stats", headers=headers)).status_code == 200
        headers.update(await recorded_download_headers(f, backup.id, secrets, headers=headers))
        entered, release = threading.Event(), threading.Event()
        actual = []
        original = source_type.copy_into

        def wait_after_real_copy(source, snapshot):
            original(source, snapshot)
            if source.files.root == f.root.absolute():
                actual.append({"verified": snapshot.integrity == "verified", "bytes": snapshot.size,
                               "thread": threading.get_ident()})
                entered.set()
                if not release.wait(15):
                    raise TimeoutError("Owned post-copy JWT fixture was not released")

        monkeypatch.setattr(source_type, "copy_into", wait_after_real_copy)
        revoked_at = datetime.now(UTC)
        changes = {"session_flag": {"is_revoked": True},
                   "session_timestamp": {"revoked_at": revoked_at},
                   "session_metadata": {"user_agent": "Owned harmless display-name update"}}.get(transition, {})

        async def durable_state_matches():
            async with AsyncSession(f.engine) as db:
                if transition in {"jti_revoked", "unrelated_jti"}:
                    index = int(transition == "unrelated_jti")
                    return await db.get(TokenRevocation, owned_hashes[index]) is not None
                row = await db.get(UserSession, session_id)
                if transition == "legacy_untracked":
                    return row is None
                if transition == "jwt_expired":
                    return datetime.now(UTC).timestamp() > claims["exp"]
                return row is not None and all(getattr(row, key) == value for key, value in changes.items())

        task = asyncio.create_task(f.client.get(f"/api/v1/backups/{backup.id}/download", headers=headers))
        try:
            for _ in range(1000):
                if entered.is_set() or task.done():
                    break
                await asyncio.sleep(.01)
            assert entered.is_set() and not task.done(), "Actual verified copy wait was not reached"
            assert len(actual) == 1 and actual[0]["verified"] and actual[0]["bytes"] == expected_bytes
            assert actual[0]["thread"] != threading.get_ident()
            if transition == "jwt_expired":
                # Real clock passage, no mocked decoder, sleep or verification.
                async with asyncio.timeout(10):
                    while datetime.now(UTC).timestamp() <= claims["exp"] + .1:
                        await asyncio.sleep(.02)
            elif transition in {"jti_revoked", "unrelated_jti"}:
                current = other_claims if transition == "unrelated_jti" else claims
                await blacklist_token(current["jti"], current["exp"])
            elif changes:
                async with AsyncSession(f.engine) as db:
                    await db.execute(update(UserSession).where(UserSession.id == session_id).values(**changes))
                    await db.commit()
            before_delivery = await durable_state_matches()
            release.set()
            response = await asyncio.wait_for(task, 5)
            after_delivery = await durable_state_matches()
            fresh = await f.client.get("/api/v1/backups/stats", headers=headers)
            delivered = (response.status_code == 200 and len(response.content) == expected_bytes
                         and hashlib.sha256(response.content).hexdigest() == expected_digest)
            # Observe all relevant behavior before the proposed refusal assertion.
            request.node.user_properties.extend({
                "real_verified_copy_wait": True, "independent_JWT_session_state_checked": before_delivery,
                "state_survives_request": after_delivery, "fresh_request_status": fresh.status_code,
                "HTTP_status": response.status_code, "response_bytes": len(response.content),
                "exact_archive_delivered": delivered,
                "integrity_header": response.headers.get("x-freesdn-artifact-integrity"),
            }.items())
            assert before_delivery and after_delivery
            if transition in REFUSALS:
                assert fresh.status_code == 401
                assert response.status_code in (401, 403)
                assert not delivered and "x-freesdn-artifact-integrity" not in response.headers
            else:
                assert fresh.status_code == 200 and response.status_code == 200 and delivered
        finally:
            release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            async with AsyncSession(f.engine) as db:
                await db.execute(delete(TokenRevocation).where(TokenRevocation.jti_hash.in_(owned_hashes)))
                await db.commit()
