# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private unrun real post-copy authority probes; no confirmed finding yet.

The disk snapshot is fully copied and verified before a real worker is paused.
A separate PostgreSQL connection then commits the account transition. No actor,
signature, storage bytes or database operation is mocked to manufacture success.
"""

import asyncio
import hashlib
import threading
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.backup_download_response import LocalDownloadSource as ConfigurationDownloadSource
from app.core.security import get_password_hash
from app.models.core import Organization, User
from app.services.vault_snapshot_response import LocalDownloadSource as VaultDownloadSource
from tests.services.test_backup_artifact_integrity_contract import (
    create_archive,
    owned_actor,
    recorded_download_headers,
)

TRANSITIONS = ["disabled", "deleted", "organization", "role", "password", "counter", "unchanged", "unrelated"]


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("secrets", [False, True])
@pytest.mark.parametrize("transition", TRANSITIONS)
async def test_prepared_download_checks_current_account_before_first_response(
    tmp_path, monkeypatch, request, credential, secrets, transition
):
    async with owned_actor(monkeypatch, tmp_path, credential) as f:
        backup, _path, raw = await create_archive(f, secrets)
        download_headers = await recorded_download_headers(f, backup.id, secrets)
        source_type = VaultDownloadSource if secrets else ConfigurationDownloadSource
        expected_digest, expected_bytes = hashlib.sha256(raw).hexdigest(), len(raw)
        del raw
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
                    raise TimeoutError("Owned post-copy fixture was not released")

        monkeypatch.setattr(source_type, "copy_into", wait_after_real_copy)
        other_org = uuid4()
        replacement_hash = get_password_hash("Owned independent password!9-" + uuid4().hex)
        value = {
            "disabled": {"is_active": False}, "deleted": {"deleted_at": datetime.now(UTC)},
            "organization": {"organization_id": other_org}, "role": {"role": "viewer"},
            "password": {"hashed_password": replacement_hash}, "counter": {"token_version": 18},
        }.get(transition, {})
        task = asyncio.create_task(f.client.get(f"/api/v1/backups/{backup.id}/download", headers=download_headers))
        durable = False
        try:
            for _ in range(1000):
                if entered.is_set() or task.done():
                    break
                await asyncio.sleep(.01)
            assert entered.is_set() and not task.done(), "Actual prepared storage wait was not reached"
            assert actual == [{"verified": True, "bytes": expected_bytes, "thread": actual[0]["thread"]}]
            assert actual[0]["thread"] != threading.get_ident()
            ticks = 0
            for _ in range(5):
                await asyncio.sleep(.001)
                ticks += 1
            async with AsyncSession(f.engine) as db:
                if transition == "organization":
                    db.add(Organization(id=other_org, name="Owned destination transition", slug=uuid4().hex))
                    await db.flush()
                if value:
                    await db.execute(update(User).where(User.id == f.actor_id).values(**value))
                elif transition == "unrelated":
                    await db.execute(update(Organization).where(Organization.id == f.org_id)
                                     .values(name="Owned unrelated display-name update"))
                await db.commit()
            async with AsyncSession(f.engine) as db:
                actor = (await db.execute(select(User).where(User.id == f.actor_id))).scalar_one()
                durable = all(getattr(actor, field) == expected for field, expected in value.items())
            release.set()
            response = await asyncio.wait_for(task, 5)
            async with AsyncSession(f.engine) as db:
                actor = (await db.execute(select(User).where(User.id == f.actor_id))).scalar_one()
                still_durable = all(getattr(actor, field) == expected for field, expected in value.items())
            # Record both actual delivery and committed-state observations BEFORE
            # asserting the proposed refusal contract. Never claim later asserts
            # ran when an earlier status assertion fails.
            delivered_archive = (response.status_code == 200 and len(response.content) == expected_bytes
                                 and hashlib.sha256(response.content).hexdigest() == expected_digest)
            observation = {"real_verified_copy_wait": True, "independent_account_state_checked": durable,
                           "account_transition_applicable": bool(value), "state_survives_request": still_durable,
                           "event_loop_ticks": ticks, "HTTP_status": response.status_code,
                           "response_bytes": len(response.content), "exact_archive_delivered": delivered_archive,
                           "integrity_header": response.headers.get("x-freesdn-artifact-integrity")}
            request.node.user_properties.extend(observation.items())
            assert durable and still_durable and ticks == 5
            if transition in {"unchanged", "unrelated"}:
                assert response.status_code == 200 and delivered_archive
            else:
                assert response.status_code in (401, 403)
                assert not delivered_archive and "x-freesdn-artifact-integrity" not in response.headers
        finally:
            release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            # Only owned fixture records: restore the foreign key so the new
            # organization can be removed without altering product state evidence.
            if transition == "organization":
                async with AsyncSession(f.engine) as db:
                    await db.execute(update(User).where(User.id == f.actor_id).values(organization_id=f.org_id))
                    await db.execute(delete(Organization).where(Organization.id == other_org))
                    await db.commit()
