# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Unrun real key changes after verified local copy; no finding claimed yet."""

import asyncio
import hashlib
import threading
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.backup_download_response import LocalDownloadSource as ConfigurationDownloadSource
from app.models.api_keys import APIKey, generate_api_key
from app.services.vault_snapshot_response import LocalDownloadSource as VaultDownloadSource
from tests.services.test_backup_artifact_integrity_contract import (
    create_archive,
    owned_actor,
    recorded_download_headers,
)

TRANSITIONS = ["disabled", "expired", "scoped", "replaced_hash", "deleted", "unchanged", "renamed"]


@pytest.mark.parametrize("secrets", [False, True])
@pytest.mark.parametrize("transition", TRANSITIONS)
async def test_prepared_download_checks_current_key_before_first_response(
    tmp_path, monkeypatch, request, secrets, transition
):
    async with owned_actor(monkeypatch, tmp_path, "key") as f:
        backup, _path, raw = await create_archive(f, secrets)
        download_headers = await recorded_download_headers(f, backup.id, secrets)
        source_type = VaultDownloadSource if secrets else ConfigurationDownloadSource
        expected_digest, expected_bytes = hashlib.sha256(raw).hexdigest(), len(raw)
        del raw
        async with AsyncSession(f.engine) as db:
            key_id = (await db.execute(select(APIKey.id).where(APIKey.user_id == f.actor_id))).scalar_one()
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
                    raise TimeoutError("Owned post-copy key fixture was not released")

        monkeypatch.setattr(source_type, "copy_into", wait_after_real_copy)
        value = {
            "disabled": {"is_active": False},
            "expired": {"expires_at": datetime.now(UTC) - timedelta(seconds=1)},
            "scoped": {"scopes": ["network:read"]},
            "replaced_hash": {"key_hash": generate_api_key()[2]},
            "renamed": {"name": "Owned harmless display-name update"},
        }.get(transition, {})

        async def durable_state_matches():
            async with AsyncSession(f.engine) as db:
                key = await db.get(APIKey, key_id)
                if transition == "deleted":
                    return key is None
                return key is not None and all(getattr(key, field) == expected for field, expected in value.items())

        task = asyncio.create_task(f.client.get(f"/api/v1/backups/{backup.id}/download", headers=download_headers))
        try:
            for _ in range(1000):
                if entered.is_set() or task.done():
                    break
                await asyncio.sleep(.01)
            assert entered.is_set() and not task.done(), "Actual verified copy wait was not reached"
            assert len(actual) == 1 and actual[0]["verified"] and actual[0]["bytes"] == expected_bytes
            assert actual[0]["thread"] != threading.get_ident()
            async with AsyncSession(f.engine) as db:
                if transition == "deleted":
                    await db.execute(delete(APIKey).where(APIKey.id == key_id))
                elif value:
                    await db.execute(update(APIKey).where(APIKey.id == key_id).values(**value))
                await db.commit()
            before_delivery = await durable_state_matches()
            release.set()
            response = await asyncio.wait_for(task, 5)
            after_delivery = await durable_state_matches()
            delivered_archive = (response.status_code == 200 and len(response.content) == expected_bytes
                                 and hashlib.sha256(response.content).hexdigest() == expected_digest)
            request.node.user_properties.extend({
                "real_verified_copy_wait": True,
                "independent_key_state_checked": before_delivery,
                "key_change_applicable": transition != "unchanged",
                "state_survives_request": after_delivery,
                "HTTP_status": response.status_code,
                "response_bytes": len(response.content),
                "exact_archive_delivered": delivered_archive,
                "integrity_header": response.headers.get("x-freesdn-artifact-integrity"),
            }.items())
            assert before_delivery and after_delivery
            if transition in {"unchanged", "renamed"}:
                assert response.status_code == 200 and delivered_archive
            else:
                assert response.status_code in (401, 403)
                assert not delivered_archive and "x-freesdn-artifact-integrity" not in response.headers
        finally:
            release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
