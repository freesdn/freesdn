# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Owned real remote archive, independent database state and cleanup observations."""

import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.backup_downloads import DownloadCapacityError, DownloadPool
from app.core.config import get_settings
from app.core.security_utils import MAX_BACKUP_IMPORT_BYTES
from app.modules.backup.models import Backup
from tests.services import webdav_owned_peer
from tests.services.test_backup_download_response_lifetime import opened
from tests.services.test_webdav_service_client_ownership import remote_actor, seeded_archive

webdav_peer = webdav_owned_peer.webdav_peer


@asynccontextmanager
async def owned_remote_actor(monkeypatch, tmp_path, credential, peer, request):
    async with remote_actor(monkeypatch, tmp_path, peer, credential) as remote:
        root = tmp_path / "owned-remote-authority-pool"
        settings = get_settings().model_copy(update={
            "BACKUP_DOWNLOAD_SPOOL": str(root), "BACKUP_DOWNLOAD_SLOTS": 1,
            "BACKUP_DOWNLOAD_FREE_BYTES": 0, "BACKUP_DOWNLOAD_SECONDS": 20.0,
        })
        monkeypatch.setattr("app.api.v1.endpoints.backups.get_settings", lambda: settings)
        monkeypatch.setattr("app.services.vault_export_public_download.get_settings", lambda: settings)
        subject = SimpleNamespace(**vars(remote.actor), remote=remote)
        try:
            yield subject
        finally:
            # Observe before the enclosing fixture closes any leaked clients.
            pool = DownloadPool(root, slots=1, limit=MAX_BACKUP_IMPORT_BYTES, free_floor=0)
            try:
                lease = pool.acquire()
            except DownloadCapacityError:
                slot_available = False
            else:
                lease.close()
                slot_available = True
            gets = [row for row in peer.requests if row["method"] == "GET"]
            observed = {
                "remote_provider_gets": len(gets),
                "remote_GET_TLS_authorized": bool(gets) and all(row["TLS"] and row["authorized"] for row in gets),
                "network_clients_open_before_fixture_cleanup": sum(not c.is_closed for c in remote.clients),
                "network_connections_before_fixture_cleanup": sum(len(c._transport._pool.connections) for c in remote.clients),
                "no_owned_snapshot_descriptors": not opened(root),
                "slot_available_before_fixture_cleanup": slot_available,
                "owned_peer_port": peer.port,
                "peer_requests": json.dumps(peer.requests, sort_keys=True),
                "remote_scope": "actual API/PG/TLS/disk after test-only loopback admission; no external IdP/vendor or production-image acceptance",
            }
            request.node.user_properties.extend(observed.items())
            assert observed["remote_provider_gets"] == 1 and observed["remote_GET_TLS_authorized"]
            assert observed["network_clients_open_before_fixture_cleanup"] == 0
            assert observed["network_connections_before_fixture_cleanup"] == 0
            assert observed["no_owned_snapshot_descriptors"] and slot_available


async def create_remote_archive(subject, secrets):
    backup_id, raw = await seeded_archive(subject.remote, secrets)
    async with AsyncSession(subject.engine) as db:
        backup = await db.get(Backup, UUID(backup_id))
        assert backup is not None
        return backup, None, raw
