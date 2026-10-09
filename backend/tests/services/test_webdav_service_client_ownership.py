# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real HTTP/PG/TLS service ownership after admitted owned destination setup."""

import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
from uuid import UUID

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_credential
from app.modules.backup.models import Backup, StorageLocation
from tests.services import webdav_owned_peer
from tests.services.test_backup_artifact_integrity_contract import (
    authorize_owned_vault,
    create_request,
    owned_actor,
    recorded_download_headers,
)

webdav_peer = webdav_owned_peer.webdav_peer


@asynccontextmanager
async def remote_actor(monkeypatch, tmp_path, peer, credential):
    async with owned_actor(monkeypatch, tmp_path, credential) as actor:
        config = peer.config()
        password = config.pop("password")
        async with AsyncSession(actor.engine) as db:
            location = await db.get(StorageLocation, actor.storage_id)
            location.storage_type = "webdav"
            location.config = config
            location.encrypted_credentials = encrypt_credential(json.dumps({"password": password}))
            await db.commit()
        clients = []
        original = httpx.AsyncClient

        def client(*args, **kwargs):
            instance = original(*args, **kwargs)
            if not isinstance(kwargs.get("transport"), httpx.ASGITransport):
                clients.append(instance)
            return instance

        with monkeypatch.context() as capture:
            capture.setattr(httpx, "AsyncClient", client)
            fixture = SimpleNamespace(actor=actor, clients=clients, peer=peer)
            try:
                yield fixture
            finally:
                # Observe service ownership before assertions; this fixture
                # closes leaked test-owned clients only during final teardown.
                for instance in clients:
                    await instance.aclose()


def body(f, secrets):
    return {**create_request(f.actor, secrets), "storage_type": "webdav"}


async def creation_headers(f, secrets):
    if not secrets:
        return {}
    proof = await authorize_owned_vault(f.actor, {"kind": "create", "backup": body(f, secrets)})
    return {"X-FreeSDN-Vault-Proof": proof}


async def seeded_archive(f, secrets):
    headers = await creation_headers(f, secrets)
    response = await f.actor.client.post("/api/v1/backups/", json=body(f, secrets), headers=headers)
    assert response.status_code == 201 and response.json()["status"] == "completed", "Owned WebDAV archive prerequisite failed"
    assert len(f.peer.files) == 1
    saved = next(iter(f.peer.files.values()))
    # Seed setup is separate from the operation whose ownership is measured.
    for client in f.clients:
        await client.aclose()
    f.clients.clear()
    f.peer.requests.clear()
    return response.json()["id"], saved


def observe(request, f, response, **values):
    pools = [getattr(getattr(client._transport, "_pool", None), "connections", []) for client in f.clients]
    request.node.user_properties.extend({
        "HTTP_status": response.status_code,
        "network_clients_created": len(f.clients),
        "network_clients_open_at_return": sum(not client.is_closed for client in f.clients),
        "pool_connections_at_return": sum(len(pool) for pool in pools),
        "owned_peer_port": f.peer.port,
        "peer_requests": json.dumps(f.peer.requests, sort_keys=True),
        "boundary": "real API, committed PG state, encrypted stored credential, owned TLS peer; test destination admission only",
        **values,
    }.items())


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("secrets", [False, True])
async def test_creation_returns_after_network_client_close(monkeypatch, tmp_path, webdav_peer, request, credential, secrets):
    async with remote_actor(monkeypatch, tmp_path, webdav_peer, credential) as f:
        headers = await creation_headers(f, secrets)
        response = await f.actor.client.post("/api/v1/backups/", json=body(f, secrets), headers=headers)
        async with AsyncSession(f.actor.engine) as db:
            rows = list(await db.scalars(select(Backup).where(Backup.organization_id == f.actor.org_id)))
            statuses = [row.status for row in rows]
        observe(request, f, response, catalogue_statuses=json.dumps(statuses), stored_files=len(f.peer.files))
        assert response.status_code == 201 and statuses == ["completed"] and len(f.peer.files) == 1
        assert f.clients and all(client.is_closed for client in f.clients)


@pytest.mark.parametrize("operation", ["download", "manifest"])
@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("secrets", [False, True])
async def test_reader_returns_after_network_client_close(monkeypatch, tmp_path, webdav_peer, request, operation, credential, secrets):
    async with remote_actor(monkeypatch, tmp_path, webdav_peer, credential) as f:
        backup_id, saved = await seeded_archive(f, secrets)
        headers = await recorded_download_headers(f.actor, backup_id, secrets) if operation == "download" else {}
        response = await f.actor.client.get(f"/api/v1/backups/{backup_id}/{operation}", headers=headers)
        observe(request, f, response, exact_download=response.content == saved if operation == "download" else None,
                secret_preview_without_IO=secrets and operation == "manifest" and not f.peer.requests)
        assert response.status_code == 200
        if operation == "download":
            assert response.content == saved and response.headers["X-FreeSDN-Artifact-Integrity"] == "verified"
        elif secrets:
            assert response.json()["requires_passphrase"] is True and not f.clients and not f.peer.requests
            return
        assert f.clients and all(client.is_closed for client in f.clients)


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("secrets", [False, True])
async def test_deletion_returns_after_network_client_close(monkeypatch, tmp_path, webdav_peer, request, credential, secrets):
    async with remote_actor(monkeypatch, tmp_path, webdav_peer, credential) as f:
        backup_id, _saved = await seeded_archive(f, secrets)
        response = await f.actor.client.delete(f"/api/v1/backups/{backup_id}")
        observe(request, f, response, stored_files_after_delete=len(f.peer.files))
        assert response.status_code == 204 and not f.peer.files
        assert f.clients and all(client.is_closed for client in f.clients)


@pytest.mark.parametrize("credential", ["jwt", "key"])
async def test_probe_returns_after_network_client_close(monkeypatch, tmp_path, webdav_peer, request, credential):
    async with remote_actor(monkeypatch, tmp_path, webdav_peer, credential) as f:
        response = await f.actor.client.post(f"/api/v1/backups/storage-locations/{f.actor.storage_id}/test")
        observe(request, f, response, successful_probe=response.json().get("success"), stored_files_after_probe=len(f.peer.files))
        assert response.status_code == 200 and response.json()["success"] is True and not f.peer.files
        assert f.clients and all(client.is_closed for client in f.clients)


@pytest.mark.parametrize("secrets", [False, True])
async def test_failed_readback_retains_failed_catalogue_and_closes_client(monkeypatch, tmp_path, webdav_peer, request, secrets):
    async with remote_actor(monkeypatch, tmp_path, webdav_peer, "jwt") as f:
        headers = await creation_headers(f, secrets)
        f.peer.override["GET"] = (500, b"owned-readback-failure", {})
        response = await f.actor.client.post("/api/v1/backups/", json=body(f, secrets), headers=headers)
        async with AsyncSession(f.actor.engine) as db:
            rows = list(await db.scalars(select(Backup).where(Backup.organization_id == f.actor.org_id)))
            statuses = [row.status for row in rows]
            retained = len(rows) == 1 and bool(rows[0].storage_path) and "artifact_identity" not in (rows[0].metadata_json or {})
        observe(request, f, response, catalogue_statuses=json.dumps(statuses),
                retained_failed_locator_without_identity=retained, stored_files=len(f.peer.files))
        assert response.status_code >= 400 and statuses == ["failed"] and retained and len(f.peer.files) == 1
        assert f.clients and all(client.is_closed for client in f.clients)


@pytest.mark.parametrize("scenario", ["redirect", "already-absent"])
@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("secrets", [False, True])
async def test_delete_result_preserves_truthful_catalogue(monkeypatch, tmp_path, webdav_peer, request, scenario, credential, secrets):
    async with remote_actor(monkeypatch, tmp_path, webdav_peer, credential) as f:
        backup_id, _saved = await seeded_archive(f, secrets)
        if scenario == "redirect":
            f.peer.override["DELETE"] = (302, b"", {"Location": "/other-object"})
        else:
            f.peer.files.clear()  # Only the owned test object is now absent.
        response = await f.actor.client.delete(f"/api/v1/backups/{backup_id}")
        async with AsyncSession(f.actor.engine) as db:
            catalogue_present = await db.get(Backup, UUID(backup_id)) is not None
        observe(request, f, response, catalogue_present=catalogue_present,
                stored_files=len(f.peer.files), scenario=scenario)
        if scenario == "redirect":
            assert response.status_code == 503
            assert catalogue_present and len(f.peer.files) == 1
        else:
            assert response.status_code == 204
            assert not catalogue_present and not f.peer.files
        assert f.clients and all(client.is_closed for client in f.clients)
