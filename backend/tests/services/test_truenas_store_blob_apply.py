# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the TrueNAS staged-apply service (storage.store_blob).

The applier runs only after the dual-gate (verified in adapter_staging tests).
Here we test what build_applier does once reached: org-scoped controller load,
payload validation, durable-blob fetch + sha256 re-verify, and force=True upload.
"""
from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException

import app.services.adapter_truenas_storage as mod
from app.core.fabric.durable_store import DurableArtifactError, durable_store
from app.services.adapter_truenas_storage import (
    GatewayTrueNASStorageService,
    _validate_dataset_path,
    _validate_filename,
)


class _Change:
    def __init__(self, payload, *, feature="storage.store_blob", operation="create") -> None:
        self.controller_id = uuid.uuid4()
        self.organization_id = uuid.uuid4()
        self.feature = feature
        self.operation = operation
        self.target_id = None
        self.payload = payload


class _FakeAdapter:
    def __init__(self) -> None:
        self.uploaded: dict | None = None

    async def upload_file(self, *, dataset_path, filename, blob, force):
        self.uploaded = {"dataset_path": dataset_path, "filename": filename,
                         "size": len(blob), "force": force}
        return {"state": "SUCCESS", "path": f"{dataset_path}/{filename}", "size": len(blob)}

    async def disconnect(self) -> None:
        pass


def _good_payload() -> dict:
    return {
        "dataset_path": "/mnt/s4_hdd/freesdn",
        "filename": "cam.jpg",
        "_artifact": {"durable_token": "a" * 32, "sha256": "deadbeef", "size": 9},
    }


@pytest.fixture
def svc(monkeypatch):
    s = GatewayTrueNASStorageService(db=None)  # type: ignore[arg-type]

    async def _get_controller(cid, org):
        return object()  # adapter is monkeypatched, so the ctrl value is unused

    monkeypatch.setattr(s, "_get_controller", _get_controller)
    return s


@pytest.fixture
def fake_adapter(monkeypatch):
    fake = _FakeAdapter()

    async def _build(ctrl):
        return fake

    monkeypatch.setattr(mod, "build_truenas_adapter", _build)
    return fake


class TestValidators:
    def test_dataset_path(self) -> None:
        assert _validate_dataset_path("/mnt/s4_hdd/freesdn/") == "/mnt/s4_hdd/freesdn"
        for bad in ("/etc", "/mnt/../x", "/mnt/s4 hdd", ""):
            with pytest.raises(HTTPException):
                _validate_dataset_path(bad)

    def test_filename(self) -> None:
        assert _validate_filename("a-b_1.jpg") == "a-b_1.jpg"
        for bad in ("a/b", "..", "", "x" * 300):
            with pytest.raises(HTTPException):
                _validate_filename(bad)


class TestApplier:
    @pytest.mark.asyncio
    async def test_happy_path_uploads_with_force(self, monkeypatch, svc, fake_adapter) -> None:
        async def _get(token, org, *, expected_sha256=None):
            assert token == "a" * 32 and expected_sha256 == "deadbeef"
            return b"jpegbytes"

        async def _del(token, org):
            return None

        monkeypatch.setattr(durable_store, "get", _get)
        monkeypatch.setattr(durable_store, "delete", _del)

        change = _Change(_good_payload())
        res = await svc.build_applier(change)(change)
        assert res["state"] == "SUCCESS"
        assert fake_adapter.uploaded == {
            "dataset_path": "/mnt/s4_hdd/freesdn", "filename": "cam.jpg",
            "size": 9, "force": True,
        }

    @pytest.mark.asyncio
    async def test_missing_artifact_ref_rejected(self, svc, fake_adapter) -> None:
        change = _Change({"dataset_path": "/mnt/s4_hdd/freesdn", "filename": "x.jpg"})
        with pytest.raises(HTTPException) as ei:
            await svc.build_applier(change)(change)
        assert ei.value.status_code == 400

    @pytest.mark.asyncio
    async def test_bad_dataset_path_rejected(self, svc, fake_adapter) -> None:
        p = _good_payload()
        p["dataset_path"] = "/etc/passwd"
        change = _Change(p)
        with pytest.raises(HTTPException) as ei:
            await svc.build_applier(change)(change)
        assert ei.value.status_code == 400

    @pytest.mark.asyncio
    async def test_sha_mismatch_surfaces_409(self, monkeypatch, svc, fake_adapter) -> None:
        async def _get(token, org, *, expected_sha256=None):
            raise DurableArtifactError("durable artifact does not match the staged sha256")

        monkeypatch.setattr(durable_store, "get", _get)
        change = _Change(_good_payload())
        with pytest.raises(HTTPException) as ei:
            await svc.build_applier(change)(change)
        assert ei.value.status_code == 409

    @pytest.mark.asyncio
    async def test_unknown_feature_rejected(self, svc, fake_adapter) -> None:
        change = _Change(_good_payload(), feature="storage.bogus")
        with pytest.raises(HTTPException) as ei:
            await svc.build_applier(change)(change)
        assert ei.value.status_code == 400


class TestDurableCleanupOnTerminalState:
    """The staging service prunes the durable blob on discard / failed apply
    (the success path is pruned by the applier). Closes the orphan-leak."""

    @pytest.mark.asyncio
    async def test_cleanup_helper_deletes_referenced_blob(self, monkeypatch) -> None:
        from app.services.adapter_staging import AdapterStagingService

        deleted: list[tuple] = []

        async def _del(token, org):
            deleted.append((token, org))

        monkeypatch.setattr(durable_store, "delete", _del)
        svc = AdapterStagingService(db=None)  # type: ignore[arg-type]

        org = uuid.uuid4()
        change = type("C", (), {
            "payload": {"_artifact": {"durable_token": "z" * 32, "sha256": "s"}},
            "organization_id": org, "id": uuid.uuid4(),
        })()
        await svc._cleanup_durable_artifact(change)
        assert deleted == [("z" * 32, org)]

    @pytest.mark.asyncio
    async def test_cleanup_noop_without_artifact(self, monkeypatch) -> None:
        from app.services.adapter_staging import AdapterStagingService

        called = []
        monkeypatch.setattr(durable_store, "delete", lambda *a: called.append(a))
        svc = AdapterStagingService(db=None)  # type: ignore[arg-type]
        change = type("C", (), {"payload": {"node": "n"}, "organization_id": uuid.uuid4(), "id": uuid.uuid4()})()
        await svc._cleanup_durable_artifact(change)  # no _artifact → no delete
        assert called == []
