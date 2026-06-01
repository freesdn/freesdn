# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the TrueNAS adapter write surface (Fabric storage.store_blob).

Pure unit tests with a fake WS client (no network): the force-gate, the
/mnt path + filename safety validators, the two-channel upload orchestration
(upload_blob → job_wait), and failure mapping.
"""
from __future__ import annotations

import pytest

from app.adapters.exceptions import AdapterAuthenticationError, AdapterError
from app.adapters.truenas.adapter import (
    TrueNASAdapter,
    _validate_filename,
    _validate_mnt_path,
)
from app.adapters.truenas.constants import UPLOAD_POST_TIMEOUT_SEC
from app.adapters.truenas.ws_client import TrueNASWSClient


class _FakeApi:
    def __init__(self, *, state: str = "SUCCESS") -> None:
        self.calls: list[tuple] = []
        self._state = state

    async def upload_blob(self, *, dest_path: str, blob: bytes, mode=None) -> int:
        self.calls.append((dest_path, len(blob), mode))
        return 99

    async def job_wait(self, job_id: int, *, timeout: float = 120.0) -> dict:
        return {"id": job_id, "state": self._state, "error": "boom" if self._state != "SUCCESS" else None}


def _adapter(state: str = "SUCCESS") -> TrueNASAdapter:
    a = TrueNASAdapter(host="nas.lab", api_key="k", verify_ssl=False)
    a._transport = "ws"
    a._api = _FakeApi(state=state)
    return a


class TestPathValidators:
    def test_valid_mnt_path(self) -> None:
        assert _validate_mnt_path("/mnt/s4_hdd/freesdn/") == "/mnt/s4_hdd/freesdn"

    def test_rejects_non_mnt(self) -> None:
        for bad in ("/etc/passwd", "mnt/x", "/data/x", ""):
            with pytest.raises(AdapterError):
                _validate_mnt_path(bad)

    def test_rejects_traversal(self) -> None:
        for bad in ("/mnt/../etc", "/mnt/s4_hdd/../../x", "/mnt/s4_hdd/a b"):
            with pytest.raises(AdapterError):
                _validate_mnt_path(bad)

    def test_filename_validator(self) -> None:
        assert _validate_filename("snap_2026.jpg") == "snap_2026.jpg"
        for bad in ("a/b.jpg", "..", "../x", "a\\b", "", "x" * 256):
            with pytest.raises(AdapterError):
                _validate_filename(bad)


class TestUploadFile:
    @pytest.mark.asyncio
    async def test_force_gate_refuses(self) -> None:
        a = _adapter()
        with pytest.raises(AdapterError, match="force-gate"):
            await a.upload_file(dataset_path="/mnt/s4_hdd/freesdn", filename="x.jpg", blob=b"x")

    @pytest.mark.asyncio
    async def test_happy_path_uploads_and_waits(self) -> None:
        a = _adapter()
        res = await a.upload_file(
            dataset_path="/mnt/s4_hdd/freesdn", filename="cam.jpg", blob=b"jpegbytes", force=True
        )
        assert res["state"] == "SUCCESS" and res["job_id"] == 99 and res["size"] == 9
        assert res["path"] == "/mnt/s4_hdd/freesdn/cam.jpg"
        assert a._api.calls == [("/mnt/s4_hdd/freesdn/cam.jpg", 9, None)]

    @pytest.mark.asyncio
    async def test_rejects_empty_blob(self) -> None:
        a = _adapter()
        with pytest.raises(AdapterError, match="empty"):
            await a.upload_file(dataset_path="/mnt/s4_hdd/freesdn", filename="x.jpg", blob=b"", force=True)

    @pytest.mark.asyncio
    async def test_rejects_unsafe_path(self) -> None:
        a = _adapter()
        with pytest.raises(AdapterError):
            await a.upload_file(dataset_path="/etc", filename="x.jpg", blob=b"x", force=True)

    @pytest.mark.asyncio
    async def test_job_failure_raises(self) -> None:
        a = _adapter(state="FAILED")
        with pytest.raises(AdapterError, match="did not succeed"):
            await a.upload_file(dataset_path="/mnt/s4_hdd/freesdn", filename="x.jpg", blob=b"x", force=True)

    @pytest.mark.asyncio
    async def test_requires_ws_transport(self) -> None:
        a = TrueNASAdapter(host="nas.lab", api_key="k")
        a._transport = "rest"  # legacy box; upload unsupported
        a._api = _FakeApi()
        with pytest.raises(AdapterError, match="WS JSON-RPC"):
            await a.upload_file(dataset_path="/mnt/s4_hdd/freesdn", filename="x.jpg", blob=b"x", force=True)


class _FakeResp:
    def __init__(self, body) -> None:
        self._body = body

    def raise_for_status(self) -> None:
        pass

    def json(self):
        return self._body

    @property
    def text(self) -> str:
        return ""


class _FakeAsyncClient:
    last: dict = {}

    def __init__(self, **kw) -> None:
        _FakeAsyncClient.last = {"init": kw}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a) -> None:
        pass

    async def post(self, path, data=None, files=None, headers=None):
        _FakeAsyncClient.last.update(path=path, data=data, files=files, headers=headers)
        return _FakeResp({"job_id": 7})


class TestUploadBlob:
    @pytest.mark.asyncio
    async def test_omits_mode_when_none_and_uses_upload_timeout(self, monkeypatch) -> None:
        import json

        monkeypatch.setattr("httpx.AsyncClient", _FakeAsyncClient)
        c = TrueNASWSClient(host="nas.lab", api_key="k", verify_ssl=False)
        jid = await c.upload_blob(dest_path="/mnt/s4_hdd/freesdn/f.jpg", blob=b"x", mode=None)
        assert jid == 7
        spec = json.loads(_FakeAsyncClient.last["data"]["data"])
        assert spec["method"] == "filesystem.put"
        assert spec["params"][0] == "/mnt/s4_hdd/freesdn/f.jpg"
        assert "mode" not in spec["params"][1]  # omitted, not null
        # dedicated upload timeout, not the 30s WS read timeout
        assert _FakeAsyncClient.last["init"]["timeout"] == UPLOAD_POST_TIMEOUT_SEC
        assert _FakeAsyncClient.last["headers"]["Authorization"] == "Bearer k"

    @pytest.mark.asyncio
    async def test_includes_mode_when_set(self, monkeypatch) -> None:
        import json

        monkeypatch.setattr("httpx.AsyncClient", _FakeAsyncClient)
        c = TrueNASWSClient(host="nas.lab", api_key="k")
        await c.upload_blob(dest_path="/mnt/s4_hdd/freesdn/f.jpg", blob=b"x", mode=0o644)
        spec = json.loads(_FakeAsyncClient.last["data"]["data"])
        assert spec["params"][1]["mode"] == 0o644

    @pytest.mark.asyncio
    async def test_rejects_crlf_api_key(self) -> None:
        c = TrueNASWSClient(host="nas.lab", api_key="k\r\nX-Injected: y")
        with pytest.raises(AdapterAuthenticationError, match="control characters"):
            await c.upload_blob(dest_path="/mnt/s4_hdd/freesdn/f.jpg", blob=b"x")
