# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Consumer-level regression tests: real files, concurrent uploads, mocked I/O."""

import asyncio
import io
import json
import logging
import stat
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from fastapi import HTTPException, UploadFile

from app.api.v1.endpoints import data
from app.core.fabric.artifact_broker import ArtifactBroker, ArtifactError
from app.core.private_files import write_private
from app.modules.cameras.service import HLSStreamService
from tests.harness_wait import HARNESS_WAIT_SECONDS


def permission(path):
    return stat.S_IMODE(Path(path).stat().st_mode)


@pytest.fixture
def upload_context(monkeypatch, tmp_path):
    monkeypatch.setattr(data, "DATA_DIR", tmp_path)
    # Authorization itself remains covered by the endpoint/site-grant tests.
    monkeypatch.setattr(data, "require_admin", lambda _user: None)
    return SimpleNamespace(id=uuid4(), organization_id=uuid4(), is_site_limited=False)


async def test_concurrent_preview_same_filename_keeps_separate_content(
    monkeypatch, tmp_path, upload_context
):
    paths = []
    observed = []
    ready = asyncio.Event()

    async def validate(path, source_format):
        assert source_format == "freesdn"
        paths.append(Path(path))
        if len(paths) == 2:
            ready.set()
        await asyncio.wait_for(ready.wait(), timeout=HARNESS_WAIT_SECONDS)
        observed.append(Path(path).read_bytes())
        assert permission(path) == 0o600
        return {"valid": True, "source_format": source_format}

    monkeypatch.setattr(data.Svc, "validate_import_file", validate)
    await asyncio.gather(
        *[
            data.validate_import_file(
                UploadFile(filename="backup.json", file=io.BytesIO(body)),
                source_format="freesdn",
                user=upload_context,
            )
            for body in (b"first", b"second")
        ]
    )
    assert len(set(paths)) == 2 and sorted(observed) == [b"first", b"second"]
    assert not list((tmp_path / "uploads").iterdir())


async def test_queued_imports_same_filename_keep_immutable_distinct_sources(
    monkeypatch, tmp_path, upload_context
):
    from app.tasks.import_export import run_import_job

    jobs = []

    async def create(_session, **kwargs):
        job = SimpleNamespace(**kwargs, id=uuid4(), status="pending", created_at=datetime.now(UTC))
        jobs.append(job)
        return job

    monkeypatch.setattr(data.Svc, "create_import_job", create)
    monkeypatch.setattr(run_import_job, "delay", Mock(return_value=SimpleNamespace(id="task-id")))
    for content in (b"first", b"second"):
        await data.create_import(
            UploadFile(filename="backup.json", file=io.BytesIO(content)),
            source_format="freesdn",
            conflict_resolution="skip",
            session=AsyncMock(),
            user=upload_context,
        )
    assert jobs[0].file_path != jobs[1].file_path
    assert [Path(j.file_path).read_bytes() for j in jobs] == [b"first", b"second"]
    assert all(j.original_filename == "backup.json" for j in jobs)
    assert all(permission(j.file_path) == 0o600 for j in jobs)
    assert permission(tmp_path / "uploads") == 0o700


@pytest.mark.parametrize("failure", ["oversize", "validator"])
async def test_preview_failure_removes_only_its_own_file(
    monkeypatch, tmp_path, upload_context, failure
):
    from app.core import security_utils

    unrelated = tmp_path / "uploads" / "queued.upload"
    write_private(unrelated, b"keep")
    if failure == "oversize":
        monkeypatch.setattr(security_utils, "MAX_CONFIG_IMPORT_BYTES", 2)
    else:
        monkeypatch.setattr(data.Svc, "validate_import_file", AsyncMock(side_effect=RuntimeError))
    with pytest.raises(HTTPException if failure == "oversize" else RuntimeError):
        await data.validate_import_file(
            UploadFile(filename="backup.json", file=io.BytesIO(b"large")),
            source_format="freesdn",
            user=upload_context,
        )
    assert list(unrelated.parent.iterdir()) == [unrelated]
    assert unrelated.read_bytes() == b"keep"


@pytest.mark.parametrize(
    "content,source_format",
    [
        (b"{", "freesdn"),
        (b"\xff", "freesdn"),
        (b"", "generic_csv"),
    ],
)
async def test_invalid_import_preview_is_a_validation_result_not_server_error(
    upload_context, tmp_path, content, source_format
):
    result = await data.validate_import_file(
        UploadFile(filename="backup.json", file=io.BytesIO(content)),
        source_format=source_format,
        user=upload_context,
    )
    assert result.valid is False and result.errors
    assert result.source_format == source_format
    assert not list((tmp_path / "uploads").iterdir())


async def test_export_download_uses_verified_descriptor_after_path_swap(
    monkeypatch, tmp_path, upload_context
):
    original = tmp_path / "export.json"
    write_private(original, b'{"entities":{}}')
    job = SimpleNamespace(
        id=uuid4(),
        organization_id=upload_context.organization_id,
        file_path=str(original),
        export_format="json",
    )
    monkeypatch.setattr(data.Svc, "get_export_job", AsyncMock(return_value=job))
    response = await data.download_export(job.id, session=AsyncMock(), user=upload_context)
    original.rename(tmp_path / "old")
    original.symlink_to("/etc/passwd")
    assert b"".join([chunk async for chunk in response.body_iterator]) == b'{"entities":{}}'
    await response.background()
    assert response.headers["content-disposition"] == f'attachment; filename="export_{job.id}.json"'


@pytest.mark.parametrize("kind", ["symlink", "outside", "parent_traversal"])
async def test_export_refuses_unsafe_paths(monkeypatch, tmp_path, upload_context, kind):
    path = tmp_path / "export.json"
    if kind == "symlink":
        path.symlink_to("/etc/passwd")
    elif kind == "outside":
        path = Path("/etc/passwd")
    else:
        path = tmp_path / ".." / "export.json"
    job = SimpleNamespace(
        id=uuid4(),
        organization_id=upload_context.organization_id,
        file_path=str(path),
        export_format="json",
    )
    monkeypatch.setattr(data.Svc, "get_export_job", AsyncMock(return_value=job))
    with pytest.raises(HTTPException) as exc:
        await data.download_export(job.id, session=AsyncMock(), user=upload_context)
    assert exc.value.status_code in (403, 404)


async def test_import_service_rejects_symlinks_and_oversize(monkeypatch, tmp_path):
    from app.services import import_export

    original = tmp_path / "data.json"
    write_private(original, b'{"entities":{}}')
    assert (await data.Svc.validate_import_file(str(original)))["valid"]
    link = tmp_path / "link.json"
    link.symlink_to(original)
    assert not (await data.Svc.validate_import_file(str(link)))["valid"]
    monkeypatch.setattr(import_export, "MAX_CONFIG_IMPORT_BYTES", 2)
    assert not (await data.Svc.validate_import_file(str(original)))["valid"]


async def test_artifact_cross_instance_handoff_is_private_and_integrity_checked(tmp_path):
    org = uuid4()
    broker = ArtifactBroker(tmp_path / "artifacts")
    ref = await broker.put(b"fixture", "application/octet-stream", org)
    second = ArtifactBroker(tmp_path / "artifacts")
    content, observed = await second.get(ref.handle, org)
    assert content == b"fixture" and observed.sha256 == ref.sha256
    root = tmp_path / "artifacts" / str(org)
    assert permission(root) == 0o700
    assert all(permission(p) == 0o600 for p in root.iterdir())
    (root / f"{ref.handle}.bin").write_bytes(b"changed")
    with pytest.raises(ArtifactError, match="integrity"):
        await second.get(ref.handle, org)


@pytest.mark.parametrize("kind", ["blob_link", "sidecar_link", "oversize", "malformed"])
async def test_artifact_reader_refuses_unsafe_or_unbounded_storage(tmp_path, kind):
    broker = ArtifactBroker(tmp_path / "artifacts", max_bytes=8)
    org = uuid4()
    ref = await broker.put(b"fixture", "text/plain", org)
    root = tmp_path / "artifacts" / str(org)
    blob = root / f"{ref.handle}.bin"
    sidecar = root / f"{ref.handle}.json"
    if kind.endswith("link"):
        path = blob if kind == "blob_link" else sidecar
        path.unlink()
        path.symlink_to("/etc/passwd")
    elif kind == "oversize":
        blob.write_bytes(b"x" * 9)
    else:
        sidecar.write_text("[]")
    with pytest.raises(ArtifactError):
        await broker.get(ref.handle, org)


@pytest.mark.parametrize(
    "field,value",
    [
        ("expires_at", "never"),
        ("expires_at", float("nan")),
        ("expires_at", float("inf")),
        ("expires_at", True),
        ("expires_at", 10**500),
        ("size", "7"),
        ("size", 999),
        ("handle", "0" * 32),
    ],
)
async def test_artifact_rejects_inconsistent_metadata(tmp_path, field, value):
    broker = ArtifactBroker(tmp_path / "artifacts")
    org = uuid4()
    ref = await broker.put(b"fixture", "text/plain", org)
    path = tmp_path / "artifacts" / str(org) / f"{ref.handle}.json"
    meta = json.loads(path.read_bytes())
    meta[field] = value
    path.write_text(json.dumps(meta))
    with pytest.raises(ArtifactError, match="metadata"):
        await broker.get(ref.handle, org)


async def test_artifact_sweep_ignores_unsafe_sidecar_and_removes_expired(tmp_path):
    broker = ArtifactBroker(tmp_path / "artifacts")
    org = uuid4()
    ref = await broker.put(b"fixture", "text/plain", org)
    root = tmp_path / "artifacts" / str(org)
    sidecar = root / f"{ref.handle}.json"
    meta = json.loads(sidecar.read_bytes())
    meta["expires_at"] = 0
    sidecar.write_text(json.dumps(meta))
    unrelated = tmp_path / "keep.json"
    unrelated.write_text("sensitive fixture")
    (root / "unsafe.json").symlink_to(unrelated)
    assert await broker.cleanup_expired() == 1
    assert unrelated.read_text() == "sensitive fixture"
    assert not sidecar.exists()


async def test_hls_process_has_private_files_and_does_not_copy_credentials_to_logs(
    monkeypatch, tmp_path, caplog
):
    service = HLSStreamService()
    monkeypatch.setattr(service, "HLS_DIR", str(tmp_path / "hls"))
    stderr = asyncio.StreamReader()
    process = SimpleNamespace(
        pid=123, returncode=None, stderr=stderr, terminate=Mock(), wait=AsyncMock(), kill=Mock()
    )
    spawn = AsyncMock(return_value=process)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    caplog.set_level(logging.INFO)
    result = await service.start_session(
        uuid4(), "source", "rtsp://user:FIXTURE_SECRET@camera/stream"
    )
    meta = service._sessions[result["session_id"]]
    assert spawn.call_args.kwargs["umask"] == 0o077
    assert spawn.call_args.kwargs["stderr"] == asyncio.subprocess.PIPE
    assert permission(meta["output_dir"]) == 0o700
    assert permission(meta["log_path"]) == 0o600
    diagnostic = b"Failed URL rtsp://user:FIXTURE_SECRET@camera/stream"
    stderr.feed_data(diagnostic)
    stderr.feed_eof()
    await asyncio.wait_for(asyncio.shield(meta["stderr_task"]), timeout=HARNESS_WAIT_SECONDS)
    assert Path(meta["log_path"]).read_bytes() == diagnostic
    assert meta["log_file"].closed
    await service.stop_session(result["session_id"])
    assert "produced no segments" in caplog.text
    assert "FIXTURE_SECRET" not in caplog.text and "rtsp://" not in caplog.text
    assert not Path(meta["output_dir"]).exists()


async def test_hls_spawn_failure_closes_private_log_and_removes_directory(monkeypatch, tmp_path):
    from app.core import private_files

    service = HLSStreamService()
    monkeypatch.setattr(service, "HLS_DIR", str(tmp_path / "hls"))
    captured = []
    create_private = private_files.create_private

    def capture_private(path):
        handle = create_private(path)
        captured.append(handle)
        assert permission(path) == 0o600
        return handle

    async def spawn(*_args, **kwargs):
        assert kwargs["stderr"] == asyncio.subprocess.PIPE
        assert kwargs["umask"] == 0o077
        assert len(captured) == 1 and not captured[0].closed
        raise FileNotFoundError("ffmpeg")

    monkeypatch.setattr(private_files, "create_private", capture_private)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    with pytest.raises(FileNotFoundError):
        await service.start_session(uuid4(), "source", "rtsp://camera/stream")
    assert captured[0].closed and not service._sessions
    assert not list((tmp_path / "hls").iterdir())
