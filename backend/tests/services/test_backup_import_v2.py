# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
``POST /backups/import`` could not ingest any file FreeSDN produces -- and
reported success for all of them.

``create_backup`` moved the payload to the v2 ``BackupArchive`` shape
(``{manifest, contributors:{core:{sites,...}}}``) but ``import_config`` was
never updated: it still did ``data = config.get("data", config)`` and then
``data.get("sites")``. A v2 archive has no ``data`` key, so ``data`` became the
archive ENVELOPE, every ``model_map`` lookup returned ``[]``, and the metadata
block read ``version: null / created_at: null / product_version: null``.

The failure was invisible because ``import_config`` returns
``{"success": false, ...}`` inside an HTTP 200. The Backups page never checks
``success`` and never renders ``message``, so a rejected file opened the preview
dialog showing "Devices 0 / Sites 0 / Created: Unknown", and clicking Import
produced a second 200 and a green "Import complete" toast. Nothing was imported,
in every case.

These tests cover the v2 round trip (the shape the product actually writes) and
the legacy pre-v2 envelope, which must keep working.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from app.services.backup import BackupService
from app.services.backup_contributors import (
    BackupArchive,
    BackupManifest,
    ContributorEntry,
)

ORG = uuid.uuid4()


def _fsdn(payload_obj: Any, *, encrypted: bool = False) -> bytes:
    """Build a .fsdn file exactly the way ``create_backup`` step 4 does."""
    raw = (
        payload_obj.model_dump_json(indent=2).encode("utf-8")
        if hasattr(payload_obj, "model_dump_json")
        else json.dumps(payload_obj, default=str).encode("utf-8")
    )
    compressed = gzip.compress(raw)
    header = {
        "backup_id": str(uuid.uuid4()),
        "checksum": hashlib.sha256(compressed).hexdigest(),
        "encrypted": encrypted,
        "compressed": True,
        "secrets": False,
        "key_id": None,
        "created_at": datetime.now(UTC).isoformat(),
        "version": "2.0",
    }
    hb = json.dumps(header).encode("utf-8")
    return len(hb).to_bytes(4, "big") + hb + compressed


def _v2_archive() -> BackupArchive:
    core = {
        "sites": [
            {"id": str(uuid.uuid4()), "name": "HQ", "organization_id": str(ORG)},
            {"id": str(uuid.uuid4()), "name": "DC", "organization_id": str(ORG)},
        ],
        "controllers": [
            {"id": str(uuid.uuid4()), "name": "omada-1", "organization_id": str(ORG)},
        ],
    }
    return BackupArchive(
        manifest=BackupManifest(
            backup_id=str(uuid.uuid4()),
            created_at=datetime(2026, 8, 20, 3, 0, tzinfo=UTC),
            organization_id=str(ORG),
            source_version="26.08.4",
            contributors=[
                ContributorEntry(
                    id="core",
                    schema_version="1.0.0",
                    counts={"sites": 2, "controllers": 1},
                )
            ],
        ),
        contributors={"core": core},
    )


def _service() -> BackupService:
    """A BackupService whose session answers every lookup with "not found",
    so a dry run walks the full record loop without a database."""
    session = MagicMock()
    empty = MagicMock()
    empty.scalars.return_value.first.return_value = None
    session.execute = AsyncMock(return_value=empty)
    BackupService._contributors_initialized = True
    return BackupService(session)


# ── the v2 shape the product actually writes ─────────────────────────


async def test_a_v2_archive_imports_its_records() -> None:
    """The whole defect in one assert: today's own backup format, read back.

    Mutation caught: restoring ``data = config.get("data", config)`` as the
    only branch -- ``would_import`` goes back to ``{}``.
    """
    out = await _service().import_config(_fsdn(_v2_archive()), dry_run=True, organization_id=ORG)
    assert out["success"] is True
    assert out["would_import"]["sites"]["created"] == 2
    assert out["would_import"]["controllers"]["created"] == 1


async def test_a_v2_archive_reports_its_provenance() -> None:
    """The import-preview dialog renders ``created_at`` and ``product_version``
    and nothing else. Both were null for every v2 archive, so the operator was
    asked to confirm an import of a file the UI could not describe.

    Mutation caught: reading the pre-v2 envelope keys (``version`` /
    ``freesdn_version``) off a v2 archive -- both come back None.
    """
    out = await _service().import_config(_fsdn(_v2_archive()), dry_run=True, organization_id=ORG)
    meta = out["metadata"]
    assert meta["product_version"] == "26.08.4"
    assert meta["created_at"] is not None
    assert meta["created_at"].startswith("2026-08-20")
    assert meta["version"] == "2.0"


# ── the legacy shape must keep working ───────────────────────────────


async def test_the_pre_v2_envelope_still_imports() -> None:
    """Old .fsdn files on disk carry ``{version, schema_version, data:{...}}``.
    Teaching the reader the v2 shape must not orphan them.

    Mutation caught: routing every payload through BackupArchive.model_validate
    -- the legacy envelope fails validation and the file is rejected outright.
    """
    legacy = {
        "version": "2.0",
        "schema_version": 2,
        "created_at": "2026-01-02T03:04:05+00:00",
        "freesdn_version": "26.01.0",
        "organization_id": str(ORG),
        "data": {"sites": [{"id": str(uuid.uuid4()), "name": "HQ"}]},
    }
    out = await _service().import_config(_fsdn(legacy), dry_run=True, organization_id=ORG)
    assert out["success"] is True
    assert out["would_import"]["sites"]["created"] == 1
    assert out["metadata"]["product_version"] == "26.01.0"
    assert out["metadata"]["created_at"] == "2026-01-02T03:04:05+00:00"


# ── rejections stay rejections ───────────────────────────────────────


async def test_an_encrypted_fsdn_is_still_refused_not_silently_emptied() -> None:
    """``/backups/{id}/download`` emits an encrypted .fsdn and the file picker
    accepts it. It must come back as an explicit refusal with a reason, never
    as a success with an empty summary.

    Mutation caught: dropping the ``header["encrypted"]`` guard in
    _parse_fsdn_file, which would hand gzip garbage to json.loads.
    """
    out = await _service().import_config(
        _fsdn(_v2_archive(), encrypted=True), dry_run=True, organization_id=ORG
    )
    assert out["success"] is False
    assert "restore endpoint" in out["message"]


async def test_an_unparseable_archive_is_refused_with_a_reason() -> None:
    """A .fsdn whose payload is neither shape must say so rather than import
    nothing under a green banner.

    Mutation caught: falling back to ``config.get("data", config)`` on a
    validation failure instead of returning success=False.
    """
    out = await _service().import_config(
        _fsdn({"manifest": {"nonsense": True}}), dry_run=True, organization_id=ORG
    )
    assert out["success"] is False
    assert "Unrecognized" in out["message"]


# ── the endpoint must not dress a refusal as a success ───────────────


class _UploadFile:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._done = False

    async def read(self, size: int = -1) -> bytes:
        if self._done:
            return b""
        self._done = True
        return self._data


class _Principal:
    is_superuser = True
    organization_id = ORG
    _scoped = False


async def _call_endpoint(data: bytes) -> Any:
    from app.api.v1.endpoints import backups as backups_api

    session = MagicMock()
    empty = MagicMock()
    empty.scalars.return_value.first.return_value = None
    session.execute = AsyncMock(return_value=empty)
    BackupService._contributors_initialized = True
    return await backups_api.import_config(
        session,
        _Principal(),
        file=_UploadFile(data),
        dry_run=True,
        overwrite_existing=False,
    )


async def test_a_refused_file_comes_back_as_400_not_200() -> None:
    """``import_config`` returns success=false inside an HTTP 200. The Backups
    page never checks ``success`` and never renders ``message``, so the refusal
    reached the operator as a preview dialog full of zeros followed by a green
    "Import complete" toast. axios only raises on a non-2xx.

    Mutation caught: deleting the ``if not result.get("success")`` guard in
    backups.py -- the call returns a dict again instead of raising.
    """
    from fastapi import HTTPException

    try:
        result = await _call_endpoint(_fsdn(_v2_archive(), encrypted=True))
    except HTTPException as exc:
        assert exc.status_code == 400
        # The reason must travel: the UI renders `detail` via getApiErrorMessage.
        assert "restore endpoint" in str(exc.detail)
    else:
        raise AssertionError(f"a refused import returned HTTP 200: {result}")


async def test_a_good_file_still_returns_its_summary() -> None:
    """The guard must only fire on a refusal.

    Mutation caught: inverting the check, or raising on every response.
    """
    result = await _call_endpoint(_fsdn(_v2_archive()))
    assert result["success"] is True
    assert result["would_import"]["sites"]["created"] == 2
