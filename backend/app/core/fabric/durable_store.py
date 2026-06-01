# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN Fabric — durable artifact store (staged-write blob handoff).

The transient :class:`~app.core.fabric.artifact_broker.ArtifactBroker` holds a
producer's bytes only for a short TTL (it is a handoff buffer between steps of a
single Connection firing). But a Fabric *write* Connection STAGES its change and
waits for an operator to sign off — which can be hours or days later, long after
the broker has swept the bytes. So when the executor stages a write that carries
an input artifact (e.g. ``cameras.snapshot`` → ``storage.store_blob``), it copies
the bytes here, and the staged change carries only a small reference
(``durable_token`` + ``sha256`` + ``size``). The apply-handler reads them back
at sign-off time and re-verifies integrity before the device write.

Mirrors the broker's security properties — org-scoped directories, server-minted
32-hex tokens (no path traversal), sha256 integrity — but is **durable** (no TTL;
mirrors the ``EvidenceArchive`` on-disk legal-hold pattern). The staging service
prunes a token when its staged change reaches a terminal state — ``delete()`` is
called on a successful apply (by the storage applier) and on a failed apply or a
discard (by ``AdapterStagingService._cleanup_durable_artifact``), so the dir does
not grow without bound.

The backing dir (``FABRIC_ARTIFACT_DURABLE_DIR``) MUST be a persistent volume in
production; the default is ephemeral on a fresh container.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import uuid
from pathlib import Path
from typing import Any
from uuid import UUID

logger = logging.getLogger(__name__)

_TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
# Same backstop ceiling as the broker's native tier — a staged blob is operator
# data, not a stream; 64 MiB is ample for a snapshot/clip-still.
DEFAULT_MAX_BYTES = 64 * 1024 * 1024


class DurableArtifactError(Exception):
    """Durable store put/get failure (size, missing, tenant mismatch, integrity)."""


class DurableArtifactStore:
    """Persistent, content-addressed, org-scoped blob store for staged writes."""

    def __init__(self, base_dir: Path | None = None, *, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        if base_dir is None:
            from app.core.config import settings

            base_dir = Path(settings.FABRIC_ARTIFACT_DURABLE_DIR)
        self._base = base_dir
        self._max = max_bytes

    def _org_dir(self, organization_id: UUID | str) -> Path:
        try:
            org = str(uuid.UUID(str(organization_id)))
        except (ValueError, AttributeError, TypeError):
            raise DurableArtifactError("invalid organization id") from None
        return self._base / org

    def _paths(self, organization_id: UUID | str, token: str) -> tuple[Path, Path]:
        if not _TOKEN_RE.match(token):
            raise DurableArtifactError("invalid durable token")
        d = self._org_dir(organization_id)
        return d / f"{token}.bin", d / f"{token}.json"

    async def put(self, data: bytes, organization_id: UUID, media_type: str) -> dict[str, Any]:
        """Persist ``data`` and return a reference dict for the staged payload."""
        size = len(data)
        if size == 0:
            raise DurableArtifactError("refusing to store empty artifact")
        if size > self._max:
            raise DurableArtifactError(f"artifact too large ({size} > {self._max} bytes)")
        token = uuid.uuid4().hex
        sha = hashlib.sha256(data).hexdigest()
        bin_path, meta_path = self._paths(organization_id, token)
        meta = {
            "durable_token": token,
            "organization_id": str(organization_id),
            "media_type": str(media_type),
            "size": size,
            "sha256": sha,
        }

        def _write() -> None:
            bin_path.parent.mkdir(parents=True, exist_ok=True)
            bin_path.write_bytes(data)
            meta_path.write_text(json.dumps(meta), encoding="utf-8")

        await asyncio.to_thread(_write)
        logger.debug("Fabric durable artifact stored: %s (%d bytes, %s)", token, size, media_type)
        return {"durable_token": token, "sha256": sha, "size": size, "media_type": str(media_type)}

    async def get(
        self, token: str, organization_id: UUID, *, expected_sha256: str | None = None
    ) -> bytes:
        """Read bytes by token for the owning org. Fail-closed on tenant
        mismatch or integrity failure; if ``expected_sha256`` is given it must
        also match (the staged payload's recorded hash)."""
        bin_path, meta_path = self._paths(organization_id, token)

        def _read() -> tuple[bytes, dict[str, Any]] | None:
            if not bin_path.exists() or not meta_path.exists():
                return None
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            return bin_path.read_bytes(), meta

        result = await asyncio.to_thread(_read)
        if result is None:
            raise DurableArtifactError("durable artifact not found")
        data, meta = result
        if str(meta.get("organization_id")) != str(organization_id):
            raise DurableArtifactError("durable artifact does not belong to this organization")
        actual = hashlib.sha256(data).hexdigest()
        if actual != meta.get("sha256"):
            raise DurableArtifactError("durable artifact integrity check failed")
        if expected_sha256 is not None and actual != expected_sha256:
            raise DurableArtifactError("durable artifact does not match the staged sha256")
        return data

    async def delete(self, token: str, organization_id: UUID) -> None:
        bin_path, meta_path = self._paths(organization_id, token)

        def _rm() -> None:
            bin_path.unlink(missing_ok=True)
            meta_path.unlink(missing_ok=True)

        await asyncio.to_thread(_rm)


# Module-level singleton (executor persists; apply-handler reads).
durable_store = DurableArtifactStore()
