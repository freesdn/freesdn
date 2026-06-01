# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN Fabric — Artifact Broker.

Cross-app binary handoff. When a source operation produces a blob (a camera
snapshot, a recorded clip, a log batch), it ``put()``s the bytes here and the
event/step carries only a small :class:`ArtifactRef` (handle + media-type +
sha256 + size). A consumer operation later ``get()``s the bytes by handle. This
keeps multi-megabyte payloads out of the event bus and the DB, and lets the
negotiator match producers to consumers by media-type.

Security properties (enterprise-grade handoff):
  * **Org-scoped** — every artifact is written under its tenant; ``get()``
    requires the same ``organization_id`` (fail-closed, cross-tenant safe).
  * **Path-safe** — handles are server-generated 32-hex tokens; any other shape
    is rejected, so a handle can never traverse the filesystem.
  * **Integrity** — sha256 is computed on ``put`` and re-verified on ``get``.
  * **Bounded** — a hard per-artifact size cap (the caller passes a tighter cap
    for the untrusted plugin tier); TTL expiry with lazy + sweep cleanup.

Backed by the local data dir (mirrors the EvidenceArchive on-disk
pattern); can later target a TrueNAS dataset as the backing store.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
import uuid
from pathlib import Path
from typing import Any
from uuid import UUID

from app.core.fabric.execution import ArtifactRef

logger = logging.getLogger(__name__)

# Default per-artifact ceiling (native tier). The executor passes a smaller cap
# for the plugin tier. A single global ceiling here is the last backstop.
DEFAULT_MAX_BYTES = 64 * 1024 * 1024  # 64 MiB
DEFAULT_TTL_SECONDS = 3600  # artifacts are transient handoff buffers, not storage

_HANDLE_RE = re.compile(r"^[0-9a-f]{32}$")


class ArtifactError(Exception):
    """Artifact put/get failure (size cap, missing, expired, tenant mismatch)."""


class ArtifactBroker:
    """Transient, content-addressed, org-scoped blob store."""

    def __init__(
        self,
        base_dir: Path | None = None,
        *,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> None:
        if base_dir is None:
            # Mirror the export data-dir convention.
            base_dir = Path("/tmp/freesdn_data") / "fabric_artifacts"
        self._base = base_dir
        self._ttl = ttl_seconds
        self._max = max_bytes

    def _org_dir(self, organization_id: UUID | str) -> Path:
        # Validate as a TRUE UUID (not a loose char-class) and use its canonical
        # form as the directory name — defeats traversal and odd sibling dirs.
        try:
            org = str(uuid.UUID(str(organization_id)))
        except (ValueError, AttributeError, TypeError):
            raise ArtifactError("invalid organization id") from None
        return self._base / org

    def _paths(self, organization_id: UUID | str, handle: str) -> tuple[Path, Path]:
        if not _HANDLE_RE.match(handle):
            # Server-generated handles only — defeats path traversal.
            raise ArtifactError("invalid artifact handle")
        d = self._org_dir(organization_id)
        return d / f"{handle}.bin", d / f"{handle}.json"

    async def put(
        self,
        data: bytes,
        media_type: str,
        organization_id: UUID,
        *,
        ttl_seconds: int | None = None,
        max_bytes: int | None = None,
    ) -> ArtifactRef:
        """Store bytes and return an :class:`ArtifactRef`. Raises on cap breach."""
        if max_bytes is not None and max_bytes < 0:
            raise ArtifactError("invalid max_bytes")
        # Explicit None check: a caller-supplied cap of 0 must mean "forbid",
        # not fall through to the default ceiling.
        cap = self._max if max_bytes is None else min(self._max, max_bytes)
        size = len(data)
        if size == 0:
            raise ArtifactError("refusing to store empty artifact")
        if size > cap:
            raise ArtifactError(f"artifact too large ({size} > {cap} bytes)")

        handle = uuid.uuid4().hex
        sha = hashlib.sha256(data).hexdigest()
        ttl = ttl_seconds if ttl_seconds is not None else self._ttl
        expires_at = time.time() + max(1, ttl)
        bin_path, meta_path = self._paths(organization_id, handle)
        meta = {
            "handle": handle,
            "organization_id": str(organization_id),
            "media_type": str(media_type),
            "size": size,
            "sha256": sha,
            "expires_at": expires_at,
        }

        def _write() -> None:
            bin_path.parent.mkdir(parents=True, exist_ok=True)
            bin_path.write_bytes(data)
            meta_path.write_text(json.dumps(meta), encoding="utf-8")

        await asyncio.to_thread(_write)
        logger.debug("Fabric artifact stored: %s (%d bytes, %s)", handle, size, media_type)
        return ArtifactRef(handle=handle, media_type=str(media_type), size=size, sha256=sha)

    async def get(self, handle: str, organization_id: UUID) -> tuple[bytes, ArtifactRef]:
        """Fetch bytes by handle for the owning org. Fail-closed on mismatch,
        expiry, or integrity failure."""
        bin_path, meta_path = self._paths(organization_id, handle)

        def _read() -> tuple[bytes, dict[str, Any]] | None:
            if not bin_path.exists() or not meta_path.exists():
                return None
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            return bin_path.read_bytes(), meta

        result = await asyncio.to_thread(_read)
        if result is None:
            raise ArtifactError("artifact not found")
        data, meta = result

        # Cross-tenant guard (defense-in-depth on top of the org-dir path).
        if str(meta.get("organization_id")) != str(organization_id):
            raise ArtifactError("artifact does not belong to this organization")
        if time.time() > float(meta.get("expires_at", 0)):
            await self.delete(handle, organization_id)
            raise ArtifactError("artifact expired")
        if hashlib.sha256(data).hexdigest() != meta.get("sha256"):
            raise ArtifactError("artifact integrity check failed")

        return data, ArtifactRef(
            handle=handle,
            media_type=str(meta.get("media_type") or "application/octet-stream"),
            size=int(meta.get("size") or len(data)),
            sha256=str(meta.get("sha256")),
        )

    async def delete(self, handle: str, organization_id: UUID) -> None:
        bin_path, meta_path = self._paths(organization_id, handle)

        def _rm() -> None:
            bin_path.unlink(missing_ok=True)
            meta_path.unlink(missing_ok=True)

        await asyncio.to_thread(_rm)

    async def cleanup_expired(self) -> int:
        """Sweep expired artifacts across all orgs. Returns count removed."""
        now = time.time()

        def _sweep() -> int:
            removed = 0
            if not self._base.exists():
                return 0
            for meta_path in self._base.glob("*/*.json"):
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                    if now > float(meta.get("expires_at", 0)):
                        meta_path.with_suffix(".bin").unlink(missing_ok=True)
                        meta_path.unlink(missing_ok=True)
                        removed += 1
                except Exception:
                    # A corrupt sidecar shouldn't halt the sweep.
                    continue
            return removed

        return await asyncio.to_thread(_sweep)


# Module-level singleton (the negotiator/executor share one broker).
artifact_broker = ArtifactBroker()
