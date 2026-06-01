# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — Gateway TrueNAS Storage service (staged blob writes).

Read-and-stage for the Fabric ``storage.store_blob`` operation: writing a blob
(a camera snapshot, a log batch) into a ZFS dataset on a TrueNAS appliance.

Production-safety contract (identical to the Proxmox/MikroTik services):

- The TrueNAS adapter is read-only by default; the write method refuses unless
  ``force=True``.
- A Fabric write is STAGED in ``adapter_pending_changes`` by the executor — it
  is never applied inline.
- Apply runs through the shared dispatcher (``adapter_omada_vpn.apply_change``)
  behind the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``); only
  then is ``build_applier`` invoked and ``force=True`` passed to the adapter.

The blob bytes do NOT live in the staged row. The executor copies them to the
durable artifact store and stamps a small reference (``durable_token`` +
``sha256`` + ``size``) into ``payload["_artifact"]``; this applier reads them
back and re-verifies the sha256 before uploading.

Supported features::

    storage.store_blob   create   → TrueNASAdapter.upload_file
"""

from __future__ import annotations

import contextlib
import re
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.truenas.adapter import TrueNASAdapter
from app.models.core import Controller
from app.services.adapter_base import GatewayServiceBase

_APPLY: dict[tuple[str, str], str] = {
    ("storage.store_blob", "create"): "upload_file",
}

# Defensive payload validation (the adapter re-validates as a backstop). Paths
# must be under /mnt with safe segments; filenames carry no separators.
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_MAX_PATH = 1024
_MAX_FILENAME = 255


def _validate_dataset_path(path: str) -> str:
    p = (path or "").strip().rstrip("/")
    if not p or len(p) > _MAX_PATH or not p.startswith("/mnt/") or ".." in p:
        raise HTTPException(400, detail=f"dataset_path must be a safe /mnt path: {path!r}")
    segments = p[len("/mnt/") :].split("/")
    if not segments or any(not _SEGMENT_RE.match(seg) for seg in segments):
        raise HTTPException(400, detail=f"dataset_path has an unsafe segment: {path!r}")
    return p


def _validate_filename(name: str) -> str:
    n = (name or "").strip()
    if (
        not n
        or len(n) > _MAX_FILENAME
        or "/" in n
        or "\\" in n
        or ".." in n
        or not _SEGMENT_RE.match(n)
    ):
        raise HTTPException(400, detail=f"invalid filename: {name!r}")
    return n


async def build_truenas_adapter(ctrl: Controller) -> TrueNASAdapter:
    """Build a connected TrueNASAdapter from a controller record.

    The generic ``_get_client`` pool path maps only username/password, never the
    API key — so storage builds its own adapter, mirroring ``build_proxmox_adapter``.
    ``Controller.password`` already auto-decrypts the API key from ``config``.
    """
    adapter = TrueNASAdapter(
        host=ctrl.host,
        username=ctrl.username or "",
        api_key=ctrl.password or "",
        port=ctrl.port or 443,
        verify_ssl=getattr(ctrl, "verify_ssl", False),
    )
    connected = await adapter.connect()
    if not connected:
        raise HTTPException(502, detail=f"failed to connect to TrueNAS at {ctrl.host}")
    return adapter


class GatewayTrueNASStorageService(GatewayServiceBase):
    """Staged blob writes to TrueNAS datasets."""

    SUPPORTED_CONTROLLER_TYPE = "truenas"

    @staticmethod
    async def _get_truenas_adapter(controller: Controller) -> TrueNASAdapter:
        return await build_truenas_adapter(controller)

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that uploads the staged blob to TrueNAS."""

        async def _apply(c: Any) -> Any:
            ctrl = await self._get_controller(c.controller_id, c.organization_id)
            adapter = await self._get_truenas_adapter(ctrl)
            try:
                method_name = _APPLY.get((c.feature, c.operation))
                if method_name is None:
                    raise HTTPException(
                        400,
                        detail=f"no applier for feature={c.feature!r} operation={c.operation!r}",
                    )
                payload = c.payload or {}
                dataset_path = _validate_dataset_path(str(payload.get("dataset_path", "")))
                filename = _validate_filename(str(payload.get("filename", "")))

                art = payload.get("_artifact")
                if not isinstance(art, dict) or not art.get("durable_token"):
                    raise HTTPException(400, detail="staged change carries no blob reference")

                from app.core.fabric.durable_store import (
                    DurableArtifactError,
                    durable_store,
                )

                try:
                    blob = await durable_store.get(
                        str(art["durable_token"]),
                        c.organization_id,
                        expected_sha256=art.get("sha256"),
                    )
                except DurableArtifactError as exc:
                    raise HTTPException(409, detail=f"staged blob unavailable: {exc}") from exc

                result = await adapter.upload_file(
                    dataset_path=dataset_path,
                    filename=filename,
                    blob=blob,
                    force=True,
                )
                # Best-effort cleanup: the blob is now durable on the appliance.
                with contextlib.suppress(Exception):
                    await durable_store.delete(str(art["durable_token"]), c.organization_id)
                return result
            finally:
                await adapter.disconnect()

        return _apply

    @staticmethod
    def store_path(pool_or_dataset_mountpoint: str, *, organization_id: UUID) -> str:
        """Suggested destination dir for org footage: ``<mountpoint>/freesdn/<org>``.

        Helper for callers/UX that want a conventional layout; the operation
        accepts any safe ``/mnt`` ``dataset_path`` the operator chooses.
        """
        base = pool_or_dataset_mountpoint.rstrip("/")
        return f"{base}/freesdn/{organization_id}"
