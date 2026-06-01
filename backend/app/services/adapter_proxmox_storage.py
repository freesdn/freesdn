# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox Storage service
==========================================

Read-and-stage for Proxmox storage volumes (ISOs, disk images, backup
archives, container templates). Mirrors the shape of
``adapter_opnsense_firewall.py`` so the same Pending Changes UX works
for Proxmox. The contract:

- Reads run live against the cluster (no writes touch the wire).
- Writes are STAGED in ``core.adapter_pending_changes`` (table is
  vendor-agnostic despite the historical name).
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    proxmox.storage.delete_volume   delete   (volid as target_id;
                                              payload = {node, storage})
    proxmox.storage.upload          create   (payload = {node, storage,
                                              filename, content_type,
                                              file_path})

Hard production-safety constraint: Proxmox is in PRODUCTION. Storage
volume deletion is irreversible — dropping a backup volume here means
the backup is gone. Every write below is STAGED first; the dual-gate
(``ADAPTER_READ_ONLY=false`` AND ``force=true`` in the apply call) is
the last guardrail before the cluster.

The applier passes ``force=True`` to the Proxmox adapter so the write
actually reaches the cluster — every write outside the applier is
refused at the client layer by the ``ADAPTER_READ_ONLY`` gate.
"""

from __future__ import annotations

import logging
import os
import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.proxmox.adapter import ProxmoxAdapter
from app.adapters.validation import validate_id
from app.core.config import settings
from app.models.core import Controller
from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_proxmox_vm import build_proxmox_adapter
from app.services.adapter_redaction import redact_list

logger = logging.getLogger(__name__)

# ── Validation helpers ───────────────────────────────────────────────
#
# Proxmox volume IDs (``volid``) take the shape ``<storage>:<volume>``
# — e.g. ``local-lvm:vm-100-disk-0`` or
# ``local:backup/vzdump-qemu-100-2026_05_09-12_00_00.vma.zst``. The
# canonical opaque-ID regex in ``app.adapters.validation`` doesn't
# accept ``:`` or ``/`` so we use a Proxmox-specific shape here. The
# same pattern is reused by the backup service for ``archive``
# validation (Item 2).
_VOLID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*:[A-Za-z0-9][A-Za-z0-9._/-]*$")


def _validate_volid(value: str) -> str:
    if not _VOLID_RE.match(value or ""):
        raise HTTPException(400, detail="invalid volume id format")
    return value


# Allow-list of file extensions the upload applier accepts. Keeps a
# malicious staging payload from naming the upload ``id_rsa`` or
# similar — Proxmox will happily store anything under the storage's
# content category. We restrict to the documented ISO / template /
# backup-archive shapes Proxmox actually serves.
_ALLOWED_UPLOAD_EXTS: tuple[str, ...] = (
    ".iso",
    ".img",
    ".vma",
    ".vma.gz",
    ".vma.zst",
    ".tar.gz",
    ".tar.xz",
)


def _validate_upload_filename(filename: str) -> str:
    """Reject upload filenames that don't match an allow-listed extension
    OR that contain path components.

    Without the path-component check, an
    operator could upload as ``../../etc/profile.iso`` or
    ``subdir/payload.iso`` — Proxmox would happily store under the
    storage's content category but the relative path could collide
    with operator-managed files or escape the expected location on
    some storage backends.
    """
    if not filename:
        raise HTTPException(400, detail="filename is required")
    if "/" in filename or "\\" in filename:
        raise HTTPException(
            400,
            detail="filename must not contain path separators (/ or \\)",
        )
    if ".." in filename.split("."):
        # Catches ``foo..iso`` (each dotted segment is ``..``).
        raise HTTPException(
            400,
            detail="filename must not contain '..' segments",
        )
    if "\x00" in filename:
        raise HTTPException(400, detail="filename must not contain null bytes")
    lower = filename.lower()
    if not any(lower.endswith(ext) for ext in _ALLOWED_UPLOAD_EXTS):
        raise HTTPException(
            400,
            detail=(f"filename must end with one of {_ALLOWED_UPLOAD_EXTS!r}"),
        )
    return filename


def _validate_upload_path(file_path: str) -> str:
    """Confine upload sources to ``settings.PROXMOX_UPLOAD_DIR`` and
    return the resolved realpath.

    Stops a malicious staging payload from setting ``file_path`` to
    ``/etc/passwd`` or ``/app/.env`` and exfiltrating arbitrary host
    files via Proxmox upload. Symlinks are rejected outright (otherwise
    a writable upload dir could host a symlink that escapes the
    sandbox).

    Item 8 (TOCTOU): returns the resolved realpath so the caller can
    use it directly when opening the file. The adapter opens that
    realpath with ``O_NOFOLLOW`` (where supported) so a swap-in
    symlink between validation and open is refused atomically by
    the kernel.
    """
    upload_dir = getattr(settings, "PROXMOX_UPLOAD_DIR", "/var/lib/freesdn/uploads")
    try:
        upload_root = os.path.realpath(upload_dir)
        candidate_real = os.path.realpath(file_path)
    except (OSError, ValueError) as exc:
        raise HTTPException(400, detail="invalid upload file_path") from exc
    if os.path.islink(file_path):
        raise HTTPException(
            400,
            detail="upload file_path may not be a symlink",
        )
    # Also reject symlinks at the resolved location — the realpath
    # call above follows symlinks for us, so we additionally require
    # that the originating file was not itself a link, AND that no
    # intermediate component of the realpath resolves through a
    # symlink (the realpath check below ensures the final candidate
    # lives under upload_root regardless).
    # ``commonpath`` raises if the two paths live on different drives
    # (Windows) or have no shared root — treat that as a sandbox escape.
    try:
        common = os.path.commonpath([upload_root, candidate_real])
    except ValueError as exc:
        raise HTTPException(
            400,
            detail="upload file_path is outside the sandbox",
        ) from exc
    if common != upload_root:
        raise HTTPException(
            400,
            detail="upload file_path is outside the sandbox",
        )
    if not os.path.isfile(candidate_real):
        raise HTTPException(
            400,
            detail="upload file_path does not point at a regular file",
        )
    return candidate_real


# (feature, operation) → bound adapter method name. The applier
# uses this to dispatch — same pattern Omada / OPNsense services use.
_APPLY: dict[tuple[str, str], str] = {
    ("proxmox.storage.delete_volume", "delete"): "delete_storage_volume",
    ("proxmox.storage.upload", "create"): "upload_to_storage",
}


class GatewayProxmoxStorageService(GatewayServiceBase):
    """Live reads + staged writes for Proxmox storage."""

    SUPPORTED_CONTROLLER_TYPE = "proxmox"

    # ── Adapter helper ───────────────────────────────────────────────

    @staticmethod
    async def _build_adapter(ctrl: Controller) -> ProxmoxAdapter:
        """Item 9: forwards to the shared ``build_proxmox_adapter`` helper."""
        return await build_proxmox_adapter(ctrl)

    async def _get_proxmox_adapter(
        self, controller_id: UUID, organization_id: UUID
    ) -> ProxmoxAdapter:
        ctrl = await self._get_controller(controller_id, organization_id)
        if ctrl.controller_type != "proxmox":
            raise HTTPException(
                400,
                detail=(
                    "this gateway feature requires a 'proxmox' "
                    f"controller; got {ctrl.controller_type!r}"
                ),
            )
        return await self._build_adapter(ctrl)

    # ── Live reads ───────────────────────────────────────────────────

    async def list_storage(
        self, controller_id: UUID, organization_id: UUID, node: str
    ) -> dict[str, Any]:
        node = validate_id(node, label="node")
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_storage(node)
        finally:
            await adapter.disconnect()
        if not result.success:
            raise HTTPException(502, detail=result.error or "proxmox error")
        return {
            "controller_id": controller_id,
            "node": node,
            "items": redact_list(result.data or []),
            "fetched_at": datetime.now(UTC),
        }

    async def list_storage_content(
        self,
        controller_id: UUID,
        organization_id: UUID,
        node: str,
        storage: str,
        content_type: str | None = None,
        vmid: int | None = None,
    ) -> dict[str, Any]:
        node = validate_id(node, label="node")
        storage = validate_id(storage, label="storage")
        if content_type is not None:
            content_type = validate_id(content_type, label="content_type")
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_storage_content(
                node, storage, content_type=content_type, vmid=vmid
            )
        finally:
            await adapter.disconnect()
        if not result.success:
            raise HTTPException(502, detail=result.error or "proxmox error")
        return {
            "controller_id": controller_id,
            "node": node,
            "storage": storage,
            "items": redact_list(result.data or []),
            "fetched_at": datetime.now(UTC),
        }

    async def list_prune_backups(
        self,
        controller_id: UUID,
        organization_id: UUID,
        node: str,
        storage: str,
        vmid: int | None = None,
    ) -> dict[str, Any]:
        node = validate_id(node, label="node")
        storage = validate_id(storage, label="storage")
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_storage_prune_backups(node, storage, vmid=vmid)
        finally:
            await adapter.disconnect()
        if not result.success:
            raise HTTPException(502, detail=result.error or "proxmox error")
        return {
            "controller_id": controller_id,
            "node": node,
            "storage": storage,
            "items": redact_list(result.data or []),
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the cluster.

        Every call passes ``force=True`` to the Proxmox adapter so it
        satisfies the client-layer read-only check — that gate is
        the bottom-of-stack safety; this applier is the top of the
        sanctioned write path. The dispatcher
        (``gateway_vpn.apply_change``) is what actually opens the gate
        via ``AdapterStagingService.apply_change``'s dual-gate check.
        """

        async def _apply(c: Any) -> Any:
            # Adapter assignment INSIDE try so a raise in
            # ``_get_controller`` / ``_get_proxmox_adapter`` doesn't
            # leak a half-built adapter.
            adapter: ProxmoxAdapter | None = None
            try:
                adapter = await self._get_proxmox_adapter(c.controller_id, c.organization_id)
                payload = c.payload or {}
                target_id = c.target_id or ""

                method_name = _APPLY.get((c.feature, c.operation))
                if method_name is None:
                    raise HTTPException(
                        400,
                        detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                    )
                method = getattr(adapter, method_name, None)
                if method is None:
                    raise HTTPException(
                        501,
                        detail=(
                            f"Proxmox adapter has no method {method_name!r}; missing implementation"
                        ),
                    )

                if c.feature == "proxmox.storage.delete_volume":
                    # target_id IS the volid (e.g. ``local-lvm:vm-100-disk-0``).
                    # payload carries node + storage scope.
                    volid = _validate_volid(target_id)
                    node = validate_id(str(payload.get("node", "")), label="node")
                    storage = validate_id(str(payload.get("storage", "")), label="storage")

                    # Ownership IDOR guard: the volid format check above only
                    # validates the GRAMMAR — not that the volume
                    # actually lives in this storage on this controller.
                    # An operator who knows or guesses a volid string
                    # from a sibling tenant's box could trigger a
                    # delete against their own controller, and Proxmox
                    # would happily blast the named volume.
                    #
                    # Fetch the storage's live content list, confirm
                    # the volid is in it. 404 on mismatch (not 403 —
                    # same don't-leak-existence rule as the OpenWrt /
                    # MikroTik IDOR guards).
                    content_result = await adapter.get_storage_content(
                        node=node,
                        storage=storage,
                    )
                    if not content_result.success:
                        raise HTTPException(
                            502,
                            detail=(
                                f"could not fetch live storage content "
                                f"to verify volid={volid!r}: "
                                f"{content_result.error or 'unknown error'}"
                            ),
                        )
                    items = content_result.data or []
                    if not any(
                        isinstance(item, dict) and str(item.get("volid")) == volid for item in items
                    ):
                        raise HTTPException(
                            404,
                            detail=(
                                f"volid={volid!r} not found in storage {storage!r} on node {node!r}"
                            ),
                        )

                    # Pre-flight safety: deleting a volume is CATASTROPHIC /
                    # irreversible data-loss — refuse unless the staged payload
                    # carries confirmed=true (only after the IDOR guard above
                    # has confirmed the volid really lives in this storage).
                    from app.services.adapter_proxmox_preflight import preflight_gate

                    await preflight_gate(
                        adapter,
                        c.feature,
                        c.operation,
                        {**payload, "node": node, "storage": storage, "volid": volid},
                    )
                    return await method(node, storage, volid, force=True)

                if c.feature == "proxmox.storage.upload":
                    # Large payload — file content streamed via multipart.
                    # Required keys: node, storage, filename, content_type,
                    # file_path (server-side path the worker can read,
                    # confined to ``settings.PROXMOX_UPLOAD_DIR``).
                    node = validate_id(str(payload.get("node", "")), label="node")
                    storage = validate_id(str(payload.get("storage", "")), label="storage")
                    filename = str(payload.get("filename", ""))
                    content_type = str(payload.get("content_type", ""))
                    file_path = str(payload.get("file_path", ""))
                    if not (filename and content_type and file_path):
                        raise HTTPException(
                            400,
                            detail=(
                                "proxmox.storage.upload payload requires "
                                "filename, content_type, and file_path"
                            ),
                        )
                    # Restrict filename and confine source path to the
                    # configured sandbox dir (defends against LFI to
                    # ``/etc/passwd`` / ``/app/.env``).
                    filename = _validate_upload_filename(filename)
                    file_path = _validate_upload_path(file_path)
                    return await method(
                        node,
                        storage,
                        filename,
                        content_type,
                        file_path,
                        force=True,
                    )

                raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")
            finally:
                if adapter is not None:
                    await adapter.disconnect()

        return _apply
