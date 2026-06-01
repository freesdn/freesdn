# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox Backup service
=========================================

Read-and-stage for Proxmox vzdump backup configuration: scheduled
backup jobs, ad-hoc runs, restore-from-archive, and retention pruning.
Mirrors ``adapter_opnsense_firewall.py``: live reads, staged writes,
shared apply dispatcher.

Hard production-safety constraint: Proxmox is in PRODUCTION. Two
operations here are catastrophic:

* ``proxmox.backup.restore`` overwrites a VM/CT with an archive — the
  on-disk state of the target is replaced.
* ``proxmox.backup.prune`` is irreversible — pruned backup files are
  gone.

Every write is STAGED first; the dual-gate (``ADAPTER_READ_ONLY=false``
AND ``force=true`` in the apply call) is the last guardrail.

Supported features::

    proxmox.backup.job        create | update | delete  (target_id = jobid)
    proxmox.backup.run        create  (ad-hoc vzdump)
    proxmox.backup.restore    create  — CATASTROPHIC (overwrites VM/CT)
    proxmox.backup.prune      create  — IRREVERSIBLE (drops backup files)

Reads:

    list_jobs() — only read method exposed by the adapter.

The applier passes ``force=True`` to the Proxmox adapter so the write
actually reaches the cluster — every write outside the applier is
refused at the client layer by the ``ADAPTER_READ_ONLY`` gate.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.proxmox.adapter import ProxmoxAdapter
from app.adapters.validation import validate_id
from app.models.core import Controller
from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_proxmox_vm import build_proxmox_adapter
from app.services.adapter_redaction import redact_list

logger = logging.getLogger(__name__)

# Same Proxmox volid grammar the storage service uses (Item 2).
# ``<storage>:<volume>`` shape — restoring an archive specified as
# anything else (``/etc/passwd`` / ``http://...``) is rejected here
# before the adapter ever sees it.
_VOLID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*:[A-Za-z0-9][A-Za-z0-9._/-]*$")


def _validate_archive(value: str) -> str:
    value = value or ""
    if not _VOLID_RE.match(value):
        raise HTTPException(
            400,
            detail=("invalid archive volume id — expected <storage>:<path> shape"),
        )
    # FILES-PROXMOX-ARCHIVE-DOTDOT: the volid grammar permits '.' and '/', so the
    # shape check alone accepts e.g. ``local:backup/../../etc/shadow``. Reject any
    # traversal / empty path segment, backslashes, and percent-encoding before the
    # value is interpolated into the Proxmox restore archive/ostemplate.
    _storage, _, path = value.partition(":")
    if "\\" in value or "%" in value or any(seg in ("", ".", "..") for seg in path.split("/")):
        raise HTTPException(
            400,
            detail="invalid archive path — traversal or empty path segments are not allowed",
        )
    return value


# Allow-list of payload keys the applier passes through to the
# adapter's ``create_backup_job`` / ``update_backup_job`` calls. Stops a
# malicious staging payload from setting Proxmox-internal flags
# (``script``, ``mailto`` could be inert but ``script`` would let an
# operator run arbitrary shell on the cluster). Update this set when
# Proxmox documents new safe vzdump options.
_BACKUP_JOB_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        "storage",
        "schedule",
        "vmid",
        "mode",
        "compress",
        "node",
        "enabled",
        "mailto",
        "mailnotification",
    }
)


def _filter_backup_job_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Drop unknown/unsafe keys from a backup-job create/update payload.

    ``force`` collides with the staging applier's keyword-only
    ``force=True`` so it's stripped here for safety even though it
    isn't in the allow-list.
    """
    return {k: v for k, v in payload.items() if k in _BACKUP_JOB_ALLOWED_KEYS}


# (feature, operation) → bound adapter method name. The applier
# uses this to dispatch — same pattern Omada / OPNsense services use.
_APPLY: dict[tuple[str, str], str] = {
    ("proxmox.backup.job", "create"): "create_backup_job",
    ("proxmox.backup.job", "update"): "update_backup_job",
    ("proxmox.backup.job", "delete"): "delete_backup_job",
    ("proxmox.backup.run", "create"): "run_backup",
    ("proxmox.backup.restore", "create"): "restore_backup",
    ("proxmox.backup.prune", "create"): "prune_backups",
}


class GatewayProxmoxBackupService(GatewayServiceBase):
    """Live reads + staged writes for Proxmox backup config."""

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

    async def list_jobs(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        adapter = await self._get_proxmox_adapter(controller_id, organization_id)
        try:
            result = await adapter.get_backup_jobs()
        finally:
            await adapter.disconnect()
        if not result.success:
            raise HTTPException(502, detail=result.error or "proxmox error")
        # ProxmoxBackupJob dataclasses → dicts for JSON response.
        items: list[dict[str, Any]] = []
        for job in result.data or []:
            if hasattr(job, "__dict__"):
                items.append(dict(job.__dict__))
            elif isinstance(job, dict):
                items.append(job)
        return {
            "controller_id": controller_id,
            "items": redact_list(items),
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the cluster.

        Every call passes ``force=True`` to the Proxmox adapter so it
        satisfies the client-layer read-only check.
        """

        async def _apply(c: Any) -> Any:
            adapter: ProxmoxAdapter | None = None
            try:
                adapter = await self._get_proxmox_adapter(c.controller_id, c.organization_id)
                payload = dict(c.payload or {})
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

                # CATASTROPHIC-by-default gate: restore (overwrites a guest), prune
                # (irreversible backup delete), and ANY backup-job delete are blocked
                # unless the staged payload carries confirmed=true. Was ungated — only
                # the env+force dual-gate stood in the way (sweep highs).
                from app.services.adapter_proxmox_preflight import preflight_gate

                await preflight_gate(adapter, c.feature, c.operation, payload)

                # restore (overwrites a VM/CT) and prune (drops backup files) are
                # documented above as catastrophic/irreversible, but the central
                # classifier currently rates them DESTRUCTIVE — and preflight_gate
                # only enforces confirmed=true for CATASTROPHIC ops. Without this
                # explicit guard the confirmation requirement would NOT actually be
                # enforced for these two irreversible operations. Use the strict
                # payload_confirmed helper (NOT bool(), which treats "false" as true).
                if c.feature in ("proxmox.backup.restore", "proxmox.backup.prune"):
                    from app.services.adapter_preflight_common import payload_confirmed

                    if not payload_confirmed(payload):
                        raise HTTPException(
                            status_code=409,
                            detail=(
                                f"{c.feature} is irreversible "
                                "(restore overwrites the guest; prune permanently "
                                "deletes backup files); re-stage with confirmed=true "
                                "to proceed"
                            ),
                        )

                # ── Backup jobs ────────────────────────────────────────
                if c.feature == "proxmox.backup.job":
                    if c.operation == "create":
                        # Allow-list payload keys so a malicious caller
                        # can't smuggle ``script`` (which would run
                        # arbitrary shell on the cluster as root).
                        kwargs = _filter_backup_job_payload(payload)
                        return await method(force=True, **kwargs)
                    if c.operation == "update":
                        job_id = validate_id(target_id, label="job_id")
                        kwargs = _filter_backup_job_payload(payload)
                        return await method(job_id, force=True, **kwargs)
                    if c.operation == "delete":
                        job_id = validate_id(target_id, label="job_id")
                        return await method(job_id, force=True)

                # ── Ad-hoc backup ──────────────────────────────────────
                if c.feature == "proxmox.backup.run":
                    node = validate_id(str(payload.get("node", "")), label="node")
                    vmid = int(payload.get("vmid", 0))
                    storage = validate_id(str(payload.get("storage", "")), label="storage")
                    mode = str(payload.get("mode", "snapshot"))
                    compress = str(payload.get("compress", "zstd"))
                    if vmid <= 0:
                        raise HTTPException(400, detail="proxmox.backup.run requires vmid > 0")
                    return await method(
                        node,
                        vmid,
                        storage,
                        mode=mode,
                        compress=compress,
                        force=True,
                    )

                # ── Restore (CATASTROPHIC) ─────────────────────────────
                if c.feature == "proxmox.backup.restore":
                    node = validate_id(str(payload.get("node", "")), label="node")
                    vm_type = str(payload.get("vm_type", "qemu"))
                    if vm_type not in ("qemu", "lxc"):
                        raise HTTPException(
                            400,
                            detail=("proxmox.backup.restore vm_type must be 'qemu' or 'lxc'"),
                        )
                    archive = str(payload.get("archive", ""))
                    if not archive:
                        raise HTTPException(
                            400,
                            detail="proxmox.backup.restore requires archive",
                        )
                    # Restrict the archive ref to the documented Proxmox
                    # ``<storage>:<path>`` volid grammar — without this,
                    # an operator could feed arbitrary host paths
                    # (``/etc/shadow``) or remote URLs into the restore
                    # call.
                    archive = _validate_archive(archive)
                    vmid = int(payload.get("vmid", 0))
                    if vmid <= 0:
                        raise HTTPException(400, detail="proxmox.backup.restore requires vmid > 0")
                    storage = payload.get("storage")
                    if storage is not None:
                        storage = validate_id(str(storage), label="storage")
                    start = bool(payload.get("start", False))
                    unique = bool(payload.get("unique", True))
                    return await method(
                        node,
                        vm_type,
                        archive,
                        vmid,
                        storage=storage,
                        start=start,
                        unique=unique,
                        force=True,
                    )

                # ── Prune (IRREVERSIBLE) ───────────────────────────────
                if c.feature == "proxmox.backup.prune":
                    node = validate_id(str(payload.get("node", "")), label="node")
                    storage = validate_id(str(payload.get("storage", "")), label="storage")
                    # Build the keep-* kwargs only when present so the
                    # adapter omits the corresponding query params.
                    kwargs: dict[str, Any] = {}
                    for key in (
                        "keep_last",
                        "keep_hourly",
                        "keep_daily",
                        "keep_weekly",
                        "keep_monthly",
                        "keep_yearly",
                    ):
                        if key in payload and payload[key] is not None:
                            kwargs[key] = int(payload[key])
                    if "vmid" in payload and payload["vmid"] is not None:
                        kwargs["vmid"] = int(payload["vmid"])
                    return await method(node, storage, **kwargs, force=True)

                raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")
            finally:
                if adapter is not None:
                    await adapter.disconnect()

        return _apply
