# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox Snapshot service
============================================

Read-and-stage for Proxmox VM/CT snapshots. Mirrors the shape of
``adapter_proxmox_vm.py`` so the same Pending Changes UX works for
snapshots.

Production-safety contract:

- Reads run live against the Proxmox cluster.
- Writes are STAGED in ``core.adapter_pending_changes``.
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Snapshot writes are particularly dangerous:

* ``rollback`` discards every change since the snapshot was taken —
  catastrophic, irreversible data loss.
* ``delete`` removes the only restore path for that snapshot.

The same VM/CT distinction the adapter exposes (``vm_type="qemu"`` vs
``"lxc"``) is carried through the staging payload.

Supported features::

    proxmox.snapshot.create    create
    proxmox.snapshot.delete    delete  (irreversible — removes restore path)
    proxmox.snapshot.rollback  create  (CATASTROPHIC — discards state since snapshot)
"""

from __future__ import annotations

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

_VALID_VM_TYPES = ("qemu", "lxc")

_APPLY: dict[tuple[str, str], str] = {
    ("proxmox.snapshot.create", "create"): "create_snapshot",
    # delete is irreversible — once gone, the snapshot's restore path
    # is gone with it.
    ("proxmox.snapshot.delete", "delete"): "delete_snapshot",
    # CATASTROPHIC — rollback discards every change since the snapshot
    # was taken. The dual-gate is the last guardrail.
    ("proxmox.snapshot.rollback", "create"): "rollback_snapshot",
}


class GatewayProxmoxSnapshotService(GatewayServiceBase):
    """Live reads + staged writes for Proxmox VM/CT snapshots."""

    SUPPORTED_CONTROLLER_TYPE = "proxmox"

    # ── Adapter resolution ───────────────────────────────────────────

    @staticmethod
    async def _get_proxmox_adapter(controller: Controller) -> ProxmoxAdapter:
        """Item 9: forwards to the shared ``build_proxmox_adapter`` helper."""
        return await build_proxmox_adapter(controller)

    # ── Live reads ───────────────────────────────────────────────────

    async def list_snapshots(
        self,
        controller_id: UUID,
        organization_id: UUID,
        node: str,
        vmid: int,
        vm_type: str,
    ) -> dict[str, Any]:
        node = validate_id(node, label="node")
        vm_type = self._validate_vm_type(vm_type)
        ctrl = await self._get_controller(controller_id, organization_id)
        adapter = await self._get_proxmox_adapter(ctrl)
        try:
            result = await adapter.get_snapshots(node, vmid, vm_type)
        finally:
            await adapter.disconnect()
        if not result.success:
            raise HTTPException(502, detail=result.error or "proxmox error")
        return {
            "controller_id": controller_id,
            "node": node,
            "vmid": vmid,
            "vm_type": vm_type,
            "items": redact_list(result.data or []),
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to Proxmox."""

        async def _apply(c: Any) -> Any:
            ctrl = await self._get_controller(c.controller_id, c.organization_id)
            adapter = await self._get_proxmox_adapter(ctrl)
            try:
                payload = c.payload or {}
                target_id = c.target_id

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

                node = validate_id(str(payload.get("node", "")), label="node")
                vmid = self._coerce_vmid(payload)
                vm_type = self._validate_vm_type(str(payload.get("vm_type", "qemu")))

                f = c.feature
                if f == "proxmox.snapshot.create":
                    snapname = validate_id(
                        str(payload.get("snapname", "")),
                        label="snapname",
                    )
                    return await method(
                        node,
                        vmid,
                        snapname,
                        description=str(payload.get("description", "")),
                        vm_type=vm_type,
                        vmstate=bool(payload.get("vmstate", False)),
                        force=True,
                    )
                if f == "proxmox.snapshot.delete":
                    # target_id is the snapname for delete (per the
                    # service contract). Validate to defend against
                    # path-traversal in the URL segment.
                    snapname_raw = target_id if target_id is not None else payload.get("snapname")
                    if snapname_raw is None:
                        raise HTTPException(400, detail="snapname is required")
                    snapname = validate_id(str(snapname_raw), label="snapname")
                    # Pre-flight safety: delete is IRREVERSIBLE — it removes
                    # the only restore path for the snapshot. Run the shared
                    # impact assessment AND require an explicit confirmed=true
                    # in the staged payload before the device write, mirroring
                    # rollback. (The preflight table classifies delete as
                    # DESTRUCTIVE, which assess()/gate() do not force-confirm,
                    # so we enforce confirmation here for the irreversible op.)
                    from app.services.adapter_proxmox_preflight import preflight_gate

                    await preflight_gate(
                        adapter,
                        c.feature,
                        c.operation,
                        {**payload, "node": node, "vmid": vmid, "snapname": snapname},
                    )
                    from app.services.adapter_preflight_common import payload_confirmed

                    if not payload_confirmed(payload):
                        raise HTTPException(
                            status_code=409,
                            detail=(
                                f"{c.feature} is irreversible (removes the only "
                                "restore path for this snapshot); re-stage with "
                                "confirmed=true to proceed"
                            ),
                        )
                    return await method(node, vmid, snapname, vm_type, force=True)
                if f == "proxmox.snapshot.rollback":
                    snapname_raw = target_id if target_id is not None else payload.get("snapname")
                    if snapname_raw is None:
                        raise HTTPException(400, detail="snapname is required")
                    snapname = validate_id(str(snapname_raw), label="snapname")
                    # Pre-flight safety: rollback is CATASTROPHIC (discards all
                    # state since the snapshot) — refuse unless the staged
                    # payload carries confirmed=true.
                    from app.services.adapter_proxmox_preflight import preflight_gate

                    await preflight_gate(
                        adapter,
                        c.feature,
                        c.operation,
                        {**payload, "node": node, "vmid": vmid, "snapname": snapname},
                    )
                    return await method(node, vmid, snapname, vm_type, force=True)
                raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")
            finally:
                await adapter.disconnect()

        return _apply

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _coerce_vmid(payload: dict[str, Any]) -> int:
        """Snapshot ops always carry vmid in payload (target_id is the
        snapname for delete, not the vmid). Bound-check (Item 18)."""
        candidate = payload.get("vmid")
        if candidate is None:
            raise HTTPException(400, detail="vmid is required in payload")
        try:
            vmid = int(str(candidate))
        except (TypeError, ValueError) as exc:
            raise HTTPException(400, detail="vmid must be an integer") from exc
        if vmid < 100 or vmid > 999_999_999:
            raise HTTPException(400, detail="vmid out of range (100..999999999)")
        return vmid

    @staticmethod
    def _validate_vm_type(vm_type: str) -> str:
        if vm_type not in _VALID_VM_TYPES:
            raise HTTPException(
                400,
                detail=(f"vm_type must be one of {_VALID_VM_TYPES}; got {vm_type!r}"),
            )
        return vm_type
