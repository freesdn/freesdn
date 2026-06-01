# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Pre-flight safety + impact assessment for Proxmox staged writes.

Before a staged Proxmox change is applied (or for a read-only dry-run preview),
this classifies the operation's destructiveness and runs READ-ONLY device checks
to surface impact — e.g. "this node has 12 running guests that will be
interrupted", "this VM is currently running", "rollback discards changes since
the snapshot". A CATASTROPHIC/irreversible operation is BLOCKED unless the staged
payload carries an explicit ``confirmed=true``, so a mission-critical write can
never be applied blind or by a stray automation.

Device-agnostic by design: the applier passes the connected adapter; all checks
are read-only (get_cluster_resources) and best-effort (a read failure degrades to
a warning, never a false block).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from fastapi import HTTPException


class Risk(StrEnum):
    SAFE = "safe"
    DESTRUCTIVE = "destructive"  # disrupts a running workload (recoverable)
    CATASTROPHIC = "catastrophic"  # irreversible / data-loss / cluster-wide


#: Per-feature base risk. Anything not listed with operation=="delete" defaults
#: to CATASTROPHIC; everything else (create/start/resume/clone/config/
#: snapshot.create/migrate-in…) is SAFE.
_FEATURE_RISK: dict[str, Risk] = {
    "proxmox.vm.destroy": Risk.CATASTROPHIC,
    "proxmox.vm.stop": Risk.DESTRUCTIVE,
    "proxmox.vm.shutdown": Risk.DESTRUCTIVE,
    "proxmox.vm.reboot": Risk.DESTRUCTIVE,
    "proxmox.vm.suspend": Risk.DESTRUCTIVE,
    "proxmox.vm.migrate": Risk.DESTRUCTIVE,
    # operation verb is "create"/generic so classify()'s delete-default never
    # catches these — pin them explicitly. guest_agent_exec runs arbitrary code
    # inside the guest; guest_agent_file_write writes arbitrary guest files;
    # remote_migrate ships the VM to another cluster and (delete_source default
    # True) destroys the source — all irreversible / mission-critical, so they
    # MUST require an explicit confirmed=true and the site_admin RBAC tier.
    "proxmox.vm.guest_agent_exec": Risk.CATASTROPHIC,
    "proxmox.vm.guest_agent_file_write": Risk.CATASTROPHIC,
    "proxmox.vm.remote_migrate": Risk.CATASTROPHIC,
    # the LXC sibling of remote_migrate (operation "create", so the
    # delete-default never catches it) also ships the container to another
    # cluster and destroys the source (delete_source default True). Pin it
    # CATASTROPHIC to reach parity with proxmox.vm.remote_migrate.
    "proxmox.container.remote_migrate": Risk.CATASTROPHIC,
    "proxmox.node.reboot": Risk.CATASTROPHIC,
    "proxmox.node.shutdown": Risk.CATASTROPHIC,
    # replacing the node TLS cert can lock the operator out of
    # pveproxy (bad cert/key). operation is "create", so pin it explicitly so the
    # staged apply path demands an explicit confirmed=true. (certificate_delete is
    # operation "delete" → already catastrophic via classify()'s delete-default.)
    "proxmox.node.certificate_upload": Risk.CATASTROPHIC,
    "proxmox.snapshot.rollback": Risk.CATASTROPHIC,
    "proxmox.snapshot.delete": Risk.DESTRUCTIVE,
    "proxmox.storage.delete_volume": Risk.CATASTROPHIC,
    "proxmox.backup.restore": Risk.CATASTROPHIC,  # overwrites VM/CT on-disk state
    "proxmox.backup.prune": Risk.CATASTROPHIC,  # irreversible: pruned files are gone
}


def classify(feature: str, operation: str) -> Risk:
    """Base destructiveness of a (feature, operation) pair."""
    if feature in _FEATURE_RISK:
        return _FEATURE_RISK[feature]
    if (operation or "").lower() == "delete":
        return Risk.CATASTROPHIC  # any unclassified delete is catastrophic-by-default
    return Risk.SAFE


@dataclass
class PreflightResult:
    feature: str
    operation: str
    risk: Risk
    warnings: list[str] = field(default_factory=list)
    impact: dict[str, Any] = field(default_factory=dict)

    @property
    def requires_confirmation(self) -> bool:
        return self.risk is Risk.CATASTROPHIC

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature": self.feature,
            "operation": self.operation,
            "risk": self.risk.value,
            "warnings": self.warnings,
            "impact": self.impact,
            "requires_confirmation": self.requires_confirmation,
        }


async def assess(
    feature: str, operation: str, payload: dict[str, Any] | None, adapter: Any | None = None
) -> PreflightResult:
    """Classify + (if an adapter is given) run READ-ONLY device impact checks."""
    payload = payload or {}
    res = PreflightResult(feature=feature, operation=operation, risk=classify(feature, operation))

    if res.risk is Risk.CATASTROPHIC:
        res.warnings.append(f"{feature} is a CATASTROPHIC / irreversible operation")
    elif res.risk is Risk.DESTRUCTIVE:
        res.warnings.append(f"{feature} disrupts a running workload")
    if feature == "proxmox.snapshot.rollback":
        res.warnings.append("rollback discards ALL changes made since the snapshot (data loss)")

    if adapter is not None:
        try:
            if feature in ("proxmox.node.reboot", "proxmox.node.shutdown"):
                node = payload.get("node")
                r = await adapter.get_cluster_resources("vm")
                if getattr(r, "success", False):
                    running = [
                        g
                        for g in (r.data or [])
                        if g.get("node") == node and g.get("status") == "running"
                    ]
                    if running:
                        res.impact["running_guests"] = len(running)
                        res.warnings.append(
                            f"node {node!r} has {len(running)} running guest(s) that will be interrupted"
                        )
            elif feature in (
                "proxmox.vm.destroy",
                "proxmox.vm.stop",
                "proxmox.vm.shutdown",
                "proxmox.vm.migrate",
            ):
                vmid = str(payload.get("vmid") or payload.get("target_id") or "")
                r = await adapter.get_cluster_resources("vm")
                if getattr(r, "success", False):
                    g = next((x for x in (r.data or []) if str(x.get("vmid")) == vmid), None)
                    if g:
                        res.impact["vm_status"] = g.get("status")
                        res.impact["vm_name"] = g.get("name")
                        if g.get("status") == "running":
                            res.warnings.append(f"VM {vmid} ({g.get('name')}) is currently RUNNING")
            elif feature == "proxmox.storage.delete_volume":
                node = payload.get("node")
                storage = payload.get("storage")
                volid = str(payload.get("volid") or payload.get("target_id") or "")
                if node and storage:
                    r = await adapter.get_storage_content(node=node, storage=storage)
                    if getattr(r, "success", False):
                        v = next((x for x in (r.data or []) if str(x.get("volid")) == volid), None)
                        if v is not None:
                            size = v.get("size")
                            res.impact["volume_size"] = size
                            res.impact["volume_format"] = v.get("format")
                            res.impact["volume_used_by"] = v.get("vmid")
                            res.warnings.append(
                                f"volume {volid!r} "
                                + (f"({size} bytes) " if size else "")
                                + "will be permanently deleted (irreversible)"
                            )
        except Exception:  # noqa: BLE001 — a read failure must NEVER false-block a write
            res.warnings.append("live pre-flight checks incomplete (device read failed)")

    return res


def gate(result: PreflightResult, payload: dict[str, Any] | None) -> None:
    """Raise 409 if a CATASTROPHIC op lacks explicit ``confirmed=true`` in payload."""
    from app.services.adapter_preflight_common import payload_confirmed

    if result.requires_confirmation and not payload_confirmed(payload):
        raise HTTPException(
            status_code=409,
            detail=(
                f"{result.feature} is catastrophic ("
                + "; ".join(result.warnings)
                + "); re-stage with confirmed=true to proceed"
            ),
        )


async def preflight_gate(
    adapter: Any, feature: str, operation: str, payload: dict[str, Any] | None
) -> PreflightResult:
    """assess + gate — call inside an applier just before the device write."""
    result = await assess(feature, operation, payload, adapter=adapter)
    gate(result, payload)
    return result


def enforce_proxmox_preflight(
    feature: str | None, operation: str | None, payload: dict[str, Any] | None
) -> None:
    """Central runtime gate for Proxmox staged changes (NO device read).

    No-op for non-``proxmox.*`` features so it can sit unconditionally on the
    shared apply chokepoint (``adapter_staging.apply_change``). For a ``proxmox.*``
    change it classifies and raises 409 if the op is CATASTROPHIC and the staged
    payload lacks ``confirmed=true``.

    This is the SINGLE sanctioned confirmation chokepoint for Proxmox, matching the
    other vendors. The per-applier ``preflight_gate`` calls remain as device-aware
    (assess) defense-in-depth, but an applier that forgets to call one can no
    longer let a catastrophic op apply unconfirmed, even if an individual applier
    omits its own gate.
    """
    if not (feature or "").startswith("proxmox."):
        return
    from app.services.adapter_preflight_common import payload_confirmed

    catastrophic = classify(feature or "", operation or "") is Risk.CATASTROPHIC
    if catastrophic and not payload_confirmed(payload):
        raise HTTPException(
            status_code=409,
            detail=(
                f"{feature} ({operation}) is a catastrophic / irreversible Proxmox "
                "operation; re-stage the change with confirmed=true to proceed"
            ),
        )
