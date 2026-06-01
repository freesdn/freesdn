# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Pre-flight safety + impact assessment for Omada staged writes.

Omada is the owner's LIVE PRODUCTION network core (OC300 + EAP670s + switches).
Its write path is already protected by the default-deny dual-gate
(``ADAPTER_READ_ONLY`` env lock + per-call ``force=true``) and the client-layer
``_request`` apply-window gate, but that gate is binary: once an operator
legitimately lowers it to push a create-only change (e.g. a new SSID), the *same*
unlocked session could also apply a staged firmware flash, a device
factory-reset/forget, a controller-config restore, or a rule/VPN/NAT/template
delete.

This module adds the missing op-aware checkpoint, mirroring
``adapter_opnsense_preflight`` / ``adapter_proxmox_preflight``: it classifies a
staged change's destructiveness and BLOCKS a CATASTROPHIC / irreversible
operation unless the staged payload carries an explicit ``confirmed=true``. Per
the owner's rule the catastrophic set is **irreversible device/controller ops
(factory-reset, forget/unadopt, firmware upgrade, backup restore) + ALL deletes**
(a stray WLAN/VPN/NAT/route/ACL delete on the production network can cut access
just as surely as a reboot). DESTRUCTIVE ops (bulk device reboot, client kick,
SSID disable) warn but are not blocked.

Scoping: unlike OPNsense, Omada staged features are **bare** (``bulk.device.forget``,
``firmware.upgrade``, ``system.backup.restore`` — no ``omada.`` prefix, a legacy
of Omada being the original adapter). So the central gate cannot key on a feature
prefix; :func:`enforce_omada_preflight` is therefore scoped by the change's
**controller type** (resolved at the single sanctioned apply chokepoint in
``AdapterStagingService.apply_change``) and is a no-op for any non-Omada
controller. This covers every Omada feature — across bulk/firmware/system/wifi/
vpn/firewall/hotspot/switch services — with no per-applier wiring to forget.
``assess`` (with a connected, read-only adapter) additionally surfaces device
impact for the dry-run preview; all such checks are best-effort and a read
failure degrades to a warning, never a false block.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from fastapi import HTTPException


class Risk(StrEnum):
    SAFE = "safe"
    DESTRUCTIVE = "destructive"  # disrupts a running workload (recoverable)
    CATASTROPHIC = "catastrophic"  # irreversible / data-loss / device-wipe / whole-config


#: Features that are CATASTROPHIC regardless of their staging ``operation``.
#: These are registered with operation=="create" in the per-service ``_APPLY``
#: tables, so they MUST be caught by FEATURE name, not just by operation=="delete".
_CATASTROPHIC_FEATURES: frozenset[str] = frozenset(
    {
        "bulk.device.factory_reset",  # wipes device(s) to factory defaults — irreversible
        "bulk.device.forget",  # unadopts device(s) from the controller (config dropped)
        "firmware.upgrade",  # flashes device firmware — brick risk, not undoable
        "firmware.upgrade.batch",  # batched firmware flash across many devices
        "system.backup.restore",  # replaces the ENTIRE controller configuration
    }
)

#: Features that disrupt a running workload but are recoverable → warn, not block.
_DESTRUCTIVE_FEATURES: frozenset[str] = frozenset(
    {
        "bulk.device.reboot",  # network blip across rebooted APs/switches
        "bulk.client.kick",  # forcibly disconnects clients (they re-associate)
        "bulk.ssid.set_state",  # disabling an SSID drops everyone on it
    }
)


def classify(feature: str, operation: str) -> Risk:
    """Base destructiveness of an Omada ``(feature, operation)`` pair.

    Owner rule: irreversible device/controller ops + ANY delete require
    confirmation (CATASTROPHIC). Caller must already have established that this
    is an Omada change (see :func:`enforce_omada_preflight`).
    """
    if feature in _CATASTROPHIC_FEATURES:
        return Risk.CATASTROPHIC
    if (operation or "").lower() == "delete":
        return Risk.CATASTROPHIC  # every Omada delete is block-unless-confirmed
    if feature in _DESTRUCTIVE_FEATURES:
        return Risk.DESTRUCTIVE
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


def _target_count(payload: dict[str, Any]) -> int | None:
    """Best-effort count of devices/clients a bulk op targets (for the preview)."""
    for key in ("device_ids", "macs", "client_macs", "target_ids", "devices"):
        v = payload.get(key)
        if isinstance(v, (list, tuple, set)):
            return len(v)
    return None


async def assess(
    feature: str, operation: str, payload: dict[str, Any] | None, adapter: Any | None = None
) -> PreflightResult:
    """Classify + (if a read-only adapter is given) surface device impact.

    Used both by the runtime gate (classification only) and the dry-run preview
    (classification + best-effort live impact). Every device read is best-effort:
    a failure appends a warning and NEVER raises (a read must not false-block).
    """
    payload = payload or {}
    res = PreflightResult(feature=feature, operation=operation, risk=classify(feature, operation))

    if res.risk is Risk.CATASTROPHIC:
        res.warnings.append(f"{feature} ({operation}) is a CATASTROPHIC / irreversible operation")
    elif res.risk is Risk.DESTRUCTIVE:
        res.warnings.append(f"{feature} ({operation}) disrupts a running workload")

    if feature in ("bulk.device.factory_reset", "bulk.device.forget"):
        n = _target_count(payload)
        res.warnings.append(
            f"this {'factory-resets' if 'factory' in feature else 'unadopts'} "
            f"{n if n is not None else 'the targeted'} device(s) — they must be re-adopted"
        )
        if n is not None:
            res.impact["device_count"] = n
    elif feature in ("firmware.upgrade", "firmware.upgrade.batch"):
        n = _target_count(payload)
        res.warnings.append("flashing firmware can brick a device and reboots it")
        if n is not None:
            res.impact["device_count"] = n
    elif feature == "system.backup.restore":
        res.warnings.append(
            "restoring a controller backup replaces the ENTIRE running configuration "
            "(can change sites/networks/WLANs/adoptions)"
        )

    if adapter is not None and feature in ("bulk.device.factory_reset", "bulk.device.forget"):
        try:
            getter = getattr(adapter, "get_devices", None)
            if getter is not None:
                r = await getter()
                rows = getattr(r, "data", None) or (r if isinstance(r, list) else [])
                res.impact["controller_device_total"] = len(rows) if rows else 0
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
                f"{result.feature} ({result.operation}) is catastrophic ("
                + "; ".join(result.warnings)
                + "); re-stage with confirmed=true to proceed"
            ),
        )


def enforce_omada_preflight(
    controller_type: str | None,
    feature: str | None,
    operation: str | None,
    payload: dict[str, Any] | None,
) -> None:
    """Central runtime gate for Omada staged changes (no device read).

    No-op for any non-Omada controller so it can sit unconditionally on the
    shared apply chokepoint. For an Omada change it classifies and raises 409 if
    the op is CATASTROPHIC and the staged payload does not carry ``confirmed=true``.
    """
    if (controller_type or "").lower() != "omada":
        return
    from app.services.adapter_preflight_common import payload_confirmed

    catastrophic = classify(feature or "", operation or "") is Risk.CATASTROPHIC
    if catastrophic and not payload_confirmed(payload):
        raise HTTPException(
            status_code=409,
            detail=(
                f"{feature} ({operation}) is a catastrophic / irreversible Omada "
                "operation; re-stage the change with confirmed=true to proceed"
            ),
        )


async def preflight_gate(
    adapter: Any, feature: str, operation: str, payload: dict[str, Any] | None
) -> PreflightResult:
    """assess + gate — assess (with live impact) then block if unconfirmed-catastrophic."""
    result = await assess(feature, operation, payload, adapter=adapter)
    gate(result, payload)
    return result
