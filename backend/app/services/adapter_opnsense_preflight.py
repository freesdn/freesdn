# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Pre-flight safety + impact assessment for OPNsense staged writes.

OPNsense is a LIVE PRODUCTION firewall. Its write path is already protected by a
default-deny dual-gate (``ADAPTER_READ_ONLY`` env lock + per-call ``force=true``),
but that gate is binary: once an operator legitimately lowers it to push a
create-only firewall change, the *same* unlocked session could also apply a
staged reboot, firmware update, backup restore, or a rule/alias/NAT/route delete.

This module adds the missing op-aware checkpoint, mirroring
``adapter_proxmox_preflight``: it classifies a staged change's destructiveness
and BLOCKS a CATASTROPHIC / irreversible operation unless the staged payload
carries an explicit ``confirmed=true``. Per the owner's rule the catastrophic
set is **system ops + ALL deletes** (a stray rule/route/NAT delete on a prod
firewall can cut access just as surely as a reboot). DESTRUCTIVE ops (service
stop/restart, IDS rule-disable, IPsec disconnect, alert-log drop) warn but are
not blocked.

The block is enforced CENTRALLY in ``AdapterStagingService.apply_change`` via
:func:`enforce_opnsense_preflight`, so it covers every ``opnsense.*`` feature —
including deletes scattered across the firewall/NAT/DNS/routing/VPN/DHCP/shaper
services — at the single sanctioned apply chokepoint, with no per-applier wiring
to forget. ``assess`` (with a connected, read-only adapter) additionally surfaces
device impact for the dry-run preview; all such checks are best-effort and a read
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
    CATASTROPHIC = "catastrophic"  # irreversible / data-loss / whole-box


#: Features that are CATASTROPHIC regardless of their staging ``operation``.
#: NOTE: several of these are registered with operation=="create" in the
#: ``_APPLY`` tables (e.g. ``backup_restore``/``backup_delete``), so they must be
#: caught by FEATURE name, not just by operation=="delete".
_CATASTROPHIC_FEATURES: frozenset[str] = frozenset(
    {
        "opnsense.system.reboot",
        "opnsense.system.halt",
        "opnsense.system.firmware_update",
        "opnsense.system.firmware_upgrade",
        "opnsense.system.backup_restore",
        "opnsense.system.backup_delete",  # removes a saved config backup (op is "create")
        "opnsense.system.config_restore",
    }
)

#: Features that disrupt a running workload but are recoverable → warn, not block.
_DESTRUCTIVE_FEATURES: frozenset[str] = frozenset(
    {
        "opnsense.services.stop",
        "opnsense.services.restart",
        "opnsense.vpn.ipsec.disconnect",
        "opnsense.ids.rule_disable",
        "opnsense.ids.alert_drop",
    }
)


def classify(feature: str, operation: str) -> Risk:
    """Base destructiveness of an OPNsense ``(feature, operation)`` pair.

    Owner rule: system ops + ANY delete require confirmation (CATASTROPHIC).
    """
    if feature in _CATASTROPHIC_FEATURES:
        return Risk.CATASTROPHIC
    if (operation or "").lower() == "delete":
        return Risk.CATASTROPHIC  # every opnsense.* delete is block-unless-confirmed
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
    if feature in ("opnsense.system.backup_restore", "opnsense.system.config_restore"):
        res.warnings.append(
            "restoring a config replaces the ENTIRE running configuration (can change "
            "interfaces/rules/access and force a reconfigure)"
        )
    if feature in ("opnsense.system.reboot", "opnsense.system.halt"):
        res.warnings.append("this interrupts ALL traffic through the firewall")

    if adapter is not None:
        target_id = str(payload.get("target_id") or payload.get("uuid") or "") or None
        try:
            if feature in (
                "opnsense.system.backup_restore",
                "opnsense.system.backup_delete",
            ):
                filename = target_id or payload.get("filename")
                getter = getattr(adapter, "get_backup_list", None)
                if getter is not None and filename:
                    r = await getter()
                    rows = getattr(r, "data", None) or (r if isinstance(r, list) else [])
                    b = next(
                        (
                            x
                            for x in rows
                            if isinstance(x, dict)
                            and str(x.get("filename") or x.get("name")) == str(filename)
                        ),
                        None,
                    )
                    if b is not None:
                        res.impact["backup"] = {
                            "filename": b.get("filename") or b.get("name"),
                            "created": b.get("created") or b.get("date"),
                        }
            elif feature == "opnsense.firewall.rule" and (operation or "").lower() == "delete":
                getter = getattr(adapter, "get_firewall_rules", None)
                if getter is not None and target_id:
                    r = await getter()
                    rows = getattr(r, "data", None) or (r if isinstance(r, list) else [])
                    rule = next(
                        (
                            x
                            for x in rows
                            if isinstance(x, dict) and str(x.get("uuid")) == target_id
                        ),
                        None,
                    )
                    if rule is not None:
                        res.impact["rule"] = {
                            "description": rule.get("description"),
                            "enabled": rule.get("enabled"),
                        }
                        res.warnings.append(
                            f"deleting firewall rule {target_id} "
                            f"({rule.get('description') or 'no description'})"
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
                f"{result.feature} ({result.operation}) is catastrophic ("
                + "; ".join(result.warnings)
                + "); re-stage with confirmed=true to proceed"
            ),
        )


def enforce_opnsense_preflight(
    feature: str | None, operation: str | None, payload: dict[str, Any] | None
) -> None:
    """Central runtime gate for OPNsense staged changes (no device read).

    No-op for non-``opnsense.*`` features so it can sit unconditionally on the
    shared apply chokepoint. For ``opnsense.*`` it classifies and raises 409 if
    the op is CATASTROPHIC and the staged payload does not carry ``confirmed=true``.
    """
    if not (feature or "").startswith("opnsense."):
        return
    from app.services.adapter_preflight_common import payload_confirmed

    catastrophic = classify(feature or "", operation or "") is Risk.CATASTROPHIC
    if catastrophic and not payload_confirmed(payload):
        raise HTTPException(
            status_code=409,
            detail=(
                f"{feature} ({operation}) is a catastrophic / irreversible OPNsense "
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
