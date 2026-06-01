# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Pre-flight safety + impact assessment for pfSense staged writes.

pfSense is a LIVE PRODUCTION firewall. Its write path is already protected by the
default-deny dual-gate (``ADAPTER_READ_ONLY`` env lock + per-call ``force=true``),
but that gate is binary: once an operator legitimately lowers it to push a
create-only firewall change, the *same* unlocked session could also apply a
staged reboot/halt or a rule/alias/NAT/route delete that cuts access just as
surely as a power op.

This module mirrors ``adapter_opnsense_preflight`` (its sibling firewall vendor):
it classifies a staged change's destructiveness and BLOCKS a CATASTROPHIC /
irreversible operation unless the staged payload carries an explicit
``confirmed=true``. Per the owner's rule the catastrophic set is **system ops
(reboot/halt/firmware/backup-restore) + ALL deletes**. DESTRUCTIVE ops (service
stop/restart) warn but are not blocked.

The block is enforced CENTRALLY in ``AdapterStagingService.apply_change`` via
:func:`enforce_pfsense_preflight`, so it covers every ``pfsense.*`` feature at the
single sanctioned apply chokepoint, with no per-applier wiring to forget.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from fastapi import HTTPException


class Risk(StrEnum):
    SAFE = "safe"
    DESTRUCTIVE = "destructive"  # disrupts a running workload (recoverable)
    CATASTROPHIC = "catastrophic"  # irreversible / data-loss / whole-box


#: Features that are CATASTROPHIC regardless of their staging ``operation``.
#: Several of these are registered with operation=="create" in the per-service
#: ``_APPLY`` tables (reboot/halt/firmware/backup-restore), so they must be
#: caught by FEATURE name, not just by operation=="delete".
_CATASTROPHIC_FEATURES: frozenset[str] = frozenset(
    {
        "pfsense.system.reboot",
        "pfsense.system.halt",
        "pfsense.system.firmware_update",
        "pfsense.system.firmware_upgrade",
        "pfsense.system.backup_restore",
        "pfsense.system.config_restore",
    }
)

#: Features that disrupt a running workload but are recoverable → warn, not block.
_DESTRUCTIVE_FEATURES: frozenset[str] = frozenset(
    {
        "pfsense.services.stop",
        "pfsense.services.restart",
    }
)


def classify(feature: str, operation: str) -> Risk:
    """Base destructiveness of a pfSense ``(feature, operation)`` pair.

    Owner rule: system ops + ANY delete require confirmation (CATASTROPHIC).
    """
    if feature in _CATASTROPHIC_FEATURES:
        return Risk.CATASTROPHIC
    if (operation or "").lower() == "delete":
        return Risk.CATASTROPHIC  # every pfsense.* delete is block-unless-confirmed
    if feature in _DESTRUCTIVE_FEATURES:
        return Risk.DESTRUCTIVE
    return Risk.SAFE


def enforce_pfsense_preflight(
    feature: str | None, operation: str | None, payload: dict[str, Any] | None
) -> None:
    """Central runtime gate for pfSense staged changes (no device read).

    No-op for non-``pfsense.*`` features so it can sit unconditionally on the
    shared apply chokepoint. For ``pfsense.*`` it classifies and raises 409 if
    the op is CATASTROPHIC and the staged payload does not carry ``confirmed=true``.
    """
    if not (feature or "").startswith("pfsense."):
        return
    from app.services.adapter_preflight_common import payload_confirmed

    catastrophic = classify(feature or "", operation or "") is Risk.CATASTROPHIC
    if catastrophic and not payload_confirmed(payload):
        raise HTTPException(
            status_code=409,
            detail=(
                f"{feature} ({operation}) is a catastrophic / irreversible pfSense "
                "operation; re-stage the change with confirmed=true to proceed"
            ),
        )
