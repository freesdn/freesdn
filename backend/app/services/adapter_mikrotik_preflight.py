# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Pre-flight safety + impact assessment for MikroTik (RouterOS) staged writes.

A MikroTik router is a LIVE PRODUCTION edge/firewall device. Its write path is
already protected by the default-deny dual-gate (``ADAPTER_READ_ONLY`` env lock +
per-call ``force=true``), but that gate is binary: once an operator legitimately
lowers it to push a create-only change, the *same* unlocked session could also
apply a staged reboot/shutdown, a firmware install (brick risk), a backup
restore (replaces the whole config), a package uninstall, or a
firewall/route/NAT/file delete that cuts access just as surely as a power op.

This module mirrors ``adapter_opnsense_preflight`` / ``adapter_pfsense_preflight``
/ ``adapter_omada_preflight``: it classifies a staged change's destructiveness
and BLOCKS a CATASTROPHIC / irreversible operation unless the staged payload
carries an explicit ``confirmed=true``. Per the owner's rule the catastrophic set
is **irreversible system ops (reboot/shutdown/firmware/backup-restore/package
uninstall) + ALL deletes**. (Note ``firmware.install`` already carries a
catastrophic-role + ``controller:write`` gate at the endpoint layer; this adds the
op-aware confirmation gate at the shared apply chokepoint so it is enforced there
too.)

The block is enforced CENTRALLY in ``AdapterStagingService.apply_change`` via
:func:`enforce_mikrotik_preflight`, so it covers every ``mikrotik.*`` feature at
the single sanctioned apply chokepoint, with no per-applier wiring to forget.
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
#: Most of these register with operation=="create" in ``adapter_mikrotik_system``'s
#: ``_APPLY`` table (reboot/shutdown/firmware.install/backup.restore/backup_load),
#: so they must be caught by FEATURE name, not just by operation=="delete".
_CATASTROPHIC_FEATURES: frozenset[str] = frozenset(
    {
        "mikrotik.system.reboot",
        "mikrotik.system.shutdown",
        "mikrotik.system.firmware.install",  # flashes firmware — brick risk, reboots
        "mikrotik.system.backup.restore",  # replaces the ENTIRE running config
        "mikrotik.system.backup_load",  # legacy restore verb (op is "create")
        "mikrotik.system.package.uninstall",  # delete op, but list explicitly for clarity
    }
)


def classify(feature: str, operation: str) -> Risk:
    """Base destructiveness of a MikroTik ``(feature, operation)`` pair.

    Owner rule: irreversible system ops + ANY delete require confirmation
    (CATASTROPHIC). Caller must already have established that this is a MikroTik
    change (see :func:`enforce_mikrotik_preflight`).
    """
    if feature in _CATASTROPHIC_FEATURES:
        return Risk.CATASTROPHIC
    if (operation or "").lower() == "delete":
        return Risk.CATASTROPHIC  # every mikrotik.* delete is block-unless-confirmed
    return Risk.SAFE


def enforce_mikrotik_preflight(
    feature: str | None, operation: str | None, payload: dict[str, Any] | None
) -> None:
    """Central runtime gate for MikroTik staged changes (no device read).

    No-op for non-``mikrotik.*`` features so it can sit unconditionally on the
    shared apply chokepoint. For ``mikrotik.*`` it classifies and raises 409 if
    the op is CATASTROPHIC and the staged payload does not carry ``confirmed=true``.
    """
    if not (feature or "").startswith("mikrotik."):
        return
    from app.services.adapter_preflight_common import payload_confirmed

    catastrophic = classify(feature or "", operation or "") is Risk.CATASTROPHIC
    if catastrophic and not payload_confirmed(payload):
        raise HTTPException(
            status_code=409,
            detail=(
                f"{feature} ({operation}) is a catastrophic / irreversible MikroTik "
                "operation; re-stage the change with confirmed=true to proceed"
            ),
        )
