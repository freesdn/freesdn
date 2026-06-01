# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN Storage — health rollup (single source of truth).

Pure, dependency-light summary of a TrueNAS appliance's health from its pools,
active alerts, and disk temperatures. Shared by the ``storage.health`` Fabric
read operation and the ``storage.poll_health`` monitoring task so the catalog
read and the emitted ``storage.*`` events agree on what "degraded" means.
"""

from __future__ import annotations

from typing import Any

# ZFS pool status classification.
_POOL_ERROR = {"FAULTED", "OFFLINE", "REMOVED", "UNAVAIL"}
_POOL_WARN = {"DEGRADED"}

_ORDER = {"ok": 0, "warning": 1, "error": 2}


def _worse(a: str, b: str) -> str:
    return a if _ORDER.get(a, 0) >= _ORDER.get(b, 0) else b


def summarize_health(
    pools: list[Any],
    alerts: list[dict[str, Any]] | None,
    disk_temps: dict[str, Any] | None,
    *,
    capacity_warn_pct: float = 85.0,
) -> dict[str, Any]:
    """Roll up appliance health to a normalized dict.

    Returns ``{status, pools[], degraded_pools[], over_capacity_pools[],
    critical_alerts, max_temp_c}`` where ``status`` is ``ok|warning|error``.
    """
    overall = "ok"
    pool_rows: list[dict[str, Any]] = []
    degraded: list[str] = []
    over_cap: list[str] = []

    for p in pools or []:
        name = getattr(p, "name", None)
        st = str(getattr(p, "status", "") or "").upper()
        usage = getattr(p, "usage", None)
        size = int(getattr(usage, "size", 0) or 0)
        alloc = int(getattr(usage, "allocated", 0) or 0)
        cap = round(alloc / size * 100, 1) if size > 0 else 0.0
        pool_rows.append({"name": name, "status": st or None, "capacity_pct": cap})
        if st in _POOL_ERROR:
            if name:
                degraded.append(name)
            overall = _worse(overall, "error")
        elif st in _POOL_WARN:
            if name:
                degraded.append(name)
            overall = _worse(overall, "warning")
        if cap >= capacity_warn_pct and name:
            over_cap.append(name)
            overall = _worse(overall, "warning")

    critical_alerts = sum(
        1
        for a in (alerts or [])
        if str((a or {}).get("level", "")).upper() in ("CRITICAL", "ERROR")
    )
    if critical_alerts:
        overall = _worse(overall, "warning")

    temps = [float(v) for v in (disk_temps or {}).values() if isinstance(v, (int, float))]
    return {
        "status": overall,
        "pools": pool_rows,
        "degraded_pools": degraded,
        "over_capacity_pools": over_cap,
        "critical_alerts": critical_alerts,
        "max_temp_c": max(temps) if temps else None,
    }
