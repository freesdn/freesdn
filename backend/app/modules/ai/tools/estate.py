# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Rolled-up answers about the estate, for the AI assistant.

The other tools in this package answer questions about ONE thing: this device,
these alerts, that VLAN. The assistant could not answer "how is my network
doing" from them, and not because it lacked reasoning -- because ``get_devices``
returns at most 50 rows. On any estate past fifty devices the model cannot see
the whole inventory, so it cannot count it, and a rollup assembled from a
truncated window is worse than no rollup: it is confidently wrong.

So the aggregation happens here, in SQL, over everything the caller may see.

These began life in a first-party ``ai-ops-tools`` PLUGIN, which was the wrong
tier for them. The plugin tier exists so people outside the project can extend
FreeSDN without a core pull request and without AGPL; a first-party plugin that
shadows a native module gets none of that and costs three things -- operators
read "plugin" as third-party and restricted, the code runs under a permission
model it does not need, and it competes with the native feature for the same
job. Native tools reach every FreeSDN user; a plugin reaches whoever installed
it.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.site_access import site_scope_filter
from app.modules.ai.tools import AITool, register_tool

logger = logging.getLogger(__name__)

#: Statuses that mean "not working right now". ``unknown`` is deliberately not
#: here: a device the platform has not heard from is not the same claim as a
#: device it knows is down, and reporting them together turns a discovery gap
#: into a fake outage.
DOWN = {"offline", "down", "error"}

#: Above this fraction of a site's devices offline, the site is unhealthy rather
#: than degraded. A quarter is a judgement call, but a fixed one beats each
#: caller inventing their own.
UNHEALTHY_OFFLINE_RATIO = 0.25

#: Availability below this over the last day means the site has been flapping,
#: even if everything happens to be up at this instant.
UNSTABLE_AVAILABILITY = 0.95


async def _site_rows(user: Any, db: AsyncSession) -> list[Any]:
    from app.models.core import Site

    q = select(Site).where(
        Site.organization_id == user.organization_id,
        Site.deleted_at.is_(None),
        site_scope_filter(user, Site.id),
    )
    return list((await db.execute(q)).scalars().all())


async def _availability_by_site(user: Any, site_ids: list[UUID]) -> dict[str, float]:
    """Mean device availability per site over the last 24 hours.

    Empty when the deployment has no time-series tier, which is a supported
    shape: the caller degrades to the point-in-time verdict rather than
    reporting a trend it does not have.

    Worth the extra query. A point-in-time view answers "is it broken now" and
    nothing else -- an estate with three of forty devices offline reads
    identically whether it has been that way for a month or started twenty
    minutes ago, and those are completely different things to tell an operator.
    """
    if not site_ids:
        return {}
    try:
        from app.db import session as db_session
        from app.models.analytics import MetricDataPoint

        factory = getattr(db_session, "logdb_session_factory", None)
        if factory is None:
            return {}

        since = datetime.now(UTC) - timedelta(hours=24)
        q = (
            select(MetricDataPoint.site_id, func.avg(MetricDataPoint.value))
            .where(
                MetricDataPoint.metric_name == "device.status",
                MetricDataPoint.time >= since,
                MetricDataPoint.site_id.in_(site_ids),
            )
            .group_by(MetricDataPoint.site_id)
        )
        async with factory() as logdb:
            rows = (await logdb.execute(q)).all()
        return {str(sid): float(avg) for sid, avg in rows if avg is not None}
    except Exception:
        # A trend is a bonus. Losing it must not lose the health report.
        logger.debug("availability trend unavailable", exc_info=True)
        return {}


async def _get_site_health(
    user: Any,
    db: AsyncSession,
    site_name: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    from app.models.alert_rules import Alert
    from app.models.devices import Device

    if not getattr(user, "organization_id", None):
        return {"error": "Organization context required", "sites": []}

    sites = await _site_rows(user, db)
    wanted = (site_name or "").strip().lower()
    by_site: dict[UUID, dict[str, Any]] = {
        s.id: {
            "site_id": str(s.id),
            "site": s.name,
            "total_devices": 0,
            "offline_devices": 0,
            "offline_names": [],
            "open_alerts": 0,
            "worst_alert_severity": None,
        }
        for s in sites
        if not wanted or wanted in str(s.name or "").lower()
    }
    if not by_site:
        return {"sites": [], "note": f"No site matches {site_name!r}" if wanted else "No sites"}

    device_rows = (
        await db.execute(
            select(Device.id, Device.name, Device.status, Device.site_id).where(
                Device.deleted_at.is_(None),
                Device.site_id.in_(list(by_site)),
            )
        )
    ).all()
    device_site = {row.id: row.site_id for row in device_rows}
    for row in device_rows:
        entry = by_site[row.site_id]
        entry["total_devices"] += 1
        if str(row.status or "").lower() in DOWN:
            entry["offline_devices"] += 1
            if len(entry["offline_names"]) < 10:
                entry["offline_names"].append(row.name)

    # An alert with no site is routed via its device. One with neither belongs
    # to no site and is reported separately rather than dropped -- dropping it
    # would let an org-wide problem vanish from a health report entirely.
    alert_rows = (
        await db.execute(
            select(Alert.severity, Alert.site_id, Alert.device_id).where(
                Alert.organization_id == user.organization_id,
                Alert.status == "firing",
            )
        )
    ).all()
    rank = {"info": 0, "warning": 1, "error": 2, "critical": 3}
    unattached = 0
    for alert in alert_rows:
        target = alert.site_id or device_site.get(alert.device_id)
        entry = by_site.get(target) if target else None
        if entry is None:
            unattached += 1
            continue
        entry["open_alerts"] += 1
        current = entry["worst_alert_severity"]
        if current is None or rank.get(str(alert.severity), 0) > rank.get(str(current), 0):
            entry["worst_alert_severity"] = alert.severity

    trend = await _availability_by_site(user, list(by_site))

    report = []
    for site_id, entry in by_site.items():
        total = entry["total_devices"]
        offline = entry["offline_devices"]
        critical = entry["worst_alert_severity"] in {"critical", "error"}

        avg = trend.get(str(site_id))
        entry["availability_24h"] = round(avg, 4) if avg is not None else None
        # Everything is fine at this instant and has not been fine all day.
        # Without this the assistant answers "site B is healthy" about a site
        # that has been flapping since breakfast.
        # ``total`` guards a real case: a site whose devices were all deleted
        # still has 24h of metric history, so it reported "recently unstable"
        # about hardware that is no longer there. A site with nothing in it
        # cannot be unstable; "empty" is the whole story.
        entry["recently_unstable"] = bool(
            total > 0 and avg is not None and avg < UNSTABLE_AVAILABILITY and offline == 0
        )

        entry["health"] = (
            "empty"
            if total == 0
            else "unhealthy"
            if offline / total >= UNHEALTHY_OFFLINE_RATIO or critical
            else "degraded"
            if offline or entry["open_alerts"] or entry["recently_unstable"]
            else "healthy"
        )
        report.append(entry)

    report.sort(key=lambda e: (-e["offline_devices"], -e["open_alerts"], e["site"] or ""))
    return {
        "sites": report,
        "unhealthy_threshold": UNHEALTHY_OFFLINE_RATIO,
        "alerts_not_attached_to_a_site": unattached,
    }


async def _get_estate_summary(user: Any, db: AsyncSession, **kwargs: Any) -> dict[str, Any]:
    from app.models.alert_rules import Alert
    from app.models.core import Site
    from app.models.devices import Device

    if not getattr(user, "organization_id", None):
        return {"error": "Organization context required"}

    site_ids = [s.id for s in await _site_rows(user, db)]
    if not site_ids:
        return {"sites": 0, "devices": 0, "note": "No sites visible to this user"}

    # COUNT in the database rather than fetching rows to len(). The whole point
    # of this tool is answering a question about an estate larger than any
    # row cap the model could page through.
    totals = (
        await db.execute(
            select(
                func.count(Device.id),
                func.count(Device.id).filter(func.lower(Device.status).in_(DOWN)),
            ).where(Device.deleted_at.is_(None), Device.site_id.in_(site_ids))
        )
    ).one()

    by_type = (
        await db.execute(
            select(Device.device_type, func.count(Device.id))
            .where(Device.deleted_at.is_(None), Device.site_id.in_(site_ids))
            .group_by(Device.device_type)
            .order_by(func.count(Device.id).desc())
        )
    ).all()

    by_severity = (
        await db.execute(
            select(Alert.severity, func.count(Alert.id))
            .where(Alert.organization_id == user.organization_id, Alert.status == "firing")
            .group_by(Alert.severity)
        )
    ).all()

    site_names = (
        (await db.execute(select(Site.name).where(Site.id.in_(site_ids)).order_by(Site.name)))
        .scalars()
        .all()
    )

    total, offline = int(totals[0] or 0), int(totals[1] or 0)
    return {
        "sites": len(site_ids),
        "site_names": list(site_names),
        "devices": total,
        "offline_devices": offline,
        "availability": round(1 - (offline / total), 4) if total else None,
        "devices_by_type": {str(t or "unknown"): int(c) for t, c in by_type},
        "open_alerts": sum(int(c) for _, c in by_severity),
        "alerts_by_severity": {str(s): int(c) for s, c in by_severity},
    }


register_tool(
    AITool(
        name="get_site_health",
        description=(
            "Per-site health rollup: device counts, how many are offline and which, open "
            "alerts and their worst severity, and 24-hour availability. Use this for "
            "'how is my network doing', 'which site has problems', or any question about "
            "a site as a whole. It aggregates the WHOLE estate, unlike get_devices, which "
            "returns at most 50 rows."
        ),
        parameters={
            "type": "object",
            "properties": {
                "site_name": {
                    "type": "string",
                    "description": "Limit to sites whose name contains this. Omit for all sites.",
                },
            },
        },
        handler=_get_site_health,
        permission="device:read",
    )
)


register_tool(
    AITool(
        name="get_estate_summary",
        description=(
            "One-paragraph picture of the whole estate: site count, device count, how many "
            "are offline, overall availability, a breakdown by device type, and open alerts "
            "by severity. Use this to open a conversation or answer 'give me an overview'."
        ),
        parameters={"type": "object", "properties": {}},
        handler=_get_estate_summary,
        permission="device:read",
    )
)
