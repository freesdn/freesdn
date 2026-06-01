# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Event Correlation Service
=========================================

Pattern-matching engine that groups related events into incidents.

Strategy:
  1. Scan recent events within each rule's time window
  2. Group by scope (site/device_group/org)
  3. Match against rule patterns (event_type, min_count, conditions)
  4. If all patterns match → create or update an incident
  5. Auto-resolve incidents whose trigger events have stopped
"""

import logging
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatch
from typing import Any
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.site_access import site_ids_for_request
from app.models.correlation import (
    CorrelationRule,
    CorrelationRuleStatus,
    Incident,
    IncidentEvent,
    IncidentStatus,
)
from app.models.events import EventRecord

logger = logging.getLogger("freesdn.enterprise.correlation")


class EventCorrelationService:
    """Correlates events into incidents based on configured rules."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------
    # Rule CRUD
    # ------------------------------------------------------------------

    async def list_rules(
        self,
        organization_id: UUID,
        status: str | None = None,
    ) -> tuple[list[CorrelationRule], int]:
        # CorrelationRule is org-level (no site_id column); its
        # rule-level data (names / conditions / fire counts) can reveal
        # sibling-site activity. Consistent with the get_stats rule-level gate,
        # hide the rule list from a site-limited caller. ``site_ids_for_request``
        # is None for unrestricted / admin / background callers (no-op).
        if site_ids_for_request() is not None:
            return [], 0
        stmt = select(CorrelationRule).where(CorrelationRule.organization_id == organization_id)
        if status:
            stmt = stmt.where(CorrelationRule.status == status)
        stmt = stmt.order_by(CorrelationRule.created_at.desc())

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await self.db.execute(count_stmt)).scalar_one()
        result = await self.db.execute(stmt)
        return list(result.scalars().all()), total

    async def get_rule(self, rule_id: UUID) -> CorrelationRule | None:
        result = await self.db.execute(select(CorrelationRule).where(CorrelationRule.id == rule_id))
        return result.scalar_one_or_none()

    async def create_rule(
        self,
        organization_id: UUID,
        data: dict[str, Any],
        created_by: UUID | None = None,
    ) -> CorrelationRule:
        rule = CorrelationRule(
            organization_id=organization_id,
            created_by=created_by,
            **data,
        )
        self.db.add(rule)
        await self.db.flush()
        return rule

    async def update_rule(self, rule_id: UUID, data: dict[str, Any]) -> CorrelationRule | None:
        rule = await self.get_rule(rule_id)
        if not rule:
            return None
        for key, value in data.items():
            if value is not None:
                setattr(rule, key, value)
        await self.db.flush()
        return rule

    async def delete_rule(self, rule_id: UUID) -> bool:
        rule = await self.get_rule(rule_id)
        if not rule:
            return False
        await self.db.delete(rule)
        await self.db.flush()
        return True

    # ------------------------------------------------------------------
    # Incident CRUD
    # ------------------------------------------------------------------

    async def list_incidents(
        self,
        organization_id: UUID,
        status: str | None = None,
        severity: str | None = None,
        site_id: UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Incident], int]:
        stmt = select(Incident).where(Incident.organization_id == organization_id)
        if status:
            stmt = stmt.where(Incident.status == status)
        if severity:
            stmt = stmt.where(Incident.severity == severity)
        if site_id:
            stmt = stmt.where(Incident.site_id == site_id)
        # (R5): fold the request caller's per-user site grant so a
        # site-limited operator cannot list sibling-site incidents via the
        # org-wide (no-site_id) path. None = unrestricted/admin/background (no-op);
        # org-level incidents (site_id IS NULL) stay visible.
        _granted = site_ids_for_request()
        if _granted is not None:
            stmt = stmt.where(or_(Incident.site_id.is_(None), Incident.site_id.in_(_granted)))
        stmt = stmt.order_by(Incident.opened_at.desc())

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await self.db.execute(count_stmt)).scalar_one()
        result = await self.db.execute(stmt.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def get_incident(self, incident_id: UUID) -> Incident | None:
        result = await self.db.execute(select(Incident).where(Incident.id == incident_id))
        return result.scalar_one_or_none()

    async def create_incident(
        self,
        organization_id: UUID,
        data: dict[str, Any],
        created_by: UUID | None = None,
    ) -> Incident:
        incident = Incident(
            organization_id=organization_id,
            created_by=created_by,
            **data,
        )
        self.db.add(incident)
        await self.db.flush()
        return incident

    async def update_incident(self, incident_id: UUID, data: dict[str, Any]) -> Incident | None:
        incident = await self.get_incident(incident_id)
        if not incident:
            return None

        now = datetime.now(UTC)

        # Handle status transitions with timestamp tracking
        new_status = data.get("status")
        if new_status and new_status != incident.status:
            if new_status == IncidentStatus.INVESTIGATING.value:
                data.setdefault("acknowledged_at", now)
            elif new_status == IncidentStatus.RESOLVED.value:
                data.setdefault("resolved_at", now)
            elif new_status == IncidentStatus.CLOSED.value:
                data.setdefault("closed_at", now)
                if not incident.resolved_at:
                    data.setdefault("resolved_at", now)

        for key, value in data.items():
            if value is not None:
                setattr(incident, key, value)
        await self.db.flush()
        return incident

    async def get_incident_events(self, incident_id: UUID) -> list[dict[str, Any]]:
        """Get events linked to an incident with inline event data."""
        stmt = (
            select(IncidentEvent, EventRecord)
            .join(EventRecord, IncidentEvent.event_id == EventRecord.id)
            .where(IncidentEvent.incident_id == incident_id)
            .order_by(EventRecord.timestamp.desc())
        )
        result = await self.db.execute(stmt)
        rows = result.all()
        return [
            {
                "id": ie.id,
                "event_id": ie.event_id,
                "matched_pattern": ie.matched_pattern,
                "added_at": ie.added_at,
                "event_type": ev.event_type,
                "event_category": ev.category.value if ev.category else None,
                "event_timestamp": ev.timestamp,
                "event_payload": ev.payload,
            }
            for ie, ev in rows
        ]

    # ------------------------------------------------------------------
    # Correlation Engine
    # ------------------------------------------------------------------

    async def correlate(
        self,
        organization_id: UUID,
        time_window_minutes: int = 15,
        site_id: UUID | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """
        Run the correlation engine: scan events, match rules, create/update incidents.

        Returns summary of what was correlated.
        """
        now = datetime.now(UTC)
        window_start = now - timedelta(minutes=time_window_minutes)

        # 1. Load active rules for this org
        rules_result = await self.db.execute(
            select(CorrelationRule).where(
                CorrelationRule.organization_id == organization_id,
                CorrelationRule.status == CorrelationRuleStatus.ACTIVE.value,
            )
        )
        rules = list(rules_result.scalars().all())

        if not rules:
            return {"rules_evaluated": 0, "incidents_created": 0, "incidents_updated": 0}

        # 2. Load recent events (within the widest time window).
        # EventRecord is a LogBase model that lives in the
        # SEPARATE TimescaleDB LogDB — querying it through self.db (the PRIMARY
        # session, which is what the Celery task passes in) sees no rows (or
        # errors if the table is absent), silently missing all correlations.
        # Read events from the LogDB session; keep rules/incidents on self.db.
        events_stmt = select(EventRecord).where(
            EventRecord.organization_id == organization_id,
            EventRecord.timestamp >= window_start,
        )
        if site_id:
            events_stmt = events_stmt.where(EventRecord.site_id == site_id)
        events_stmt = events_stmt.order_by(EventRecord.timestamp.desc())

        logdb_factory = None
        try:
            from app.db.session import get_logdb_factory

            logdb_factory = get_logdb_factory()
        except RuntimeError:
            logdb_factory = None

        if logdb_factory is not None:
            async with logdb_factory() as logdb:
                events_result = await logdb.execute(events_stmt)
                recent_events = list(events_result.scalars().all())
        else:
            # LogDB not configured (dev/single-DB): fall back to self.db.
            events_result = await self.db.execute(events_stmt)
            recent_events = list(events_result.scalars().all())

        incidents_created = 0
        incidents_updated = 0
        events_correlated = 0

        # 3. For each rule, check if its patterns match
        for rule in rules:
            rule_window = now - timedelta(seconds=rule.time_window_seconds)
            rule_events = [e for e in recent_events if e.timestamp >= rule_window]

            # Group events by scope
            scoped_groups = self._group_by_scope(rule_events, rule.scope)

            for scope_key, group_events in scoped_groups.items():
                matched_events = self._match_patterns(
                    group_events, rule.event_patterns, rule.conditions
                )

                if not matched_events:
                    continue

                if dry_run:
                    events_correlated += len(matched_events)
                    incidents_created += 1
                    continue

                # Check for existing open incident from this rule + scope
                existing = await self._find_existing_incident(organization_id, rule.id, scope_key)

                if existing:
                    # Update existing incident with new events
                    new_events = await self._add_events_to_incident(existing, matched_events, rule)
                    if new_events:
                        existing.event_count += new_events
                        incidents_updated += 1
                        events_correlated += new_events
                else:
                    # Create new incident
                    site_uuid = self._extract_site_id(scope_key, rule.scope)
                    affected = list(
                        {
                            str(e.payload.get("device_id", ""))
                            for e in matched_events
                            if e.payload.get("device_id")
                        }
                    )

                    incident = Incident(
                        organization_id=organization_id,
                        rule_id=rule.id,
                        site_id=site_uuid,
                        title=self._generate_title(rule, matched_events),
                        description=self._generate_description(rule, matched_events),
                        severity=rule.severity,
                        status=IncidentStatus.OPEN.value,
                        event_count=len(matched_events),
                        affected_devices=affected,
                        context={
                            "scope_key": str(scope_key),
                            "rule_name": rule.name,
                            "patterns_matched": len(rule.event_patterns),
                        },
                    )
                    self.db.add(incident)
                    await self.db.flush()

                    # Link events
                    for event in matched_events:
                        self.db.add(
                            IncidentEvent(
                                incident_id=incident.id,
                                event_id=event.id,
                                matched_pattern=event.event_type,
                            )
                        )

                    incidents_created += 1
                    events_correlated += len(matched_events)

                # Update rule stats
                rule.fire_count += 1
                rule.last_fired_at = now

        if not dry_run:
            await self.db.commit()

        return {
            "rules_evaluated": len(rules),
            "incidents_created": incidents_created,
            "incidents_updated": incidents_updated,
            "events_correlated": events_correlated,
            "dry_run": dry_run,
        }

    async def auto_resolve_incidents(self, organization_id: UUID) -> int:
        """
        Auto-resolve incidents whose rules have auto_resolve_seconds set
        and no new events have arrived within that window.
        """
        now = datetime.now(UTC)
        resolved_count = 0

        # Load incidents with their rule's auto_resolve_seconds in one query
        stmt = (
            select(Incident, CorrelationRule.auto_resolve_seconds)
            .join(CorrelationRule, Incident.rule_id == CorrelationRule.id)
            .where(
                Incident.organization_id == organization_id,
                Incident.status.in_(
                    [
                        IncidentStatus.OPEN.value,
                        IncidentStatus.INVESTIGATING.value,
                    ]
                ),
                CorrelationRule.auto_resolve_seconds.isnot(None),
            )
        )
        result = await self.db.execute(stmt)
        incident_rows = result.all()

        if not incident_rows:
            return 0

        # Batch-load latest event timestamps for all incidents in one query
        incident_ids = [row[0].id for row in incident_rows]
        latest_stmt = (
            select(
                IncidentEvent.incident_id,
                func.max(EventRecord.timestamp).label("latest_ts"),
            )
            .join(EventRecord, IncidentEvent.event_id == EventRecord.id)
            .where(IncidentEvent.incident_id.in_(incident_ids))
            .group_by(IncidentEvent.incident_id)
        )
        latest_result = await self.db.execute(latest_stmt)
        latest_by_incident = {row.incident_id: row.latest_ts for row in latest_result.all()}

        for incident, auto_resolve in incident_rows:
            latest_event_time = latest_by_incident.get(incident.id)
            if not latest_event_time:
                continue

            if auto_resolve and (now - latest_event_time).total_seconds() > auto_resolve:
                incident.status = IncidentStatus.RESOLVED.value
                incident.resolved_at = now
                incident.resolution_notes = "Auto-resolved: no new events within window"
                resolved_count += 1

        if resolved_count:
            await self.db.commit()

        return resolved_count

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    async def get_stats(self, organization_id: UUID, site_id: UUID | None = None) -> dict[str, Any]:
        now = datetime.now(UTC)
        day_ago = now - timedelta(hours=24)
        # narrow incident counts to the selected site when supplied.
        site_pred = [Incident.site_id == site_id] if site_id else []
        # (R5): constrain the incident aggregates to the caller's
        # per-user site grant (org-wide path). None = unrestricted/admin/background.
        _granted = site_ids_for_request()
        if _granted is not None:
            site_pred.append(or_(Incident.site_id.is_(None), Incident.site_id.in_(_granted)))

        # CorrelationRule carries NO site_id column — its scope is a
        # free-text ``scope`` field, not a per-site grant dimension. So a
        # site-limited caller has no legitimate site-scoped view of the
        # rule-level aggregates; org-wide rule counts / top-firing rules would
        # leak sibling-site activity. Expose rule-level figures ONLY to
        # unrestricted callers (``_granted is None`` = super/org-admin/
        # background); return 0 / [] for a site-limited operator.
        _rule_level_allowed = _granted is None

        total_rules = (
            (
                await self.db.execute(
                    select(func.count()).where(CorrelationRule.organization_id == organization_id)
                )
            ).scalar_one()
            if _rule_level_allowed
            else 0
        )

        active_rules = (
            (
                await self.db.execute(
                    select(func.count()).where(
                        CorrelationRule.organization_id == organization_id,
                        CorrelationRule.status == CorrelationRuleStatus.ACTIVE.value,
                    )
                )
            ).scalar_one()
            if _rule_level_allowed
            else 0
        )

        open_incidents = (
            await self.db.execute(
                select(func.count()).where(
                    Incident.organization_id == organization_id,
                    Incident.status.in_(
                        [
                            IncidentStatus.OPEN.value,
                            IncidentStatus.INVESTIGATING.value,
                            IncidentStatus.MITIGATING.value,
                        ]
                    ),
                    *site_pred,
                )
            )
        ).scalar_one()

        incidents_24h = (
            await self.db.execute(
                select(func.count()).where(
                    Incident.organization_id == organization_id,
                    Incident.opened_at >= day_ago,
                    *site_pred,
                )
            )
        ).scalar_one()

        # Top firing rules — rule-level (no site dimension); see _rule_level_allowed.
        # Site-limited callers get an empty list rather than org-wide rule names.
        if _rule_level_allowed:
            top_rules_result = await self.db.execute(
                select(
                    CorrelationRule.id,
                    CorrelationRule.name,
                    CorrelationRule.fire_count,
                    CorrelationRule.last_fired_at,
                )
                .where(
                    CorrelationRule.organization_id == organization_id,
                    CorrelationRule.fire_count > 0,
                )
                .order_by(CorrelationRule.fire_count.desc())
                .limit(5)
            )
            top_rules = [
                {
                    "id": str(r.id),
                    "name": r.name,
                    "fire_count": r.fire_count,
                    "last_fired_at": r.last_fired_at.isoformat() if r.last_fired_at else None,
                }
                for r in top_rules_result.all()
            ]
        else:
            top_rules = []

        return {
            "total_rules": total_rules,
            "active_rules": active_rules,
            "open_incidents": open_incidents,
            "incidents_last_24h": incidents_24h,
            # events_correlated_last_24h is incident-derived — it joins
            # IncidentEvent -> Incident, which carries site_id. Fold the SAME
            # per-user site-grant predicate (``site_pred``, computed above) the
            # incident counts use, so a site-limited caller is not handed a
            # cross-/sibling-site correlated-event total. ``site_pred`` is empty
            # for unrestricted callers (no-op) and never builds in_(None).
            "events_correlated_last_24h": (
                await self.db.execute(
                    select(func.count())
                    .select_from(IncidentEvent)
                    .join(Incident, IncidentEvent.incident_id == Incident.id)
                    .where(
                        Incident.organization_id == organization_id,
                        IncidentEvent.added_at >= day_ago,
                        *site_pred,
                    )
                )
            ).scalar_one(),
            "top_firing_rules": top_rules,
        }

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _group_by_scope(
        self, events: list[EventRecord], scope: str
    ) -> dict[str, list[EventRecord]]:
        """Group events by the rule's scope boundary."""
        groups: dict[str, list[EventRecord]] = {}
        for event in events:
            if scope == "site":
                key = str(event.site_id) if event.site_id else "no-site"
            elif scope == "organization":
                key = str(event.organization_id)
            else:
                # device_group — use correlation_id or fall back to site
                key = str(event.correlation_id or event.site_id or "unknown")
            groups.setdefault(key, []).append(event)
        return groups

    def _match_patterns(
        self,
        events: list[EventRecord],
        patterns: list[dict[str, Any]],
        conditions: dict[str, Any] | None,
    ) -> list[EventRecord]:
        """
        Check if a group of events matches ALL patterns in a rule.
        Returns the matched events if all patterns satisfied, else empty list.
        """
        all_matched: list[EventRecord] = []

        for pattern in patterns:
            event_type_glob = pattern.get("event_type", "*")
            min_count = pattern.get("min_count", 1)
            category_filter = pattern.get("category")
            pattern_conditions = pattern.get("conditions", {})

            matched_for_pattern = []
            for event in events:
                if not fnmatch(event.event_type, event_type_glob):
                    continue
                if category_filter and event.category and event.category.value != category_filter:
                    continue
                if pattern_conditions:
                    if not self._payload_matches(event.payload, pattern_conditions):
                        continue
                matched_for_pattern.append(event)

            if len(matched_for_pattern) < min_count:
                return []  # This pattern not satisfied
            all_matched.extend(matched_for_pattern)

        # Apply rule-level conditions
        if conditions:
            all_matched = [e for e in all_matched if self._payload_matches(e.payload, conditions)]

        return all_matched

    def _payload_matches(self, payload: dict[str, Any], conditions: dict[str, Any]) -> bool:
        """Check if event payload matches JSONB conditions (simple key=value)."""
        if not payload or not conditions:
            return True
        return all(payload.get(key) == expected for key, expected in conditions.items())

    async def _find_existing_incident(
        self,
        organization_id: UUID,
        rule_id: UUID,
        scope_key: str,
    ) -> Incident | None:
        """Find an open incident from the same rule + scope."""
        result = await self.db.execute(
            select(Incident).where(
                Incident.organization_id == organization_id,
                Incident.rule_id == rule_id,
                Incident.status.in_(
                    [
                        IncidentStatus.OPEN.value,
                        IncidentStatus.INVESTIGATING.value,
                    ]
                ),
                Incident.context["scope_key"].astext == scope_key,
            )
        )
        return result.scalar_one_or_none()

    async def _add_events_to_incident(
        self, incident: Incident, events: list[EventRecord], rule: CorrelationRule
    ) -> int:
        """Add new events to an existing incident, skipping duplicates."""
        existing_event_ids = set()
        result = await self.db.execute(
            select(IncidentEvent.event_id).where(IncidentEvent.incident_id == incident.id)
        )
        for row in result.all():
            existing_event_ids.add(row[0])

        added = 0
        for event in events:
            if event.id not in existing_event_ids:
                self.db.add(
                    IncidentEvent(
                        incident_id=incident.id,
                        event_id=event.id,
                        matched_pattern=event.event_type,
                    )
                )
                added += 1

        # Update affected devices
        new_devices = list(
            {str(e.payload.get("device_id", "")) for e in events if e.payload.get("device_id")}
        )
        current = set(incident.affected_devices or [])
        current.update(new_devices)
        incident.affected_devices = list(current)

        return added

    def _extract_site_id(self, scope_key: str, scope: str) -> UUID | None:
        """Extract UUID from scope key if scope is site-based."""
        if scope == "site":
            try:
                return UUID(scope_key)
            except ValueError:
                return None
        return None

    def _generate_title(self, rule: CorrelationRule, events: list[EventRecord]) -> str:
        """Generate a human-readable incident title."""
        event_types = list({e.event_type for e in events})
        if len(event_types) == 1:
            return f"[{rule.name}] {len(events)} {event_types[0]} events"
        return f"[{rule.name}] {len(events)} correlated events ({len(event_types)} types)"

    def _generate_description(self, rule: CorrelationRule, events: list[EventRecord]) -> str:
        """Generate an incident description from matched events."""
        type_counts = {}
        for e in events:
            type_counts[e.event_type] = type_counts.get(e.event_type, 0) + 1

        lines = [
            f"Correlation rule '{rule.name}' fired.",
            f"Time window: {rule.time_window_seconds}s, Scope: {rule.scope}",
            "",
            "Event breakdown:",
        ]
        for et, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  - {et}: {count} events")

        return "\n".join(lines)
