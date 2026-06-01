# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Alert Rules Engine Service
==========================================

Evaluates alert rules against events/metrics and manages alert lifecycle.

Strategy:
  1. For each active rule, evaluate conditions against recent data
  2. Generate fingerprints for deduplication
  3. Fire new alerts or increment existing ones
  4. Dispatch notifications via notification service
  5. Auto-resolve alerts when conditions clear
"""

import hashlib
import logging
import statistics
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import cast, func, or_, select, update
from sqlalchemy.dialects.postgresql import JSONB as PG_JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.events import Event, EventCategory, EventPriority, get_event_bus
from app.core.site_access import site_scope_filter
from app.models.alert_rules import (
    Alert,
    AlertRule,
    AlertRuleStatus,
    AlertRuleType,
    AlertSeverity,
    AlertStatus,
)
from app.models.events import EventRecord

logger = logging.getLogger("freesdn.enterprise.alert_rules")


class AlertRuleService:
    """Manages alert rules and evaluates them to fire/resolve alerts."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------
    # Rule CRUD
    # ------------------------------------------------------------------

    async def list_rules(
        self,
        organization_id: UUID,
        status: str | None = None,
        rule_type: str | None = None,
        site_id: UUID | None = None,
        current_user: Any | None = None,
    ) -> tuple[list[AlertRule], int]:
        stmt = select(AlertRule).where(
            AlertRule.organization_id == organization_id,
            AlertRule.deleted_at.is_(None),
        )
        if status:
            stmt = stmt.where(AlertRule.status == status)
        if rule_type:
            stmt = stmt.where(AlertRule.rule_type == rule_type)
        if site_id:
            # Show rules scoped to this site (via scope_ids) or org-wide rules
            stmt = stmt.where(
                or_(
                    AlertRule.scope == "organization",
                    AlertRule.scope_ids.op("@>")(cast([str(site_id)], PG_JSONB)),
                )
            )
        # Per-user site grant: a site-limited caller sees ONLY site-scoped
        # rules that target a site they can access. Org-wide / device-scoped
        # rules are not site-resolvable here, so they are hidden from a
        # site-limited operator (fail-closed). No-op for unrestricted users.
        if current_user is not None and getattr(current_user, "is_site_limited", False):
            granted = list(getattr(current_user, "accessible_site_ids", None) or [])
            if granted:
                stmt = stmt.where(
                    AlertRule.scope == "site",
                    or_(
                        *[
                            AlertRule.scope_ids.op("@>")(cast([str(sid)], PG_JSONB))
                            for sid in granted
                        ]
                    ),
                )
            else:
                # Site-limited with no grants — fail closed.
                stmt = stmt.where(AlertRule.id.is_(None))
        stmt = stmt.order_by(AlertRule.created_at.desc())

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await self.db.execute(count_stmt)).scalar_one()
        result = await self.db.execute(stmt)
        return list(result.scalars().all()), total

    async def get_rule(self, rule_id: UUID) -> AlertRule | None:
        result = await self.db.execute(
            select(AlertRule).where(
                AlertRule.id == rule_id,
                AlertRule.deleted_at.is_(None),
            )
        )
        return result.scalar_one_or_none()

    async def create_rule(
        self,
        organization_id: UUID,
        data: dict[str, Any],
        created_by: UUID | None = None,
    ) -> AlertRule:
        rule = AlertRule(
            organization_id=organization_id,
            created_by=created_by,
            **data,
        )
        self.db.add(rule)
        await self.db.flush()
        await self.db.refresh(rule)
        logger.info("Created alert rule %s: %s", rule.id, rule.name)
        return rule

    async def update_rule(
        self,
        rule_id: UUID,
        data: dict[str, Any],
        updated_by: UUID | None = None,
    ) -> AlertRule | None:
        rule = await self.get_rule(rule_id)
        if not rule:
            return None
        # ``exclude_unset=True`` at the endpoint already removed
        # missing fields from ``data``. The previous ``is not None``
        # guard prevented operators from explicitly clearing nullable
        # columns (e.g. PATCH {"scope_ids": null}).
        for key, value in data.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
        if updated_by:
            rule.updated_by = updated_by
        await self.db.flush()
        await self.db.refresh(rule)
        logger.info("Updated alert rule %s", rule.id)
        return rule

    async def delete_rule(self, rule_id: UUID) -> bool:
        rule = await self.get_rule(rule_id)
        if not rule:
            return False
        rule.deleted_at = datetime.now(UTC)
        await self.db.flush()
        logger.info("Soft-deleted alert rule %s", rule.id)
        return True

    # ------------------------------------------------------------------
    # Alert CRUD
    # ------------------------------------------------------------------

    async def list_alerts(
        self,
        organization_id: UUID,
        status: str | None = None,
        severity: str | None = None,
        rule_id: UUID | None = None,
        site_id: UUID | None = None,
        limit: int = 50,
        offset: int = 0,
        current_user: Any | None = None,
    ) -> tuple[list[Alert], int]:
        stmt = select(Alert).where(Alert.organization_id == organization_id)
        if status:
            stmt = stmt.where(Alert.status == status)
        if severity:
            stmt = stmt.where(Alert.severity == severity)
        if rule_id:
            stmt = stmt.where(Alert.rule_id == rule_id)
        if site_id:
            stmt = stmt.where(Alert.site_id == site_id)
        # Per-user site grant: a site-limited caller only sees alerts in
        # granted sites (no-op for super_admin / org_admin / grant-less).
        if current_user is not None:
            stmt = stmt.where(site_scope_filter(current_user, Alert.site_id))
        stmt = stmt.order_by(Alert.fired_at.desc())

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await self.db.execute(count_stmt)).scalar_one()
        result = await self.db.execute(stmt.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def get_alert(self, alert_id: UUID) -> Alert | None:
        # ``Alert`` doesn't carry ``SoftDeleteMixin`` — accessing
        # ``Alert.deleted_at`` raised AttributeError at module-class
        # load and 500'd every GET /alerts/{id}, /acknowledge,
        # /resolve, /suppress request. Without the soft-delete column
        # there's nothing to filter on; the row either exists or
        # doesn't.
        result = await self.db.execute(select(Alert).where(Alert.id == alert_id))
        return result.scalar_one_or_none()

    async def acknowledge_alert(
        self,
        alert_id: UUID,
        user_id: UUID,
        note: str | None = None,
    ) -> Alert | None:
        alert = await self.get_alert(alert_id)
        if not alert or alert.status not in (AlertStatus.FIRING, AlertStatus.ACKNOWLEDGED):
            return None
        alert.status = AlertStatus.ACKNOWLEDGED
        alert.acknowledged_at = datetime.now(UTC)
        alert.acknowledged_by = user_id
        if note:
            alert.extra_metadata = {**(alert.extra_metadata or {}), "acknowledge_note": note}
        await self.db.flush()
        await self.db.refresh(alert)
        logger.info("Alert %s acknowledged by %s", alert_id, user_id)
        return alert

    async def resolve_alert(
        self,
        alert_id: UUID,
        user_id: UUID,
        note: str | None = None,
    ) -> Alert | None:
        alert = await self.get_alert(alert_id)
        if not alert or alert.status == AlertStatus.RESOLVED:
            return None
        alert.status = AlertStatus.RESOLVED
        alert.resolved_at = datetime.now(UTC)
        alert.resolved_by = user_id
        if note:
            alert.extra_metadata = {**(alert.extra_metadata or {}), "resolution_note": note}
        await self.db.flush()
        await self.db.refresh(alert)
        logger.info("Alert %s resolved by %s", alert_id, user_id)

        # --- Publish event ---
        try:
            event_bus = get_event_bus()
            await event_bus.publish(
                Event(
                    event_type="alert.resolved",
                    category=EventCategory.SECURITY,
                    priority=EventPriority.NORMAL,
                    organization_id=(str(alert.organization_id) if alert.organization_id else None),
                    payload={
                        "alert_id": str(alert.id),
                        "rule_id": str(alert.rule_id) if alert.rule_id else None,
                        "severity": alert.severity,
                        "title": alert.title,
                        "resolved_by": str(user_id),
                    },
                )
            )
        except Exception as e:
            logger.error("Failed to publish alert.resolved event: %s", e)

        # --- Notify on resolve if rule configured ---
        if alert.rule_id:
            try:
                rule = await self.get_rule(alert.rule_id)
                if rule and rule.notify_on_resolve and rule.notification_channels:
                    from app.services.notification_helpers import dispatch_notifications

                    await dispatch_notifications(
                        db=self.db,
                        channels_config=rule.notification_channels,
                        title=f"[RESOLVED] {alert.title}",
                        body=f"Alert has been resolved: {alert.title}",
                        organization_id=alert.organization_id,
                    )
            except Exception as e:
                logger.error("Failed to dispatch resolve notifications: %s", e)

        return alert

    async def suppress_alert(
        self,
        alert_id: UUID,
        suppress_minutes: int,
        reason: str | None = None,
    ) -> Alert | None:
        alert = await self.get_alert(alert_id)
        if not alert:
            return None
        alert.suppressed = True
        alert.suppressed_until = datetime.now(UTC) + timedelta(minutes=suppress_minutes)
        alert.suppression_reason = reason
        await self.db.flush()
        await self.db.refresh(alert)
        logger.info("Alert %s suppressed for %d minutes", alert_id, suppress_minutes)
        return alert

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    async def get_stats(
        self,
        organization_id: UUID,
        site_id: UUID | None = None,
        current_user: Any | None = None,
    ) -> dict[str, int]:
        now = datetime.now(UTC)
        day_ago = now - timedelta(hours=24)

        # Rule counts. AlertRule has no site_id column; its site targeting is
        # scope/scope_ids (app/models/alert_rules.py). Mirror list_rules so a
        # site-limited caller's rule counts are confined to site-scoped rules
        # targeting a granted site instead of leaking org-wide rule totals
        # No-op for unrestricted / org-admin / super_admin /
        # background callers (current_user is None or not site-limited).
        rule_base: list[Any] = [
            AlertRule.organization_id == organization_id,
            AlertRule.deleted_at.is_(None),
        ]
        if site_id:
            rule_base.append(
                or_(
                    AlertRule.scope == "organization",
                    AlertRule.scope_ids.op("@>")(cast([str(site_id)], PG_JSONB)),
                )
            )
        if current_user is not None and getattr(current_user, "is_site_limited", False):
            granted = list(getattr(current_user, "accessible_site_ids", None) or [])
            if granted:
                rule_base.append(AlertRule.scope == "site")
                rule_base.append(
                    or_(
                        *[
                            AlertRule.scope_ids.op("@>")(cast([str(sid)], PG_JSONB))
                            for sid in granted
                        ]
                    )
                )
            else:
                # Site-limited with no grants — fail closed.
                rule_base.append(AlertRule.id.is_(None))
        rule_counts = await self.db.execute(
            select(
                AlertRule.status,
                func.count(AlertRule.id),
            )
            .where(
                *rule_base,
            )
            .group_by(AlertRule.status)
        )
        rule_map: dict[str, int] = {}
        total_rules = 0
        for row in rule_counts.all():
            rule_map[row[0]] = row[1]
            total_rules += row[1]

        # Alert counts (alerts have site_id)
        alert_base: list[Any] = [Alert.organization_id == organization_id]
        if site_id:
            alert_base.append(Alert.site_id == site_id)
        # Per-user site grant: confine alert aggregates to granted sites for
        # a site-limited caller (no-op otherwise).
        if current_user is not None:
            alert_base.append(site_scope_filter(current_user, Alert.site_id))

        alert_counts = await self.db.execute(
            select(
                Alert.status,
                func.count(Alert.id),
            )
            .where(
                *alert_base,
            )
            .group_by(Alert.status)
        )
        alert_map: dict[str, int] = {}
        total_alerts = 0
        for row in alert_counts.all():
            alert_map[row[0]] = row[1]
            total_alerts += row[1]

        # Alerts in last 24h
        alerts_24h = (
            await self.db.execute(
                select(func.count(Alert.id)).where(
                    *alert_base,
                    Alert.fired_at >= day_ago,
                )
            )
        ).scalar_one()

        # Critical firing
        critical_firing = (
            await self.db.execute(
                select(func.count(Alert.id)).where(
                    *alert_base,
                    Alert.status == AlertStatus.FIRING,
                    Alert.severity == AlertSeverity.CRITICAL,
                )
            )
        ).scalar_one()

        return {
            "total_rules": total_rules,
            "active_rules": rule_map.get(AlertRuleStatus.ACTIVE, 0),
            "disabled_rules": rule_map.get(AlertRuleStatus.DISABLED, 0),
            "total_alerts": total_alerts,
            "firing_alerts": alert_map.get(AlertStatus.FIRING, 0),
            "acknowledged_alerts": alert_map.get(AlertStatus.ACKNOWLEDGED, 0),
            "alerts_last_24h": alerts_24h,
            "critical_firing": critical_firing,
        }

    # ------------------------------------------------------------------
    # Evaluation Engine
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_fingerprint(rule: AlertRule, context: dict[str, Any]) -> str:
        """Generate a dedup fingerprint for an alert from rule + context."""
        parts = [
            str(rule.id),
            rule.rule_type,
            str(context.get("site_id", "")),
            str(context.get("device_id", "")),
            str(context.get("metric", "")),
            str(context.get("event_type", "")),
        ]
        raw = "|".join(parts)
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    async def _find_existing_alert(
        self,
        rule: AlertRule,
        fingerprint: str,
    ) -> Alert | None:
        """Find an existing non-resolved alert with this fingerprint within the dedupe window."""
        cutoff = datetime.now(UTC) - timedelta(seconds=rule.dedupe_window_seconds)
        result = await self.db.execute(
            select(Alert)
            .where(
                Alert.rule_id == rule.id,
                Alert.fingerprint == fingerprint,
                Alert.status.in_([AlertStatus.FIRING, AlertStatus.ACKNOWLEDGED]),
                Alert.fired_at >= cutoff,
            )
            .order_by(Alert.fired_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def _fire_alert(
        self,
        rule: AlertRule,
        context: dict[str, Any],
    ) -> Alert | None:
        """Fire a new alert, increment an existing deduped one, or return None if in cooldown."""
        fingerprint = self._generate_fingerprint(rule, context)
        existing = await self._find_existing_alert(rule, fingerprint)
        now = datetime.now(UTC)

        if existing:
            # Deduplicate: increment count
            existing.occurrence_count += 1
            existing.last_occurrence_at = now
            await self.db.flush()
            logger.debug("Deduped alert %s (count=%d)", existing.id, existing.occurrence_count)
            return existing

        # Check cooldown
        if rule.last_fired_at:
            cooldown_until = rule.last_fired_at + timedelta(seconds=rule.cooldown_seconds)
            if now < cooldown_until:
                logger.debug("Rule %s in cooldown until %s", rule.id, cooldown_until)
                # Return a suppressed placeholder — don't actually fire
                return None

        # Fire new alert
        alert = Alert(
            organization_id=rule.organization_id,
            rule_id=rule.id,
            site_id=context.get("site_id"),
            device_id=context.get("device_id"),
            severity=rule.severity,
            title=f"[{rule.severity.upper()}] {rule.name}",
            message=context.get("message", f"Alert rule '{rule.name}' triggered"),
            details=context.get("details", {}),
            fingerprint=fingerprint,
            source="alert_engine",
            tags=rule.tags,
        )
        self.db.add(alert)

        # Update rule stats
        rule.last_fired_at = now
        rule.fire_count += 1

        await self.db.flush()
        await self.db.refresh(alert)
        logger.info("Fired alert %s for rule %s", alert.id, rule.name)

        # --- Dispatch notifications ---
        if rule.notification_channels:
            try:
                from app.services.notification_helpers import dispatch_notifications

                await dispatch_notifications(
                    db=self.db,
                    channels_config=rule.notification_channels,
                    title=alert.title,
                    body=alert.message,
                    organization_id=rule.organization_id,
                )
            except Exception as e:
                logger.error("Failed to dispatch alert notifications: %s", e)

        # --- Publish event ---
        try:
            event_bus = get_event_bus()
            await event_bus.publish(
                Event(
                    event_type="alert.fired",
                    category=EventCategory.SECURITY,
                    priority=EventPriority.HIGH,
                    organization_id=(str(rule.organization_id) if rule.organization_id else None),
                    payload={
                        "alert_id": str(alert.id),
                        "rule_id": str(rule.id),
                        "rule_name": rule.name,
                        "severity": alert.severity,
                        "title": alert.title,
                        "message": alert.message,
                        "device_id": str(alert.device_id) if alert.device_id else None,
                        "site_id": str(alert.site_id) if alert.site_id else None,
                    },
                )
            )
        except Exception as e:
            logger.error("Failed to publish alert.fired event: %s", e)

        return alert

    @staticmethod
    def _logdb_factory():
        """Return the LogDB session factory or ``None`` if not configured.

        ``EventRecord`` lives in the LogDB (TimescaleDB) instance, NOT
        the primary database. Earlier the evaluator used ``self.db``
        (primary) which raised ``UndefinedTableError`` on every
        threshold/pattern rule — caught by the per-rule try/except in
        ``evaluate_all_rules`` so the endpoint still 200'd with 0
        rules evaluated, but every rule logged a SQL stack trace on
        every check interval.
        """
        try:
            from app.db.session import get_logdb_factory

            return get_logdb_factory()
        except RuntimeError:
            return None

    async def _resolve_scope_site_ids(self, rule: AlertRule) -> list[Any] | None:
        """resolve a rule's scope to the OWNING site_ids that must
        confine its evaluator data reads.

        ``None`` = no site restriction (scope == "organization" / empty scope_ids
        → legitimately org-wide). For ``site`` scope the scope_ids ARE the sites;
        for ``device`` / ``device_group`` scope we resolve the owning sites of
        those devices/groups (via the main DB), so an evaluator never reads beyond
        the rule's anchored sites. ``_verify_scope_ids`` (endpoint) already pins a
        site-limited author's scope_ids inside their grant, so this confines every
        rule they create to their granted sites — closing the prior gap where
        device/device_group/anomaly evaluators read ORG-WIDE rows. A non-empty
        scope that resolves to zero live sites returns ``[]`` (fail closed).
        """
        scope = getattr(rule, "scope", None)
        raw = getattr(rule, "scope_ids", None) or []
        if scope == "organization" or scope is None or not raw:
            return None
        ids: list[Any] = []
        for s in raw:
            try:
                ids.append(UUID(str(s)))
            except (ValueError, TypeError):
                continue
        if scope == "site":
            return ids
        if scope == "device":
            from app.models.devices import Device

            rows = (await self.db.execute(select(Device.site_id).where(Device.id.in_(ids)))).all()
            return [r[0] for r in rows if r[0] is not None]
        if scope == "device_group":
            from app.models.enterprise import DeviceGroup

            rows = (
                await self.db.execute(select(DeviceGroup.site_id).where(DeviceGroup.id.in_(ids)))
            ).all()
            return [r[0] for r in rows if r[0] is not None]
        return []  # unknown scope → fail closed (no rows)

    @staticmethod
    def _site_in(site_ids: list[Any] | None, site_col: Any) -> list[Any]:
        """Predicate confining ``site_col`` to ``site_ids``; no-op when None
        (org-wide). An empty list yields ``IN ()`` → no rows (fail closed)."""
        return [site_col.in_(site_ids)] if site_ids is not None else []

    async def evaluate_threshold_rule(
        self,
        rule: AlertRule,
    ) -> list[Alert]:
        """Evaluate a threshold rule against recent events."""
        conditions = rule.conditions
        metric = conditions.get("metric", "")
        operator = conditions.get("operator", ">")
        threshold = conditions.get("value", 0)
        time_window = rule.check_interval_seconds or 300

        logdb_factory = self._logdb_factory()
        if logdb_factory is None:
            logger.debug("Skipping threshold rule %s: LogDB not configured", rule.id)
            return []

        # Look for recent events that carry metric data
        cutoff = datetime.now(UTC) - timedelta(seconds=time_window)
        scope_sites = await self._resolve_scope_site_ids(rule)
        stmt = select(EventRecord).where(
            EventRecord.organization_id == rule.organization_id,
            EventRecord.timestamp >= cutoff,
            EventRecord.event_type.like(f"%{metric.replace('%', '').replace('_', '')}%"),
            *self._site_in(scope_sites, EventRecord.site_id),
        )
        async with logdb_factory() as logdb:
            result = await logdb.execute(stmt.limit(500))
            events = list(result.scalars().all())

        fired: list[Alert] = []
        for event in events:
            payload_data: dict[str, Any] = event.payload or {}  # type: ignore[assignment]
            value = payload_data.get("value")
            if value is None:
                continue
            try:
                value = float(value)
            except (TypeError, ValueError):
                continue

            matched = False
            if (
                operator == ">"
                and value > threshold
                or operator == ">="
                and value >= threshold
                or operator == "<"
                and value < threshold
                or operator == "<="
                and value <= threshold
                or operator == "=="
                and value == threshold
                or operator == "!="
                and value != threshold
            ):
                matched = True

            if matched:
                alert = await self._fire_alert(
                    rule,
                    {
                        "site_id": event.site_id,
                        "device_id": payload_data.get("device_id"),
                        "metric": metric,
                        "message": f"{metric} is {value} (threshold: {operator} {threshold})",
                        "details": {
                            "metric": metric,
                            "value": value,
                            "threshold": threshold,
                            "operator": operator,
                            "event_id": str(event.id),
                        },
                    },
                )
                if alert:
                    fired.append(alert)

        return fired

    async def evaluate_pattern_rule(
        self,
        rule: AlertRule,
    ) -> list[Alert]:
        """Evaluate a pattern rule against event counts."""
        conditions = rule.conditions
        event_type = conditions.get("event_type", "")
        min_count = conditions.get("min_count", 1)
        time_window = rule.check_interval_seconds or 300

        logdb_factory = self._logdb_factory()
        if logdb_factory is None:
            logger.debug("Skipping pattern rule %s: LogDB not configured", rule.id)
            return []

        cutoff = datetime.now(UTC) - timedelta(seconds=time_window)
        scope_sites = await self._resolve_scope_site_ids(rule)
        stmt = (
            select(
                EventRecord.site_id,
                func.count(EventRecord.id).label("cnt"),
            )
            .where(
                EventRecord.organization_id == rule.organization_id,
                EventRecord.timestamp >= cutoff,
                EventRecord.event_type.like(event_type.replace("_", r"\_").replace("*", "%")),
                *self._site_in(scope_sites, EventRecord.site_id),
            )
            .group_by(EventRecord.site_id)
        )

        async with logdb_factory() as logdb:
            result = await logdb.execute(stmt)
            rows = result.all()
        fired: list[Alert] = []

        for row in rows:
            site_id, count = row
            if count >= min_count:
                alert = await self._fire_alert(
                    rule,
                    {
                        "site_id": site_id,
                        "event_type": event_type,
                        "message": f"{count} events matching '{event_type}' (threshold: {min_count})",
                        "details": {
                            "event_type": event_type,
                            "event_count": count,
                            "min_count": min_count,
                        },
                    },
                )
                if alert:
                    fired.append(alert)

        return fired

    async def evaluate_anomaly_rule(
        self,
        rule: AlertRule,
    ) -> list[Alert]:
        """Evaluate an anomaly rule via z-score against a metric baseline.

        Reads ``conditions.metric`` (the metric_name in
        ``analytics.metric_data``) and an optional
        ``conditions.std_dev_threshold`` (default 3.0). Pulls recent
        samples of that metric from the LogDB over a baseline window,
        computes the mean + stddev of the baseline, then flags the
        latest sample when it deviates by more than
        ``std_dev_threshold * stddev`` from the mean.

        Defensive on purpose: missing metric, no samples, fewer than 2
        baseline samples, or a zero-variance baseline all return ``[]``
        without firing or crashing — anomaly detection should never be
        a source of false positives or stack traces.
        """
        conditions = rule.conditions or {}
        metric = conditions.get("metric", "")
        if not metric:
            logger.debug("Skipping anomaly rule %s: no metric configured", rule.id)
            return []

        try:
            std_dev_threshold = float(conditions.get("std_dev_threshold", 3.0))
        except (TypeError, ValueError):
            std_dev_threshold = 3.0
        if std_dev_threshold <= 0:
            std_dev_threshold = 3.0

        # Baseline window: prefer an explicit window, else derive a wide
        # one from the check interval so we have enough samples to build
        # a meaningful mean/stddev (a single check_interval is usually
        # too short for a baseline).
        try:
            baseline_seconds = int(
                conditions.get("baseline_window_seconds")
                or (rule.check_interval_seconds or 300) * 20
            )
        except (TypeError, ValueError):
            baseline_seconds = (rule.check_interval_seconds or 300) * 20
        baseline_seconds = max(baseline_seconds, 300)

        logdb_factory = self._logdb_factory()
        if logdb_factory is None:
            logger.debug("Skipping anomaly rule %s: LogDB not configured", rule.id)
            return []

        # ``MetricDataPoint`` lives in the LogDB alongside ``EventRecord``.
        from app.models.analytics import MetricDataPoint

        cutoff = datetime.now(UTC) - timedelta(seconds=baseline_seconds)
        scope_sites = await self._resolve_scope_site_ids(rule)
        stmt = (
            select(MetricDataPoint.value, MetricDataPoint.site_id)
            .where(
                MetricDataPoint.organization_id == rule.organization_id,
                MetricDataPoint.metric_name == metric,
                MetricDataPoint.time >= cutoff,
                # confine the anomaly metric query to the rule's resolved
                # scope sites (previously read org-wide with no scope predicate).
                *self._site_in(scope_sites, MetricDataPoint.site_id),
            )
            .order_by(MetricDataPoint.time.asc())
            .limit(5000)
        )
        async with logdb_factory() as logdb:
            result = await logdb.execute(stmt)
            rows = result.all()

        if not rows:
            logger.debug("Anomaly rule %s: no samples for metric %s", rule.id, metric)
            return []

        # Build numeric series; the most-recent value is the candidate,
        # the rest form the baseline.
        series: list[float] = []
        latest_site_id = None
        for value, site_id in rows:
            try:
                series.append(float(value))
            except (TypeError, ValueError):
                continue
            latest_site_id = site_id  # rows are time-ascending → last wins

        if len(series) < 3:
            # Need at least 2 baseline points + 1 candidate for a
            # meaningful stddev.
            logger.debug("Anomaly rule %s: insufficient samples (%d)", rule.id, len(series))
            return []

        latest = series[-1]
        baseline = series[:-1]
        mean = statistics.mean(baseline)
        stddev = statistics.stdev(baseline)

        if stddev == 0:
            # Flat baseline — no variance, so z-score is undefined. Don't
            # fire (avoids dividing by zero and spurious alerts on
            # constant metrics).
            logger.debug("Anomaly rule %s: zero-variance baseline", rule.id)
            return []

        z_score = abs(latest - mean) / stddev
        if z_score <= std_dev_threshold:
            return []

        fired: list[Alert] = []
        alert = await self._fire_alert(
            rule,
            {
                "site_id": latest_site_id,
                "metric": metric,
                "message": (
                    f"{metric} = {latest:.4g} is anomalous "
                    f"(z={z_score:.2f} > {std_dev_threshold}, "
                    f"baseline mean={mean:.4g}, stddev={stddev:.4g})"
                ),
                "details": {
                    "metric": metric,
                    "value": latest,
                    "z_score": z_score,
                    "std_dev_threshold": std_dev_threshold,
                    "baseline_mean": mean,
                    "baseline_stddev": stddev,
                    "baseline_samples": len(baseline),
                    "baseline_window_seconds": baseline_seconds,
                },
            },
        )
        if alert:
            fired.append(alert)

        return fired

    async def evaluate_rule(self, rule: AlertRule) -> list[Alert]:
        """Evaluate a single alert rule and return any fired alerts."""
        now = datetime.now(UTC)

        if rule.rule_type == AlertRuleType.THRESHOLD:
            alerts = await self.evaluate_threshold_rule(rule)
        elif rule.rule_type == AlertRuleType.PATTERN:
            alerts = await self.evaluate_pattern_rule(rule)
        elif rule.rule_type == AlertRuleType.ANOMALY:
            alerts = await self.evaluate_anomaly_rule(rule)
        else:
            # Custom rules are extensible — skip for now
            logger.debug("Skipping rule %s (type=%s not yet implemented)", rule.id, rule.rule_type)
            alerts = []

        # Update last evaluated timestamp
        rule.last_evaluated_at = now
        await self.db.flush()

        return alerts

    async def evaluate_all_rules(
        self,
        organization_id: UUID,
        current_user: Any | None = None,
    ) -> dict[str, Any]:
        """Evaluate all active rules for an organization.

        Per-user site grant: a site-limited caller may only
        trigger evaluation of site-scoped rules targeting a site they can
        access — mirroring ``list_rules`` / ``get_stats``.
        Otherwise a ``site_admin`` (who holds default ``alert:update``)
        could fire alerts + burn notification quota for sibling-site /
        org-wide rules and read org-wide evaluated/fired counts. Org-wide
        and device-scoped rules are not site-resolvable here, so they are
        hidden (fail-closed). No-op for unrestricted / org-admin /
        super_admin / background callers (current_user is None or not
        site-limited) — they keep full org-wide evaluation.
        """
        # Eager-load the alerts relationship to avoid N+1 queries during
        # fingerprint dedup lookups in _find_existing_alert / _fire_alert.
        rule_filters: list[Any] = [
            AlertRule.organization_id == organization_id,
            AlertRule.status == AlertRuleStatus.ACTIVE,
            AlertRule.deleted_at.is_(None),
        ]
        if current_user is not None and getattr(current_user, "is_site_limited", False):
            granted = list(getattr(current_user, "accessible_site_ids", None) or [])
            if granted:
                rule_filters.append(AlertRule.scope == "site")
                rule_filters.append(
                    or_(
                        *[
                            AlertRule.scope_ids.op("@>")(cast([str(sid)], PG_JSONB))
                            for sid in granted
                        ]
                    )
                )
            else:
                # Site-limited with no grants — fail closed.
                rule_filters.append(AlertRule.id.is_(None))
        stmt = (
            select(AlertRule)
            .options(selectinload(AlertRule.alerts))
            .where(*rule_filters)
            .order_by(AlertRule.created_at.desc())
        )
        result = await self.db.execute(stmt)
        rules = list(result.scalars().all())

        total_fired = 0
        rules_evaluated = 0

        for rule in rules:
            try:
                fired = await self.evaluate_rule(rule)
                total_fired += len(fired)
                rules_evaluated += 1
            except Exception:
                logger.exception("Error evaluating rule %s", rule.id)

        logger.info(
            "Evaluation for org %s: %d rules evaluated, %d alerts fired",
            organization_id,
            rules_evaluated,
            total_fired,
        )
        return {
            "rules_evaluated": rules_evaluated,
            "alerts_fired": total_fired,
        }

    # ------------------------------------------------------------------
    # Auto-Resolution
    # ------------------------------------------------------------------

    async def auto_resolve_alerts(self, organization_id: UUID) -> int:
        """Resolve firing alerts whose auto-resolve window has elapsed."""
        now = datetime.now(UTC)

        # Get active rules with auto_resolve enabled
        rule_result = await self.db.execute(
            select(AlertRule).where(
                AlertRule.organization_id == organization_id,
                AlertRule.auto_resolve.is_(True),
                AlertRule.auto_resolve_after_seconds.isnot(None),
                AlertRule.deleted_at.is_(None),
            )
        )
        rules = list(rule_result.scalars().all())

        resolved_count = 0
        for rule in rules:
            cutoff = now - timedelta(seconds=rule.auto_resolve_after_seconds or 0)
            updated = await self.db.execute(
                update(Alert)
                .where(
                    Alert.rule_id == rule.id,
                    Alert.status.in_([AlertStatus.FIRING, AlertStatus.ACKNOWLEDGED]),
                    Alert.last_occurrence_at < cutoff,
                )
                .values(
                    status=AlertStatus.RESOLVED,
                    resolved_at=now,
                )
            )
            resolved_count += updated.rowcount  # type: ignore[attr-defined]

        if resolved_count:
            logger.info("Auto-resolved %d alerts for org %s", resolved_count, organization_id)
        return resolved_count

    async def unsuppress_expired(self) -> int:
        """Remove suppression from alerts whose suppression window expired."""
        now = datetime.now(UTC)
        result = await self.db.execute(
            update(Alert)
            .where(
                Alert.suppressed.is_(True),
                Alert.suppressed_until <= now,
            )
            .values(suppressed=False, suppressed_until=None)
        )
        count: int = result.rowcount  # type: ignore[attr-defined]
        if count:
            logger.info("Unsuppressed %d alerts", count)
        return count
