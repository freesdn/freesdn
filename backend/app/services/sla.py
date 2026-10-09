# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - SLA Monitoring Service
======================================

Evaluates SLA policies against health scores and metrics,
detects breaches, tracks compliance over time.
"""

import logging
import math
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events import Event, EventCategory, EventPriority, get_event_bus
from app.core.site_access import site_ids_for_request
from app.models.enterprise import DeviceHealth, HealthStatus
from app.models.sla import (
    SLABreach,
    SLABreachSeverity,
    SLABreachStatus,
    SLAPolicy,
    SLAPolicyScope,
    SLAPolicyStatus,
    SLASnapshot,
)

logger = logging.getLogger("freesdn.enterprise.sla")


class SLAMonitoringService:
    """Manages SLA policies, evaluates compliance, and tracks breaches."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------
    # Per-user site grant
    # ------------------------------------------------------------------

    @staticmethod
    def _policy_grant_predicate(current_user: Any | None = None) -> Any | None:
        """Predicate restricting site-scoped policies to the caller's grants.

        Returns ``None`` (no restriction) for unrestricted callers / system
        context. Otherwise it confines a site-limited caller to the
        policy scopes whose OWNING SITE is granted: ``site`` (scope_id is the
        site), and ``device_group`` / ``camera`` / ``nvr`` (whose owning site is
        resolved via a subquery on the resource's ``site_id``). Genuinely
        org-wide scopes with no single owning site (``organization``, ``ssid``)
        stay visible to org members. ``site_group`` spans multiple sites and may
        include siblings, so it is NOT visible to a site-limited caller (fail
        closed). The previous ``scope != site`` arm wrongly admitted every
        non-site scope, leaking sibling-site device_group/camera/nvr policies.

        Reads the request-scoped contextvar when ``current_user`` is omitted,
        so the periodic Celery evaluator (no request user) stays a no-op.
        """
        ids = site_ids_for_request(current_user)
        if ids is None:
            return None
        granted = list(ids)
        if not granted:
            # site-limited caller with no grants -> see nothing site-derived.
            return SLAPolicy.scope.in_([SLAPolicyScope.ORGANIZATION.value, "ssid"])

        from app.models.enterprise import DeviceGroup
        from app.modules.cameras.models import NVR, Camera

        return or_(
            # org-wide scopes (no single owning site): visible to org members.
            SLAPolicy.scope.in_([SLAPolicyScope.ORGANIZATION.value, "ssid"]),
            # site-anchored scopes: confine to the caller's granted sites.
            and_(
                SLAPolicy.scope == SLAPolicyScope.SITE.value,
                SLAPolicy.scope_id.in_(granted),
            ),
            and_(
                SLAPolicy.scope == "device_group",
                SLAPolicy.scope_id.in_(
                    select(DeviceGroup.id).where(DeviceGroup.site_id.in_(granted))
                ),
            ),
            and_(
                SLAPolicy.scope == "camera",
                SLAPolicy.scope_id.in_(select(Camera.id).where(Camera.site_id.in_(granted))),
            ),
            and_(
                SLAPolicy.scope == "nvr",
                SLAPolicy.scope_id.in_(select(NVR.id).where(NVR.site_id.in_(granted))),
            ),
        )

    # ------------------------------------------------------------------
    # Policy CRUD
    # ------------------------------------------------------------------

    async def list_policies(
        self,
        organization_id: UUID,
        status: str | None = None,
        scope: str | None = None,
        site_id: UUID | None = None,
        limit: int = 50,
        offset: int = 0,
        current_user: Any | None = None,
    ) -> tuple[list[SLAPolicy], int]:
        stmt = select(SLAPolicy).where(SLAPolicy.organization_id == organization_id)
        if status:
            stmt = stmt.where(SLAPolicy.status == status)
        if scope:
            stmt = stmt.where(SLAPolicy.scope == scope)
        grant = self._policy_grant_predicate(current_user)
        if grant is not None:
            stmt = stmt.where(grant)
        if site_id:
            stmt = stmt.where(
                or_(
                    SLAPolicy.scope == SLAPolicyScope.ORGANIZATION.value,
                    and_(
                        SLAPolicy.scope == SLAPolicyScope.SITE.value,
                        SLAPolicy.scope_id == site_id,
                    ),
                )
            )
        stmt = stmt.order_by(SLAPolicy.created_at.desc())

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await self.db.execute(count_stmt)).scalar_one()
        result = await self.db.execute(stmt.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def get_policy(self, policy_id: UUID) -> SLAPolicy | None:
        result = await self.db.execute(select(SLAPolicy).where(SLAPolicy.id == policy_id))
        return result.scalar_one_or_none()

    async def create_policy(
        self,
        organization_id: UUID,
        data: dict[str, Any],
        created_by: UUID | None = None,
    ) -> SLAPolicy:
        # Convert SLAThresholds model to dict if needed
        thresholds = data.get("thresholds", {})
        if hasattr(thresholds, "model_dump"):
            data["thresholds"] = thresholds.model_dump(exclude_none=True)

        policy = SLAPolicy(
            organization_id=organization_id,
            created_by=created_by,
            **data,
        )
        self.db.add(policy)
        await self.db.flush()
        return policy

    async def update_policy(self, policy_id: UUID, data: dict[str, Any]) -> SLAPolicy | None:
        policy = await self.get_policy(policy_id)
        if not policy:
            return None

        thresholds = data.get("thresholds")
        if thresholds and hasattr(thresholds, "model_dump"):
            data["thresholds"] = thresholds.model_dump(exclude_none=True)

        reset_observation = any(
            key in data and data[key] is not None and data[key] != getattr(policy, key)
            for key in (
                "status",
                "thresholds",
                "scope",
                "scope_id",
                "breach_after_consecutive",
                "evaluation_window_minutes",
            )
        )
        for key, value in data.items():
            if value is not None:
                setattr(policy, key, value)
        if reset_observation:
            policy.current_compliance_percent = None
            policy.last_evaluated_at = None
        await self.db.flush()
        return policy

    async def delete_policy(self, policy_id: UUID) -> bool:
        policy = await self.get_policy(policy_id)
        if not policy:
            return False
        await self.db.delete(policy)
        await self.db.flush()
        return True

    # ------------------------------------------------------------------
    # Breach Management
    # ------------------------------------------------------------------

    async def list_breaches(
        self,
        organization_id: UUID,
        policy_id: UUID | None = None,
        status: str | None = None,
        site_id: UUID | None = None,
        limit: int = 50,
        offset: int = 0,
        current_user: Any | None = None,
    ) -> tuple[list[SLABreach], int]:
        stmt = select(SLABreach).where(SLABreach.organization_id == organization_id)
        if policy_id:
            stmt = stmt.where(SLABreach.policy_id == policy_id)
        if status:
            stmt = stmt.where(SLABreach.status == status)
        if site_id and not policy_id:
            # Filter breaches whose policy is site-scoped to this site or org-wide
            # Skip when policy_id is provided — caller already scoped to a specific policy
            stmt = stmt.join(SLAPolicy, SLABreach.policy_id == SLAPolicy.id).where(
                or_(
                    SLAPolicy.scope == SLAPolicyScope.ORGANIZATION.value,
                    and_(
                        SLAPolicy.scope == SLAPolicyScope.SITE.value,
                        SLAPolicy.scope_id == site_id,
                    ),
                )
            )
        # Per-user site grant: a site-limited caller may only see breaches whose
        # owning policy is org-level or anchored to a granted site. Constrain
        # ``policy_id`` to an accessible-policy subquery rather than a join, so
        # the predicate composes whether or not the site_id-join above ran.
        grant = self._policy_grant_predicate(current_user)
        if grant is not None:
            accessible_policies = (
                select(SLAPolicy.id)
                .where(SLAPolicy.organization_id == organization_id)
                .where(grant)
                .scalar_subquery()
            )
            stmt = stmt.where(SLABreach.policy_id.in_(accessible_policies))
        stmt = stmt.order_by(SLABreach.started_at.desc())

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await self.db.execute(count_stmt)).scalar_one()
        result = await self.db.execute(stmt.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def acknowledge_breach(
        self,
        breach_id: UUID,
        user_id: UUID,
        notes: str | None = None,
        organization_id: UUID | None = None,
    ) -> SLABreach | None:
        conditions = [SLABreach.id == breach_id]
        if organization_id:
            conditions.append(SLABreach.organization_id == organization_id)
        result = await self.db.execute(select(SLABreach).where(*conditions))
        breach = result.scalar_one_or_none()
        if not breach:
            return None
        if breach.status == SLABreachStatus.RESOLVED.value:
            return breach

        breach.status = SLABreachStatus.ACKNOWLEDGED.value
        breach.acknowledged_at = datetime.now(UTC)
        breach.acknowledged_by = user_id
        if notes:
            breach.notes = notes
        await self.db.flush()
        return breach

    # ------------------------------------------------------------------
    # Compliance Evaluation
    # ------------------------------------------------------------------

    async def evaluate_all_policies(
        self,
        organization_id: UUID,
        current_user: Any | None = None,
    ) -> dict[str, Any]:
        """
        Evaluate all active SLA policies for an organization.

        For each policy:
          1. Gather relevant health scores based on scope
          2. Check each threshold
          3. Create/resolve breaches as needed
          4. Record compliance snapshot

        Per-user site grant: when triggered from a request by a site-limited
        operator, the evaluation (which mutates breaches + snapshots and fires
        notifications) must NOT fan out to sibling-site policies. Constrain the
        evaluated set to accessible policies. The periodic Celery evaluator runs
        in background context (no request user) → ``_policy_grant_predicate``
        returns ``None`` and the full org set is evaluated, unchanged.
        """
        now = datetime.now(UTC)

        stmt = select(SLAPolicy).where(
            SLAPolicy.organization_id == organization_id,
            SLAPolicy.status == SLAPolicyStatus.ACTIVE.value,
        )
        grant = self._policy_grant_predicate(current_user)
        if grant is not None:
            stmt = stmt.where(grant)
        # The scheduler and an operator may evaluate the same organization.
        # Keep each policy's read/update/create sequence in one transaction;
        # a concurrent pass skips policies already being evaluated.
        stmt = stmt.order_by(SLAPolicy.id).with_for_update(skip_locked=True)
        result = await self.db.execute(stmt.execution_options(populate_existing=True))
        policies = list(result.scalars().all())

        evaluated = 0
        breaches_created = 0
        breaches_resolved = 0

        for policy in policies:
            eval_result = await self._evaluate_policy(policy, now)
            evaluated += 1
            breaches_created += eval_result.get("breaches_created", 0)
            breaches_resolved += eval_result.get("breaches_resolved", 0)

        await self.db.commit()

        return {
            "policies_evaluated": evaluated,
            "breaches_created": breaches_created,
            "breaches_resolved": breaches_resolved,
        }

    async def _evaluate_policy(self, policy: SLAPolicy, now: datetime) -> dict[str, Any]:
        """Evaluate a single SLA policy against current metrics."""
        thresholds = {
            key: value for key, value in (policy.thresholds or {}).items() if value is not None
        }
        previous_evaluated_at = policy.last_evaluated_at
        previous_compliance = policy.current_compliance_percent
        # An evaluation attempt is not evidence of compliance. Clear stale
        # current values even when no configured target can be measured.
        policy.current_compliance_percent = None
        policy.last_evaluated_at = now
        if not thresholds:
            return {"breaches_created": 0, "breaches_resolved": 0}

        # Gather health data based on scope
        health_data = await self._gather_health_data(policy)

        if not health_data:
            return {"breaches_created": 0, "breaches_resolved": 0}

        required = max(1, min(policy.breach_after_consecutive or 1, 100))
        observations = {key: self._extract_metric(health_data, key) for key in thresholds}
        complete_observation = all(value is not None for value in observations.values())
        previous_metrics: dict[str, Any] = {}
        # A numeric snapshot exists only for a complete observation. Match the
        # previous attempt exactly so missing/partial passes break the sequence.
        # Legacy snapshots lack counter metadata and start a fresh sequence.
        if (
            required > 1
            and complete_observation
            and previous_compliance is not None
            and previous_evaluated_at is not None
        ):
            previous = await self.db.execute(
                select(SLASnapshot.metrics)
                .where(
                    SLASnapshot.policy_id == policy.id,
                    SLASnapshot.recorded_at == previous_evaluated_at,
                )
                .order_by(SLASnapshot.id)
                .limit(1)
            )
            previous_metrics = previous.scalar_one_or_none() or {}

        breaches_created = 0
        breaches_resolved = 0
        metrics_snapshot = {}
        any_breach = False
        breached_metric_count = 0

        # Acknowledged incidents remain unresolved. Keep every matching row
        # so historical duplicates also recover; do not silently discard one.
        _active_rows = await self.db.execute(
            select(SLABreach).where(
                SLABreach.policy_id == policy.id,
                SLABreach.status.in_(
                    [SLABreachStatus.ACTIVE.value, SLABreachStatus.ACKNOWLEDGED.value]
                ),
            )
        )
        active_breaches: dict[str, list[SLABreach]] = {}
        for breach_row in _active_rows.scalars():
            active_breaches.setdefault(breach_row.violated_metric, []).append(breach_row)

        # Evaluate each threshold
        for metric_name, threshold_value in thresholds.items():
            if threshold_value is None:
                continue

            actual_value = observations[metric_name]
            if actual_value is None:
                continue

            metrics_snapshot[metric_name] = {
                "threshold": threshold_value,
                "actual": actual_value,
            }

            is_violated = self._is_threshold_violated(metric_name, threshold_value, actual_value)
            consecutive = 0
            if is_violated:
                previous_metric = previous_metrics.get(metric_name, {})
                prior_count = previous_metric.get("consecutive_violations", 0)
                if (
                    previous_metric.get("threshold") != threshold_value
                    or previous_metric.get("required_consecutive") != required
                    or type(prior_count) is not int
                    or prior_count < 0
                ):
                    prior_count = 0
                consecutive = min(required, prior_count + 1)
            metrics_snapshot[metric_name]["consecutive_violations"] = consecutive
            metrics_snapshot[metric_name]["required_consecutive"] = required

            if is_violated:
                breached_metric_count += 1
                deviation = abs(actual_value - threshold_value) / max(threshold_value, 0.01) * 100

                # Check for existing active breach on this metric (fetched once)
                existing_breaches = active_breaches.get(metric_name, [])
                if not existing_breaches and consecutive < required:
                    continue
                any_breach = True

                if not existing_breaches:
                    severity = (
                        SLABreachSeverity.CRITICAL.value
                        if deviation > 20
                        else SLABreachSeverity.WARNING.value
                    )
                    breach = SLABreach(
                        policy_id=policy.id,
                        organization_id=policy.organization_id,
                        severity=severity,
                        violated_metric=metric_name,
                        threshold_value=threshold_value,
                        actual_value=actual_value,
                        deviation_percent=round(deviation, 2),
                        context={
                            "scope": policy.scope,
                            "scope_id": str(policy.scope_id) if policy.scope_id else None,
                            "all_metrics": metrics_snapshot,
                        },
                    )
                    self.db.add(breach)
                    active_breaches[metric_name] = [breach]
                    breaches_created += 1

                    # Notify on new breach
                    if policy.notification_channels:
                        try:
                            from app.services.notification_helpers import dispatch_notifications

                            await dispatch_notifications(
                                db=self.db,
                                channels_config=policy.notification_channels,
                                title=f"SLA Breach: {policy.name} - {metric_name}",
                                body=(
                                    f"SLA policy '{policy.name}' breached on {metric_name}. "
                                    f"Threshold: {threshold_value}, Actual: {actual_value} "
                                    f"(deviation: {round(deviation, 1)}%)"
                                ),
                                organization_id=policy.organization_id,
                            )
                        except Exception as e:
                            logger.error("Failed to dispatch SLA breach notifications: %s", e)

                    # Publish event
                    try:
                        event_bus = get_event_bus()
                        await event_bus.publish(
                            Event(
                                event_type="sla.breach.created",
                                category=EventCategory.SYSTEM,
                                priority=EventPriority.HIGH,
                                payload={
                                    "policy_id": str(policy.id),
                                    "policy_name": policy.name,
                                    "severity": severity,
                                    "violated_metric": metric_name,
                                    "threshold_value": threshold_value,
                                    "actual_value": actual_value,
                                    "deviation_percent": round(deviation, 2),
                                    "organization_id": str(policy.organization_id),
                                },
                            )
                        )
                    except Exception as e:
                        logger.error("Failed to publish sla.breach.created event: %s", e)
                else:
                    for existing_breach in existing_breaches:
                        existing_breach.actual_value = actual_value
                        existing_breach.deviation_percent = round(deviation, 2)
            else:
                # Metric is compliant — resolve any active breach (fetched once)
                for existing_breach in active_breaches.get(metric_name, []):
                    existing_breach.status = SLABreachStatus.RESOLVED.value
                    existing_breach.resolved_at = now
                    existing_breach.duration_minutes = int(
                        (now - existing_breach.started_at).total_seconds() / 60
                    )
                    breaches_resolved += 1

                    # Publish resolve event
                    try:
                        event_bus = get_event_bus()
                        await event_bus.publish(
                            Event(
                                event_type="sla.breach.resolved",
                                category=EventCategory.SYSTEM,
                                priority=EventPriority.NORMAL,
                                payload={
                                    "policy_id": str(policy.id),
                                    "policy_name": policy.name,
                                    "violated_metric": metric_name,
                                    "duration_minutes": existing_breach.duration_minutes,
                                    "organization_id": str(policy.organization_id),
                                },
                            )
                        )
                    except Exception as e:
                        logger.error("Failed to publish sla.breach.resolved event: %s", e)

        # Breaches from measured targets still matter when other targets are
        # unavailable. Missing targets are neither successes nor recoveries;
        # do not manufacture a whole-policy percentage or numeric snapshot.
        if len(metrics_snapshot) != len(thresholds):
            return {
                "breaches_created": breaches_created,
                "breaches_resolved": breaches_resolved,
            }
        total_metrics = len(thresholds)
        compliant_metrics = total_metrics - breached_metric_count
        compliance_pct = compliant_metrics / total_metrics * 100

        # Update policy stats
        policy.current_compliance_percent = round(compliance_pct, 2)
        policy.last_evaluated_at = now

        # Record snapshot
        self.db.add(
            SLASnapshot(
                policy_id=policy.id,
                recorded_at=now,
                compliance_percent=round(compliance_pct, 2),
                metrics=metrics_snapshot,
                in_breach=any_breach,
            )
        )

        return {
            "breaches_created": breaches_created,
            "breaches_resolved": breaches_resolved,
        }

    async def _gather_health_data(self, policy: SLAPolicy) -> dict[str, Any]:
        """Gather aggregated health metrics based on policy scope."""
        if policy.scope == SLAPolicyScope.SITE.value and policy.scope_id:
            # Average health for all devices in this site
            result = await self.db.execute(
                select(
                    func.avg(DeviceHealth.measured_score),
                    func.count(DeviceHealth.id),
                    func.count().filter(DeviceHealth.health_status == HealthStatus.HEALTHY.value),
                    func.count().filter(DeviceHealth.health_status == HealthStatus.CRITICAL.value),
                ).where(
                    DeviceHealth.site_id == policy.scope_id,
                    DeviceHealth.organization_id == policy.organization_id,
                )
            )
            row = result.one_or_none()
            if row is None or row[0] is None:
                return {}
            return {
                "avg_health_score": float(row[0]),
                "total_devices": row[1],
                "healthy_count": row[2],
                "critical_count": row[3],
            }

        elif policy.scope == SLAPolicyScope.ORGANIZATION.value:
            result = await self.db.execute(
                select(
                    func.avg(DeviceHealth.measured_score),
                    func.count(DeviceHealth.id),
                ).where(DeviceHealth.organization_id == policy.organization_id)
            )
            row = result.one_or_none()
            if row is None or row[0] is None:
                return {}
            return {
                "avg_health_score": float(row[0]),
                "total_devices": row[1],
            }

        elif policy.scope == SLAPolicyScope.CAMERA.value and policy.scope_id:
            # Real availability uptime from CameraHealthSnapshot.is_online over
            # the policy's evaluation window (the snapshots are written every
            # 60s by the poll_camera_health task). uptime% = online/total.
            from app.modules.cameras.models import CameraHealthSnapshot

            window = policy.evaluation_window_minutes or 60
            since = datetime.now(UTC) - timedelta(minutes=window)
            result = await self.db.execute(
                select(
                    func.count(CameraHealthSnapshot.id),
                    func.count().filter(CameraHealthSnapshot.is_online.is_(True)),
                ).where(
                    CameraHealthSnapshot.camera_id == policy.scope_id,
                    # Re-assert tenancy independently of the create-time scope
                    # check — index-backed, zero behaviour change.
                    CameraHealthSnapshot.organization_id == policy.organization_id,
                    CameraHealthSnapshot.captured_at >= since,
                )
            )
            row = result.one_or_none()
            total = row[0] if row else 0
            if row is None or not total:
                return {}
            online = row[1] or 0
            uptime = float(online) / float(total) * 100.0
            return {
                "uptime_percent": uptime,
                "total_snapshots": total,
                "online_snapshots": online,
                "total_devices": 1,
            }

        elif policy.scope == SLAPolicyScope.NVR.value and policy.scope_id:
            # All cameras on one NVR: join snapshots through Camera.nvr_id
            # (CameraHealthSnapshot has no nvr_id of its own).
            from app.modules.cameras.models import Camera, CameraHealthSnapshot

            window = policy.evaluation_window_minutes or 60
            since = datetime.now(UTC) - timedelta(minutes=window)
            result = await self.db.execute(
                select(
                    func.count(CameraHealthSnapshot.id),
                    func.count().filter(CameraHealthSnapshot.is_online.is_(True)),
                    func.count(func.distinct(CameraHealthSnapshot.camera_id)),
                )
                .select_from(CameraHealthSnapshot)
                .join(Camera, Camera.id == CameraHealthSnapshot.camera_id)
                .where(
                    Camera.nvr_id == policy.scope_id,
                    Camera.organization_id == policy.organization_id,
                    CameraHealthSnapshot.captured_at >= since,
                )
            )
            row = result.one_or_none()
            total = row[0] if row else 0
            if row is None or not total:
                return {}
            online = row[1] or 0
            uptime = float(online) / float(total) * 100.0
            return {
                "uptime_percent": uptime,
                "total_snapshots": total,
                "online_snapshots": online,
                "total_devices": row[2] or 0,
            }

        # Fallback — org-wide
        return {}

    def _extract_metric(self, health_data: dict[str, Any], metric_name: str) -> float | None:
        """Extract a metric value from health data for threshold comparison."""
        metric_map = {
            "health_score_min": "avg_health_score",
            "uptime_percent_min": "uptime_percent",
            "latency_ms_max": "avg_latency_ms",
            "packet_loss_percent_max": "avg_packet_loss",
            "client_satisfaction_min": "client_satisfaction",
            "error_rate_max": "error_rate",
        }
        key = metric_map.get(metric_name, metric_name)
        value = health_data.get(key)
        if value is None:
            return None
        measured = float(value)
        return measured if math.isfinite(measured) else None

    def _is_threshold_violated(self, metric_name: str, threshold: float, actual: float) -> bool:
        """Check if a metric violates its threshold (min or max)."""
        if metric_name.endswith("_min"):
            return actual < threshold
        elif metric_name.endswith("_max"):
            return actual > threshold
        return False

    async def _find_active_breach(self, policy_id: UUID, metric: str) -> SLABreach | None:
        result = await self.db.execute(
            select(SLABreach)
            .where(
                SLABreach.policy_id == policy_id,
                SLABreach.violated_metric == metric,
                SLABreach.status.in_(
                    [SLABreachStatus.ACTIVE.value, SLABreachStatus.ACKNOWLEDGED.value]
                ),
            )
            .order_by(SLABreach.started_at, SLABreach.id)
            .limit(1)
        )
        return result.scalar_one_or_none()

    # ------------------------------------------------------------------
    # Compliance Summary
    # ------------------------------------------------------------------

    async def get_compliance_summary(
        self,
        organization_id: UUID,
        site_id: UUID | None = None,
        current_user: Any | None = None,
    ) -> dict[str, Any]:
        """Get org-wide SLA compliance overview, optionally scoped to a site."""
        now = datetime.now(UTC)
        day_ago = now - timedelta(hours=24)

        # Build policy scope filter
        policy_base = [SLAPolicy.organization_id == organization_id]
        if site_id:
            policy_base.append(
                or_(
                    SLAPolicy.scope == SLAPolicyScope.ORGANIZATION.value,
                    and_(
                        SLAPolicy.scope == SLAPolicyScope.SITE.value,
                        SLAPolicy.scope_id == site_id,
                    ),
                )
            )
        # Per-user site grant: a site-limited caller's org-wide rollup must
        # exclude site-scoped policies for ungranted sibling sites.
        _grant = self._policy_grant_predicate(current_user)
        if _grant is not None:
            policy_base.append(_grant)
            # Subquery of the policies this caller may see, to constrain the raw
            # SLABreach counts below (which otherwise only join SLAPolicy when an
            # explicit site_id is supplied).
            _accessible_policies = (
                select(SLAPolicy.id)
                .where(SLAPolicy.organization_id == organization_id)
                .where(_grant)
                .scalar_subquery()
            )
        else:
            _accessible_policies = None

        total = (await self.db.execute(select(func.count()).where(*policy_base))).scalar_one()

        active = (
            await self.db.execute(
                select(func.count()).where(
                    *policy_base,
                    SLAPolicy.status == SLAPolicyStatus.ACTIVE.value,
                )
            )
        ).scalar_one()

        # Breach filter: join to policy to scope by site
        breach_stmt = (
            select(func.count())
            .select_from(SLABreach)
            .where(
                SLABreach.organization_id == organization_id,
                SLABreach.status.in_(
                    [SLABreachStatus.ACTIVE.value, SLABreachStatus.ACKNOWLEDGED.value]
                ),
            )
        )
        if site_id:
            breach_stmt = breach_stmt.join(SLAPolicy, SLABreach.policy_id == SLAPolicy.id).where(
                or_(
                    SLAPolicy.scope == SLAPolicyScope.ORGANIZATION.value,
                    and_(
                        SLAPolicy.scope == SLAPolicyScope.SITE.value,
                        SLAPolicy.scope_id == site_id,
                    ),
                )
            )
        if _accessible_policies is not None:
            breach_stmt = breach_stmt.where(SLABreach.policy_id.in_(_accessible_policies))
        active_breaches = (await self.db.execute(breach_stmt)).scalar_one()

        avg_compliance = (
            await self.db.execute(
                select(func.avg(SLAPolicy.current_compliance_percent)).where(
                    *policy_base,
                    SLAPolicy.status == SLAPolicyStatus.ACTIVE.value,
                    SLAPolicy.current_compliance_percent.isnot(None),
                )
            )
        ).scalar_one_or_none()

        breaches_24h_stmt = (
            select(func.count())
            .select_from(SLABreach)
            .where(
                SLABreach.organization_id == organization_id,
                SLABreach.started_at >= day_ago,
            )
        )
        if site_id:
            breaches_24h_stmt = breaches_24h_stmt.join(
                SLAPolicy, SLABreach.policy_id == SLAPolicy.id
            ).where(
                or_(
                    SLAPolicy.scope == SLAPolicyScope.ORGANIZATION.value,
                    and_(
                        SLAPolicy.scope == SLAPolicyScope.SITE.value,
                        SLAPolicy.scope_id == site_id,
                    ),
                )
            )
        if _accessible_policies is not None:
            breaches_24h_stmt = breaches_24h_stmt.where(
                SLABreach.policy_id.in_(_accessible_policies)
            )
        breaches_24h = (await self.db.execute(breaches_24h_stmt)).scalar_one()

        # Worst policy
        worst_result = await self.db.execute(
            select(SLAPolicy)
            .where(
                *policy_base,
                SLAPolicy.status == SLAPolicyStatus.ACTIVE.value,
                SLAPolicy.current_compliance_percent.isnot(None),
            )
            .order_by(SLAPolicy.current_compliance_percent.asc())
            .limit(1)
        )
        worst_policy = worst_result.scalar_one_or_none()

        # Recent compliance trend (last 24h snapshots for scoped policies)
        trend_stmt = (
            select(SLASnapshot)
            .join(SLAPolicy, SLASnapshot.policy_id == SLAPolicy.id)
            .where(
                *policy_base,
                SLASnapshot.recorded_at >= day_ago,
            )
            .order_by(SLASnapshot.recorded_at.desc())
            .limit(100)
        )
        trend_result = await self.db.execute(trend_stmt)
        trend = list(trend_result.scalars().all())

        return {
            "total_policies": total,
            "active_policies": active,
            "active_breaches": active_breaches,
            "avg_compliance_percent": round(float(avg_compliance), 2)
            if avg_compliance is not None
            else None,
            "worst_policy": worst_policy,
            "breaches_last_24h": breaches_24h,
            "compliance_trend": trend,
        }
