# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Enterprise Services
==================================

Core business logic for the enterprise config management layer:
  - Template resolution (hierarchy merge)
  - Device lifecycle state machine
  - Health score computation
  - Desired-state reconciliation loop
  - Deep-merge utility
"""

from __future__ import annotations

import copy
import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redaction import redact_secrets
from app.models.devices import Device
from app.models.enterprise import (
    LIFECYCLE_TRANSITIONS,
    BulkOperation,
    BulkOperationStatus,
    ConfigPushResult,
    ConfigTemplate,
    DeviceConfig,
    DeviceGroupMembership,
    DeviceHealth,
    DeviceLifecycleLog,
    LifecycleState,
    LifecycleTrigger,
    SiteGroup,
    TemplateScope,
)

logger = logging.getLogger("freesdn.enterprise")


# ==========================================================================
# Deep Merge Utility
# ==========================================================================


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """
    Recursively merge *override* into *base*, returning a new dict.

    - Dicts are merged recursively.
    - Lists, scalars, and other types are replaced entirely by *override*.
    - Keys present only in *base* are preserved.
    """
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


# ==========================================================================
# Config Template Resolver
# ==========================================================================


class TemplateResolver:
    """
    Resolves the desired_config for a device by merging templates
    through the hierarchy: Org → Site Group → Site → Device Group → Device.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def resolve(self, device: Device) -> dict[str, Any]:
        """
        Walk the template hierarchy and produce the resolved desired_config.

        Merge order (each level overrides the previous):
          1. Organization-level templates
          2. Site Group-level templates (if site belongs to a group)
          3. Site-level templates
          4. Device Group-level templates (for each group the device belongs to)
          5. Per-device overrides (from DeviceConfig.device_overrides)

        Returns resolved config dict.
        Also populates self.template_chain with applied template names.
        """
        config: dict[str, Any] = {}
        self.template_chain: list[str] = []

        # Resolve the org_id from the site relationship
        org_id = device.site.organization_id if device.site else None
        if not org_id:
            return config

        # 1. Organization templates
        org_templates = await self._get_templates(
            org_id=org_id,
            scope=TemplateScope.ORGANIZATION,
            scope_id=None,
            device_type=device.device_type,
        )
        for t in org_templates:
            config = deep_merge(config, t.config)
            self.template_chain.append(f"[org] {t.name}")

        # 2. Site Group templates
        site_group_id = getattr(device.site, "site_group_id", None)
        if site_group_id:
            # Walk up the site group hierarchy (child → parent → grandparent)
            sg_chain = await self._get_site_group_chain(site_group_id)
            for sg_id in sg_chain:  # already ordered root → leaf
                sg_templates = await self._get_templates(
                    org_id=org_id,
                    scope=TemplateScope.SITE_GROUP,
                    scope_id=sg_id,
                    device_type=device.device_type,
                )
                for t in sg_templates:
                    config = deep_merge(config, t.config)
                    self.template_chain.append(f"[site_group] {t.name}")

        # 3. Site templates
        site_templates = await self._get_templates(
            org_id=org_id,
            scope=TemplateScope.SITE,
            scope_id=device.site_id,
            device_type=device.device_type,
        )
        for t in site_templates:
            config = deep_merge(config, t.config)
            self.template_chain.append(f"[site] {t.name}")

        # 4. Device Group templates
        group_ids = await self._get_device_group_ids(device.id)
        for gid in group_ids:
            dg_templates = await self._get_templates(
                org_id=org_id,
                scope=TemplateScope.DEVICE_GROUP,
                scope_id=gid,
                device_type=device.device_type,
            )
            for t in dg_templates:
                config = deep_merge(config, t.config)
                self.template_chain.append(f"[device_group] {t.name}")

        # 5. Per-device overrides
        dc_result = await self.db.execute(
            select(DeviceConfig).where(DeviceConfig.device_id == device.id)
        )
        dc = dc_result.scalar_one_or_none()
        if dc and dc.device_overrides:
            config = deep_merge(config, dc.device_overrides)
            self.template_chain.append("[device_overrides]")

        return config

    # ── Private Helpers ──

    async def _get_templates(
        self,
        org_id: UUID,
        scope: TemplateScope,
        scope_id: UUID | None,
        device_type: str | None,
    ) -> Sequence[ConfigTemplate]:
        """Fetch active templates for a given scope, ordered by priority."""
        conditions = [
            ConfigTemplate.organization_id == org_id,
            ConfigTemplate.scope == scope,
            ConfigTemplate.is_active == True,  # noqa: E712
            ConfigTemplate.deleted_at == None,  # noqa: E711
        ]
        if scope_id is not None:
            conditions.append(ConfigTemplate.scope_id == scope_id)
        else:
            conditions.append(ConfigTemplate.scope_id == None)  # noqa: E711

        # Match device_type or templates with device_type=NULL (applies to all)
        if device_type:
            conditions.append(
                (ConfigTemplate.device_type == device_type) | (ConfigTemplate.device_type == None)  # noqa: E711
            )
        else:
            conditions.append(ConfigTemplate.device_type == None)  # noqa: E711

        result = await self.db.execute(
            select(ConfigTemplate).where(and_(*conditions)).order_by(ConfigTemplate.priority.asc())
        )
        return result.scalars().all()

    async def _get_site_group_chain(self, sg_id: UUID) -> list[UUID]:
        """Walk parent_id chain and return IDs ordered root → leaf."""
        chain: list[UUID] = []
        current_id: UUID | None = sg_id
        seen: set[UUID] = set()
        while current_id and current_id not in seen:
            seen.add(current_id)
            chain.append(current_id)
            result = await self.db.execute(
                select(SiteGroup.parent_id).where(SiteGroup.id == current_id)
            )
            current_id = result.scalar_one_or_none()
        chain.reverse()  # root first
        return chain

    async def _get_device_group_ids(self, device_id: UUID) -> list[UUID]:
        """Get IDs of all groups a device belongs to (explicit membership)."""
        result = await self.db.execute(
            select(DeviceGroupMembership.group_id).where(
                DeviceGroupMembership.device_id == device_id
            )
        )
        return list(result.scalars().all())


# ==========================================================================
# Device Lifecycle State Machine
# ==========================================================================


class LifecycleService:
    """
    Enforces the device lifecycle FSM and logs all transitions.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def transition(
        self,
        device: Device,
        to_state: LifecycleState,
        trigger: LifecycleTrigger,
        triggered_by: UUID | None = None,
        details: dict[str, Any] | None = None,
        error_message: str | None = None,
    ) -> Device:
        """
        Transition a device to a new lifecycle state.

        Validates the transition is legal, updates the device,
        and writes an audit log entry.

        Raises:
            ValueError: if the transition is not allowed
        """
        from_state = LifecycleState(device.lifecycle_state)
        allowed = LIFECYCLE_TRANSITIONS.get(from_state, set())

        if to_state not in allowed:
            raise ValueError(
                f"Invalid lifecycle transition: {from_state} → {to_state}. "
                f"Allowed: {sorted(s.value for s in allowed)}"
            )

        now = datetime.now(UTC)

        # Update device
        device.lifecycle_state = to_state.value
        device.lifecycle_changed_at = now
        device.lifecycle_error = error_message if to_state == LifecycleState.ERROR else None

        # Auto-set management flags based on state
        if to_state == LifecycleState.MANAGED:
            device.is_managed = True
            device.is_adopted = True
            device.adopted_at = device.adopted_at or now
        elif to_state == LifecycleState.DECOMMISSIONED or to_state == LifecycleState.IGNORED:
            device.is_managed = False

        # Write audit log
        log_entry = DeviceLifecycleLog(
            device_id=device.id,
            organization_id=device.site.organization_id,
            from_state=from_state,
            to_state=to_state,
            trigger=trigger,
            triggered_by=triggered_by,
            details=details,
        )
        self.db.add(log_entry)

        logger.info(
            "Device %s lifecycle: %s → %s (trigger=%s)",
            device.id,
            from_state,
            to_state,
            trigger,
        )
        return device


# ==========================================================================
# Health Score Computation
# ==========================================================================

# Weight configuration
HEALTH_WEIGHTS = {
    "reachability": 30,
    "latency": 15,
    "drift": 20,
    "error": 15,
    "utilization": 10,
    "firmware": 10,
}


class HealthService:
    """
    Computes composite health scores from multiple signals.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def compute_device_health(
        self,
        device: Device,
        *,
        reachability_score: int | None = None,
        latency_score: int | None = None,
        drift_score: int | None = None,
        error_score: int | None = None,
        utilization_score: int | None = None,
        firmware_score: int | None = None,
    ) -> DeviceHealth:
        """
        Compute and persist the health score for a device.

        Any score not provided is left at its previous value.
        Returns the updated DeviceHealth row.
        """
        result = await self.db.execute(
            select(DeviceHealth).where(DeviceHealth.device_id == device.id)
        )
        health = result.scalar_one_or_none()

        if health is None:
            health = DeviceHealth(
                device_id=device.id,
                organization_id=device.site.organization_id,
                site_id=device.site_id,
            )
            self.db.add(health)

        # Update component scores (keep previous if not provided)
        if reachability_score is not None:
            health.reachability_score = reachability_score
        if latency_score is not None:
            health.latency_score = latency_score
        if drift_score is not None:
            health.drift_score = drift_score
        if error_score is not None:
            health.error_score = error_score
        if utilization_score is not None:
            health.utilization_score = utilization_score
        if firmware_score is not None:
            health.firmware_score = firmware_score

        # Compute weighted average of available scores
        total_weight = 0
        weighted_sum = 0
        for key, weight in HEALTH_WEIGHTS.items():
            score = getattr(health, f"{key}_score", None)
            if score is not None:
                total_weight += weight
                weighted_sum += score * weight

        if total_weight > 0:
            health.health_score = round(weighted_sum / total_weight)
        else:
            health.health_score = 100  # no data = assume healthy

        health.health_status = DeviceHealth.compute_status(health.health_score)
        health.updated_at = datetime.now(UTC)

        # Append to sparkline history (keep last 288 entries = 24h at 5-min intervals)
        history = list(health.score_history) if health.score_history else []
        history.append(
            {
                "t": health.updated_at.isoformat(),
                "s": health.health_score,
            }
        )
        if len(history) > 288:
            history = history[-288:]
        health.score_history = history

        return health

    @staticmethod
    def score_reachability(is_online: bool, flap_count_last_hour: int = 0) -> int:
        """Score reachability: 100=up, 0=down, penalize flapping."""
        if not is_online:
            return 0
        # Each flap in the last hour costs 10 points
        return max(0, 100 - (flap_count_last_hour * 10))

    @staticmethod
    def score_latency(avg_ms: float | None) -> int:
        """Score latency: <10ms=100, >500ms=0, linear interpolation."""
        if avg_ms is None:
            return 100  # no data = assume good
        if avg_ms <= 10:
            return 100
        if avg_ms >= 500:
            return 0
        return round(100 - ((avg_ms - 10) / 490) * 100)

    @staticmethod
    def score_drift(has_drift: bool) -> int:
        """Score config drift: 100=no drift, 0=drifted."""
        return 0 if has_drift else 100

    @staticmethod
    def score_utilization(cpu_pct: float | None = None, mem_pct: float | None = None) -> int:
        """Score resource utilization. Uses worst of CPU/memory."""
        scores = []
        for pct in (cpu_pct, mem_pct):
            if pct is not None:
                if pct <= 80:
                    scores.append(100)
                elif pct >= 95:
                    scores.append(0)
                else:
                    scores.append(round(100 - ((pct - 80) / 15) * 100))
        return min(scores) if scores else 100

    @staticmethod
    def score_firmware(is_latest: bool, versions_behind: int = 0) -> int:
        """Score firmware currency."""
        if is_latest:
            return 100
        if versions_behind <= 1:
            return 70
        if versions_behind <= 3:
            return 40
        return 0  # very outdated or EOL


# ==========================================================================
# Reconciliation Service
# ==========================================================================


class ReconciliationService:
    """
    The reconciliation loop: compares desired_config vs running_config
    for each device and either reports or auto-fixes drift.

    Used by the Celery periodic task.
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.template_resolver = TemplateResolver(db)
        self.health_service = HealthService(db)
        self.lifecycle_service = LifecycleService(db)

    async def reconcile_device(
        self,
        device: Device,
        adapter: Any,  # BaseAdapter instance (avoid circular import)
    ) -> dict[str, Any]:
        """
        Reconcile a single device's config against desired state.

        Steps:
          1. Resolve desired_config from template hierarchy
          2. Read running_config from device via adapter
          3. Compute drift
          4. If drift and auto_remediate: push desired_config
          5. Update health score
          6. Return result summary

        Returns:
            dict with keys: status, drift, push_result
        """
        # Get or create DeviceConfig
        dc_result = await self.db.execute(
            select(DeviceConfig).where(DeviceConfig.device_id == device.id)
        )
        dc = dc_result.scalar_one_or_none()
        if dc is None:
            dc = DeviceConfig(
                device_id=device.id,
                organization_id=device.site.organization_id,
            )
            self.db.add(dc)

        now = datetime.now(UTC)

        # 1. Resolve desired config
        desired = await self.template_resolver.resolve(device)
        dc.desired_config = desired
        dc.desired_updated_at = now

        # 2. Read running config
        try:
            running = await adapter.get_running_config(device.external_id or device.mac_address)
        except Exception as exc:
            logger.warning(
                "Failed to read running config for device %s: %s",
                device.id,
                exc,
            )
            return {"status": "error", "error": str(exc)}

        dc.running_config = running
        dc.running_synced_at = now

        # 3. Compute drift
        drift = await adapter.diff_config(desired, running)
        dc.has_drift = drift is not None
        # diff embeds raw desired/running VALUES (incl. RADIUS
        # secrets / PSKs / SNMP communities). has_drift is already set from the
        # raw diff above, so store a redacted copy — the secret never lands in
        # the drift_details column and the API read-path stays clean too.
        dc.drift_details = redact_secrets(drift) if drift else drift
        dc.drift_detected_at = now if drift else dc.drift_detected_at

        # 4. Update drift health score
        await self.health_service.compute_device_health(
            device,
            drift_score=HealthService.score_drift(dc.has_drift),
        )

        if not drift:
            dc.drift_acknowledged = False
            return {"status": "compliant"}

        # 5. Drift detected
        logger.info("Drift detected on device %s", device.id)

        push_result_data: dict[str, Any] = {"status": "drift_detected", "drift": drift}

        if dc.auto_remediate:
            # 6. Auto-fix: auto-backup before push, then push desired config
            try:
                from app.services.auto_backup import AutoBackupService

                backup_svc = AutoBackupService(self.db)
                await backup_svc.backup_before_change(device, "config_push")
            except Exception:
                logger.debug(
                    "Auto-backup failed for device %s, proceeding with push",
                    device.id,
                    exc_info=True,
                )

            try:
                result = await adapter.push_full_config(
                    device.external_id or device.mac_address,
                    desired,
                )
                dc.pushed_config = desired
                dc.pushed_at = now

                if result.success:
                    dc.push_result = ConfigPushResult.SUCCESS
                    dc.push_error = None

                    # Re-read running config to verify convergence
                    try:
                        new_running = await adapter.get_running_config(
                            device.external_id or device.mac_address
                        )
                        dc.running_config = new_running
                        dc.running_synced_at = datetime.now(UTC)

                        # Re-check drift
                        verify_drift = await adapter.diff_config(desired, new_running)
                        dc.has_drift = verify_drift is not None
                        # redact raw secret values before persisting.
                        dc.drift_details = (
                            redact_secrets(verify_drift) if verify_drift else verify_drift
                        )
                    except Exception:
                        pass  # Verification failed, but push succeeded

                    push_result_data["push_status"] = "success"

                    # Record config version after successful push
                    try:
                        from app.services.config_versions import ConfigVersionService

                        cv_svc = ConfigVersionService(self.db)
                        await cv_svc.record_version(
                            device_id=device.id,
                            config=desired,
                            source="config_push",
                        )
                    except Exception:
                        logger.debug(
                            "Config version recording failed for device %s",
                            device.id,
                            exc_info=True,
                        )
                else:
                    dc.push_result = ConfigPushResult.FAILED
                    dc.push_error = result.error
                    push_result_data["push_status"] = "failed"
                    push_result_data["push_error"] = result.error

            except Exception as exc:
                dc.push_result = ConfigPushResult.FAILED
                dc.push_error = str(exc)
                push_result_data["push_status"] = "error"
                push_result_data["push_error"] = str(exc)

        dc.config_version += 1
        return push_result_data

    async def reconcile_site(
        self,
        site_id: UUID,
        adapter_factory: Any,
    ) -> dict[str, Any]:
        """
        Reconcile all managed devices in a site.

        adapter_factory: callable(device) -> BaseAdapter (async context manager)
        Returns summary with per-device results.
        """
        result = await self.db.execute(
            select(Device).where(
                Device.site_id == site_id,
                Device.lifecycle_state == LifecycleState.MANAGED,
                Device.deleted_at == None,  # noqa: E711
            )
        )
        devices = result.scalars().all()

        summary = {"total": len(devices), "compliant": 0, "drifted": 0, "errors": 0}
        device_results: list[dict[str, Any]] = []

        for device in devices:
            try:
                adapter = await adapter_factory(device)
                async with adapter:
                    device_result = await self.reconcile_device(device, adapter)
                    device_results.append({"device_id": str(device.id), **device_result})
                    if device_result["status"] == "compliant":
                        summary["compliant"] += 1
                    elif device_result["status"] == "error":
                        summary["errors"] += 1
                    else:
                        summary["drifted"] += 1
            except Exception as exc:
                logger.error("Reconciliation failed for device %s: %s", device.id, exc)
                device_results.append(
                    {
                        "device_id": str(device.id),
                        "status": "error",
                        "error": str(exc),
                    }
                )
                summary["errors"] += 1

        return {**summary, "devices": device_results}


# ==========================================================================
# Bulk Operation Service
# ==========================================================================


class BulkOperationService:
    """
    Manages bulk operation jobs — creation, progress tracking,
    staged rollout execution, and automatic rollback on failure.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_job(
        self,
        organization_id: UUID,
        operation: str,
        target: dict[str, Any],
        device_ids: list[UUID],
        config: dict[str, Any] | None = None,
        rollout_strategy: dict[str, Any] | None = None,
        triggered_by: UUID | None = None,
    ) -> BulkOperation:
        """Create a new bulk operation job record."""
        job = BulkOperation(
            organization_id=organization_id,
            operation=operation,
            status=BulkOperationStatus.PENDING,
            target=target,
            config=config,
            rollout_strategy=rollout_strategy,
            devices_total=len(device_ids),
            triggered_by=triggered_by,
            device_results=[],
        )
        self.db.add(job)
        await self.db.commit()
        await self.db.refresh(job)
        logger.info(
            "Created bulk operation %s: %s for %d devices",
            job.id,
            operation,
            len(device_ids),
        )
        return job

    async def get_job(self, job_id: UUID) -> BulkOperation | None:
        """Retrieve a bulk operation by ID."""
        result = await self.db.execute(select(BulkOperation).where(BulkOperation.id == job_id))
        return result.scalar_one_or_none()

    async def list_jobs(
        self,
        organization_id: UUID,
        status_filter: str | None = None,
        limit: int = 50,
    ) -> Sequence[BulkOperation]:
        """List bulk operations for an organization."""
        conditions = [BulkOperation.organization_id == organization_id]
        if status_filter:
            conditions.append(BulkOperation.status == status_filter)

        result = await self.db.execute(
            select(BulkOperation)
            .where(and_(*conditions))
            .order_by(BulkOperation.created_at.desc())
            .limit(limit)
        )
        return result.scalars().all()

    async def start_job(self, job: BulkOperation) -> BulkOperation:
        """Mark a job as running."""
        job.status = BulkOperationStatus.RUNNING
        job.started_at = datetime.now(UTC)
        await self.db.commit()
        return job

    async def record_device_result(
        self,
        job: BulkOperation,
        device_id: UUID,
        status: str,
        error: str | None = None,
        duration_ms: int | None = None,
    ) -> BulkOperation:
        """
        Record the result for a single device in the job.
        Updates progress counters atomically.
        """
        result_entry = {
            "device_id": str(device_id),
            "status": status,
        }
        if error:
            result_entry["error"] = error
        if duration_ms is not None:
            result_entry["duration_ms"] = duration_ms

        # Append to device_results
        job.device_results = [*job.device_results, result_entry]

        if status == "success":
            job.devices_completed += 1
        elif status in ("failed", "error"):
            job.devices_failed += 1
        elif status == "skipped":
            job.devices_skipped += 1

        await self.db.commit()
        return job

    async def complete_job(
        self,
        job: BulkOperation,
        status: str = BulkOperationStatus.COMPLETED,
        error_message: str | None = None,
    ) -> BulkOperation:
        """Mark a job as completed (or failed)."""
        job.status = status
        job.completed_at = datetime.now(UTC)
        if error_message:
            job.error_message = error_message
        await self.db.commit()
        logger.info(
            "Bulk operation %s completed: status=%s, completed=%d, failed=%d",
            job.id,
            status,
            job.devices_completed,
            job.devices_failed,
        )
        return job

    async def cancel_job(self, job: BulkOperation) -> BulkOperation:
        """Cancel a pending or running job."""
        if job.status not in (BulkOperationStatus.PENDING, BulkOperationStatus.RUNNING):
            raise ValueError(f"Cannot cancel job in {job.status} state")
        job.status = BulkOperationStatus.CANCELLED
        job.completed_at = datetime.now(UTC)
        await self.db.commit()
        return job

    def should_rollback(self, job: BulkOperation) -> bool:
        """
        Check if the job's failure rate exceeds the configured threshold,
        triggering automatic rollback.
        """
        strategy = job.rollout_strategy or {}
        threshold = strategy.get("failure_threshold_percent", 5)
        rollback_enabled = strategy.get("rollback_on_failure", True)

        if not rollback_enabled:
            return False

        total_processed = job.devices_completed + job.devices_failed
        if total_processed == 0:
            return False

        failure_pct = (job.devices_failed / total_processed) * 100
        return failure_pct > threshold

    def get_stage_device_count(self, job: BulkOperation, stage_index: int) -> int:
        """
        For staged rollouts, calculate how many devices should be included
        in the given stage.
        """
        strategy = job.rollout_strategy or {}
        stages = strategy.get("stages", [])

        if not stages or stage_index >= len(stages):
            return job.devices_total  # immediate rollout

        pct = stages[stage_index].get("percent", 100)
        return max(1, (job.devices_total * pct) // 100)
