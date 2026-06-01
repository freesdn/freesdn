# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Distribution Engine Service
==========================================

Translates canonical resource models into device-specific adapter
calls, executes them in tiered order, and records results.

Uses the Saga pattern: each tier has a compensating rollback action.
Only one distribution runs per site at a time (DistributionLock).
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events import Event, EventCategory, get_event_bus
from app.modules.firewall.models import GatewayConnection
from app.modules.gateway.adapter_helpers import build_adapter
from app.modules.gateway.models import (
    CanonicalVLAN,
    DistributionLock,
    DistributionRecord,
    DistributionStatus,
    NetworkRole,
    SiteRoleAssignment,
    SiteRoleMap,
)

logger = logging.getLogger(__name__)

LOCK_TTL_SECONDS = 300  # 5 minutes

# Actions that _execute_step is allowed to dispatch via getattr.
# Prevents arbitrary method calls if plan data were ever tampered with.
_ALLOWED_ACTIONS: frozenset[str] = frozenset(
    {
        "verify_reachable",
        "verify_all",
        "create_vlan_interface",
        "create_dhcp_scope",
        "create_alias",
        "create_vlan",
        "suppress_dhcp",
        "delete_vlan_interface",
        "delete_dhcp_scope",
        "delete_alias",
        "delete_vlan",
    }
)


class DistributionError(Exception):
    """Error during distribution execution."""


class DistributionLockError(DistributionError):
    """Could not acquire distribution lock."""


class DistributionService:
    """
    Plans and executes tiered distribution of canonical resources
    to brain and limb devices.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    # ─── Lock Management ────────────────────────────────────────────────

    @asynccontextmanager
    async def _site_lock(self, site_id: UUID, distribution_id: UUID) -> AsyncIterator[None]:
        """Acquire and release a per-site distribution lock.

        Uses atomic INSERT to avoid TOCTOU race conditions:
        the DistributionLock table has a unique constraint on site_id,
        so concurrent INSERTs will fail with IntegrityError.
        """
        from sqlalchemy.exc import IntegrityError

        now = datetime.now(UTC)
        # Clean expired locks first
        await self.db.execute(delete(DistributionLock).where(DistributionLock.expires_at < now))
        await self.db.flush()

        # Atomic lock acquisition — unique constraint on site_id prevents
        # two concurrent distributions from both succeeding.
        lock = DistributionLock(
            site_id=site_id,
            locked_by=f"worker-{uuid4().hex[:8]}",
            locked_at=now,
            expires_at=now + timedelta(seconds=LOCK_TTL_SECONDS),
            distribution_id=distribution_id,
        )
        self.db.add(lock)
        try:
            await self.db.flush()
        except IntegrityError:
            await self.db.rollback()
            raise DistributionLockError(f"Site {site_id} is locked by another distribution")

        try:
            yield
        finally:
            await self.db.execute(
                delete(DistributionLock).where(DistributionLock.site_id == site_id)
            )
            await self.db.flush()

    # ─── VLAN Distribution ──────────────────────────────────────────────

    async def distribute_vlan(
        self,
        vlan: CanonicalVLAN,
        role_map: SiteRoleMap,
        *,
        triggered_by: UUID | None = None,
    ) -> DistributionRecord:
        """Distribute a canonical VLAN across all devices in the site."""

        brain = next(
            (a for a in role_map.assignments if a.role == NetworkRole.BRAIN),
            None,
        )
        limbs = [a for a in role_map.assignments if a.role == NetworkRole.LIMB]

        plan = self._build_vlan_plan(vlan, brain, limbs)
        record = DistributionRecord(
            organization_id=vlan.organization_id,
            site_id=vlan.site_id,
            resource_type="vlan",
            resource_id=vlan.id,
            action="create",
            plan=plan,
            status=DistributionStatus.PENDING,
            triggered_by=triggered_by,
        )
        self.db.add(record)
        await self.db.flush()

        async with self._site_lock(vlan.site_id, record.id):
            await self._execute_plan(record, brain, limbs, vlan)

        await self._publish_lifecycle(record)
        return record

    def _build_vlan_plan(
        self,
        vlan: CanonicalVLAN,
        brain: SiteRoleAssignment | None,
        limbs: list[SiteRoleAssignment],
    ) -> dict[str, Any]:
        """Build tiered execution plan for a VLAN distribution."""
        steps: list[dict[str, Any]] = []

        # Tier 0 — prerequisites
        if brain:
            steps.append(
                {
                    "tier": 0,
                    "device_id": str(brain.gateway_id),
                    "action": "verify_reachable",
                    "params": {},
                }
            )
        for limb in limbs:
            steps.append(
                {
                    "tier": 0,
                    "device_id": str(limb.gateway_id),
                    "action": "verify_reachable",
                    "params": {},
                }
            )

        # Tier 1 — brain L3
        if brain:
            steps.append(
                {
                    "tier": 1,
                    "device_id": str(brain.gateway_id),
                    "action": "create_vlan_interface",
                    "params": {
                        "vlan_id": vlan.vlan_id,
                        "name": vlan.name,
                        "subnet": vlan.subnet,
                        "gateway_ip": vlan.gateway_ip,
                        "description": f"[FreeSdn:managed] {vlan.name}",
                    },
                }
            )

        # Tier 2 — brain services
        if brain and vlan.dhcp_enabled:
            steps.append(
                {
                    "tier": 2,
                    "device_id": str(brain.gateway_id),
                    "action": "create_dhcp_scope",
                    "params": {
                        "interface": f"vlan{vlan.vlan_id}",
                        "range_start": vlan.dhcp_range_start,
                        "range_end": vlan.dhcp_range_end,
                        "gateway": vlan.gateway_ip,
                        "subnet": vlan.subnet,
                    },
                }
            )
        if brain:
            steps.append(
                {
                    "tier": 2,
                    "device_id": str(brain.gateway_id),
                    "action": "create_alias",
                    "params": {
                        "name": f"FreeSdn_VLAN{vlan.vlan_id}_net",
                        "type": "network",
                        "members": [vlan.subnet],
                        "description": f"[FreeSdn:managed] {vlan.name} subnet",
                    },
                }
            )

        # Tier 3 — limbs L2
        for limb in limbs:
            steps.append(
                {
                    "tier": 3,
                    "device_id": str(limb.gateway_id),
                    "action": "create_vlan",
                    "params": {"vlan_id": vlan.vlan_id, "name": vlan.name},
                }
            )
            if limb.suppress_dhcp:
                steps.append(
                    {
                        "tier": 3,
                        "device_id": str(limb.gateway_id),
                        "action": "suppress_dhcp",
                        "params": {"vlan_id": vlan.vlan_id},
                    }
                )

        # Tier 5 — verification
        steps.append({"tier": 5, "action": "verify_all", "params": {}})

        return {"steps": steps}

    async def _preload_gateways(
        self,
        steps: list[dict[str, Any]],
        *,
        org_id: UUID | None = None,
    ) -> dict[UUID, GatewayConnection]:
        """Batch-load all GatewayConnections referenced in a plan.

        Returns a dict keyed by gateway UUID.  Eliminates per-step N+1
        queries when the same device appears in multiple tiers.
        Scoped to organization to prevent cross-org device access.
        """
        raw_ids: set[str] = set()
        for s in steps:
            did = s.get("device_id")
            if did:
                raw_ids.add(did)
        if not raw_ids:
            return {}

        uuids = [UUID(rid) for rid in raw_ids]
        q = select(GatewayConnection).where(GatewayConnection.id.in_(uuids))
        if org_id is not None:
            q = q.where(GatewayConnection.org_id == org_id)
        result = await self.db.execute(q)
        return {gw.id: gw for gw in result.scalars().all()}

    async def _execute_plan(
        self,
        record: DistributionRecord,
        brain: SiteRoleAssignment | None,
        limbs: list[SiteRoleAssignment],
        vlan: CanonicalVLAN,
    ) -> None:
        """Execute the distribution plan tier by tier.

        On mid-plan failure, we **build
        and persist a rollback plan** from the steps that already
        succeeded. The plan is NOT auto-executed — destructively
        compensating committed writes is risky (a "rollback" of a
        VLAN create is a VLAN delete that destroys real config). We
        instead surface the rollback plan in
        ``record.rollback_plan`` and ``record.rollback_executed=False``
        so the operator can inspect + execute it via the
        ``/distribution/{id}/rollback`` endpoint.
        """
        record.status = DistributionStatus.EXECUTING
        record.started_at = datetime.now(UTC)
        step_results: list[dict[str, Any]] = []
        succeeded_steps: list[dict[str, Any]] = []

        try:
            steps = record.plan.get("steps", [])

            # Pre-load all referenced gateways in one query (avoid N+1)
            # Scoped to organization to prevent cross-org device access
            gw_cache = await self._preload_gateways(
                steps,
                org_id=record.organization_id,
            )

            tiers = sorted({s["tier"] for s in steps})

            for tier in tiers:
                tier_steps = [s for s in steps if s["tier"] == tier]
                for step in tier_steps:
                    t0 = time.monotonic()
                    try:
                        await self._execute_step(step, gw_cache)
                        elapsed = int((time.monotonic() - t0) * 1000)
                        step_results.append(
                            {
                                **step,
                                "status": "success",
                                "duration_ms": elapsed,
                            }
                        )
                        succeeded_steps.append(step)
                    except Exception as exc:
                        elapsed = int((time.monotonic() - t0) * 1000)
                        step_results.append(
                            {
                                **step,
                                "status": "failed",
                                "duration_ms": elapsed,
                                # type-name only — adapter exceptions can
                                # carry controller URLs / auth fragments.
                                "error": type(exc).__name__,
                            }
                        )
                        raise DistributionError(
                            f"Tier {tier} failed on {step.get('action')}: {type(exc).__name__}"
                        ) from exc

            record.status = DistributionStatus.COMPLETED
        except DistributionError as exc:
            record.status = DistributionStatus.FAILED
            record.error_message = str(exc)
            # Build a compensating plan from steps that DID succeed.
            # Operator inspects + executes manually via the rollback
            # endpoint — auto-rollback would risk destroying live
            # config the user may want to keep (e.g., the brain
            # already had the VLAN, we shouldn't delete it just
            # because a limb push failed).
            if succeeded_steps:
                record.rollback_plan = self._build_compensation_plan(
                    succeeded_steps,
                )
                record.rollback_executed = False
                logger.error(
                    "Distribution %s failed mid-plan; %d step(s) "
                    "succeeded and need compensation — rollback plan "
                    "persisted to record.rollback_plan",
                    record.id,
                    len(succeeded_steps),
                )
            else:
                logger.error("Distribution %s failed: %s", record.id, exc)
        finally:
            record.step_results = step_results
            record.completed_at = datetime.now(UTC)
            await self.db.flush()

    @staticmethod
    def _build_compensation_plan(
        succeeded_steps: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Build a reverse-order compensation plan from the steps
        that already committed before the failure. Inverts each
        action: ``create_vlan`` → ``delete_vlan``, ``set_alias`` →
        ``delete_alias``, etc. Unsupported actions are flagged for
        manual review rather than guessed.
        """
        _INVERSE = {
            "create_vlan": "delete_vlan",
            "create_l3_vlan": "delete_l3_vlan",
            "add_alias": "delete_alias",
            "set_alias": "delete_alias",
            "create_dhcp_scope": "delete_dhcp_scope",
            "set_dhcp_scope": "delete_dhcp_scope",
            "verify_reachable": None,  # nothing to undo
            "verify_all": None,
        }
        comp_steps: list[dict[str, Any]] = []
        # Reverse the order — undo most-recent-first.
        for step in reversed(succeeded_steps):
            inverse = _INVERSE.get(step.get("action", ""))
            if inverse is None:
                if step.get("action", "").startswith("verify"):
                    continue
                # Unknown action — annotate but don't skip silently,
                # so the operator sees an explicit "manual review".
                comp_steps.append(
                    {
                        **step,
                        "action": "manual_review",
                        "original_action": step.get("action"),
                    }
                )
                continue
            comp_steps.append({**step, "action": inverse})
        return {"steps": comp_steps, "compensates_failed": True}

    async def _execute_step(
        self,
        step: dict[str, Any],
        gw_cache: dict[UUID, GatewayConnection],
    ) -> None:
        """Execute a single distribution step."""
        action = step.get("action", "")

        if action == "verify_all":
            # Final verification tier — nothing to check at this stage;
            # individual step results already capture per-device outcomes.
            return

        if action == "verify_reachable":
            device_id = step.get("device_id")
            if not device_id:
                return
            gw_uuid = UUID(device_id)
            gw = gw_cache.get(gw_uuid)
            if gw is None:
                raise DistributionError(
                    f"Gateway {device_id} not found — cannot verify reachability"
                )
            # Attempt to build an adapter and connect to prove reachability
            adapter = build_adapter(gw)
            try:
                async with adapter:
                    pass  # successful connect/disconnect proves reachability
            except Exception as exc:
                raise DistributionError(f"Gateway {device_id} is unreachable: {exc}") from exc
            return

        # Security: reject unknown actions before getattr dispatch
        if action not in _ALLOWED_ACTIONS:
            raise DistributionError(f"Disallowed distribution action: {action}")

        device_id = step.get("device_id")
        if not device_id:
            return

        gw_uuid = UUID(device_id)
        gw = gw_cache.get(gw_uuid)
        if gw is None:
            raise DistributionError(f"Gateway {device_id} not found")

        adapter = build_adapter(gw)
        params = step.get("params", {})

        async with adapter:
            method = getattr(adapter, action, None)
            if method is None:
                raise DistributionError(f"Adapter missing method: {action}")
            result = await method(**params)
            if not result.success:
                raise DistributionError(result.error or f"{action} failed")

    # ─── Fabric orchestration plane (lifecycle events) ──────────────────

    async def _publish_lifecycle(self, record: DistributionRecord) -> None:
        """Surface a finished distribution on the event bus as a first-class
        Fabric trigger (``gateway.distribution.completed`` / ``.failed``).

        Fire-and-forget and fail-closed: a telemetry failure must never fail or
        roll back the distribution itself, so every error is swallowed. This is
        observability/orchestration only — it grants no new write authority and
        does not touch the staged-write path. ``organization_id`` is lifted onto
        the Event so the fail-closed bus router scopes it to the owning tenant.
        """
        try:
            steps = record.step_results or []
            succeeded = sum(1 for s in steps if s.get("status") == "success")
            completed = record.status == DistributionStatus.COMPLETED
            org_id = record.organization_id
            payload = {
                "distribution_id": str(record.id),
                "resource_type": record.resource_type,
                "resource_id": str(record.resource_id) if record.resource_id else None,
                "site_id": str(record.site_id) if record.site_id else None,
                "organization_id": str(org_id) if org_id else None,
                "action": record.action,
                "status": getattr(record.status, "value", str(record.status)),
                "steps_total": len(steps),
                "steps_succeeded": succeeded,
                "rollback_required": bool(getattr(record, "rollback_plan", None)),
            }
            bus = get_event_bus()
            await bus.publish(
                Event(
                    event_type=(
                        "gateway.distribution.completed"
                        if completed
                        else "gateway.distribution.failed"
                    ),
                    category=EventCategory.SYSTEM,
                    source="gateway",
                    organization_id=str(org_id) if org_id else None,
                    payload=payload,
                )
            )
        except Exception:
            logger.debug("Failed to emit distribution lifecycle event", exc_info=True)

    # ─── Retract ────────────────────────────────────────────────────────

    async def retract_vlan(
        self,
        vlan: CanonicalVLAN,
        role_map: SiteRoleMap,
        *,
        triggered_by: UUID | None = None,
    ) -> DistributionRecord:
        """Remove a VLAN from all devices (reverse of distribute).

        Deletion order is the reverse of creation:
        limbs first (remove L2 VLANs), then brain (DHCP → alias → L3).
        """
        brain = next(
            (a for a in role_map.assignments if a.role == NetworkRole.BRAIN),
            None,
        )
        limbs = [a for a in role_map.assignments if a.role == NetworkRole.LIMB]

        plan = self._build_retract_plan(vlan, brain, limbs)
        record = DistributionRecord(
            organization_id=vlan.organization_id,
            site_id=vlan.site_id,
            resource_type="vlan",
            resource_id=vlan.id,
            action="delete",
            plan=plan,
            status=DistributionStatus.PENDING,
            triggered_by=triggered_by,
        )
        self.db.add(record)
        await self.db.flush()

        async with self._site_lock(vlan.site_id, record.id):
            await self._execute_plan(record, brain, limbs, vlan)

        await self._publish_lifecycle(record)
        return record

    def _build_retract_plan(
        self,
        vlan: CanonicalVLAN,
        brain: SiteRoleAssignment | None,
        limbs: list[SiteRoleAssignment],
    ) -> dict[str, Any]:
        """Build tiered deletion plan (reverse order of creation).

        Tier 0: Verify reachability
        Tier 1: Remove L2 VLANs from limbs
        Tier 2: Remove alias from brain
        Tier 3: Remove DHCP scope from brain
        Tier 4: Remove L3 VLAN interface from brain
        Tier 5: Final verification
        """
        steps: list[dict[str, Any]] = []

        # Tier 0 — prerequisites
        if brain:
            steps.append(
                {
                    "tier": 0,
                    "device_id": str(brain.gateway_id),
                    "action": "verify_reachable",
                    "params": {},
                }
            )
        for limb in limbs:
            steps.append(
                {
                    "tier": 0,
                    "device_id": str(limb.gateway_id),
                    "action": "verify_reachable",
                    "params": {},
                }
            )

        # Tier 1 — limbs: remove L2 VLANs first (reverse of create Tier 3)
        for limb in limbs:
            steps.append(
                {
                    "tier": 1,
                    "device_id": str(limb.gateway_id),
                    "action": "delete_vlan",
                    "params": {"vlan_id": vlan.vlan_id},
                }
            )

        # Tier 2 — brain: remove alias
        if brain:
            steps.append(
                {
                    "tier": 2,
                    "device_id": str(brain.gateway_id),
                    "action": "delete_alias",
                    "params": {"name": f"FreeSdn_VLAN{vlan.vlan_id}_net"},
                }
            )

        # Tier 3 — brain: remove DHCP scope
        if brain and vlan.dhcp_enabled:
            steps.append(
                {
                    "tier": 3,
                    "device_id": str(brain.gateway_id),
                    "action": "delete_dhcp_scope",
                    "params": {"interface": f"vlan{vlan.vlan_id}"},
                }
            )

        # Tier 4 — brain: remove L3 VLAN interface (last)
        if brain:
            steps.append(
                {
                    "tier": 4,
                    "device_id": str(brain.gateway_id),
                    "action": "delete_vlan_interface",
                    "params": {"vlan_id": vlan.vlan_id},
                }
            )

        # Tier 5 — verification
        steps.append({"tier": 5, "action": "verify_all", "params": {}})

        return {"steps": steps}

    # ─── Queries ────────────────────────────────────────────────────────

    async def list_distributions(
        self,
        org_id: UUID,
        *,
        site_id: UUID | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[DistributionRecord], int]:
        from sqlalchemy import func as sqlfunc

        from app.core.site_access import current_user_var, site_scope_filter

        # Per-user site grant: fold the request-scoped caller's
        # granted-site set into the SQL so a site-limited operator never sees
        # sibling-site distributions — and the ``total`` reflects only granted
        # rows (a Python post-filter at the route would corrupt pagination).
        # No-op for super/org admins and grant-less users; fail-closed (empty
        # IN) for a site-limited user with zero grants. ``current_user_var`` is
        # unset in Celery/background context, so this no-ops there.
        grant_filter = site_scope_filter(current_user_var.get(), DistributionRecord.site_id)

        q = (
            select(DistributionRecord)
            .where(
                DistributionRecord.organization_id == org_id,
                grant_filter,
            )
            .order_by(DistributionRecord.created_at.desc())
        )
        cq = (
            select(sqlfunc.count())
            .select_from(DistributionRecord)
            .where(
                DistributionRecord.organization_id == org_id,
                grant_filter,
            )
        )
        if site_id:
            q = q.where(DistributionRecord.site_id == site_id)
            cq = cq.where(DistributionRecord.site_id == site_id)
        if status:
            q = q.where(DistributionRecord.status == status)
            cq = cq.where(DistributionRecord.status == status)
        total = (await self.db.execute(cq)).scalar() or 0
        items = list((await self.db.execute(q.limit(limit).offset(offset))).scalars().all())
        return items, total

    async def get_distribution(
        self,
        dist_id: UUID,
        *,
        org_id: UUID | None = None,
    ) -> DistributionRecord | None:
        q = select(DistributionRecord).where(DistributionRecord.id == dist_id)
        if org_id is not None:
            q = q.where(DistributionRecord.organization_id == org_id)
        result = await self.db.execute(q)
        record = result.scalar_one_or_none()
        if record is not None:
            # Defense in depth: enforce the request-scoped
            # per-user site grant even if a future non-route caller skips the
            # API-layer ``assert_can_access_site``. 404 shape (no existence
            # oracle); no-op for super/org admins and background context.
            from app.core.site_access import assert_site_access_for_request

            assert_site_access_for_request(record.site_id, detail="Distribution not found")
        return record

    # ─── Lock Cleanup ───────────────────────────────────────────────────

    async def cleanup_expired_locks(self) -> int:
        """Remove expired distribution locks.  Returns count of locks removed."""
        now = datetime.now(UTC)
        result = await self.db.execute(
            delete(DistributionLock).where(DistributionLock.expires_at < now)
        )
        await self.db.flush()
        return result.rowcount  # type: ignore[return-value]
