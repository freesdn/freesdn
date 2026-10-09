# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Durable, read-only observation of acknowledged Proxmox operations.

The staging status records dispatch, not provider completion. This observer
never calls an applier, retries a write, or infers success from missing history.
Provider error text is deliberately not copied into the public observation:
task logs can contain URLs, credentials and guest-controlled output.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.validation import validate_upid
from app.db.session import CelerySessionLocal
from app.models.core import Controller, Site
from app.models.staging import AdapterPendingChange
from app.services.adapter_proxmox_vm import build_proxmox_adapter

# PVE::UPID::decode accepts an extended pstart for hosts with long uptime.
# Keep URL metacharacters excluded; API-token principals contain '!'.
_UPID = re.compile(
    r"UPID:([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?):"
    r"[0-9A-Fa-f]{8}:[0-9A-Fa-f]{8,9}:[0-9A-Fa-f]{8}:"
    r"[A-Za-z0-9_.-]+:[A-Za-z0-9_.@-]*:[A-Za-z0-9_.@!-]+:"
)
_TERMINAL = {"succeeded", "warnings", "failed"}
# These adapters return a raw task ID instead of an explicit {upid: ...} slot.
# Even vzdump's synchronous "OK" can mean no matching VM was backed up; it
# must not be mistaken for an observed completed backup.
_REQUIRED_TASK_FEATURES = {
    "proxmox.storage.delete_volume",
    "proxmox.storage.upload",
    "proxmox.vm.create",
    "proxmox.container.create",
    "proxmox.snapshot.create",
    "proxmox.snapshot.delete",
    "proxmox.snapshot.rollback",
    "proxmox.backup.run",
    "proxmox.backup.restore",
    "proxmox.vm.destroy",
    "proxmox.container.destroy",
    "proxmox.vm.clone",
    "proxmox.vm.migrate",
    "proxmox.container.clone",
    "proxmox.container.migrate",
    *(
        f"proxmox.vm.{action}"
        for action in ("start", "stop", "shutdown", "reboot", "suspend", "resume")
    ),
    *(f"proxmox.container.{action}" for action in ("start", "stop", "shutdown", "reboot")),
}


def task_node(upid: Any) -> str | None:
    if not isinstance(upid, str) or len(upid) > 512:
        return None
    match = _UPID.fullmatch(upid)
    if not match or ".." in upid:
        return None
    validate_upid(upid)
    return match[1]


def accepted_task(feature: str, response: dict[str, Any]) -> dict[str, Any] | None:
    """Extract only the adapter's task slot, never nested guest output."""
    if not feature.startswith("proxmox."):
        return None
    data = response.get("data", response)
    if feature == "proxmox.firewall.operation":
        if isinstance(data, dict) and data.get("firewall_operation") in (
            "create",
            "update",
            "delete",
            "move",
            "options",
        ):
            return {"status": "pending", "detail": "firewall_awaiting_configuration_readback"}
        return {"status": "unknown", "detail": "invalid_firewall_acknowledgement"}
    if feature == "proxmox.cluster.task_stop":
        upid = data.get("task_stop") if isinstance(data, dict) else None
        node = task_node(upid)
        if node and isinstance(data, dict) and data.get("node") == node:
            return {
                "id": upid,
                "node": node,
                "status": "pending",
                "detail": "task_stop_awaiting_observation",
            }
        return {"status": "unknown", "detail": "invalid_task_stop_acknowledgement"}
    candidate = data.get("upid") if isinstance(data, dict) else data
    explicit_task = isinstance(data, dict) and "upid" in data
    node = task_node(candidate)
    if node:
        return {"id": candidate, "node": node, "status": "pending"}
    if feature == "proxmox.backup.job":
        if isinstance(data, dict) and data.get("backup_job") in ("create", "update", "delete"):
            return {"status": "pending", "detail": "backup_job_awaiting_configuration_readback"}
        return {"status": "unknown", "detail": "invalid_backup_job_acknowledgement"}
    from app.services.hypervisor_certificates import ACTIONS as CERTIFICATE_ACTIONS
    from app.services.hypervisor_certificates import FEATURES as CERTIFICATE_FEATURES

    if feature in CERTIFICATE_FEATURES:
        action = data.get("certificate_operation") if isinstance(data, dict) else None
        if action in ("upload", "delete") and CERTIFICATE_ACTIONS[action][0] == feature:
            return {"status": "pending", "detail": "certificate_awaiting_readback"}
        return {"status": "unknown", "detail": "invalid_certificate_acknowledgement"}
    from app.services.hypervisor_cluster_operations import ACTIONS, FEATURES

    if feature in FEATURES:
        action = data.get("cluster_operation") if isinstance(data, dict) else None
        if isinstance(action, str) and action in ACTIONS and ACTIONS[action][0] == feature:
            return (
                {"status": "unknown", "detail": "node_power_requires_manual_verification"}
                if action.startswith("node.")
                else {"status": "pending", "detail": "ha_configuration_awaiting_readback"}
            )
        return {"status": "unknown", "detail": "invalid_cluster_acknowledgement"}
    from app.services.hypervisor_guest_changes import accepted_readback

    verified = accepted_readback(feature, data)
    if verified is not None:
        return verified
    if (
        feature in _REQUIRED_TASK_FEATURES
        or explicit_task
        or (isinstance(candidate, str) and candidate.startswith("UPID:"))
    ):
        # The provider accepted HTTP, but did not give a usable task handle.
        # Retain uncertainty without persisting untrusted content as an ID.
        return {"status": "unknown", "detail": "invalid_task_id"}
    return None


async def observe_task(session: AsyncSession, change: AdapterPendingChange) -> None:
    """Observe one locked row; caller commits the result before releasing it."""
    now = datetime.now(UTC)
    previous = change.provider_task or {}
    if previous.get("status") in _TERMINAL:
        change.provider_task_next_poll_at = None
        return
    observation: dict[str, Any] = {
        "id": previous.get("id"),
        "node": previous.get("node"),
        "status": "unknown",
        "checked_at": now.isoformat(),
        "detail": "observation_unavailable",
    }
    upid = previous.get("id")
    node = task_node(upid)
    from app.services.hypervisor_backup_jobs import is_reviewed_backup_job
    from app.services.hypervisor_certificates import is_reviewed_certificate
    from app.services.hypervisor_cluster_operations import is_reviewed_cluster_operation
    from app.services.hypervisor_creation import is_reviewed_creation
    from app.services.hypervisor_deletion import is_reviewed_deletion
    from app.services.hypervisor_firewall_operations import is_reviewed_firewall
    from app.services.hypervisor_guest_changes import is_reviewed_guest_change
    from app.services.hypervisor_storage_operations import is_reviewed_storage
    from app.services.hypervisor_task_control import is_reviewed_task_stop

    firewall = is_reviewed_firewall(change)
    task_stop = is_reviewed_task_stop(change)
    backup_job = is_reviewed_backup_job(change)
    storage_operation = is_reviewed_storage(change)
    certificate = is_reviewed_certificate(change)
    cluster_operation = is_reviewed_cluster_operation(change)
    creation = is_reviewed_creation(change)
    deletion = is_reviewed_deletion(change)
    guest_change = is_reviewed_guest_change(change)
    has_task = isinstance(upid, str) and node is not None and previous.get("node") == node
    if (
        not has_task
        and not guest_change
        and not cluster_operation
        and not certificate
        and not backup_job
        and not task_stop
        and not firewall
    ):
        observation.update(id=None, node=None, detail="invalid_task_id")
        change.provider_task = observation
        change.provider_task_next_poll_at = None
        return

    # Freeze target ownership while using its credentials. A reassigned,
    # deleted, inactive or cross-tenant controller must receive no request.
    target = (
        await session.execute(
            select(Controller, Site)
            .join(Site, Site.id == Controller.site_id)
            .where(Controller.id == change.controller_id)
            .with_for_update(read=True, of=(Controller, Site))
        )
    ).one_or_none()
    if (
        target is None
        or target.Controller.controller_type not in ("proxmox", "pve")
        or target.Controller.deleted_at is not None
        or not target.Controller.is_active
        or not target.Controller.sync_enabled
        or target.Site.deleted_at is not None
        or not target.Site.is_active
        or target.Site.organization_id != change.organization_id
        or target.Site.id != change.site_id
    ):
        observation["detail"] = "target_unavailable_or_scope_changed"
    else:
        adapter = None
        try:
            # Includes authentication, GET retries and disconnect. The outer
            # worker deadline is a second bound; cancellation only loses a GET.
            async with asyncio.timeout(10):
                adapter = await build_proxmox_adapter(target.Controller)
                if firewall:
                    from app.services.hypervisor_firewall_operations import (
                        readback as firewall_readback,
                    )

                    observation.update(await firewall_readback(adapter, change))
                    result = None
                elif task_stop:
                    from app.services.hypervisor_task_control import readback as task_stop_readback

                    observation.update(await task_stop_readback(adapter, change))
                    result = None
                elif backup_job:
                    from app.services.hypervisor_backup_jobs import readback as backup_job_readback

                    observation.update(await backup_job_readback(adapter, change))
                    result = None
                elif certificate and not has_task:
                    from app.services.hypervisor_certificates import (
                        readback as certificate_readback,
                    )

                    observation.update(await certificate_readback(adapter, change, None))
                    result = None
                elif cluster_operation:
                    from app.services.hypervisor_cluster_operations import (
                        readback as cluster_readback,
                    )

                    observation.update(await cluster_readback(adapter, change))
                    result = None
                elif not has_task:
                    from app.services.hypervisor_guest_changes import readback, validated_plan

                    observation.update(await readback(adapter, validated_plan(change)))
                    result = None
                else:
                    assert isinstance(node, str) and isinstance(upid, str)
                    result = await adapter.get_task_status(node, upid)
                if result is not None and result.success and result.data is not None:
                    task = result.data
                    if task.upid != upid or task.node != node:
                        observation["detail"] = "task_identity_mismatch"
                    elif task.status == "running":
                        observation.update(status="running", detail=None)
                    elif task.status == "stopped" and task.exitstatus:
                        if task.exitstatus == "OK":
                            observation.update(status="succeeded", detail=None)
                        elif re.fullmatch(r"WARNINGS: [0-9]+", task.exitstatus):
                            observation.update(status="warnings", detail="provider_warnings")
                        elif task.exitstatus == "unexpected status" or task.exitstatus.startswith(
                            "unable to get last line from task log"
                        ):
                            observation["detail"] = "provider_result_unavailable"
                        else:
                            observation.update(status="failed", detail="provider_task_failed")
                    else:
                        observation["detail"] = "provider_result_unavailable"
                    if storage_operation and observation["status"] == "failed":
                        observation.update(status="unknown", detail="storage_provider_task_failed")
                    if storage_operation and observation["status"] in {"succeeded", "warnings"}:
                        from app.services.hypervisor_storage_operations import (
                            readback as storage_readback,
                        )

                        had_warnings = observation["status"] == "warnings"
                        observation.update(status="unknown", detail="storage_state_not_verified")
                        assert isinstance(upid, str)
                        observation.update(await storage_readback(adapter, change, upid))
                        if had_warnings and observation["status"] == "succeeded":
                            observation.update(
                                status="warnings", detail="storage_verified_with_warnings"
                            )
                    if certificate and observation["status"] == "failed":
                        # ACME may fail after installing files but before proxy
                        # reload/revocation completes. Do not unlock a blind retry.
                        observation.update(
                            status="unknown", detail="certificate_provider_task_failed"
                        )
                    if certificate and observation["status"] in {"succeeded", "warnings"}:
                        from app.services.hypervisor_certificates import (
                            readback as certificate_readback,
                        )

                        had_warnings = observation["status"] == "warnings"
                        observation.update(status="unknown", detail="certificate_not_verified")
                        observation.update(await certificate_readback(adapter, change, upid))
                        if had_warnings and observation["status"] == "succeeded":
                            observation.update(
                                status="warnings",
                                detail="certificate_endpoint_verified_with_warnings",
                            )
                    if creation and observation["status"] == "succeeded":
                        from app.services.hypervisor_creation import readback as creation_readback

                        assert isinstance(upid, str)
                        observation.update(status="unknown", detail="guest_creation_not_verified")
                        observation.update(await creation_readback(adapter, change, upid))
                    if deletion and observation["status"] == "succeeded":
                        from app.services.hypervisor_deletion import readback as deletion_readback

                        observation.update(status="unknown", detail="guest_absence_not_verified")
                        assert isinstance(upid, str)
                        observation.update(await deletion_readback(adapter, change, upid))
                    if guest_change and observation["status"] == "succeeded":
                        from app.services.hypervisor_guest_changes import readback, validated_plan

                        # A completed provider task is insufficient if the intended
                        # state cannot be verified. Failure here must reset success.
                        observation.update(status="unknown", detail="guest_state_not_verified")
                        observation.update(await readback(adapter, validated_plan(change)))
        except Exception:
            # Missing history, permissions, timeout and malformed provider data
            # all mean unobserved, never failed or successful execution.
            observation["detail"] = "observation_unavailable"
        finally:
            if adapter is not None:
                with contextlib.suppress(Exception):
                    async with asyncio.timeout(2):
                        await adapter.disconnect()

    if observation["status"] in _TERMINAL:
        observation["finished_at"] = now.isoformat()
        change.provider_task_next_poll_at = None
    elif observation["status"] == "running":
        change.provider_task_next_poll_at = now + timedelta(seconds=30)
    elif change.applied_at is not None and now - change.applied_at > timedelta(days=7):
        # Do not poll missing/expired history forever. Keep the uncertainty
        # visible for manual verification; long-running observed tasks continue.
        if guest_change or certificate:
            # A saved-but-inactive configuration must not become an unresolvable
            # pending row when automatic observation expires.
            observation["status"] = "unknown"
        observation["detail"] = "manual_verification_required"
        change.provider_task_next_poll_at = None
    else:
        change.provider_task_next_poll_at = now + timedelta(minutes=5)
    change.provider_task = observation


async def poll_due_tasks() -> dict[str, int]:
    """Bounded work with DB claims; multiple workers safely skip locked rows."""
    polled = 0
    deadline = time.monotonic() + 40
    while polled < 20 and time.monotonic() < deadline:
        async with CelerySessionLocal() as session:
            change = (
                await session.execute(
                    select(AdapterPendingChange)
                    .where(
                        AdapterPendingChange.status == "applied",
                        AdapterPendingChange.feature.startswith("proxmox."),
                        AdapterPendingChange.provider_task_next_poll_at <= datetime.now(UTC),
                    )
                    .order_by(
                        AdapterPendingChange.provider_task_next_poll_at, AdapterPendingChange.id
                    )
                    .limit(1)
                    .with_for_update(skip_locked=True)
                    .execution_options(populate_existing=True)
                )
            ).scalar_one_or_none()
            if change is None:
                break
            await observe_task(session, change)
            await session.commit()
            polled += 1
    return {"polled": polled}
