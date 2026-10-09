# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Reviewed firewall writes; stored configuration is not effective-policy proof."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from copy import deepcopy
from typing import Any
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.base import AdapterResult
from app.adapters.exceptions import AdapterOutcomeUnknownError
from app.adapters.proxmox.permissions import has_privileges
from app.core.dependencies import CurrentUser
from app.core.site_access import assert_site_access_for_request
from app.models.core import Controller, Site
from app.modules.hypervisor.firewall_schemas import (
    FirewallOperationRequest,
    FirewallOperationResponse,
    FirewallReviewRequest,
)
from app.schemas.gateway_vpn import ProviderTaskResponse
from app.services.adapter_preflight_common import payload_confirmed
from app.services.adapter_proxmox_vm import build_proxmox_adapter, close_proxmox_adapter
from app.services.hypervisor_operations import HypervisorOperationService

FEATURE = "proxmox.firewall.operation"
LEGACY_FEATURES = {
    "proxmox.firewall.cluster_rule",
    "proxmox.firewall.guest_rule",
    "proxmox.firewall.guest_options",
    "proxmox.cluster.firewall_options",
}
CONTROL = {"request_id", "expected_digest", "force", "confirmed", "recovery_confirmed"}
FLAGS = {"enable", "dhcp", "ipfilter", "macfilter", "ndp", "radv", "ebtables"}


def digest(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(data) > 262144:
        raise HTTPException(502, detail="Firewall review is too large")
    return hashlib.sha256(data.encode()).hexdigest()


def _flag(value: Any) -> int:
    if type(value) in (int, bool) and value in (0, 1):
        return int(value)
    if isinstance(value, str) and value in ("0", "1"):
        return int(value)
    raise HTTPException(502, detail="Malformed firewall flag")


def _native_digest(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{40}", value):
        raise HTTPException(502, detail="Native firewall digest unavailable")
    return value


def _rule(raw: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw.get("action"), str) or raw.get("type") not in ("in", "out", "group"):
        raise HTTPException(502, detail="Malformed firewall rule")
    if raw.get("errors"):
        raise HTTPException(409, detail="Native rule errors require inspection in Proxmox")
    result = {
        k: v
        for k, v in raw.items()
        if k not in {"pos", "digest", "ipversion", "errors"} and v is not None and v != ""
    }
    result["enable"] = _flag(raw.get("enable", 0))
    return result


async def configuration(adapter: Any, target: dict[str, Any]) -> dict[str, Any]:
    result = await adapter.get_firewall_configuration(target)
    data = result.data
    if not result.success or not isinstance(data, dict):
        raise HTTPException(502, detail="Firewall configuration unavailable")
    rules, options = data.get("rules"), data.get("options")
    if not isinstance(rules, list) or len(rules) > 10000 or not isinstance(options, dict):
        raise HTTPException(502, detail="Malformed firewall configuration")
    native_digests = set()
    ordered = []
    for i, row in enumerate(rules):
        if not isinstance(row, dict) or type(row.get("pos")) is not int or row["pos"] != i:
            raise HTTPException(502, detail="Firewall rule ordering unavailable")
        native_digests.add(_native_digest(row.get("digest")))
        ordered.append(_rule(row))
    if len(native_digests) > 1:
        raise HTTPException(502, detail="Inconsistent firewall rule digests")
    # Native lists attach the same digest to each row; an empty list has none.
    native_rules = next(iter(native_digests), None)
    native_options = _native_digest(options.get("digest"))
    normalized_options = {
        k: (_flag(v) if k in FLAGS else v) for k, v in options.items() if k != "digest"
    }
    identity = data.get("identity")
    if target["scope"] == "guest":
        if not isinstance(identity, dict):
            raise HTTPException(502, detail="Guest configuration identity unavailable")
        _native_digest(identity.get("digest"))
    state = {
        "rules": ordered,
        "options": normalized_options,
        "identity": identity,
        "rules_digest": native_rules,
        "options_digest": native_options,
    }
    digest(state)
    return state


def is_reviewed_firewall(change: Any) -> bool:
    version = (change.payload or {}).get("firewall_operation_version")
    return change.feature == FEATURE and type(version) is int and version == 1


def validated_plan(change: Any) -> dict[str, Any]:
    raw = change.payload or {}
    try:
        if not is_reviewed_firewall(change):
            raise ValueError("version")
        body = FirewallOperationRequest(
            request_id=UUID(int=0),
            **{
                k: v for k, v in raw.items() if k not in {"firewall_operation_version", "confirmed"}
            },
        )
        plan = {
            "firewall_operation_version": 1,
            **body.model_dump(exclude={"request_id", "force", "confirmed"}),
        }
        if (
            change.operation != "create"
            or change.target_id != digest(body.target.model_dump())
            or {k: v for k, v in raw.items() if k != "confirmed"} != plan
        ):
            raise ValueError("contract")
        if body.recovery_confirmed is not True:
            raise ValueError("recovery")
        return plan
    except (KeyError, ValueError, TypeError, AttributeError):
        raise HTTPException(
            400, detail="Use a reviewed firewall operation; legacy intents must be reviewed again"
        ) from None


def request_from_plan(plan: dict[str, Any]) -> FirewallReviewRequest:
    return FirewallReviewRequest.model_validate(
        {k: v for k, v in plan.items() if k not in CONTROL | {"firewall_operation_version"}}
    )


async def review_state(adapter: Any, body: FirewallReviewRequest) -> dict[str, Any]:
    async with asyncio.timeout(25):
        target = body.target.model_dump()
        before = await configuration(adapter, target)
        result = await adapter.get_firewall_permissions(target)
        permissions = result.data
        required = (
            ("VM.Audit", "VM.Config.Network")
            if body.target.scope == "guest"
            else ("Sys.Audit", "Sys.Modify")
        )
        if not result.success or not isinstance(permissions, dict):
            raise HTTPException(502, detail="Firewall privileges unavailable")
        if not has_privileges(permissions, *required):
            raise HTTPException(
                403,
                detail="Firewall operation requires explicit native audit and modify privileges",
            )
        desired = deepcopy(before)
        desired.pop("rules_digest")
        desired.pop("options_digest")
        rules = desired["rules"]
        pos = body.pos
        if pos is not None and pos >= len(rules):
            raise HTTPException(409, detail="Rule position changed; review again")
        if body.action == "create":
            assert body.rule is not None
            rules.insert(0, _rule(body.rule.model_dump(exclude_none=True)))
        elif body.action == "delete":
            del rules[pos]
        elif body.action == "move":
            assert pos is not None and body.moveto is not None
            if body.moveto >= len(rules) or body.moveto == pos:
                raise HTTPException(409, detail="Choose a different existing destination position")
            rule = rules.pop(pos)
            # PVE moveto is the original row to insert before, not a final index.
            rules.insert(body.moveto - (pos < body.moveto), rule)
        elif body.action == "update":
            assert body.rule is not None and pos is not None
            # Patch represented fields. Omitted fields and native extensions survive.
            rules[pos].update(_rule(body.rule.model_dump(exclude_none=True)))
        elif body.action == "options":
            assert body.options is not None
            desired["options"].update(
                {
                    k: int(v) if isinstance(v, bool) else v
                    for k, v in body.options.model_dump(exclude_none=True).items()
                }
            )
        review = {"target": target, "action": body.action, "before": before, "desired": desired}
        return {
            **review,
            "expected_digest": digest({"request": body.model_dump(), **review}),
            "warnings": [
                "Firewall changes can disconnect management and workloads. Verify independent console or out-of-band recovery before applying.",
                "Saved configuration does not prove compiled policy, connectivity, security-group/IP-set contents or packet filtering. There is no automatic rollback.",
                "Rule creation inserts at position zero and has no native digest precondition. External operators and duplicate controller registrations are outside FreeSDN locking.",
                "Move inserts before the selected original row. Guest replacement, migration and changes to inherited policy need independent inspection.",
            ],
        }


async def apply_firewall(domain: Any, change: Any) -> AdapterResult:
    plan = validated_plan(change)
    if not payload_confirmed(change.payload):
        raise HTTPException(409, detail="Firewall operation requires explicit confirmation")
    target = (
        await domain.db.execute(
            select(Controller, Site)
            .join(Site, Site.id == Controller.site_id)
            .where(
                Controller.id == change.controller_id,
                Controller.controller_type.in_(("proxmox", "pve")),
                Controller.deleted_at.is_(None),
                Controller.is_active.is_(True),
                Controller.sync_enabled.is_(True),
                Site.id == change.site_id,
                Site.organization_id == change.organization_id,
                Site.deleted_at.is_(None),
                Site.is_active.is_(True),
            )
            .with_for_update(read=True, of=(Controller, Site))
            .execution_options(populate_existing=True)
        )
    ).one_or_none()
    if target is None:
        raise HTTPException(404, detail="Active Proxmox controller not found")
    assert_site_access_for_request(target.Site.id, detail="site not found")
    adapter = None
    try:
        adapter = await build_proxmox_adapter(target.Controller)
        body = request_from_plan(plan)
        current = await review_state(adapter, body)
        if current["expected_digest"] != plan["expected_digest"]:
            raise HTTPException(
                409, detail="Firewall configuration changed since review; review again"
            )
        data: dict[str, Any] = {}
        if body.rule is not None:
            data = {
                k: int(v) if isinstance(v, bool) else v
                for k, v in body.rule.model_dump(exclude_none=True).items()
                if v != ""
            }
        if body.options is not None:
            data = {
                k: int(v) if isinstance(v, bool) else v
                for k, v in body.options.model_dump(exclude_none=True).items()
            }
        if body.action == "move":
            data = {"moveto": body.moveto}
        if body.action != "create":
            data["digest"] = current["before"][
                "options_digest" if body.action == "options" else "rules_digest"
            ]
        result = await adapter.apply_firewall_operation(
            body.target.model_dump(), body.action, data, body.pos, force=True
        )
        if not result.success:
            return result
        if result.data is not None:
            raise AdapterOutcomeUnknownError(
                "Firewall acknowledgement not verified", adapter_id="proxmox"
            )
        return AdapterResult.ok(
            {
                "firewall_operation": body.action,
                "intent_digest": digest(plan),
                "expected": current["desired"],
            }
        )
    finally:
        if adapter is not None:
            await close_proxmox_adapter(adapter)


async def readback(adapter: Any, change: Any) -> dict[str, str]:
    plan = validated_plan(change)
    ack = (change.applied_response or {}).get("data", {})
    if (
        not isinstance(ack, dict)
        or ack.get("intent_digest") != digest(plan)
        or ack.get("firewall_operation") != plan["action"]
        or not isinstance(ack.get("expected"), dict)
    ):
        return {"status": "unknown", "detail": "firewall_acknowledgement_unavailable"}
    current = await configuration(adapter, plan["target"])
    current.pop("rules_digest")
    current.pop("options_digest")
    if current != ack["expected"]:
        return {"status": "unknown", "detail": "firewall_configuration_not_verified"}
    return {
        "status": "succeeded",
        "detail": "firewall_configuration_verified_effective_policy_unverified",
    }


class HypervisorFirewallOperationService:
    def __init__(self, db: AsyncSession, user: CurrentUser) -> None:
        self.ops = HypervisorOperationService(db, user)

    async def review(self, controller_id: UUID, body: FirewallReviewRequest) -> dict[str, Any]:
        if self.ops.user.is_scoped or not self.ops.user.has_min_role("site_admin"):
            raise HTTPException(403, detail="An unscoped site-admin role is required")
        ctrl, site = await self.ops._target(controller_id)
        assert_site_access_for_request(site.id, detail="site not found")
        adapter = None
        try:
            adapter = await build_proxmox_adapter(ctrl)
            return await review_state(adapter, body)
        finally:
            if adapter is not None:
                await close_proxmox_adapter(adapter)

    async def submit(
        self, controller_id: UUID, body: FirewallOperationRequest
    ) -> FirewallOperationResponse:
        from app.services.adapter_proxmox_firewall import GatewayProxmoxFirewallService

        if body.force is not True or self.ops.staging.is_read_only():
            raise HTTPException(
                403, detail="Firewall changes require ADAPTER_READ_ONLY=false and force=true"
            )
        if body.confirmed is not True or body.recovery_confirmed is not True:
            raise HTTPException(409, detail="Confirm the operation and independent recovery access")
        change = await self.ops._record(
            controller_id,
            body.request_id,
            FEATURE,
            "create",
            digest(body.target.model_dump()),
            {
                "firewall_operation_version": 1,
                **body.model_dump(exclude={"request_id", "force", "confirmed"}),
            },
        )
        change_id = change.id
        if change.status == "pending":
            domain = GatewayProxmoxFirewallService(self.ops.db)
            try:
                change = await self.ops.staging.apply_change(
                    change_id,
                    force=True,
                    confirmed=True,
                    actor_id=self.ops.user.id,
                    applier=self.ops.guard_applier(change, domain.build_applier(change)),
                )
            except HTTPException:
                saved = await self.ops._existing(change_id)
                if saved is None or saved.status == "pending":
                    raise
                change = saved
        task = change.provider_task
        return FirewallOperationResponse(
            request_id=body.request_id,
            change_id=change_id,
            status=change.status,
            provider_task=ProviderTaskResponse.model_validate(task) if task else None,
            message="Request recorded. Inspect Pending Changes and independently verify connectivity and effective policy.",
        )
