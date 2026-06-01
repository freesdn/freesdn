# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Adapter staging service
==================================

Implements the read-only / preview pattern that gates writes to managed
controllers. When ``settings.ADAPTER_READ_ONLY`` (or the legacy
``settings.OMADA_READ_ONLY``) is True, every UI-authored mutation
becomes a row in ``core.adapter_pending_changes`` and the live device
is left untouched. Operators review the pending queue and explicitly
opt in to apply each change in a non-prod environment.

This service is adapter-agnostic by design — every vendor adapter
(Omada, UniFi, MikroTik, OPNsense, pfSense, Proxmox, …) stages writes
through the same table. The dispatcher routes by ``feature`` prefix to
the right vendor's applier at apply-time. The adapter contract defines
the production-safety invariants every adapter inherits.

Read paths bypass this service entirely — they call the adapter
directly. Only writes route through ``stage_change()``.

Usage shape:

    staging = AdapterStagingService(db)

    # Always-safe — records the intent, may or may not push:
    pending = await staging.stage_change(
        organization_id=current_user.organization_id,
        controller_id=ctrl.id,
        feature="vpn.ipsec.policy",
        operation="create",
        payload={"name": "branch-1", "remoteSubnet": "10.20.0.0/16", ...},
        site_id=site.id,
        omada_site_id="abc123",
    )

    # Returns the pending row. The user can then review it in the UI.
    # When they explicitly hit "Apply", the endpoint calls:
    #   await staging.apply_change(pending.id, ...)
    # which is the only code path that ever touches the live controller.

The legacy ``AdapterStagingService`` symbol is exported at the bottom as
a deprecated alias for any external code that imported the old name
through the rename.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.site_access import (
    assert_site_access_for_request,
    current_user_var,
    site_scope_filter,
)
from app.models.staging import AdapterPendingChange

# ── Cross-cutting integration ────────────────────────────────────────
#
# Every state transition (stage / apply-success / apply-fail / discard)
# emits a single event to the event bus. Downstream subscribers wire
# automatically: WebSocket forwarder broadcasts to browser clients
# (instant cross-tab + cross-operator updates), automation engine
# matches rules (notify-slack-on-failure, auto-rollback-on-firmware-
# install-failure, etc.), and plugins subscribe by pattern. This is
# the load-bearing hook for platform integration — without it the entire
# stage-and-apply pipeline was invisible to notifications, webhooks (via
# automation), real-time UI, and plugins.
#
# Event taxonomy::
#
#     controller.change.staged         INFO     a row landed in the queue
#     controller.change.applied        HIGH     write succeeded against device
#     controller.change.failed         HIGH     write failed at device or applier
#     controller.change.discarded      LOW      operator dropped from queue
#
# Catastrophic features (reboot/restore/firmware) emit at CRITICAL.

_CATASTROPHIC_EVENT_PREFIXES = (
    "mikrotik.system.reboot",
    "mikrotik.system.shutdown",
    "mikrotik.system.firmware.install",
    "mikrotik.system.backup.restore",
    "unifi.devices.restart",
    "unifi.devices.disable",
    "unifi.devices.upgrade",
    # Destructive config deletes — escalate to CRITICAL-priority audit +
    # out-of-band notify (the confirmed=true preflight remains the access gate).
    # Prefix-matched, so "unifi.firewall.delete" covers delete_policy/zone/rule/
    # group/nat (audit #1 F3).
    "unifi.networks.delete",
    "unifi.wlans.delete_ssid",
    "unifi.firewall.delete",
    "unifi.vpn.delete",
    "opnsense.system.reboot",
    "opnsense.system.firmware_update",
    "pfsense.system.reboot",
    "pfsense.system.firmware_update",
    "proxmox.node.shutdown",
    "proxmox.node.reboot",
    # Omada features are bare (no vendor prefix — legacy of being the original
    # adapter); these are the irreversible device/controller ops that warrant a
    # CRITICAL-priority change event (out-of-band notify + escalated audit).
    "bulk.device.factory_reset",
    "bulk.device.forget",
    "firmware.upgrade",  # also matches firmware.upgrade.batch
    "system.backup.restore",
)

# Feature families permitted to stage with ``controller_id = NULL`` — appliance-local
# daemon writes that have no vendor controller (the overlay/VPN plane). Centralized so
# the staging permit (``stage_change`` below) and the apply/discard site-grant guard
# (``adapter_omada_vpn.py``) reason about the SAME set. A controllerless change carries
# no ``site_id`` to bound it, so a *site-limited* operator must be denied on EVERY
# family listed here (audit Finding 1); the apply/discard guard is deliberately
# prefix-agnostic (it denies any ``controller_id is None`` change for a site-limited
# user), and ``tests/services/gateway/test_overlay_vpn_writes.py`` asserts that every
# prefix here is covered. Adding a family is a deliberate authz decision.
CONTROLLERLESS_FEATURE_PREFIXES: tuple[str, ...] = ("overlay.",)

# Backstop on un-applied changes a single org can accumulate. A runaway Connection
# / API loop staging writes (each also copies a durable artifact to disk) must not
# fill the queue + the persistent volume without bound. Generous — well above any
# realistic legitimate backlog (apply or discard to make room).
_MAX_PENDING_PER_ORG = 2000


def _event_priority_for(feature: str, fallback: str = "normal") -> str:
    """Pick the right event priority based on the feature's blast radius."""
    if feature.startswith(_CATASTROPHIC_EVENT_PREFIXES):
        return "critical"
    return fallback


_OUTCOME_FROM_EVENT: dict[str, str] = {
    "controller.change.staged": "staged",
    "controller.change.applied": "applied",
    "controller.change.failed": "failed",
    "controller.change.discarded": "discarded",
}


async def _publish_change_event(
    change: Any,
    *,
    event_type: str,
    priority: str = "normal",
    actor_id: UUID | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    """Publish a controller.change.* event + bump the Prometheus
    counter. Best-effort — never raises.

    The event bus is the single fan-out point: WebSocket forwarder
    (real-time UI), automation engine (rule matching → notifications +
    webhooks + scripts), and plugins all subscribe. A publish failure
    must never break the staging path.

    The Prometheus increment is co-located with the event so Grafana
    + alertmanager see exactly the same lifecycle the UI sees — no
    drift between the audit log, the event stream, and the metrics.
    """
    vendor = (change.feature or "").split(".", 1)[0] or "unknown"

    # Prometheus counter — separate try/except so a Prom failure
    # doesn't block the event bus publish (and vice versa).
    try:
        from app.core.metrics import staged_changes_total

        outcome = _OUTCOME_FROM_EVENT.get(event_type, "unknown")
        staged_changes_total.labels(
            vendor=vendor,
            operation=change.operation or "unknown",
            outcome=outcome,
        ).inc()
    except Exception:
        import logging

        logging.getLogger(__name__).debug(
            "metric increment skipped for %s",
            event_type,
            exc_info=True,
        )

    try:
        from app.core.events import (
            Event,
            EventCategory,
            EventPriority,
            get_event_bus,
        )

        # Map the string priority into the EventPriority enum. Default
        # to NORMAL if the caller passed an unknown value.
        try:
            ep = EventPriority(priority)
        except ValueError:
            ep = EventPriority.NORMAL

        payload: dict[str, Any] = {
            "change_id": str(change.id),
            # None for controllerless overlay.* daemon writes (not the string "None")
            "controller_id": str(change.controller_id) if change.controller_id else None,
            "feature": change.feature,
            "operation": change.operation,
            "target_id": change.target_id,
            "vendor": vendor,
            "status": change.status,
        }
        if change.site_id is not None:
            payload["site_id"] = str(change.site_id)
        if change.applied_at is not None:
            payload["applied_at"] = change.applied_at.isoformat()
        if actor_id is not None:
            payload["actor_id"] = str(actor_id)
        if extra:
            payload.update(extra)

        await get_event_bus().publish(
            Event(
                event_type=event_type,
                category=EventCategory.CONTROLLER,
                priority=ep,
                payload=payload,
                organization_id=str(change.organization_id),
                source="staging",
            )
        )
    except Exception:
        # The event bus is best-effort. A broken Redis pub/sub or a
        # subscriber raising MUST NEVER fail the apply / discard path.
        import logging

        log = logging.getLogger(__name__)
        # For catastrophic-priority events (rule/route/firewall deletes
        # — see ``_CATASTROPHIC_EVENT_PREFIXES``), escalate the log
        # level to ERROR and include the full payload so an operator
        # scraping logs can reconstruct the missed notification.
        # Subscribers downstream (automation, WebSocket forwarders)
        # won't see this event — alertmanager can match on the ERROR
        # log + counter to page someone for replay. Building a real
        # DLQ table is a planned future enhancement.
        is_catastrophic = (change.feature or "").startswith(
            _CATASTROPHIC_EVENT_PREFIXES
        ) or priority in ("critical", "high")
        if is_catastrophic:
            log.error(
                "DROPPED critical event %s for change=%s (feature=%s op=%s priority=%s payload=%s)",
                event_type,
                getattr(change, "id", "?"),
                change.feature,
                change.operation,
                priority,
                payload,
                exc_info=True,
            )
            # Best-effort Prometheus counter so dashboards can alert
            # on critical-event drops without parsing logs.
            try:
                from app.core.metrics import event_publish_failures_total

                event_publish_failures_total.labels(
                    vendor=vendor,
                    priority=priority,
                ).inc()
            except Exception:
                pass
        else:
            log.warning(
                "event bus publish failed for %s (change=%s)",
                event_type,
                getattr(change, "id", "?"),
                exc_info=True,
            )


# ── Defense-in-depth: payload keys that flow into Omada client URL ──
# At apply time, every ``build_applier`` may extract these keys from
# ``payload`` and pass them as positional args to Omada client methods
# that interpolate them into URL paths via f-strings (the client does
# NOT URL-encode path segments). Validate at stage time so a bad value
# never reaches the DB row, let alone the live controller.
#
# False positives (a legitimate JSON field named ``mac`` that doesn't
# flow into a URL) still satisfy the safe-id regex, so this is
# strictly defensive.
# Any string value that contains these tokens is a path-traversal
# attempt — refuse it regardless of which key carries it. The narrow
# regex here intentionally leaves room for legitimate dotted IPv4 /
# version strings, etc., while catching ``..``, ``/``, and ``\``.
_PATH_TRAVERSAL_RE = re.compile(r"\.\.|/|\\")


def _validate_url_path_payload_keys(payload: dict[str, Any]) -> None:
    from app.adapters.validation import validate_id, validate_mac

    mac_keys = {"mac", "switch_mac", "device_mac", "ap_mac"}
    id_keys = {
        "wlan_id",
        "ssid_id",
        "portal_id",
        "backup_id",
        "template_id",
        "target_site_id",
        "schedule_id",
        "user_id",
        "admin_id",
        "policy_id",
        "operator_id",
        # Additional URL-path-bound keys.
        # Each of these flows into f-string-built Omada URLs in at
        # least one ``build_applier``; a path-traversal payload here
        # would short-circuit the staging gate.
        "change_id",
        "network_id",
        "route_id",
        "lag_id",
        "binding_id",
        "reservation_id",
        "rule_id",
        "port_id",
        "vlan_id",
    }

    for key, value in payload.items():
        if not isinstance(key, str):
            continue
        # Strict allow-list validators for known URL-path-bound keys.
        validator: Any = None
        if key in mac_keys:
            validator = validate_mac
        elif key in id_keys or key == "device_mac":
            validator = lambda v, _k=key: validate_id(v, label=_k)  # noqa: E731

        if validator is not None:
            if isinstance(value, str):
                validator(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        validator(item)

        # Defense-in-depth fallback: any string value at the top level
        # of the payload whose key SUFFIX suggests it might be
        # interpolated into a URL (``*_id``, ``*_mac``, ``id``, ``mac``)
        # but isn't in the strict allowlist above is still subjected to
        # the path-traversal regex. We deliberately do NOT recurse into
        # nested dicts — those frequently carry legitimate CIDRs, file
        # paths, or descriptions and would false-positive.
        if (
            validator is None
            and isinstance(key, str)
            and (key.endswith("_id") or key.endswith("_mac") or key in {"id", "mac"})
        ):
            if isinstance(value, str) and _PATH_TRAVERSAL_RE.search(value):
                raise HTTPException(
                    400,
                    detail=(f"payload[{key!r}] contains path-traversal characters"),
                )
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and _PATH_TRAVERSAL_RE.search(item):
                        raise HTTPException(
                            400,
                            detail=(
                                f"payload[{key!r}] list element contains path-traversal characters"
                            ),
                        )


class AdapterStagingService:
    """Centralised staging + apply for managed-controller writes."""

    # Maximum time a row may remain in ``applying`` before opportunistic
    # callers flip it to ``failed``. A successful apply finishes in well
    # under this window even on slow controllers; anything that's been
    # in ``applying`` longer almost certainly hit a worker crash or a
    # network timeout that wasn't trapped.
    APPLYING_TTL_SECONDS: int = 300

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    # ── Mode detection ──────────────────────────────────────────────────

    async def _recover_stale_applying(self, organization_id: UUID | None = None) -> int:
        """Auto-flip rows stuck in ``applying`` longer than the TTL to
        ``failed`` so they don't poison the queue forever.

        Returns the number of rows recovered. Best-effort: any DB error
        is swallowed because this is a maintenance hook attached to
        normal queue traffic, not an authoritative cleanup. A future
        scheduled task can replace this with a stricter sweep.
        """
        cutoff = datetime.now(UTC) - timedelta(seconds=self.APPLYING_TTL_SECONDS)
        stmt = (
            update(AdapterPendingChange)
            .where(
                AdapterPendingChange.status == "applying",
                AdapterPendingChange.updated_at < cutoff,
            )
            .values(
                status="failed",
                failure_reason="auto-recovered from stale 'applying' state",
            )
        )
        if organization_id is not None:
            stmt = stmt.where(AdapterPendingChange.organization_id == organization_id)
        try:
            result = await self.db.execute(stmt)
            await self.db.commit()
            return int(result.rowcount or 0)
        except Exception:
            await self.db.rollback()
            return 0

    @staticmethod
    def is_read_only() -> bool:
        """Returns True when controller writes are gated.

        A single, platform-wide flag: ``ADAPTER_READ_ONLY``. The legacy
        per-vendor ``OMADA_READ_ONLY`` is no longer OR'd in — one clear state
        (read-only ↔ read-write) governs every adapter, so an operator never
        has to reason about which of several flags is winning. The code default
        is fail-safe True; the shipped deployment default is read-write (see
        docker-compose ``ADAPTER_READ_ONLY``). Resolved at call time so the
        Settings-UI runtime toggle takes effect without a restart.
        """
        from app.core.runtime_flags import is_adapter_read_only

        return is_adapter_read_only()

    # ── Stage ───────────────────────────────────────────────────────────

    async def stage_change(
        self,
        *,
        organization_id: UUID,
        controller_id: UUID | None,
        feature: str,
        operation: str,
        payload: dict[str, Any],
        site_id: UUID | None = None,
        omada_site_id: str | None = None,
        target_id: str | None = None,
        notes: str | None = None,
        actor_id: UUID | None = None,
    ) -> AdapterPendingChange:
        """Record a write intent. Does NOT touch the controller."""
        # Containment guard: controller_id may be NULL ONLY for the appliance-local
        # daemon families in CONTROLLERLESS_FEATURE_PREFIXES (the ``overlay.*`` VPN
        # plane today — no vendor controller). Every other feature MUST target a
        # controller, preserving the controller-bound write plane's "every staged
        # change has a controller" invariant despite the column now being nullable
        # (migration 004). Without this, a future non-overlay write staged with a NULL
        # controller would skip the controller-grant authz the apply path keys on
        # ``controller_id is not None``.
        if controller_id is None and not feature.startswith(CONTROLLERLESS_FEATURE_PREFIXES):
            allowed = ", ".join(p + "*" for p in CONTROLLERLESS_FEATURE_PREFIXES)
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail=f"feature {feature!r} requires a controller_id (only {allowed} may be controllerless)",
            )
        if operation not in ("create", "update", "delete"):
            # Caller/input error — surface as 400, not a bare ValueError that
            # the global handler would turn into an opaque 500.
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail=f"operation must be create|update|delete, got {operation!r}",
            )
        # Per-user site grant: a staged write targets ``site_id``;
        # a site-limited caller may only stage into sites they're granted.
        # This is the shared chokepoint — every per-domain stage endpoint
        # (bulk / mikrotik / pfsense / opnsense / ...) funnels through here,
        # so a single guard at this layer covers callers that never thread
        # ``current_user``. Reads the request-scoped contextvar; no-op for
        # super_admin / org_admin / grant-less users and in system context.
        assert_site_access_for_request(site_id, detail="site not found")
        # Defense-in-depth: target_id and well-known URL-path payload
        # keys flow into Omada client URLs at apply time (the client
        # does NOT URL-encode path segments). Reject malformed values
        # here so they never reach the DB row, let alone the live
        # controller.
        from app.adapters.validation import validate_id

        if target_id is not None:
            validate_id(target_id, label="target_id")
        _validate_url_path_payload_keys(payload or {})

        # ``confirmed`` is a reserved APPLY-TIME control — the destructive-op
        # preflights read it, and apply_change overwrites it with the apply
        # request's flag. It is never durable staged data, so strip it here: a
        # direct-API caller must not be able to pre-seed a confirmation into the
        # stored payload (which would otherwise persist and ride into the applier
        # body). Confirmation is supplied by the sanctioned apply request only.
        if isinstance(payload, dict) and "confirmed" in payload:
            payload = {k: v for k, v in payload.items() if k != "confirmed"}

        # Opportunistic recovery: any rows stuck in ``applying`` past
        # the TTL get flipped to ``failed`` so the queue stays clean.
        await self._recover_stale_applying(organization_id)

        # DoS hygiene: bound the un-applied (pending) backlog per org so a runaway
        # Connection / API loop can't fill the queue + durable-artifact volume.
        pending_count = (
            await self.db.execute(
                select(func.count())
                .select_from(AdapterPendingChange)
                .where(
                    AdapterPendingChange.organization_id == organization_id,
                    AdapterPendingChange.status == "pending",
                )
            )
        ).scalar() or 0
        if pending_count >= _MAX_PENDING_PER_ORG:
            # Legitimate quota/backpressure condition — surface as 429 (Too
            # Many Requests) so the caller can back off and apply/discard,
            # rather than a bare ValueError masquerading as a 500 server fault.
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"pending-change limit reached for this organization "
                    f"({_MAX_PENDING_PER_ORG}); apply or discard some before staging more"
                ),
            )

        change = AdapterPendingChange(
            organization_id=organization_id,
            controller_id=controller_id,
            site_id=site_id,
            omada_site_id=omada_site_id,
            feature=feature,
            operation=operation,
            target_id=target_id,
            payload=payload,
            status="pending",
            notes=notes,
            created_by=actor_id,
        )
        self.db.add(change)
        await self.db.commit()
        await self.db.refresh(change)
        await _publish_change_event(
            change,
            event_type="controller.change.staged",
            priority="normal",
            actor_id=actor_id,
        )
        return change

    # ── List / filter ───────────────────────────────────────────────────

    async def list_pending(
        self,
        *,
        organization_id: UUID,
        controller_id: UUID | None = None,
        site_id: UUID | None = None,
        feature_prefixes: list[str] | None = None,
        feature_prefix: str | None = None,
        status_filter: str | None = "pending",
        limit: int = 200,
    ) -> list[AdapterPendingChange]:
        """Return pending changes for the org, optionally narrowed.

        ``feature_prefixes`` (preferred) accepts multiple prefixes that
        are OR'd together (e.g. ``["bulk.", "site."]`` for the bulk page).
        ``feature_prefix`` (legacy single-value) is still honoured for
        callers that have only one prefix to filter on.
        """
        # Opportunistic recovery before listing — operators inspecting
        # the queue should see ``failed`` for stale rows, not the
        # misleading ``applying``.
        await self._recover_stale_applying(organization_id)
        stmt = select(AdapterPendingChange).where(
            AdapterPendingChange.organization_id == organization_id,
        )
        if controller_id is not None:
            stmt = stmt.where(AdapterPendingChange.controller_id == controller_id)
        if site_id is not None:
            stmt = stmt.where(AdapterPendingChange.site_id == site_id)
        # Per-user site grant: the per-domain ``/changes`` list
        # endpoints (mikrotik / pfsense / opnsense / bulk / by-gateway)
        # scope only on org + controller_id — a site-limited operator
        # listing a controller that spans sibling sites would otherwise
        # see staged rows for sites they don't hold a grant on. AND the
        # caller's granted-site predicate into the query at this shared
        # chokepoint. ``true()`` (no-op) for super_admin / org_admin /
        # grant-less users and in system context.
        stmt = stmt.where(site_scope_filter(current_user_var.get(), AdapterPendingChange.site_id))
        prefixes = list(feature_prefixes or [])
        if feature_prefix is not None:
            prefixes.append(feature_prefix)
        # Drop empty strings to avoid "LIKE %" returning everything.
        prefixes = [p for p in prefixes if p]
        if prefixes:
            stmt = stmt.where(or_(*[AdapterPendingChange.feature.like(f"{p}%") for p in prefixes]))
        if status_filter is not None:
            stmt = stmt.where(AdapterPendingChange.status == status_filter)
        stmt = stmt.order_by(AdapterPendingChange.created_at.desc()).limit(limit)

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get(self, change_id: UUID) -> AdapterPendingChange | None:
        change = await self.db.get(AdapterPendingChange, change_id)
        # Per-user site grant: a site-limited caller fetching a
        # staged change by id must not be able to read a sibling-site row
        # (the apply / discard endpoints fetch via this method before their
        # permission checks). 404 (not 403) to avoid an existence oracle —
        # the row's existence is itself information. No-op for super_admin /
        # org_admin / grant-less users and in system context.
        if change is not None:
            assert_site_access_for_request(change.site_id, detail="pending change not found")
        return change

    # ── Discard ─────────────────────────────────────────────────────────

    async def discard(
        self,
        change_id: UUID,
        *,
        organization_id: UUID,
        actor_id: UUID | None = None,
        force: bool = False,
    ) -> AdapterPendingChange:
        """Mark a pending change as discarded.

        Tenant-scoped: refuses to mutate a row that doesn't belong to
        ``organization_id``. The check happens BEFORE any state change
        so a cross-tenant UUID guess can't flip another org's row and
        only then 404 the caller.

        ``force`` allows discarding from ``"applying"`` state for
        operator recovery (when a previous apply crashed mid-call and
        left the row stuck). Without ``force``, only ``"pending"`` is
        discardable.
        """
        # STAGE-RACE-1: discard previously
        # used a plain ``self.get(change_id)`` followed by an
        # unconditional status flip. Concurrent apply + discard on the
        # same row could both see ``status="pending"`` in stale
        # snapshots, apply could win the SELECT FOR UPDATE race, commit
        # ``status="applied"``, and discard could then overwrite it
        # with ``status="discarded"`` — silently corrupting the audit
        # trail (applied write actually happened, but the FE sees
        # "discarded"). Fix: claim the row with the same
        # ``SELECT ... FOR UPDATE`` lock apply uses. The concurrent
        # discard now blocks behind apply's lock, then sees the new
        # status and 409s cleanly.
        claim_stmt = (
            select(AdapterPendingChange)
            .where(AdapterPendingChange.id == change_id)
            .with_for_update()
        )
        change = (await self.db.execute(claim_stmt)).scalar_one_or_none()
        if change is None or change.organization_id != organization_id:
            raise HTTPException(404, detail="pending change not found")
        # Per-user site grant: block a site-limited operator from
        # discarding another site's queued change by id, BEFORE the status
        # mutation. Same 404 shape as the org check above. No-op for
        # super_admin / org_admin / grant-less users and in system context.
        assert_site_access_for_request(change.site_id, detail="pending change not found")
        allowed = ("pending",) if not force else ("pending", "applying")
        if change.status not in allowed:
            raise HTTPException(
                409,
                detail=(f"cannot discard a change with status={change.status!r}"),
            )
        change.status = "discarded"
        change.updated_by = actor_id
        # Prune any durable Fabric blob this staged write referenced — a
        # discarded write is never applied, so the blob is now garbage.
        await self._cleanup_durable_artifact(change)
        await self.db.commit()
        await self.db.refresh(change)
        # emit an AuditLogRecord on
        # discard for the same reasons we audit on apply — a tenant
        # admin needs the full lifecycle (stage → apply OR discard) to
        # reconstruct who killed a queued operation and why. Without
        # this, an operator could silently drop another operator's
        # staged change with no DB trail. Audit-write failures are loud
        # but never fail the discard.
        try:
            from app.services.audit import AuditService

            audit = AuditService(self.db)
            await audit.log(
                action=f"discard:{change.feature}:{change.operation}",
                resource_type="controller",
                resource_id=change.controller_id,
                organization_id=change.organization_id,
                site_id=change.site_id,
                actor_id=actor_id,
                new_state={
                    "feature": change.feature,
                    "operation": change.operation,
                    "target_id": change.target_id,
                    "forced": force,
                },
                extra_metadata={
                    "change_id": str(change.id),
                    "feature": change.feature,
                },
                tags=["staging", "discard"],
            )
        except Exception:
            import logging

            logging.getLogger(__name__).exception(
                "audit row for discard change=%s feature=%s could not be "
                "written; discard already succeeded",
                change_id,
                change.feature,
            )
        await _publish_change_event(
            change,
            event_type="controller.change.discarded",
            priority="low",
            actor_id=actor_id,
            extra={"forced": force},
        )
        return change

    async def _cleanup_durable_artifact(self, change: AdapterPendingChange) -> None:
        """Prune the durable Fabric blob a staged write referenced, once the
        change reaches a terminal state (applied/failed/discarded).

        A Fabric storage write (e.g. ``storage.store_blob``) carries its blob in
        the durable artifact store, referenced by ``payload._artifact``. The
        executor persists it at stage time so it survives sign-off latency; this
        prunes it the moment the change is terminal so the durable dir does not
        grow without bound on discards or failed applies. Best-effort: a cleanup
        failure must never affect the staging outcome.
        """
        payload = change.payload if isinstance(change.payload, dict) else {}
        art = payload.get("_artifact")
        token = art.get("durable_token") if isinstance(art, dict) else None
        if not token:
            return
        try:
            from app.core.fabric.durable_store import durable_store

            await durable_store.delete(str(token), change.organization_id)
        except Exception:
            import logging

            logging.getLogger(__name__).debug(
                "durable artifact cleanup skipped for change=%s", change.id, exc_info=True
            )

    # ── Apply ───────────────────────────────────────────────────────────

    async def apply_change(
        self,
        change_id: UUID,
        *,
        force: bool = False,
        confirmed: bool = False,
        applier: Any | None = None,
        actor_id: UUID | None = None,
    ) -> AdapterPendingChange:
        """Push a staged change to the live controller.

        ``applier``: an awaitable ``async (change) -> dict`` that performs
        the actual API call. Each feature module (VPN, firmware, etc.)
        builds its own applier and passes it in. This keeps the staging
        service feature-agnostic.

        True dual-gate, evaluated in order: ``ADAPTER_READ_ONLY`` (or the
        legacy ``OMADA_READ_ONLY``) is a HARD environment lock — when True it
        refuses regardless of ``force`` (``force`` cannot bypass it). Only once
        that env lock is open does the second gate apply: ``force`` must also be
        True. The intent is that operators must explicitly opt in twice (env
        flag off + force flag) to push to a live prod controller — no
        path applies a change accidentally.

        Concurrency: claims the row with ``SELECT ... FOR UPDATE`` and
        flips ``status`` to ``"applying"`` inside the same transaction
        before invoking the applier. A second concurrent apply call on
        the same change finds ``status != "pending"`` and 409s. This
        prevents a double-click from pushing a duplicate ``create``
        twice to the live controller.
        """
        # True dual-gate: both conditions are independent hard locks.
        # Gate 1: env lock — no API caller can bypass this regardless of
        # the force flag.  Operators must set ADAPTER_READ_ONLY=false in
        # the deployment environment before any apply is possible.
        if self.is_read_only():
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=("ADAPTER_READ_ONLY is enabled; set it to false to apply changes"),
            )
        # Gate 2: explicit intent — the caller must pass force=true to
        # confirm they understand this pushes directly to the live
        # controller.  This guard is only reached when the env lock is
        # already open (ADAPTER_READ_ONLY=false).
        if not force:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=("force=true is required to apply a staged change"),
            )

        if applier is None:
            raise HTTPException(
                500,
                detail=(
                    "no applier provided — feature modules must pass an "
                    "applier callable that knows how to talk to the "
                    "controller for this feature"
                ),
            )

        # Atomic claim: lock the row, verify it's still pending, flip
        # to "applying" inside the same transaction. Anything else racing
        # us will block on the lock and find status != "pending".
        claim_stmt = (
            select(AdapterPendingChange)
            .where(AdapterPendingChange.id == change_id)
            .with_for_update()
        )
        change = (await self.db.execute(claim_stmt)).scalar_one_or_none()
        if change is None:
            raise HTTPException(404, detail="pending change not found")
        # Per-user site grant: a site-limited operator must not be
        # able to push another site's staged change to the live device by
        # supplying its id. Enforced at the chokepoint BEFORE the row is
        # flipped to "applying" and BEFORE the applier touches the
        # controller. 404 to avoid an existence oracle. No-op for
        # super_admin / org_admin / grant-less users and in system context.
        assert_site_access_for_request(change.site_id, detail="pending change not found")
        if change.status != "pending":
            raise HTTPException(
                409,
                detail=f"change is {change.status}, not pending",
            )
        # Apply-time confirmation (all vendors): the destructive-op pre-flights
        # below refuse unless the change carries ``confirmed=true``. Confirmation is
        # an apply-time decision made in the Pending-Changes drawer (the single
        # sanctioned apply path), where the operator reviews the diff and
        # acknowledges the destructive op — NOT durable staged data.
        #
        # The apply request's ``confirmed`` flag is therefore AUTHORITATIVE: it
        # unconditionally overwrites any ``confirmed`` already in the stored payload
        # in a LOCAL view used ONLY for the pre-flights. A direct-API caller (not the
        # UI) CAN stage ``payload.confirmed=true`` into the free-form payload; without
        # this override an unconfirmed apply would inherit that stored ``true`` and
        # sail through the catastrophic gate. Overwriting with the apply-request flag
        # (a typed ``bool``) means an unconfirmed apply always presents
        # ``confirmed=False`` regardless of what was staged — and the pre-flights
        # still evaluate it through the strict ``payload_confirmed`` helper. The
        # stored ``change.payload`` is never mutated here (no DB write; stage-time
        # already strips the reserved key so it can't reach the applier body or a
        # re-apply either).
        preflight_payload = {**(change.payload or {}), "confirmed": confirmed}
        # Vendor pre-flight (OPNsense): block a catastrophic/irreversible op
        # — reboot/halt/firmware/backup_restore/backup_delete or ANY delete —
        # unless the staged payload carries confirmed=true. This is a second,
        # op-aware checkpoint beyond the dual-gate above: an operator who has
        # legitimately opened ADAPTER_READ_ONLY for a create-only firewall
        # change cannot, in the same session, blind-apply a staged reboot or a
        # rule/route/NAT delete. Runs at the single sanctioned apply chokepoint
        # (covers every opnsense.* feature, no per-applier wiring to forget) and
        # BEFORE the row flips to "applying" so a refusal leaves it pending.
        # No-op for non-opnsense features. (Proxmox enforces the equivalent
        # inside its own appliers.)
        from app.services.adapter_opnsense_preflight import enforce_opnsense_preflight

        enforce_opnsense_preflight(change.feature, change.operation, preflight_payload)
        # Vendor pre-flight (Omada): same op-aware checkpoint for the owner's
        # live production network core. Omada staged features are BARE (no
        # ``omada.`` prefix — a legacy of Omada being the original adapter), so
        # the gate cannot key on a feature prefix; it is scoped by the change's
        # controller type instead. A catastrophic Omada op (firmware flash,
        # device factory-reset/forget, controller backup-restore, or ANY delete)
        # is blocked unless the staged payload carries confirmed=true. No-op for
        # any non-Omada controller. One indexed PK lookup at the chokepoint.
        from app.db.models import Controller
        from app.services.adapter_omada_preflight import enforce_omada_preflight

        controller_type = (
            await self.db.execute(
                select(Controller.controller_type).where(Controller.id == change.controller_id)
            )
        ).scalar_one_or_none()
        enforce_omada_preflight(
            str(controller_type) if controller_type is not None else None,
            change.feature,
            change.operation,
            preflight_payload,
        )
        # Vendor pre-flight (pfSense + MikroTik): same op-aware checkpoint as
        # OPNsense/Omada above, closing the asymmetry where a prod firewall rule
        # delete / router reboot / firmware install could be blind-applied on a
        # single force toggle. Both vendors carry a ``<vendor>.`` feature prefix,
        # so each gate keys on that prefix and is a no-op for other features —
        # safe to sit unconditionally on this shared apply chokepoint. A
        # CATASTROPHIC op (reboot/halt/shutdown, firmware, backup/config restore,
        # package uninstall, or ANY delete) is blocked unless the staged payload
        # carries confirmed=true. Runs BEFORE the row flips to "applying" so a
        # refusal leaves it pending.
        from app.services.adapter_mikrotik_preflight import enforce_mikrotik_preflight
        from app.services.adapter_pfsense_preflight import enforce_pfsense_preflight

        enforce_pfsense_preflight(change.feature, change.operation, preflight_payload)
        enforce_mikrotik_preflight(change.feature, change.operation, preflight_payload)
        # Vendor pre-flight (UniFi): same op-aware checkpoint. UniFi features carry
        # a ``unifi.`` prefix so the gate keys on it (no-op for others). Closes the
        # asymmetry where the devices applier (unifi.devices.restart/.disable)
        # applied with force=True and NO confirmation, unlike every other vendor.
        from app.services.adapter_unifi_preflight import enforce_unifi_preflight

        enforce_unifi_preflight(change.feature, change.operation, preflight_payload)
        # Vendor pre-flight (UniFi per-site grant): the new UniFi domains stage with
        # ``site_id=None`` and carry the upstream UniFi site as ``payload.site``, so
        # the generic ``assert_site_access_for_request(change.site_id)`` above cannot
        # see it. A site-limited operator who can reach the controller must still
        # only apply to the FreeSDN site the slug maps to (controller.site_mappings)
        # — enforced centrally here so EVERY unifi.* domain applier is covered at the
        # single chokepoint. No-op for non-UniFi features, the default site, and
        # unrestricted users.
        if (change.feature or "").startswith("unifi."):
            from app.services.adapter_unifi_common import enforce_unifi_site_grant

            unifi_ctrl = await self.db.get(Controller, change.controller_id)
            if unifi_ctrl is not None:
                enforce_unifi_site_grant(unifi_ctrl, (change.payload or {}).get("site"))
        # Vendor pre-flight (Proxmox): the SAME central chokepoint as the other
        # vendors. Proxmox previously relied solely on per-applier preflight_gate
        # calls (comment above said "Proxmox enforces the equivalent inside its own
        # appliers"). A per-applier gate can be omitted, so enforce it centrally at
        # this single chokepoint so no applier can ever skip it; the
        # per-applier gates remain as device-aware defense-in-depth. No device read
        # here (classification only), so no adapter is needed at the chokepoint.
        from app.services.adapter_proxmox_preflight import enforce_proxmox_preflight

        enforce_proxmox_preflight(change.feature, change.operation, preflight_payload)
        # Universal catastrophic-DELETE backstop (fail-closed). Every vendor pre-flight
        # above gates only ITS OWN feature prefix, but a vendor with no registered
        # pre-flight — openwrt.* / pbx.* (FreePBX) / storage.* (TrueNAS) today, and any
        # future adapter — would otherwise let a staged DELETE apply on a bare
        # ``force=true`` with NO confirmation, the exact asymmetry the per-vendor gates
        # were added over several waves to close (an operator who legitimately lowered
        # ADAPTER_READ_ONLY for a create could blind-apply a rule/NAT/extension delete
        # that cuts access). Enforce the owner rule "ALL deletes require explicit
        # confirmation" once, centrally, so a newly-added vendor can never silently ship
        # a blind-applyable delete. Reads the authoritative ``preflight_payload`` (whose
        # ``confirmed`` is the apply-request flag), and is redundant/harmless for the
        # six covered vendors — they already 409'd above.
        from app.services.adapter_preflight_common import payload_confirmed

        if (change.operation or "").lower() == "delete" and not payload_confirmed(
            preflight_payload
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    f"{change.feature} (delete) is a destructive operation; re-apply "
                    "with confirmed=true (the Pending-Changes drawer's typed-APPLY step)."
                ),
            )
        change.status = "applying"
        change.updated_by = actor_id
        await self.db.commit()
        await self.db.refresh(change)

        try:
            # Open the approved staged-apply window so adapter clients that gate
            # direct writes on read-only mode (the Omada client) permit THIS
            # sanctioned write. We only reach here after the ADAPTER_READ_ONLY +
            # force gate above, so the operator has explicitly opted in.
            from app.adapters.apply_context import apply_window

            with apply_window():
                response = await applier(change)
            # An applier may RETURN a failed AdapterResult (success=False) instead
            # of raising — e.g. the device/controller API rejected the write. Treat
            # that as a FAILED apply so the change is never recorded "applied"
            # against a device that never took it (the DB<->device consistency
            # invariant). Routed through the HTTPException handler below so the
            # real vendor cause lands in failure_reason and surfaces as 502 —
            # rather than a silent "applied" on a write the device refused.
            if getattr(response, "success", None) is False:
                raise HTTPException(
                    status_code=502,
                    detail=(
                        getattr(response, "error", None)
                        or getattr(response, "message", None)
                        or "adapter reported the write did not succeed"
                    ),
                )
            change.status = "applied"
            change.applied_at = datetime.now(UTC)
            change.applied_response = response if isinstance(response, dict) else {"data": response}
            change.updated_by = actor_id
            # emit an AuditLogRecord row on every successful
            # apply so a tenant admin can reconstruct exactly which
            # operator pushed which RouterOS / Omada / OPNsense /
            # pfSense / Proxmox mutation to the live controller. The
            # write is inside a savepoint (see ``AuditService._store_entry``)
            # so an audit-write failure won't roll back the apply
            # itself.
            try:
                from app.services.audit import AuditService

                audit = AuditService(self.db)
                payload_keys = (
                    sorted((change.payload or {}).keys())
                    if isinstance(change.payload, dict)
                    else []
                )
                await audit.log(
                    action=f"apply:{change.feature}:{change.operation}",
                    resource_type="controller",
                    resource_id=change.controller_id,
                    organization_id=change.organization_id,
                    site_id=change.site_id,
                    actor_id=actor_id,
                    new_state={
                        "feature": change.feature,
                        "operation": change.operation,
                        "target_id": change.target_id,
                        "payload_keys": payload_keys,
                    },
                    extra_metadata={
                        "change_id": str(change.id),
                        "feature": change.feature,
                    },
                    tags=["staging", "apply"],
                )
            except Exception:
                # Audit failures are loud but never fail the apply —
                # the action already happened on the live device.
                import logging

                logging.getLogger(__name__).exception(
                    "audit row for change=%s feature=%s could not be "
                    "written; apply already succeeded",
                    change_id,
                    change.feature,
                )
            # NOTE: the ``controller.change.applied`` success event is published
            # only AFTER the authoritative final commit below succeeds — see the
            # trailing block. Publishing it here (before the commit) would let a
            # final-commit failure roll the DB row back to a pre-applied state
            # while subscribers (automation, WebSocket, plugins) had already
            # been told the write was applied. The audit row above is written in
            # a savepoint and is also flushed by the same final commit.
        except HTTPException as exc:
            change.status = "failed"
            # The applier raises HTTPException(status, detail=<vendor/validation
            # message>) deliberately — e.g. the FreePBX GraphQL rejection
            # "Extension 200 already exists" or "field not found". Persist that
            # real cause so the drawer's failed rows are diagnosable instead of
            # the opaque "applier raised HTTPException". This detail is already
            # exposed in the re-raised 502 response below, so persisting it adds
            # no new leakage. (The generic-Exception branch below stays
            # sanitized to the class name, since those carry raw client errors.)
            _detail = exc.detail
            change.failure_reason = (
                str(_detail)[:1000] if _detail else "applier raised HTTPException"
            )
            change.updated_by = actor_id
            # Terminal failure: the write won't be retried (apply claims only
            # 'pending'), so prune the durable blob it referenced.
            await self._cleanup_durable_artifact(change)
            await self.db.commit()
            await self.db.refresh(change)
            await _publish_change_event(
                change,
                event_type="controller.change.failed",
                priority="high",
                actor_id=actor_id,
                extra={
                    "failure_reason": change.failure_reason,
                    "http_status": exc.status_code,
                },
            )
            raise
        except Exception as exc:
            # Sanitize what the operator sees: ``repr(exc)`` and ``str(exc)``
            # for httpx / Omada client errors can include the controller's
            # internal URL, response headers, or echoed credential
            # fragments. Surface only the exception class to the user;
            # log the full repr server-side so operators can correlate
            # by request_id.
            import logging

            logging.getLogger(__name__).exception(
                "apply_change failed for change=%s feature=%s",
                change_id,
                change.feature,
            )
            short = type(exc).__name__
            change.status = "failed"
            change.failure_reason = short
            change.updated_by = actor_id
            # Terminal failure: prune the durable blob this write referenced.
            await self._cleanup_durable_artifact(change)
            await self.db.commit()
            await self.db.refresh(change)
            await _publish_change_event(
                change,
                event_type="controller.change.failed",
                priority="high",
                actor_id=actor_id,
                extra={"failure_reason": short},
            )
            raise HTTPException(
                502,
                detail=f"controller rejected the change ({short})",
            ) from exc

        try:
            await self.db.commit()
            await self.db.refresh(change)
        except Exception:
            # Defensive: if the final
            # commit fails after a successful applier run, roll back
            # so the session doesn't carry uncommitted mutations into
            # the next request. The applier ALREADY ran on the live
            # controller — we can't undo that — but the DB state will
            # at least be coherent and the operator gets a clear 5xx.
            try:
                await self.db.rollback()
            except Exception:
                pass
            # The device write DID happen. If we simply roll back and return,
            # the row is left at ``applying`` and ``_recover_stale_applying``
            # will later flip it to ``failed`` after the TTL — mislabeling a
            # real, applied write as failed. Make a best-effort second commit
            # of the terminal ``applied`` state (in a fresh transaction) so the
            # bookkeeping reflects what actually happened on the device. This is
            # best-effort: if it too fails we still raise so the operator sees a
            # clear error, but we never claim the write didn't happen.
            try:
                await self.db.execute(
                    update(AdapterPendingChange)
                    .where(AdapterPendingChange.id == change_id)
                    .values(
                        status="applied",
                        applied_at=datetime.now(UTC),
                        updated_by=actor_id,
                        failure_reason=(
                            "device write succeeded but post-write bookkeeping "
                            "commit failed; recovered to 'applied'"
                        ),
                    )
                )
                await self.db.commit()
            except Exception:
                try:
                    await self.db.rollback()
                except Exception:
                    pass
            raise
        # Authoritative commit succeeded — only now is it safe to tell
        # subscribers the write was applied. Publishing AFTER the commit means
        # a final-commit failure (handled above) never emits a false "applied"
        # event. Catastrophic features escalate to CRITICAL so automation rules
        # can match "any critical apply on this tenant" for out-of-band notify.
        await _publish_change_event(
            change,
            event_type="controller.change.applied",
            priority=_event_priority_for(change.feature, "high"),
            actor_id=actor_id,
        )
        return change


# Deprecated alias. The class was renamed from ``OmadaStagingService``
# in v2.7 once the staging pattern became adapter-agnostic in practice
# (MikroTik, UniFi, OPNsense, pfSense, Proxmox all stage through here).
# External code that imported the old name keeps working through the
# rename. New code MUST use ``AdapterStagingService``.
OmadaStagingService = AdapterStagingService
