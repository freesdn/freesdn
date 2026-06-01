# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN Fabric — the Operation Executor.

Invokes a single :class:`Operation` and returns a normalized
:class:`OperationResult`, routing by trust tier + write-ness. This is the
security heart of the Fabric — the one place that decides *how* a capability
actually runs:

  * **native read** (``tier=native, write=False``)  → call the module's handler
    directly (``handler(ctx) -> OperationResult``); the handler may produce an
    artifact through the broker.
  * **native write** (``tier=native, write=True``)   → **never executed raw**.
    The executor STAGES the change via ``AdapterStagingService`` and returns the
    pending-change id. Application requires an operator's explicit sign-off
    through the staged-change pipeline (dual-gate). The Fabric never force-applies.
  * **plugin** (``tier=plugin``)                      → run the plugin's
    SDK-bounded handler (``handler(params) -> dict``) behind a hard timeout,
    sanitize errors, and bound the output size. A plugin operation may never be
    a native write and never force-applies (writes only ever come from a
    native, operator-authored path).

Permission enforcement (the author must hold ``op.permission``) is performed by
the Negotiator, which holds the authoring user; the executor trusts that gate
and focuses on tier-correct, bounded invocation. ``organization_id`` is threaded
fail-closed throughout.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING
from uuid import UUID

from app.core.fabric.execution import OperationContext, OperationResult
from app.core.fabric.operations import Operation, OperationTier

if TYPE_CHECKING:
    from app.core.fabric.artifact_broker import ArtifactBroker

logger = logging.getLogger(__name__)

#: Hard ceiling on how long an untrusted plugin operation may run.
PLUGIN_OP_TIMEOUT_SECONDS = 30.0
#: Tighter artifact cap for the plugin tier (vs the broker's native default).
PLUGIN_ARTIFACT_MAX_BYTES = 16 * 1024 * 1024
#: Cap on a plugin operation's JSON output (prevents memory blowups from a
#: misbehaving/hostile plugin returning a giant dict).
PLUGIN_OUTPUT_MAX_BYTES = 256 * 1024


class OperationExecutor:
    """Tier-aware, bounded invoker for Fabric operations."""

    def __init__(self, artifact_broker: ArtifactBroker | None = None) -> None:
        if artifact_broker is None:
            from app.core.fabric.artifact_broker import artifact_broker as _default

            artifact_broker = _default
        self._artifacts = artifact_broker

    async def execute(self, op: Operation, ctx: OperationContext) -> OperationResult:
        """Invoke ``op`` under ``ctx`` and return a normalized result.

        Never raises for operational failures — every path returns an
        ``OperationResult`` so the Negotiator can record the outcome and decide
        whether to continue the chain.
        """
        try:
            if op.tier is OperationTier.PLUGIN:
                return await self._execute_plugin(op, ctx)
            if op.write:
                return await self._execute_native_write(op, ctx)
            return await self._execute_native_read(op, ctx)
        except Exception as exc:  # noqa: BLE001 — normalize all failures
            logger.exception("Fabric executor: operation %s failed", op.id)
            return OperationResult.fail(f"operation {op.id} failed: {exc}", "EXEC_ERROR")

    # ── native read ──────────────────────────────────────────────────────

    async def _execute_native_read(self, op: Operation, ctx: OperationContext) -> OperationResult:
        if op.handler is None:
            return OperationResult.fail(f"operation {op.id} declares no handler", "NOT_SUPPORTED")
        result = await op.handler(ctx)
        if not isinstance(result, OperationResult):
            return OperationResult.fail(
                f"operation {op.id} handler returned {type(result).__name__}, expected OperationResult",
                "BAD_HANDLER",
            )
        # If the op declares produced media-types, a returned artifact must match.
        if result.artifact and op.produces and result.artifact.media_type not in op.produces:
            return OperationResult.fail(
                f"operation {op.id} produced {result.artifact.media_type!r} "
                f"not in declared {op.produces}",
                "MEDIA_MISMATCH",
            )
        return result

    # ── native write → STAGE ONLY (operator sign-off required to apply) ──

    async def _execute_native_write(self, op: Operation, ctx: OperationContext) -> OperationResult:
        if ctx.db is None:
            return OperationResult.fail("write operation requires a DB session", "NO_DB")
        # Appliance-local daemon writes (VPN/overlay) have no vendor controller —
        # route them to a dedicated branch that stages with controller_id=None
        # (the staging guard permits NULL only for ``overlay.*``). Like every
        # native write it STAGES ONLY; an operator applies via the dual-gate.
        if (op.feature or "").startswith("overlay."):
            return await self._execute_overlay_write(op, ctx)
        controller_raw = ctx.params.get("controller_id")
        if not controller_raw:
            return OperationResult.fail(
                f"write operation {op.id} requires 'controller_id' in params", "NO_TARGET"
            )
        try:
            controller_id = UUID(str(controller_raw))
        except (ValueError, TypeError):
            return OperationResult.fail("invalid controller_id", "BAD_TARGET")

        # Fail-closed multi-tenancy on the WRITE plane: the target controller
        # MUST belong to the Connection's org. controller_id can be templated
        # from an untrusted event payload, so we never stage a controller the
        # org doesn't own (mirrors the universal _get_controller org guard).
        if not await _controller_in_org(ctx.db, controller_id, ctx.organization_id):
            return OperationResult.fail(
                "controller_id does not belong to this organization", "CROSS_TENANT_TARGET"
            )

        site_raw = ctx.params.get("site_id")
        site_id = None
        if site_raw:
            try:
                site_id = UUID(str(site_raw))
            except (ValueError, TypeError):
                return OperationResult.fail("invalid site_id", "BAD_TARGET")
            if not await _site_in_org(ctx.db, site_id, ctx.organization_id):
                return OperationResult.fail(
                    "site_id does not belong to this organization", "CROSS_TENANT_TARGET"
                )

        # Staging op verb. update/delete dispatch by target_id, so it must be
        # extracted, strictly validated, and passed as the dedicated argument
        # (not smuggled in payload, where it would skip the strict validator).
        staging_op = str(ctx.params.get("_staging_operation") or "create")
        target_id = None
        target_raw = ctx.params.get("target_id")
        if target_raw is not None:
            from app.adapters.validation import validate_id

            try:
                target_id = validate_id(str(target_raw), label="target_id")
            except Exception:
                return OperationResult.fail("invalid target_id", "BAD_TARGET")
        if staging_op in ("update", "delete") and not target_id:
            return OperationResult.fail(
                f"{staging_op} operation {op.id} requires 'target_id'", "NO_TARGET_ID"
            )

        # Payload = everything except routing keys.
        payload = {
            k: v
            for k, v in ctx.params.items()
            if k not in ("controller_id", "site_id", "_staging_operation", "target_id")
        }

        # A write op that consumes an input artifact (accepts non-empty, e.g.
        # storage.store_blob) is unappliable without one — fail CLEARLY here
        # rather than staging a change that 400s at sign-off. This covers both
        # the direct /invoke path (which never threads an artifact) and a fire
        # from an artifact-less source (e.g. ingest.external → store_blob).
        if op.accepts and ctx.input_artifact is None:
            return OperationResult.fail(
                f"operation {op.id} requires an input artifact "
                f"({', '.join(op.accepts)}) but none was provided",
                "ARTIFACT_REQUIRED",
            )

        # Durable artifact handoff: a write that consumes a producer's blob
        # (e.g. cameras.snapshot → storage.store_blob) carries it in
        # ctx.input_artifact, which lives in the TTL-bounded broker. Sign-off
        # can be hours/days later, so copy the bytes to the durable store NOW
        # and stamp only a small reference into the staged payload — never the
        # bytes themselves (keeps the staging row small + secret-free).
        durable_token: str | None = None
        if ctx.input_artifact is not None and ctx.artifacts is not None:
            from app.core.fabric.durable_store import durable_store

            try:
                data, _ref = await ctx.artifacts.get(ctx.input_artifact.handle, ctx.organization_id)
                ref = await durable_store.put(
                    data, ctx.organization_id, ctx.input_artifact.media_type
                )
                payload["_artifact"] = ref
                durable_token = ref.get("durable_token")
            except Exception as exc:  # noqa: BLE001 — normalize for the negotiator
                return OperationResult.fail(
                    f"could not persist input artifact for staging: {exc}",
                    "ARTIFACT_UNAVAILABLE",
                )

        from app.services.adapter_staging import AdapterStagingService

        svc = AdapterStagingService(ctx.db)
        try:
            change = await svc.stage_change(
                organization_id=ctx.organization_id,
                controller_id=controller_id,
                feature=op.feature or op.id,
                operation=staging_op,
                payload=payload,
                site_id=site_id,
                target_id=target_id,
                notes=f"Staged by Fabric operation {op.id}",
                actor_id=ctx.actor_id,
            )
        except Exception as exc:  # noqa: BLE001
            # stage_change failed (e.g. the per-org pending cap, or a DB error)
            # AFTER we wrote the durable blob — delete it so it isn't orphaned on
            # the persistent volume (no TTL/sweep on the durable store).
            if durable_token is not None:
                import contextlib

                from app.core.fabric.durable_store import durable_store

                with contextlib.suppress(Exception):
                    await durable_store.delete(durable_token, ctx.organization_id)
            return OperationResult.fail(f"could not stage change: {exc}", "STAGE_FAILED")
        # STAGED, not applied. An operator applies via the PendingChanges pipeline
        # (dual-gate + force). The Fabric never auto-forces a device write.
        res = OperationResult.ok(
            output={
                "staged": True,
                "change_id": str(change.id),
                "feature": op.feature or op.id,
                "operation": staging_op,
            }
        )
        res.staged_change_id = str(change.id)
        return res

    # ── native write (daemon/overlay, no controller) → STAGE ONLY ────────

    async def _execute_overlay_write(self, op: Operation, ctx: OperationContext) -> OperationResult:
        """Stage an appliance-local overlay (VPN daemon) write — no controller.

        Tenancy is the Connection's org (``ctx.organization_id``, fail-closed by the
        negotiator). The change stages with ``controller_id=None`` (permitted by the
        staging guard only for ``overlay.*``) and a NON-SECRET payload — the applier
        re-reads + decrypts credentials from the VPN connection record at apply time,
        so auth keys never sit in the staged row. STAGED, not applied: an operator
        applies via the PendingChanges dual-gate; the Fabric never auto-forces it.
        """
        # ctx.db is already guaranteed non-None by the _execute_native_write caller.
        # The connection-bound ops (wireguard/openvpn/netbird) target a stored VPN
        # connection record; Tailscale singleton ops carry no connection_id.
        connection_id = ctx.params.get("connection_id")
        target_id = None
        if connection_id is not None:
            from app.adapters.validation import validate_id

            try:
                target_id = validate_id(str(connection_id), label="connection_id")
            except Exception:
                return OperationResult.fail("invalid connection_id", "BAD_TARGET")

        # EMPTY payload by design. The overlay applier re-reads + decrypts everything
        # it needs from the VPNConnectionRecord (resolved via target_id) and NEVER
        # reads change.payload — so copying any caller param here would only retain
        # it in the staged row in plaintext. An operator passing a secret-bearing
        # extra (e.g. authorization_header / x_api_key) must NOT have it persisted to
        # the pending-change JSON. connection_id is already captured as target_id.
        payload: dict = {}

        from app.services.adapter_staging import AdapterStagingService

        svc = AdapterStagingService(ctx.db)
        try:
            change = await svc.stage_change(
                organization_id=ctx.organization_id,
                controller_id=None,
                feature=op.feature or op.id,
                operation="create",
                payload=payload,
                target_id=target_id,
                notes=f"Staged by Fabric operation {op.id}",
                actor_id=ctx.actor_id,
            )
        except Exception as exc:  # noqa: BLE001 — normalize for the negotiator
            return OperationResult.fail(f"could not stage change: {exc}", "STAGE_FAILED")
        res = OperationResult.ok(
            output={
                "staged": True,
                "change_id": str(change.id),
                "feature": op.feature or op.id,
                "operation": "create",
            }
        )
        res.staged_change_id = str(change.id)
        return res

    # ── plugin → sandboxed, bounded ──────────────────────────────────────

    async def _execute_plugin(self, op: Operation, ctx: OperationContext) -> OperationResult:
        if op.handler is None:
            return OperationResult.fail(f"plugin operation {op.id} has no handler", "NOT_SUPPORTED")
        # Plugin write operations are categorically refused: device writes only
        # ever originate from a native, operator-authored path through staging.
        if op.write:
            return OperationResult.fail(
                f"plugin operation {op.id} may not be a write", "PLUGIN_WRITE_FORBIDDEN"
            )
        try:
            raw = await asyncio.wait_for(op.handler(ctx.params), timeout=PLUGIN_OP_TIMEOUT_SECONDS)
        except TimeoutError:
            return OperationResult.fail(
                f"plugin operation {op.id} timed out after {PLUGIN_OP_TIMEOUT_SECONDS}s",
                "PLUGIN_TIMEOUT",
            )
        except Exception:  # noqa: BLE001 — sanitize plugin internals
            logger.exception("Fabric: plugin operation %s raised", op.id)
            return OperationResult.fail(
                f"plugin operation {op.id} encountered an internal error", "PLUGIN_ERROR"
            )

        if not isinstance(raw, dict):
            raw = {"result": raw}
        # Bound the output WITHOUT materializing the whole serialization: encode
        # incrementally and bail the instant the byte budget is exceeded, so the
        # guard itself can't be turned into the memory blowup it's meant to stop.
        total = 0
        try:
            for chunk in json.JSONEncoder(default=str).iterencode(raw):
                total += len(chunk)
                if total > PLUGIN_OUTPUT_MAX_BYTES:
                    return OperationResult.fail(
                        f"plugin operation {op.id} output exceeds {PLUGIN_OUTPUT_MAX_BYTES} bytes",
                        "PLUGIN_OUTPUT_TOO_LARGE",
                    )
        except (TypeError, ValueError):
            return OperationResult.fail(
                f"plugin operation {op.id} returned non-serializable output", "PLUGIN_BAD_OUTPUT"
            )
        return OperationResult.ok(output=raw)


async def _controller_in_org(db: object, controller_id: UUID, organization_id: UUID) -> bool:
    """True iff the controller exists and belongs to the org (Controller→Site join)."""
    from sqlalchemy import select

    from app.models.core import Controller, Site

    row = (
        await db.execute(  # type: ignore[attr-defined]
            select(Controller.id)
            .join(Site, Controller.site_id == Site.id)
            .where(Controller.id == controller_id, Site.organization_id == organization_id)
        )
    ).scalar_one_or_none()
    return row is not None


async def _site_in_org(db: object, site_id: UUID, organization_id: UUID) -> bool:
    """True iff the site exists and belongs to the org."""
    from sqlalchemy import select

    from app.models.core import Site

    row = (
        await db.execute(  # type: ignore[attr-defined]
            select(Site.id).where(
                Site.id == site_id,
                Site.organization_id == organization_id,
                Site.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    return row is not None


# Module-level singleton.
operation_executor = OperationExecutor()
