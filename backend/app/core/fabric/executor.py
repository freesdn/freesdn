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
        except Exception:  # noqa: BLE001 — normalize without disclosing client internals
            # Database/adapter exceptions can contain credentials, SQL parameters
            # and private URLs. Keep them out of operation history and logs alike.
            logger.warning("Fabric executor: operation %s failed", op.id)
            return OperationResult.fail(f"operation {op.id} failed", "EXEC_ERROR")

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
        controller = await _controller_in_org(ctx.db, controller_id, ctx.organization_id)
        if not controller:
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

        # ── F-02: controller/site coherence + the caller's per-user site grant ──
        #
        # The two guards above prove the controller is in the org and the site is
        # in the org — INDEPENDENTLY. Neither proves they have anything to do with
        # each other, and neither consults ``ctx.accessible_site_ids``. That left a
        # site-grant escalation: a site_admin granted only Site A could invoke a
        # write with controller_id = a controller that lives in Site B and
        # site_id = their own Site A. ``AdapterStagingService.stage_change``'s
        # contextvar guard sees Site A and passes; the row lands with
        # controller_id=B, site_id=A. At apply time the site-grant assert reads the
        # stored Site A and, BECAUSE site_id is non-NULL, the controller-site
        # fallback in ``adapter_omada_vpn.apply_change`` is skipped — so the applier
        # drives controller B on a Site A grant.
        #
        # Two independent checks close it:
        #
        #   (1) a supplied site_id must be a site the controller actually SERVES;
        #   (2) a site-limited caller must hold a grant for the controller's own
        #       site AND for the supplied site.
        #
        # (2) mirrors what every non-Fabric stage path already enforces: they go
        # through ``GatewayServiceBase.stage_change`` → ``_resolve_controller_or_
        # gateway``, which asserts the grant on ``ctrl.site_id``. The Fabric calls
        # ``AdapterStagingService.stage_change`` directly and so skipped it. And the
        # grant has to be read from ``ctx.accessible_site_ids`` rather than the
        # request contextvar, because the negotiator + automation paths have no
        # request principal at all — that contextvar is unset there, so the staging
        # chokepoint's own guard no-ops for exactly the unattended paths.
        #
        # NOTE — deliberately NOT "staged site_id := controller.site_id". One
        # physical controller legitimately fronts SEVERAL FreeSDN sites through
        # ``Controller.site_mappings`` ({omada_site_id: freesdn_site_uuid}); the
        # Omada bulk applier resolves the Omada-side site from ``change.site_id``
        # (services/adapter_omada_bulk.py:73). Forcing the controller's own site
        # would silently retarget every multi-site Omada write. "Served by" is the
        # honest invariant, not "equal to".
        grants = ctx.accessible_site_ids
        if site_id is not None or grants is not None:
            own_site = _as_uuid(getattr(controller, "site_id", None))
            if own_site is None:
                # Fail CLOSED. Both checks below are relative to the controller's
                # own site; if we cannot resolve it we cannot prove either, and a
                # write is not the place to assume.
                return OperationResult.fail(
                    "could not resolve the target controller's site", "SITE_UNRESOLVED"
                )
            if site_id is not None and site_id not in _sites_served_by(controller):
                return OperationResult.fail(
                    "site_id is not a site served by controller_id", "CROSS_SITE_TARGET"
                )
            if grants is not None:
                if own_site not in grants:
                    return OperationResult.fail(
                        "controller_id is outside this caller's granted sites",
                        "SITE_NOT_GRANTED",
                    )
                if site_id is not None and site_id not in grants:
                    return OperationResult.fail(
                        "site_id is outside this caller's granted sites", "SITE_NOT_GRANTED"
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
            except Exception:  # noqa: BLE001 — normalize for the negotiator
                logger.warning("Fabric: artifact persistence for operation %s failed", op.id)
                return OperationResult.fail(
                    "could not persist input artifact for staging",
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
        except Exception:  # noqa: BLE001
            logger.warning("Fabric: staging operation %s failed", op.id)
            # stage_change failed (e.g. the per-org pending cap, or a DB error)
            # AFTER we wrote the durable blob — delete it so it isn't orphaned on
            # the persistent volume (no TTL/sweep on the durable store).
            if durable_token is not None:
                import contextlib

                from app.core.fabric.durable_store import durable_store

                with contextlib.suppress(Exception):
                    await durable_store.delete(durable_token, ctx.organization_id)
            return OperationResult.fail("could not stage change", "STAGE_FAILED")
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
        except Exception:  # noqa: BLE001 — normalize for the negotiator
            logger.warning("Fabric: overlay staging operation %s failed", op.id)
            return OperationResult.fail("could not stage change", "STAGE_FAILED")
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
            logger.warning("Fabric: plugin operation %s raised", op.id)
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


def _as_uuid(value: object) -> UUID | None:
    """Best-effort UUID coercion; ``None`` when the value is not one."""
    if isinstance(value, UUID):
        return value
    if value is None:
        return None
    try:
        return UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        return None


def _sites_served_by(controller: object) -> set[UUID]:
    """Every FreeSDN site the controller may legitimately carry a write for.

    That is its OWN ``site_id`` plus every FreeSDN site id in
    ``Controller.site_mappings`` (``{omada_site_id: freesdn_site_uuid}``). One
    physical controller can front SEVERAL FreeSDN sites — that is exactly what
    ``site_mappings`` is for, and the Omada bulk applier resolves the Omada-side
    site from the staged ``site_id`` through it — so ``site_id !=
    controller.site_id`` is legitimate and must NOT be rejected outright. What is
    not legitimate is a ``site_id`` the controller has no relationship with at
    all: that is the pair that turns the apply-time site-grant check into a
    check on a site the write will never touch.
    """
    served: set[UUID] = set()
    own = _as_uuid(getattr(controller, "site_id", None))
    if own is not None:
        served.add(own)
    mappings = getattr(controller, "site_mappings", None) or {}
    if isinstance(mappings, dict):
        for mapped in mappings.values():
            parsed = _as_uuid(mapped)
            if parsed is not None:
                served.add(parsed)
    return served


async def _controller_in_org(db: object, controller_id: UUID, organization_id: UUID) -> object:
    """The non-deleted ``Controller`` row under a live site in the org for ``controller_id``, else ``None``.

    Returns the ROW (not a bool) because the write plane needs the controller's
    own ``site_id`` + ``site_mappings`` to prove the staged ``site_id`` and the
    caller's site grant relate to the same controller — see the F-02 block in
    ``_execute_native_write``. Callers must test it for truthiness, never for
    ``is not None``: the existing executor tests stub this helper with a plain
    ``True``/``False`` and both must keep meaning what they meant.
    """
    from sqlalchemy import select

    from app.models.core import Controller, Site

    return (
        await db.execute(  # type: ignore[attr-defined]
            select(Controller)
            .join(Site, Controller.site_id == Site.id)
            .where(
                Controller.id == controller_id,
                Controller.deleted_at.is_(None),
                Site.organization_id == organization_id,
                Site.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()


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
