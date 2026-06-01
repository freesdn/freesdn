# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — FreePBX staged-write service base
===========================================

Bridges a ``voip.pbx`` row into the controller-centric staged-write
pipeline (:class:`AdapterStagingService`).

Why a bridge is needed
----------------------
The platform's staging pipeline is built around ``core.controllers``:
``GatewayServiceBase._get_controller`` queries that table and the
``adapter_pending_changes`` staging table FKs to ``core.controllers.id``.
A FreePBX PBX, however, lives in its own ``voip.pbx`` table (with
PBX-specific AMI/ARI/OAuth2 credential columns). The firewall module hit
the identical dual-table problem (``firewall.gateway_connections`` vs
``core.controllers``) and solved it with a Controller *facade* plus a
lazy *auto-pair* — this base mirrors that proven pattern for FreePBX.

Design
------
* **Reads / apply** build the live :class:`FreePBXAdapter` straight from
  the PBX row via the shared ``build_freepbx_adapter_from_pbx`` factory
  (so AMI/ARI/OAuth2 creds + the TLS-ack gate are honoured) — they never
  touch ``core.controllers``.
* **Staging** (``_stage``) lazily creates a ``core.controllers`` row with
  the SAME UUID as the PBX so the staging-table FK resolves. This happens
  ONLY when a write is actually staged — a plain read never creates a
  controller row.
* The live write itself is still gated twice: the staging
  ``apply_change`` dual-gate (``ADAPTER_READ_ONLY`` env + per-call
  ``force=True``) runs before any applier, and the adapter's own
  ``_check_write_allowed`` is the defence-in-depth backstop.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.site_access import assert_site_access_for_request
from app.models.core import Controller, Site
from app.services.adapter_base import GatewayServiceBase

_FREEPBX_CONTROLLER_TYPE = "freepbx"


class FreePBXServiceBase(GatewayServiceBase):
    """Shared plumbing for FreePBX live-read + staged-write services."""

    SUPPORTED_CONTROLLER_TYPE = _FREEPBX_CONTROLLER_TYPE

    # ── PBX resolution (voip.pbx, tenant + site-grant scoped) ───────────

    async def _load_pbx(self, pbx_id: UUID, organization_id: UUID) -> Any:
        """Resolve a ``voip.pbx`` row scoped to the org and the caller's
        per-user site grant. Raises 404 if missing / not owned.

        Cached per-request on ``self._pbx_cache`` so a stage → apply chain
        (and any read in between) only hits the DB once.
        """
        if not hasattr(self, "_pbx_cache"):
            self._pbx_cache: dict[UUID, Any] = {}
        cached = self._pbx_cache.get(pbx_id)
        if cached is not None:
            return cached

        from app.modules.voip.models import PBX

        stmt = (
            select(PBX)
            .join(Site, PBX.site_id == Site.id)
            .where(
                PBX.id == pbx_id,
                PBX.deleted_at.is_(None),
                Site.organization_id == organization_id,
            )
        )
        pbx = (await self.db.execute(stmt)).scalar_one_or_none()
        if pbx is None:
            raise HTTPException(404, detail="PBX not found")
        # Per-user site grant chokepoint: a site-limited caller must hold a
        # grant for the PBX's site (no-op for super_admin / org_admin and in
        # system context). Mirrors GatewayServiceBase._resolve_*.
        assert_site_access_for_request(pbx.site_id, detail="PBX not found")
        self._pbx_cache[pbx_id] = pbx
        return pbx

    @staticmethod
    def _pbx_to_facade(pbx: Any) -> Controller:
        """A transient (never-persisted) Controller carrying the fields a
        FreePBX service reads. The live adapter is built from the PBX row
        itself (see :meth:`_get_client`), so the facade only needs an id +
        controller_type for the base-class type check.
        """
        facade = Controller(
            id=pbx.id,
            site_id=pbx.site_id,
            name=pbx.name,
            controller_type=_FREEPBX_CONTROLLER_TYPE,
            host=pbx.ip_address,
            port=pbx.api_port,
            use_ssl=True,
            verify_ssl=not bool(getattr(pbx, "tls_verify_disabled_acknowledged", False)),
            status="unknown",
            config={},
        )
        facade._is_pbx_facade = True  # type: ignore[attr-defined]
        return facade

    async def _get_controller(self, controller_id: UUID, organization_id: UUID) -> Controller:
        """Override: resolve from ``voip.pbx`` and return a transient
        Controller facade. Does NOT persist anything — reads are free of
        side effects. Persisting the paired controller happens lazily in
        :meth:`_stage`.
        """
        pbx = await self._load_pbx(controller_id, organization_id)
        return self._pbx_to_facade(pbx)

    async def _get_client(self, controller: Controller) -> Any:
        """Override: return the connected :class:`FreePBXAdapter` (NOT the
        inner REST client) built from the PBX row.

        FreePBX exposes its write helpers (create/update/delete extension,
        trunk, …) on the ADAPTER so they run the ``_check_write_allowed``
        gate, so services call ``client.create_extension(...)`` where
        ``client`` is the adapter. The adapter is adopted into the shared
        pool so the pool's cleanup loop owns teardown (no per-apply socket
        leak).
        """
        if controller.controller_type != _FREEPBX_CONTROLLER_TYPE:
            raise HTTPException(
                400,
                detail=(
                    f"this PBX feature requires a {_FREEPBX_CONTROLLER_TYPE!r} "
                    f"controller; got {controller.controller_type!r}"
                ),
            )
        from app.modules.voip.adapter_factory import build_freepbx_adapter_from_pbx

        pbx = self._pbx_cache.get(controller.id) if hasattr(self, "_pbx_cache") else None
        if pbx is None:
            from app.modules.voip.models import PBX

            pbx = await self.db.get(PBX, controller.id)
            if pbx is None:
                raise HTTPException(404, detail="PBX not found")

        # SSRF defence (parity with GatewayServiceBase._get_client): the PBX
        # host is operator-supplied (PBXCreate/PBXUpdate.ip_address has no
        # field_validator), so refuse loopback / link-local / cloud-metadata
        # targets and pin the connection to the resolved IP literal so a DNS
        # rebind cannot re-point it at connect time. The factory reads
        # ``pbx.ip_address`` directly, so we substitute the pinned host for the
        # synchronous build only and restore it immediately (no ``await`` in
        # between → no flush window, the cached row is left untouched).
        self._validate_controller_host(pbx.ip_address)
        effective_host = self._pin_controller_host(controller)
        original_ip = pbx.ip_address
        if effective_host and effective_host != original_ip:
            pbx.ip_address = effective_host
            try:
                adapter = build_freepbx_adapter_from_pbx(pbx)
            finally:
                pbx.ip_address = original_ip
        else:
            adapter = build_freepbx_adapter_from_pbx(pbx)
        if not getattr(adapter, "_connected", False):
            try:
                await adapter.connect()
            except Exception:
                raise HTTPException(
                    502,
                    detail="PBX is unreachable — verify host / credentials and try again",
                ) from None
        # Hand teardown to the pool so the httpx/AMI sessions don't leak.
        try:
            from app.adapters.pool import adapter_pool

            await adapter_pool.adopt(
                adapter,
                adapter_id=_FREEPBX_CONTROLLER_TYPE,
                controller_id=str(controller.id),
                host=pbx.ip_address,
            )
        except Exception:
            pass
        return adapter

    # ── Auto-pair: satisfy the staging-table controllers FK ─────────────

    async def _auto_pair_controller_for_pbx(self, pbx: Any) -> Controller:
        """Lazily create a ``core.controllers`` row whose id == the PBX id
        so ``adapter_pending_changes.controller_id`` (FK → controllers)
        resolves. Idempotent; mirrors the firewall-gateway auto-pair.
        """
        existing = await self.db.get(Controller, pbx.id)
        if existing is not None and existing.deleted_at is None:
            return existing

        ctrl = Controller(
            id=pbx.id,
            site_id=pbx.site_id,
            name=pbx.name,
            controller_type=_FREEPBX_CONTROLLER_TYPE,
            host=pbx.ip_address,
            port=pbx.api_port,
            use_ssl=True,
            verify_ssl=not bool(getattr(pbx, "tls_verify_disabled_acknowledged", False)),
            status="unknown",
            config={"paired_from": "voip.pbx"},
        )
        self.db.add(ctrl)
        try:
            await self.db.flush()
        except IntegrityError:
            # Concurrent first-stage on the same PBX: the loser re-reads
            # the row the winner persisted and proceeds.
            await self.db.rollback()
            winner = await self.db.get(Controller, pbx.id)
            if winner is not None and winner.deleted_at is None:
                return winner
            raise HTTPException(409, detail="PBX pair-up raced; retry")
        return ctrl

    # ── Stage helper (subclasses validate feature, then call this) ──────

    async def _stage(
        self,
        *,
        feature: str,
        operation: str,
        payload: dict[str, Any],
        controller_id: UUID,
        organization_id: UUID,
        target_id: str | None = None,
        notes: str | None = None,
        actor_id: UUID | None = None,
    ) -> Any:
        """Record a write intent. NEVER touches the PBX.

        Resolves + tenant-checks the PBX, lazily auto-pairs the controllers
        row for the staging FK, then persists the pending change. The live
        write happens later via ``AdapterStagingService.apply_change`` under
        the dual-gate.
        """
        pbx = await self._load_pbx(controller_id, organization_id)
        await self._auto_pair_controller_for_pbx(pbx)
        return await self.staging.stage_change(
            organization_id=organization_id,
            controller_id=pbx.id,
            feature=feature,
            operation=operation,
            payload=payload,
            target_id=target_id,
            notes=notes,
            actor_id=actor_id,
        )
