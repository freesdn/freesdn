# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Adapter staging models
=================================

When the deployment is gated read-only against an upstream controller
(Omada, OPNsense, MikroTik, UniFi, Hikvision, …), every UI-authored
write becomes an :class:`AdapterPendingChange` row. The change can later
be reviewed, edited, discarded, or explicitly applied — only the apply
step touches the real device.

The table was originally named ``omada_pending_changes`` because Omada
was the first adapter wired to the staging pattern. Migration 019
renamed it to ``adapter_pending_changes`` once the table became
adapter-agnostic (MikroTik, UniFi, OPNsense, pfSense, Proxmox all stage
through it). The class follows the same rename; ``OmadaPendingChange``
is kept as a deprecated alias for in-flight callers.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import AuditMixin, Base, UUIDMixin


class AdapterPendingChange(Base, UUIDMixin, AuditMixin):
    """A staged write operation against a managed controller.

    Created when the UI submits a CRUD operation while the system is in
    read-only mode (``settings.ADAPTER_READ_ONLY`` or the legacy
    ``settings.OMADA_READ_ONLY`` True). The change accumulates here
    until an operator explicitly applies it, at which point the adapter
    is invoked and the row is updated with the controller's response.

    Lifecycle:
        ``pending``    — created, not yet applied
        ``applying``   — apply in-flight (atomic FOR UPDATE claim)
        ``applied``    — successfully pushed to the controller
        ``discarded``  — operator chose not to apply
        ``failed``     — apply attempted but the controller rejected
    """

    __tablename__ = "adapter_pending_changes"
    __table_args__ = (
        Index("ix_adapter_pending_org_status", "organization_id", "status"),
        Index("ix_adapter_pending_controller", "controller_id", "status"),
        Index("ix_adapter_pending_feature", "feature", "status"),
        {"schema": "core"},
    )

    # ── Tenancy / target ────────────────────────────────────────────────
    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Nullable ONLY for appliance-local daemon writes (the ``overlay.*`` feature
    # family — Tailscale/NetBird/WireGuard/OpenVPN connect/disconnect), which have
    # no vendor controller but still ride the staging chokepoint. Enforced at the
    # app layer: AdapterStagingService.stage_change refuses a NULL controller_id for
    # any non-``overlay.`` feature, so every controller-bound write keeps the
    # "every staged change targets a controller" invariant. See migration 004.
    controller_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.controllers.id", ondelete="CASCADE"),
        nullable=True,
    )
    site_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="SET NULL"),
        nullable=True,
    )
    # External (vendor-side) site identifier used in the API path.
    # Historically named ``omada_site_id`` — kept under that name for
    # schema stability since renaming a column requires a deeper
    # migration and the value is opaque to non-Omada adapters.
    omada_site_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # ── What this change is ─────────────────────────────────────────────
    # Dotted string. New features add their own value without a migration:
    #   "vpn.ipsec.policy"
    #   "vpn.wireguard.peer"
    #   "firmware.upgrade"
    #   "firmware.schedule"
    #   "firewall.urlfilter.rule"
    #   "wifi.ssid.advanced"
    #   "unifi.clients.block"
    #   "mikrotik.system.reboot"
    feature: Mapped[str] = mapped_column(String(128), nullable=False)

    operation: Mapped[str] = mapped_column(
        String(16), nullable=False
    )  # "create" | "update" | "delete"

    # Entity ID being modified (UPDATE / DELETE). NULL for CREATE.
    target_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # The payload that will be sent to the controller when applied.
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)

    # ── Lifecycle ───────────────────────────────────────────────────────
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending", server_default="pending"
    )
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    applied_response: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<AdapterPendingChange {self.feature} {self.operation} status={self.status}>"


# Deprecated alias. Kept so external code that imported the old class
# name (third-party plugins, downstream forks) keeps working through
# the rename. New code MUST use ``AdapterPendingChange``.
OmadaPendingChange = AdapterPendingChange
