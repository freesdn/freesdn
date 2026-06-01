# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN Fabric — persistence models.

A ``Connection`` is an operator-authored wire in the universal interconnect:
*source event → conditions → step chain*. ``ConnectionRun`` is the per-firing
audit record. Both are org-scoped (fail-closed multi-tenancy); the Connection's
``created_by`` is the authoring operator whose RBAC permissions the engine
enforces for every step (a plugin can never author a Connection).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import AuditMixin, Base, TimestampMixin, UUIDMixin


class Connection(Base, UUIDMixin, AuditMixin):
    """An operator-authored Fabric wire."""

    __tablename__ = "connections"
    __table_args__ = ({"schema": "fabric"},)

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")

    # Trigger: a bus event pattern (exact, ``a.b.*``, ``a.b.#`` or ``*``).
    source_event: Mapped[str] = mapped_column(String(255), nullable=False)
    # Optional ConditionGroup (app.services.automation.ConditionGroup.from_dict shape).
    conditions: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # Ordered steps: [{"operation_id", "params", "continue_on_error"}].
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)

    cooldown_seconds: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    # Lightweight run stats (full history lives in ConnectionRun).
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    run_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")


class ConnectionRun(Base, UUIDMixin, TimestampMixin):
    """Audit record of a single Connection firing."""

    __tablename__ = "connection_runs"
    __table_args__ = ({"schema": "fabric"},)

    connection_id: Mapped[UUID] = mapped_column(
        ForeignKey("fabric.connections.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_event_type: Mapped[str] = mapped_column(String(255), nullable=False)
    trigger_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
