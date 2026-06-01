# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Automation Models
=================================

Database models for the automation engine:
  - AutomationRuleRecord: Persisted automation rules
  - AutomationExecutionRecord: Rule execution history
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDMixin


class AutomationRuleRecord(Base, UUIDMixin):
    """Persisted automation rule."""

    __tablename__ = "automation_rules"
    __table_args__ = (
        Index("ix_auto_rules_org_status", "organization_id", "status"),
        Index("ix_auto_rules_trigger", "trigger_type"),
        {"schema": "core"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    trigger_type: Mapped[str] = mapped_column(String(30), nullable=False)
    trigger_config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    conditions: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    actions: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    max_triggers_per_hour: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    trigger_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_triggered: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default="now()",
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL"),
    )


class AutomationExecutionRecord(Base, UUIDMixin):
    """Record of a single rule execution."""

    __tablename__ = "automation_executions"
    __table_args__ = (
        Index("ix_auto_exec_rule", "rule_id"),
        Index("ix_auto_exec_triggered", "triggered_at"),
        Index("ix_auto_exec_org_triggered", "organization_id", "triggered_at"),
        {"schema": "core"},
    )

    rule_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.automation_rules.id", ondelete="CASCADE"),
        nullable=False,
    )
    # organization_id is denormalized here so we can query by org without joining rules
    # (rules may be deleted but we want to keep execution history)
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="SET NULL"),
    )
    triggered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    trigger_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    actions_executed: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    error: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
