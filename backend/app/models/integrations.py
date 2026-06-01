# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Integration Models
==================================

An Integration is a typed, user-friendly wrapper around a Webhook record.
Where the Webhooks page is a power-user tool (raw JSON, manual URL config),
the Integrations section is for guided, named service connections (n8n,
Slack, PagerDuty, etc.) with a setup wizard, event-type presets, and a
per-integration delivery log with DLQ replay.

Each Integration record owns exactly one Webhook record.  Creating/deleting
an Integration creates/deletes the underlying Webhook automatically.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import AuditMixin, Base, UUIDMixin


class Integration(Base, UUIDMixin, AuditMixin):
    """
    Named integration with an external service.

    Backed by a Webhook record for delivery mechanics.  The integration
    layer adds:
    - Human-friendly type (n8n, slack, pagerduty…)
    - Guided event-type subscriptions grouped by category
    - Per-integration delivery statistics (denormalized for fast display)
    - Separate DLQ replay UI distinct from the raw Webhooks page
    """

    __tablename__ = "integrations"
    __table_args__ = (
        Index("ix_integrations_org", "organization_id"),
        Index("ix_integrations_type", "integration_type"),
        {"schema": "core"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"), nullable=False
    )

    # Identity
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    # Integration type — drives the setup wizard template and icon
    integration_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # Supported values: n8n | slack | teams | pagerduty | jira | servicenow | webhook

    # Underlying Webhook record (1:1)
    webhook_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.webhooks.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )

    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Event type subscriptions in canonical dot-notation format.
    # e.g. ["device.status.changed", "alert.created", "backup.complete"]
    # Stored here (redundantly with Webhook.event_types) so the Integrations
    # page can display them without joining to Webhook.
    event_subscriptions: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    # Integration-type-specific non-secret config
    # n8n: {"workflow_name": "Device Monitor"}
    # jira: {"project_key": "NET", "issue_type": "Bug"}
    # pagerduty: {"severity_mapping": {"critical": "critical", "warning": "warning"}}
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    # Denormalized stats for quick display (updated by the delivery task)
    last_delivery_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_delivery_status: Mapped[str | None] = mapped_column(String(20))
    # "delivered" | "failed" | "retrying"
    delivery_count_7d: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    success_count_7d: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
