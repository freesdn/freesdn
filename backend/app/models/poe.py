# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - PoE Schedule Models
==================================

PoE power scheduling: time-based power on/off for ports or device groups.
Supports day-of-week filtering and timezone-aware scheduling.
"""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import AuditMixin, Base, SoftDeleteMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.core import Organization
    from app.models.devices import Device
    from app.models.enterprise import DeviceGroup


class PoESchedule(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    PoESchedule -- Time-based PoE power control.

    Defines when PoE should be powered off and on for a set of ports
    on a specific device or device group. Evaluated every minute by
    the ``poe.evaluate_schedules`` Celery task.
    """

    __tablename__ = "poe_schedules"
    __table_args__ = (
        Index("ix_poe_schedules_org_id", "organization_id"),
        Index("ix_poe_schedules_device_id", "device_id"),
        Index("ix_poe_schedules_enabled", "enabled"),
        Index("ix_poe_schedules_org_enabled", "organization_id", "enabled"),
        CheckConstraint(
            "(device_id IS NOT NULL AND device_group_id IS NULL) "
            "OR (device_id IS NULL AND device_group_id IS NOT NULL)",
            name="ck_poe_schedule_xor_target",
        ),
        {"schema": "devices"},
    )

    # Foreign Keys
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("devices.devices.id", ondelete="CASCADE"),
        nullable=True,
        comment="Target a specific device. NULL if using device_group_id.",
    )
    device_group_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("devices.device_groups.id", ondelete="CASCADE"),
        nullable=True,
        comment="Target all devices in a group. NULL if using device_id.",
    )

    # Identity
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Schedule settings
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    port_numbers: Mapped[list[str]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
        comment="List of port numbers to control, e.g. [1, 2, 5]",
    )
    power_off_time: Mapped[str] = mapped_column(
        String(5),
        nullable=False,
        comment="Time to disable PoE, e.g. '22:00'",
    )
    power_on_time: Mapped[str] = mapped_column(
        String(5),
        nullable=False,
        comment="Time to enable PoE, e.g. '06:00'",
    )
    days_of_week: Mapped[list[str]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
        comment="Days of week (0=Mon, 6=Sun), e.g. [0,1,2,3,4] for weekdays",
    )
    timezone: Mapped[str] = mapped_column(
        String(50),
        default="UTC",
        nullable=False,
    )

    # Status tracking
    last_action: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
        comment="Last action taken: 'power_off' or 'power_on'",
    )
    last_action_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization")
    device: Mapped["Device | None"] = relationship("Device")
    device_group: Mapped["DeviceGroup | None"] = relationship("DeviceGroup")
