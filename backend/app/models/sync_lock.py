# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Device Sync Lock Model
====================================

Prevents concurrent device sync runs.  Follows the same pattern as
``gateway.DistributionLock`` — a single-row table with an auto-expiring
lock that is cleaned up on each run.
"""

from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class DeviceSyncLock(Base):
    """Row-level lock to prevent concurrent DeviceSyncService runs."""

    __tablename__ = "device_sync_locks"
    __table_args__ = ({"schema": "devices"},)

    lock_key: Mapped[str] = mapped_column(String(100), primary_key=True)
    locked_by: Mapped[str] = mapped_column(String(100), nullable=False)
    locked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
