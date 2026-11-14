# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Installation-wide settings
====================================

One row per setting, for values that belong to the whole installation rather
than to an organization and that must survive a cache loss. The first is the
Settings read-only switch (key ``adapter_read_only``), which used to live only
in a Valkey key: a flush, a lost volume or a Valkey error could turn an
operator's "read-only" back into the environment default, which the shipped
compose file sets to read-write.

``version`` goes up by one on every write. Caches carry it, so a cache refill
from an older read can never overwrite a newer value (see
``app.core.runtime_flags``).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import BigInteger, DateTime, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

#: Key of the Settings read-only switch. Value: ``{"read_only": bool}``.
ADAPTER_READ_ONLY_KEY = "adapter_read_only"


class PlatformSetting(Base):
    """An installation-wide setting, keyed by name."""

    __tablename__ = "platform_settings"
    __table_args__ = ({"schema": "core"},)

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1, server_default="1")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    # A snapshot of who made the change, like AuditMixin.updated_by: no foreign
    # key, so deleting the user keeps the record of who set it.
    updated_by: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)

    def __repr__(self) -> str:
        return f"<PlatformSetting {self.key} v{self.version}>"
