# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Database Base Model
=================================

SQLAlchemy 2.0 declarative base with common mixins and utilities.
"""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, MetaData, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Naming convention for constraints (helps with migrations)
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Base class for all primary-database models."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    # Type annotation map for custom types
    type_annotation_map = {
        UUID: PG_UUID(as_uuid=True),
    }


class LogBase(DeclarativeBase):
    """Base class for LogDB (TimescaleDB) models.

    Models that inherit from LogBase live in the separate LogDB instance and
    are **excluded** from Alembic migrations and ``Base.metadata.create_all()``.
    Their DDL is managed by ``scripts/migrate_logdb.py`` (raw SQL / hypertables).
    """

    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    type_annotation_map = {
        UUID: PG_UUID(as_uuid=True),
    }


class UUIDMixin:
    """Mixin that adds UUID primary key."""

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )


class TimestampMixin:
    """Mixin that adds created_at and updated_at timestamps."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class SoftDeleteMixin:
    """Mixin that adds soft delete capability."""

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
    )

    @property
    def is_deleted(self) -> bool:
        """Check if record is soft deleted."""
        return self.deleted_at is not None

    @classmethod
    def alive(cls) -> Any:
        """SQL predicate selecting only rows that are NOT soft-deleted.

        The blessed, greppable way to filter a soft-deletable model::

            select(Device).where(Device.alive())

        Identical to ``cls.deleted_at.is_(None)`` but recognised by the
        soft-delete CI guard (``tests/test_soft_delete_guard.py``) as a
        satisfying filter, and a single place to evolve the semantics.
        """
        return cls.deleted_at.is_(None)


class AuditMixin(TimestampMixin):
    """Mixin that adds audit fields including who created/updated."""

    created_by: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True,
    )
    updated_by: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True,
    )
