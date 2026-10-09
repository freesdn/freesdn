# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Retained public release intent and decisions, without credentials or binaries.

The coordinator must construct request_bytes from an allowlist of normalized
public metadata, authenticate each phase and couple a decision to release SQL.
This table is not that coordinator and is not proof of durable filesystem state.
Actor/organization/release UUIDs are non-cascading history snapshots. Loss of a
tenant, account or release must not discard unresolved cleanup or replay history.
"""

from collections.abc import Callable
from datetime import datetime
from typing import cast
from uuid import UUID

from sqlalchemy import (
    DDL,
    BigInteger,
    CheckConstraint,
    DateTime,
    Index,
    LargeBinary,
    SmallInteger,
    String,
    event,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.agent_release_operation_schema import RELEASE_OPERATION_CHECKS, RELEASE_OPERATION_DDL
from app.db.base import Base


class AgentReleaseOperation(Base):
    __tablename__ = "agent_release_operations"
    __table_args__ = (
        *(CheckConstraint(sql, name=name) for name, sql in RELEASE_OPERATION_CHECKS),
        Index(
            "uq_release_operation_unresolved",
            "release_id",
            unique=True,
            postgresql_where=text("phase IN ('reserved', 'prepared')"),
        ),
        Index(
            "uq_release_operation_publish_identity",
            "release_id",
            unique=True,
            postgresql_where=text("kind = 'publish'"),
        ),
        Index(
            "uq_release_operation_owned_object",
            "artifact_id",
            unique=True,
            postgresql_where=text("kind = 'publish' AND storage_kind = 'owned'"),
        ),
        Index("ix_release_operation_scope_phase", "organization_id", "phase", "created_at"),
        {"schema": "agents"},
    )

    operation_id: Mapped[UUID] = mapped_column(primary_key=True)
    format_version: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    release_id: Mapped[UUID] = mapped_column(nullable=False)
    organization_id: Mapped[UUID | None] = mapped_column()
    requested_by: Mapped[UUID] = mapped_column(nullable=False)
    storage_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    artifact_id: Mapped[UUID | None] = mapped_column()
    request_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    expected_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    expected_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    phase: Mapped[str] = mapped_column(String(16), nullable=False)
    decision: Mapped[str | None] = mapped_column(String(16))
    transition_sequence: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    prepared_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cleaned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_transition_by: Mapped[UUID] = mapped_column(nullable=False)


for statement in RELEASE_OPERATION_DDL:
    event.listen(
        AgentReleaseOperation.__table__,
        "after_create",
        cast(Callable[[str], DDL], DDL)(statement.replace("%", "%%")).execute_if(
            dialect="postgresql"
        ),
    )
