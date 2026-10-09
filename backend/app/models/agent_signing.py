# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Installation-wide public identity; never tenant settings or private key bytes."""

from collections.abc import Callable
from datetime import datetime
from typing import cast
from uuid import UUID

from sqlalchemy import (
    DDL,
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    SmallInteger,
    String,
    event,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.agent_signing_enrollment_schema import ENROLLMENT_DDL
from app.db.agent_signing_schema import SIGNING_SCHEMA_DDL
from app.db.base import Base


class AgentSigningIntent(Base):
    """Retained initialization/adoption history, including cancelled operations.

    Actor UUIDs are audit snapshots, deliberately not cascading user/tenant FKs.
    Deleting an account must not delete or rewrite the platform's signing identity.
    No row is inserted by schema creation; missing records do not prove freshness.
    The coordinator must authenticate every transition and serialize with identity.
    """

    __tablename__ = "agent_signing_intents"
    __table_args__ = (
        CheckConstraint("singleton_id = 1", name="singleton"),
        CheckConstraint("identity_epoch > 0", name="epoch"),
        CheckConstraint("kind IN ('initialize', 'adopt')", name="kind"),
        CheckConstraint(
            "(kind = 'initialize' AND expected_public_sha256 IS NULL) OR "
            "(kind = 'adopt' AND expected_public_sha256 IS NOT NULL "
            "AND expected_public_sha256 ~ '^[0-9a-f]{64}$')",
            name="expected_identity",
        ),
        CheckConstraint("state IN ('pending', 'prepared', 'activated', 'cancelled')", name="state"),
        CheckConstraint(
            "(public_key_pem IS NULL AND public_key_sha256 IS NULL AND prepared_at IS NULL) OR "
            "(public_key_pem IS NOT NULL AND public_key_sha256 IS NOT NULL AND prepared_at IS NOT NULL "
            "AND octet_length(public_key_pem) BETWEEN 1 AND 4096 "
            "AND public_key_sha256 = encode(sha256(public_key_pem), 'hex') "
            "AND (kind = 'initialize' OR public_key_sha256 = expected_public_sha256))",
            name="public_binding",
        ),
        CheckConstraint(
            "(state = 'pending' AND prepared_at IS NULL AND closed_at IS NULL AND closed_by IS NULL) OR "
            "(state = 'prepared' AND prepared_at IS NOT NULL AND closed_at IS NULL AND closed_by IS NULL) OR "
            "(state = 'activated' AND prepared_at IS NOT NULL AND closed_at IS NOT NULL AND closed_by IS NOT NULL) OR "
            "(state = 'cancelled' AND closed_at IS NOT NULL AND closed_by IS NOT NULL)",
            name="phase_fields",
        ),
        CheckConstraint(
            "(prepared_at IS NULL OR prepared_at >= created_at) AND "
            "(closed_at IS NULL OR closed_at >= created_at) AND "
            "(prepared_at IS NULL OR closed_at IS NULL OR closed_at >= prepared_at)",
            name="time_order",
        ),
        Index(
            "ix_signing_one_open_intent",
            "singleton_id",
            unique=True,
            postgresql_where=text("state IN ('pending', 'prepared')"),
        ),
        {"schema": "agents"},
    )

    operation_id: Mapped[UUID] = mapped_column(primary_key=True)
    singleton_id: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    installation_id: Mapped[UUID] = mapped_column(nullable=False)
    identity_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    # Persist the operator's independent expectation before private-key I/O.
    # A resumed adoption must not replace it with whatever files now contain.
    expected_public_sha256: Mapped[str | None] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    requested_by: Mapped[UUID] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    public_key_pem: Mapped[bytes | None] = mapped_column(LargeBinary)
    public_key_sha256: Mapped[str | None] = mapped_column(String(64))
    prepared_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_by: Mapped[UUID | None] = mapped_column()


class AgentSigningIdentity(Base):
    """One immutable active public identity, bound to its completed operation.

    No ordinary mutation/rotation/delete interface exists. A future rotation needs a
    reviewed identity-history migration and agent-pin transition, not row replacement.
    Cryptographic P-256 validation and authority remain coordinator responsibilities.
    """

    __tablename__ = "agent_signing_identities"
    __table_args__ = (
        CheckConstraint("singleton_id = 1", name="singleton"),
        CheckConstraint("format_version = 1", name="format"),
        CheckConstraint("purpose = 'agent-release'", name="purpose"),
        CheckConstraint("identity_epoch > 0", name="epoch"),
        CheckConstraint(
            "octet_length(public_key_pem) BETWEEN 1 AND 4096 AND "
            "public_key_sha256 = encode(sha256(public_key_pem), 'hex')",
            name="public_binding",
        ),
        {"schema": "agents"},
    )

    singleton_id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, autoincrement=False)
    format_version: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    installation_id: Mapped[UUID] = mapped_column(nullable=False)
    identity_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False)
    operation_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.agent_signing_intents.operation_id", ondelete="RESTRICT"),
        nullable=False,
    )
    public_key_pem: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    public_key_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    activated_by: Mapped[UUID] = mapped_column(nullable=False)
    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


# FK ordering makes the intent table available before this hook installs guards.
# No CREATE OR REPLACE: unexpected existing functions must refuse, not be erased.
for statement in SIGNING_SCHEMA_DDL:
    event.listen(
        AgentSigningIdentity.__table__,
        "after_create",
        cast(Callable[[str], DDL], DDL)(statement.replace("%", "%%")).execute_if(
            dialect="postgresql"
        ),
    )


class AgentSigningEnrollment(Base):
    """Immutable pin delivered with an agent credential in the same transaction.

    Preexisting agents receive no invented trust pin from migration. Deleting an
    agent removes its enrollment row; installation identity/history remain intact.
    Re-enrollment and future rotation require explicit operator-supported flows.
    """

    __tablename__ = "agent_signing_enrollments"
    __table_args__ = (
        CheckConstraint("signing_singleton_id = 1", name="singleton"),
        CheckConstraint("identity_epoch > 0", name="epoch"),
        CheckConstraint("public_key_sha256 ~ '^[0-9a-f]{64}$'", name="fingerprint"),
        {"schema": "agents"},
    )

    agent_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "agents.remote_agents.id", ondelete="CASCADE", name="fk_signing_enrollment_agent"
        ),
        primary_key=True,
    )
    signing_singleton_id: Mapped[int] = mapped_column(
        SmallInteger,
        ForeignKey(
            "agents.agent_signing_identities.singleton_id",
            ondelete="RESTRICT",
            name="fk_signing_enrollment_identity",
        ),
        nullable=False,
    )
    installation_id: Mapped[UUID] = mapped_column(nullable=False)
    identity_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False)
    public_key_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    enrolled_by: Mapped[UUID] = mapped_column(nullable=False)


for statement in ENROLLMENT_DDL:
    event.listen(
        AgentSigningEnrollment.__table__,
        "after_create",
        cast(Callable[[str], DDL], DDL)(statement.replace("%", "%%")).execute_if(
            dialect="postgresql"
        ),
    )
