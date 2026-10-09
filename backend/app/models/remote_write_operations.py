# SPDX-License-Identifier: AGPL-3.0-only
"""Retained remote-write history; UUID snapshots deliberately do not cascade.

A retained locator does not grant mutation authority or prove a verified backup.
"""

from collections.abc import Callable
from typing import cast

from sqlalchemy import (
    DDL,
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    Index,
    LargeBinary,
    SmallInteger,
    String,
    Table,
    event,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

from app.core.security_utils import MAX_BACKUP_IMPORT_BYTES
from app.db.base import Base

metadata = Base.metadata
operations = Table(
    "remote_write_operations",
    metadata,
    Column("operation_id", PG_UUID(as_uuid=True), primary_key=True),
    Column("backup_id", PG_UUID(as_uuid=True), nullable=False, unique=True),
    Column("organization_id", PG_UUID(as_uuid=True), nullable=False),
    Column("intent_bytes", LargeBinary, nullable=False),
    Column("intent_sha256", String(64), nullable=False),
    Column("payload_size", BigInteger, nullable=False),
    Column("phase", String(16), nullable=False),
    Column("sequence", SmallInteger, nullable=False),
    Column(
        "created_at", DateTime(timezone=True), nullable=False, server_default=func.clock_timestamp()
    ),
    Column(
        "updated_at", DateTime(timezone=True), nullable=False, server_default=func.clock_timestamp()
    ),
    CheckConstraint("octet_length(intent_bytes) BETWEEN 1 AND 8192", name="remote_intent_size"),
    CheckConstraint("intent_sha256 ~ '^[0-9a-f]{64}$'", name="remote_intent_hash"),
    CheckConstraint(
        f"payload_size BETWEEN 1 AND {MAX_BACKUP_IMPORT_BYTES}", name="remote_payload_bound"
    ),
    CheckConstraint(
        "intent_sha256 = encode(sha256(intent_bytes), 'hex')", name="remote_intent_digest"
    ),
    CheckConstraint(
        "(phase='reserved' AND sequence=0) OR (phase='dispatched' AND sequence=1) "
        "OR (phase='acknowledged' AND sequence=2) OR (phase='cancelled' AND sequence=1)",
        name="remote_phase_sequence",
    ),
    Index("ix_remote_write_scope_created", "organization_id", "created_at"),
    schema="backup",
)

# History has non-cascading UUID snapshots: deleting a backup, destination or
# tenant must not silently erase an unresolved remote write. There is no public
# purge path; a reviewed retention/retirement migration remains necessary.
_DDL = (
    """CREATE FUNCTION backup.guard_remote_write_operation() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$ BEGIN
      IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'Remote operation history must be retained';
      END IF;
      IF TG_OP = 'INSERT' THEN
        IF NEW.phase <> 'reserved' OR NEW.sequence <> 0 THEN
          RAISE EXCEPTION 'Remote operation must begin reserved';
        END IF;
        RETURN NEW;
      END IF;
      IF (to_jsonb(NEW) - ARRAY['phase','sequence','updated_at']) IS DISTINCT FROM
         (to_jsonb(OLD) - ARRAY['phase','sequence','updated_at']) THEN
        RAISE EXCEPTION 'Remote operation intent is immutable';
      END IF;
      IF NOT ((OLD.phase='reserved' AND NEW.phase IN ('dispatched','cancelled'))
          OR (OLD.phase='dispatched' AND NEW.phase='acknowledged'))
         OR NEW.sequence <> OLD.sequence + 1 THEN
        RAISE EXCEPTION 'Invalid remote operation transition';
      END IF;
      RETURN NEW;
    END $$""",
    """CREATE TRIGGER guard_remote_write_operation BEFORE INSERT OR UPDATE OR DELETE
    ON backup.remote_write_operations FOR EACH ROW
    EXECUTE FUNCTION backup.guard_remote_write_operation()""",
    """CREATE TRIGGER guard_remote_write_no_truncate BEFORE TRUNCATE
    ON backup.remote_write_operations FOR EACH STATEMENT
    EXECUTE FUNCTION backup.guard_remote_write_operation()""",
)
for statement in _DDL:
    event.listen(
        operations,
        "after_create",
        cast(Callable[[str], DDL], DDL)(statement).execute_if(dialect="postgresql"),
    )
