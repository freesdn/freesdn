# SPDX-License-Identifier: AGPL-3.0-only
"""Retain planned remote writes before mutation; never adopt legacy backup files.

Frozen native schema. Existing rows block history-destructive downgrade.
Application registration and incremental upgrades must expose the same guards.
"""
from uuid import uuid4

import sqlalchemy as sa
from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    Index,
    LargeBinary,
    SmallInteger,
    String,
    Table,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

from alembic import op

revision = "028_remote_write_history"
down_revision = "027_agent_release_references"
branch_labels = None
depends_on = None
_TABLE = "remote_write_operations"


def _table(schema, name, *, temporary=False):
    metadata = sa.MetaData(naming_convention={
        "pk": "pk_remote_write_operations",
        "uq": "uq_remote_write_operations_%(column_0_name)s",
        "ck": "ck_remote_write_operations_%(constraint_name)s",
    })
    options = {"prefixes": ["TEMPORARY"], "postgresql_on_commit": "DROP"} if temporary else {}
    table = Table(
        name, metadata,
        Column("operation_id", PG_UUID(as_uuid=True), primary_key=True),
        Column("backup_id", PG_UUID(as_uuid=True), nullable=False, unique=True),
        Column("organization_id", PG_UUID(as_uuid=True), nullable=False),
        Column("intent_bytes", LargeBinary, nullable=False),
        Column("intent_sha256", String(64), nullable=False),
        Column("payload_size", BigInteger, nullable=False),
        Column("phase", String(16), nullable=False),
        Column("sequence", SmallInteger, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.clock_timestamp()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.clock_timestamp()),
        CheckConstraint("octet_length(intent_bytes) BETWEEN 1 AND 8192", name="remote_intent_size"),
        CheckConstraint("intent_sha256 ~ '^[0-9a-f]{64}$'", name="remote_intent_hash"),
        CheckConstraint(f"payload_size BETWEEN 1 AND {209715200}", name="remote_payload_bound"),
        CheckConstraint("intent_sha256 = encode(sha256(intent_bytes), 'hex')", name="remote_intent_digest"),
        CheckConstraint("(phase='reserved' AND sequence=0) OR (phase='dispatched' AND sequence=1) "
                        "OR (phase='acknowledged' AND sequence=2) OR (phase='cancelled' AND sequence=1)",
                        name="remote_phase_sequence"),
        Index("ix_remote_write_scope_created", "organization_id", "created_at"),
        schema=schema, **options,
    )
    return table


def _shape(connection, schema, names, expected_foreign):
    """Compare PostgreSQL-parsed semantics; never erase parentheses or casts."""
    result = []
    for name in names:
        target = {"relation": connection.dialect.identifier_preparer.quote_schema(schema)
                  + "." + connection.dialect.identifier_preparer.quote(name)}
        columns = connection.execute(sa.text("""
            SELECT attname, format_type(atttypid, atttypmod), attnotnull,
                   attidentity, attgenerated, attcollation,
                   pg_get_expr(d.adbin, d.adrelid) AS default_expression
            FROM pg_attribute a LEFT JOIN pg_attrdef d
              ON d.adrelid=a.attrelid AND d.adnum=a.attnum
            WHERE a.attrelid=to_regclass(:relation) AND a.attnum>0 AND NOT a.attisdropped
            ORDER BY a.attnum
        """), target).all()
        # PostgreSQL18 names NOT NULL constraints after each relation. Compare
        # their full column/enforcement contract and multiplicity, not that name.
        constraints = connection.execute(sa.text("""
            SELECT CASE WHEN contype='n' THEN '<not-null>' ELSE conname::text END AS constraint_name,
                   contype, conkey::text, ARRAY(SELECT a.attname FROM unnest(c.confkey) WITH ORDINALITY AS k(attnum, ord) JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.attnum ORDER BY k.ord),
                   pg_get_expr(conbin, conrelid), convalidated, condeferrable, condeferred,
                   confupdtype, confdeltype, confmatchtype,
                   COALESCE((to_jsonb(c)->>'conenforced')::boolean, true) AS enforced
            FROM pg_constraint c WHERE conrelid=to_regclass(:relation)
            ORDER BY constraint_name, contype, conkey::text
        """), target).all()
        # FK target identity is checked separately: temp and durable relations
        # deliberately have different names, but every action/key must match.
        foreign = connection.execute(sa.text("""
            SELECT ns.nspname, cl.relname FROM pg_constraint c
            JOIN pg_class cl ON cl.oid=c.confrelid
            JOIN pg_namespace ns ON ns.oid=cl.relnamespace
            WHERE c.conrelid=to_regclass(:relation) AND c.contype='f' ORDER BY c.conname
        """), target).all()
        if [tuple(row) for row in foreign] != expected_foreign:
            raise RuntimeError("Release operation schema refused: unexpected foreign reference")
        indexes = connection.execute(sa.text("""
            SELECT idx.relname, am.amname, i.indisunique, i.indisvalid, i.indisready,
                   i.indimmediate, i.indnatts, i.indnkeyatts, i.indkey::text,
                   i.indclass::text, i.indcollation::text, i.indoption::text,
                   i.indnullsnotdistinct, pg_get_expr(i.indpred,i.indrelid),
                   pg_get_expr(i.indexprs,i.indrelid)
            FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid
            JOIN pg_am am ON am.oid=idx.relam
            WHERE i.indrelid=to_regclass(:relation) ORDER BY idx.relname
        """), target).all()
        table_policy = connection.execute(sa.text("""
            SELECT relkind, relrowsecurity, relforcerowsecurity, reloptions,
                   EXISTS(SELECT 1 FROM pg_inherits WHERE inhrelid=c.oid OR inhparent=c.oid),
                   EXISTS(SELECT 1 FROM pg_rewrite WHERE ev_class=c.oid)
            FROM pg_class c WHERE oid=to_regclass(:relation)
        """), target).one()
        result.append((columns, constraints, indexes, table_policy))
    return result


_DDL = ("CREATE FUNCTION backup.guard_remote_write_operation() RETURNS trigger\n    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$ BEGIN\n      IF TG_OP IN ('DELETE', 'TRUNCATE') THEN\n        RAISE EXCEPTION 'Remote operation history must be retained';\n      END IF;\n      IF TG_OP = 'INSERT' THEN\n        IF NEW.phase <> 'reserved' OR NEW.sequence <> 0 THEN\n          RAISE EXCEPTION 'Remote operation must begin reserved';\n        END IF;\n        RETURN NEW;\n      END IF;\n      IF (to_jsonb(NEW) - ARRAY['phase','sequence','updated_at']) IS DISTINCT FROM\n         (to_jsonb(OLD) - ARRAY['phase','sequence','updated_at']) THEN\n        RAISE EXCEPTION 'Remote operation intent is immutable';\n      END IF;\n      IF NOT ((OLD.phase='reserved' AND NEW.phase IN ('dispatched','cancelled'))\n          OR (OLD.phase='dispatched' AND NEW.phase='acknowledged'))\n         OR NEW.sequence <> OLD.sequence + 1 THEN\n        RAISE EXCEPTION 'Invalid remote operation transition';\n      END IF;\n      RETURN NEW;\n    END $$", 'CREATE TRIGGER guard_remote_write_operation BEFORE INSERT OR UPDATE OR DELETE\n    ON backup.remote_write_operations FOR EACH ROW\n    EXECUTE FUNCTION backup.guard_remote_write_operation()', 'CREATE TRIGGER guard_remote_write_no_truncate BEFORE TRUNCATE\n    ON backup.remote_write_operations FOR EACH STATEMENT\n    EXECUTE FUNCTION backup.guard_remote_write_operation()')


def _verify(connection):
    name = "remote_write_expected_" + uuid4().hex
    expected = _table("pg_temp", name, temporary=True)
    expected.create(connection)
    persistence = connection.scalar(sa.text("SELECT relpersistence::text FROM pg_class WHERE oid='backup.remote_write_operations'::regclass"))
    if persistence != 'p':
        raise RuntimeError("Remote write history must be a permanent logged table")
    if _shape(connection, "backup", (_TABLE,), []) != _shape(connection, "pg_temp", (name,), []):
        raise RuntimeError("Remote write schema differs from frozen definition; preserve for recovery")
    functions = connection.execute(sa.text("""
        SELECT p.prosrc,p.proconfig,p.prosecdef,p.proleakproof,p.proisstrict,
               p.provolatile::text,p.proparallel::text,p.prokind::text,p.pronargs,p.prorettype::regtype::text,l.lanname
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang
        WHERE n.nspname='backup' AND p.proname='guard_remote_write_operation'
    """)).all()
    if [tuple(r) for r in functions] != [(_DDL[0].split('$$')[1], ['search_path=pg_catalog, pg_temp'],
                                         False,False,False,'v','u','f',0,'trigger','plpgsql')]:
        raise RuntimeError("Remote write history function differs from frozen definition")
    triggers = connection.execute(sa.text("""
        SELECT t.tgname,t.tgtype,t.tgenabled::text,t.tgdeferrable,t.tginitdeferred,t.tgnargs,
               t.tgattr::text,pg_get_expr(t.tgqual,t.tgrelid),n.nspname,p.proname,t.tgconstrrelid
        FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE t.tgrelid='backup.remote_write_operations'::regclass AND NOT t.tgisinternal ORDER BY t.tgname
    """)).all()
    expected_triggers = [('guard_remote_write_no_truncate',34,'O',False,False,0,'',None,'backup','guard_remote_write_operation',0),
                         ('guard_remote_write_operation',31,'O',False,False,0,'',None,'backup','guard_remote_write_operation',0)]
    if [tuple(r) for r in triggers] != expected_triggers:
        raise RuntimeError("Remote write history triggers differ from frozen definition")
    expected.drop(connection)


def _online():
    if op.get_context().as_sql or op.get_bind().dialect.name != 'postgresql':
        raise RuntimeError("Remote write migration requires online PostgreSQL inspection")
    connection = op.get_bind()
    values = connection.execute(sa.text("SELECT current_setting('transaction_isolation'), current_setting('session_replication_role')")).one()
    if tuple(values) != ('read committed', 'origin'):
        raise RuntimeError("Remote write migration requires origin triggers and READ COMMITTED")
    return connection


def upgrade():
    connection = _online()
    if not sa.inspect(connection).has_table(_TABLE, schema='backup'):
        _table('backup', _TABLE).create(connection)
        for statement in _DDL:
            connection.execute(sa.text(statement))
    connection.execute(sa.text("LOCK TABLE backup.remote_write_operations IN ACCESS EXCLUSIVE MODE"))
    _verify(connection)


def downgrade():
    connection = _online()
    connection.execute(sa.text("LOCK TABLE backup.remote_write_operations IN ACCESS EXCLUSIVE MODE"))
    _verify(connection)
    if connection.scalar(sa.text("SELECT EXISTS (SELECT 1 FROM backup.remote_write_operations)")):
        raise RuntimeError("Refusing downgrade that would discard retained remote write history")
    connection.execute(sa.text("DROP TABLE backup.remote_write_operations"))
    connection.execute(sa.text("DROP FUNCTION backup.guard_remote_write_operation()"))
