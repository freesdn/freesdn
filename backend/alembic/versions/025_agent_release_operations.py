# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Retain release operation history; no artifact adoption or endpoint enablement.

Frozen native definitions. Existing rows, including terminal rows, block a
history-destructive downgrade. No application imports or filesystem operations.
"""
from uuid import uuid4

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "025_agent_release_operations"
down_revision = "024_agent_signing_enrollment"
branch_labels = None
depends_on = None
_TABLE = "agent_release_operations"


def _table(schema, name, *, temporary=False):
    metadata = sa.MetaData()
    options = {"prefixes": ["TEMPORARY"], "postgresql_on_commit": "DROP"} if temporary else {}
    table = sa.Table(name, metadata,
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("format_version", sa.SmallInteger(), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("release_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("requested_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("storage_kind", sa.String(16), nullable=False),
        sa.Column("artifact_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("request_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("expected_sha256", sa.String(64), nullable=False),
        sa.Column("expected_size", sa.BigInteger(), nullable=False),
        sa.Column("phase", sa.String(16), nullable=False),
        sa.Column("decision", sa.String(16), nullable=True),
        sa.Column("transition_sequence", sa.SmallInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cleaned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_transition_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.PrimaryKeyConstraint("operation_id", name="pk_agent_release_operations"),
        *(sa.CheckConstraint(sql, name="ck_agent_release_operations_"+key) for key,sql in _CHECKS),
        schema=schema, **options,
    )
    sa.Index("uq_release_operation_unresolved", table.c.release_id, unique=True,
             postgresql_where=sa.text("phase IN ('reserved', 'prepared')"))
    sa.Index("uq_release_operation_publish_identity", table.c.release_id, unique=True,
             postgresql_where=sa.text("kind = 'publish'"))
    sa.Index("uq_release_operation_owned_object", table.c.artifact_id, unique=True,
             postgresql_where=sa.text("kind = 'publish' AND storage_kind = 'owned'"))
    sa.Index("ix_release_operation_scope_phase", table.c.organization_id, table.c.phase, table.c.created_at)
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


def _verify(connection):
    name="release_operation_expected_"+uuid4().hex
    temporary=_table("pg_temp",name,temporary=True)
    temporary.create(connection)
    persistence=connection.execute(sa.text("SELECT relpersistence::text FROM pg_class WHERE oid='agents.agent_release_operations'::regclass")).scalar_one()
    if persistence != 'p':
        raise RuntimeError("Release operation history must be a logged permanent table")
    if _shape(connection,"agents",(_TABLE,),[]) != _shape(connection,"pg_temp",(name,),[]):
        raise RuntimeError("Release operation schema differs from frozen definition; preserve for recovery")
    functions=connection.execute(sa.text("""
        SELECT p.prosrc,p.proconfig,p.prosecdef,p.proleakproof,p.proisstrict,
               p.provolatile::text,p.proparallel::text,p.prokind::text,p.pronargs,p.prorettype::regtype::text,l.lanname
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang
        WHERE n.nspname='agents' AND p.proname='guard_release_operation'
    """)).all()
    expected=[(_DDL[0].split('$release_operation$')[1], ['search_path=pg_catalog, pg_temp'],
               False,False,False,'v','u','f',0,'trigger','plpgsql')]
    if [tuple(row) for row in functions]!=expected:
        raise RuntimeError("Release operation guard differs from frozen definition")
    triggers=connection.execute(sa.text("""
        SELECT t.tgname,t.tgtype,t.tgenabled::text,t.tgdeferrable,t.tginitdeferred,t.tgnargs,
               t.tgattr::text,pg_get_expr(t.tgqual,t.tgrelid),n.nspname,p.proname,t.tgconstrrelid
        FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE t.tgrelid='agents.agent_release_operations'::regclass AND NOT t.tgisinternal ORDER BY t.tgname
    """)).all()
    expected_triggers=[('guard_release_operation',31,'O',False,False,0,'',None,'agents','guard_release_operation',0),
                       ('guard_release_operation_no_truncate',34,'O',False,False,0,'',None,'agents','guard_release_operation',0)]
    if [tuple(row) for row in triggers]!=expected_triggers:
        raise RuntimeError("Release operation trigger differs from frozen definition")
    temporary.drop(connection)


def upgrade():
    connection=op.get_bind()
    if not sa.inspect(connection).has_table(_TABLE,schema="agents"):
        _table("agents",_TABLE).create(connection)
        for statement in _DDL:
            op.execute(sa.text(statement))
    op.execute("LOCK TABLE agents.agent_release_operations IN ACCESS EXCLUSIVE MODE")
    _verify(connection)
    # No legacy release is adopted; no rows or files are generated here.


def downgrade():
    connection=op.get_bind()
    op.execute("LOCK TABLE agents.agent_release_operations IN ACCESS EXCLUSIVE MODE")
    _verify(connection)
    if connection.scalar(sa.text("SELECT EXISTS(SELECT 1 FROM agents.agent_release_operations)")):
        raise RuntimeError("Release operation downgrade refused while history remains")
    op.drop_table(_TABLE,schema="agents")
    op.execute("DROP FUNCTION agents.guard_release_operation()")


_CHECKS = (('format', 'format_version = 1'), ('kind', "kind IN ('publish', 'delete')"), ('storage', "storage_kind IN ('owned', 'external', 'legacy') AND ((storage_kind = 'owned' AND artifact_id IS NOT NULL) OR (storage_kind IN ('external', 'legacy') AND artifact_id IS NULL)) AND (kind = 'delete' OR storage_kind <> 'legacy') AND (kind <> 'publish' OR storage_kind <> 'owned' OR artifact_id = operation_id)"), ('request_binding', "octet_length(request_bytes) BETWEEN 1 AND 65536 AND request_sha256 = encode(sha256(request_bytes), 'hex')"), ('artifact_binding', "expected_sha256 ~ '^[0-9a-f]{64}$' AND expected_size BETWEEN 0 AND 10737418240 AND (storage_kind <> 'owned' OR expected_size <= 524288000)"), ('sequence', 'transition_sequence BETWEEN 0 AND 3'), ('phase', "phase IN ('reserved', 'prepared', 'decided', 'cleaned')"), ('decision_kind', "decision IS NULL OR decision = 'cancelled' OR (kind = 'publish' AND decision = 'published') OR (kind = 'delete' AND decision = 'deleted')"), ('phase_fields', "(phase = 'reserved' AND transition_sequence = 0 AND prepared_at IS NULL AND decision IS NULL AND decided_at IS NULL AND cleaned_at IS NULL) OR (phase = 'prepared' AND transition_sequence = 1 AND prepared_at IS NOT NULL AND decision IS NULL AND decided_at IS NULL AND cleaned_at IS NULL) OR (phase = 'decided' AND decision IS NOT NULL AND decided_at IS NOT NULL AND cleaned_at IS NULL AND ((prepared_at IS NOT NULL AND transition_sequence = 2) OR (prepared_at IS NULL AND transition_sequence = 1 AND decision = 'cancelled'))) OR (phase = 'cleaned' AND decision IS NOT NULL AND decision IN ('deleted', 'cancelled') AND decided_at IS NOT NULL AND cleaned_at IS NOT NULL AND ((prepared_at IS NOT NULL AND transition_sequence = 3) OR (prepared_at IS NULL AND transition_sequence = 2 AND decision = 'cancelled')))"), ('time_order', '(prepared_at IS NULL OR prepared_at >= created_at) AND (decided_at IS NULL OR decided_at >= created_at) AND (prepared_at IS NULL OR decided_at IS NULL OR decided_at >= prepared_at) AND (cleaned_at IS NULL OR cleaned_at >= decided_at)'))

_DDL = ("CREATE FUNCTION agents.guard_release_operation() RETURNS trigger\nLANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $release_operation$\nBEGIN\n    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN\n        RAISE EXCEPTION 'Release operation history must be retained' USING ERRCODE = '23514';\n    END IF;\n    IF TG_OP = 'INSERT' THEN\n        IF NEW.phase IS DISTINCT FROM 'reserved' OR NEW.transition_sequence IS DISTINCT FROM 0\n           OR NEW.last_transition_by IS DISTINCT FROM NEW.requested_by THEN\n            RAISE EXCEPTION 'Release operation must begin reserved' USING ERRCODE = '23514';\n        END IF;\n        RETURN NEW;\n    END IF;\n    IF NEW IS NOT DISTINCT FROM OLD THEN\n        RETURN NEW;\n    END IF;\n    IF ROW(NEW.operation_id, NEW.format_version, NEW.kind, NEW.release_id,\n           NEW.organization_id, NEW.requested_by, NEW.storage_kind, NEW.artifact_id,\n           NEW.request_bytes, NEW.request_sha256, NEW.expected_sha256, NEW.expected_size,\n           NEW.created_at)\n       IS DISTINCT FROM\n       ROW(OLD.operation_id, OLD.format_version, OLD.kind, OLD.release_id,\n           OLD.organization_id, OLD.requested_by, OLD.storage_kind, OLD.artifact_id,\n           OLD.request_bytes, OLD.request_sha256, OLD.expected_sha256, OLD.expected_size,\n           OLD.created_at) THEN\n        RAISE EXCEPTION 'Release operation intent is immutable' USING ERRCODE = '23514';\n    END IF;\n    IF NEW.transition_sequence IS DISTINCT FROM OLD.transition_sequence + 1\n       OR (OLD.prepared_at IS NOT NULL AND NEW.prepared_at IS DISTINCT FROM OLD.prepared_at)\n       OR (OLD.decided_at IS NOT NULL AND NEW.decided_at IS DISTINCT FROM OLD.decided_at)\n       OR (OLD.decision IS NOT NULL AND NEW.decision IS DISTINCT FROM OLD.decision)\n       OR (OLD.cleaned_at IS NOT NULL AND NEW.cleaned_at IS DISTINCT FROM OLD.cleaned_at) THEN\n        RAISE EXCEPTION 'Release operation cannot rewind or rewrite a decision' USING ERRCODE = '23514';\n    END IF;\n    IF NOT (\n        (OLD.phase = 'reserved' AND NEW.phase = 'prepared') OR\n        (OLD.phase IN ('reserved', 'prepared') AND NEW.phase = 'decided'\n         AND NEW.decision = 'cancelled') OR\n        (OLD.phase = 'prepared' AND NEW.phase = 'decided'\n         AND ((OLD.kind = 'publish' AND NEW.decision = 'published') OR\n              (OLD.kind = 'delete' AND NEW.decision = 'deleted'))) OR\n        (OLD.phase = 'decided' AND OLD.decision IN ('deleted', 'cancelled')\n         AND NEW.phase = 'cleaned')\n    ) THEN\n        RAISE EXCEPTION 'Release operation transition refused' USING ERRCODE = '23514';\n    END IF;\n    RETURN NEW;\nEND\n$release_operation$", 'CREATE TRIGGER guard_release_operation BEFORE INSERT OR UPDATE OR DELETE\nON agents.agent_release_operations FOR EACH ROW EXECUTE FUNCTION agents.guard_release_operation()', 'CREATE TRIGGER guard_release_operation_no_truncate BEFORE TRUNCATE\nON agents.agent_release_operations FOR EACH STATEMENT EXECUTE FUNCTION agents.guard_release_operation()')
