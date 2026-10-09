# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Persist enrollment pins; never backfill trust for existing agents.

Frozen definitions, native parser comparisons and exact trigger verification.
Existing enrollment rows prevent downgrade. This migration performs no key I/O.
"""
from uuid import uuid4

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "024_agent_signing_enrollment"
down_revision = "023_agent_signing_identity"
branch_labels = None
depends_on = None
_TABLE = "agent_signing_enrollments"


def _tables(schema, names, *, temporary=False):
    metadata = sa.MetaData()
    options = {"prefixes": ["TEMPORARY"], "postgresql_on_commit": "DROP"} if temporary else {}
    agents = sa.Table(names[0], metadata, sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True), schema=schema, **options)
    identities = sa.Table(names[1], metadata, sa.Column("singleton_id", sa.SmallInteger(), primary_key=True, autoincrement=False), schema=schema, **options)
    pins = sa.Table(names[2], metadata,
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("signing_singleton_id", sa.SmallInteger(), nullable=False),
        sa.Column("installation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("identity_epoch", sa.BigInteger(), nullable=False),
        sa.Column("public_key_sha256", sa.String(64), nullable=False),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("enrolled_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.PrimaryKeyConstraint("agent_id", name="pk_agent_signing_enrollments"),
        sa.ForeignKeyConstraint(["agent_id"], [agents.c.id], ondelete="CASCADE", name="fk_signing_enrollment_agent"),
        sa.ForeignKeyConstraint(["signing_singleton_id"], [identities.c.singleton_id], ondelete="RESTRICT", name="fk_signing_enrollment_identity"),
        *(sa.CheckConstraint(sql, name="ck_agent_signing_enrollments_"+name) for name,sql in _CHECKS),
        schema=schema, **options,
    )
    return agents, identities, pins


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
        # Compare NOT NULL column/enforcement contracts, not relation-derived names.
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
            raise RuntimeError("Signing schema refused: unexpected identity reference")
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
    suffix=uuid4().hex
    names=("signing_agent_"+suffix,"signing_active_"+suffix,"signing_enrollment_"+suffix)
    temporary=_tables("pg_temp",names,temporary=True)
    for table in temporary:
        table.create(connection)
    temp_schema=connection.scalar(sa.text("SELECT nspname FROM pg_namespace WHERE oid=pg_my_temp_schema()"))
    actual=_shape(connection,"agents",(_TABLE,),[("agents","remote_agents"),("agents","agent_signing_identities")])
    expected=_shape(connection,"pg_temp",(names[2],),[(temp_schema,names[0]),(temp_schema,names[1])])
    if actual!=expected:
        raise RuntimeError("Enrollment schema differs from the frozen definition; preserve for recovery")
    functions=connection.execute(sa.text("""
        SELECT p.prosrc,p.proconfig,p.prosecdef,p.proleakproof,p.proisstrict,
               p.provolatile::text,p.proparallel::text,p.prokind::text,p.pronargs,p.prorettype::regtype::text,l.lanname
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang
        WHERE n.nspname='agents' AND p.proname='guard_signing_enrollment'
    """)).all()
    expected_function=[(_DDL[0].split('$enrollment$')[1], ['search_path=pg_catalog, pg_temp'],
                        False,False,False,'v','u','f',0,'trigger','plpgsql')]
    if [tuple(row) for row in functions]!=expected_function:
        raise RuntimeError("Enrollment guard differs from frozen definition")
    triggers=connection.execute(sa.text("""
        SELECT t.tgname,t.tgtype,t.tgenabled::text,t.tgdeferrable,t.tginitdeferred,t.tgnargs,
               t.tgattr::text,pg_get_expr(t.tgqual,t.tgrelid),n.nspname,p.proname,t.tgconstrrelid
        FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE t.tgrelid='agents.agent_signing_enrollments'::regclass AND NOT t.tgisinternal ORDER BY t.tgname
    """)).all()
    expected_triggers=[('guard_signing_enrollment',31,'O',False,False,0,'',None,'agents','guard_signing_enrollment',0),
                       ('guard_signing_enrollment_no_truncate',34,'O',False,False,0,'',None,'agents','guard_signing_enrollment',0)]
    if [tuple(row) for row in triggers]!=expected_triggers:
        raise RuntimeError("Enrollment trigger differs from frozen definition")
    for table in reversed(temporary):
        table.drop(connection)


def upgrade():
    connection=op.get_bind()
    if not sa.inspect(connection).has_table(_TABLE,schema="agents"):
        # Virtual parent definitions only resolve FK DDL; never create or alter
        # the existing agent/identity tables here.
        _tables("agents",("remote_agents","agent_signing_identities",_TABLE))[2].create(connection)
        for statement in _DDL:
            op.execute(sa.text(statement))
    op.execute("LOCK TABLE agents.agent_signing_enrollments IN ACCESS EXCLUSIVE MODE")
    _verify(connection)
    # No old agent receives an invented fingerprint.


def downgrade():
    connection=op.get_bind()
    op.execute("LOCK TABLE agents.agent_signing_enrollments IN ACCESS EXCLUSIVE MODE")
    _verify(connection)
    if connection.scalar(sa.text("SELECT EXISTS(SELECT 1 FROM agents.agent_signing_enrollments)")):
        raise RuntimeError("Enrollment downgrade refused while recorded trust pins remain")
    op.drop_table(_TABLE,schema="agents")
    op.execute("DROP FUNCTION agents.guard_signing_enrollment()")

_DDL = ("CREATE FUNCTION agents.guard_signing_enrollment() RETURNS trigger\nLANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $enrollment$\nDECLARE identity_record record;\nBEGIN\n    IF TG_OP = 'TRUNCATE' THEN\n        RAISE EXCEPTION 'Enrollment history cannot be truncated' USING ERRCODE = '23514';\n    END IF;\n    IF TG_OP = 'DELETE' THEN\n        IF EXISTS (SELECT 1 FROM agents.remote_agents WHERE id = OLD.agent_id) THEN\n            RAISE EXCEPTION 'Delete the agent through its lifecycle, not its trust pin' USING ERRCODE = '23514';\n        END IF;\n        RETURN OLD;\n    END IF;\n    IF TG_OP = 'UPDATE' THEN\n        IF NEW IS DISTINCT FROM OLD THEN\n            RAISE EXCEPTION 'Enrolled signing identity is immutable' USING ERRCODE = '23514';\n        END IF;\n        RETURN NEW;\n    END IF;\n    SELECT installation_id, identity_epoch, public_key_sha256 INTO identity_record\n      FROM agents.agent_signing_identities WHERE singleton_id = 1 FOR SHARE;\n    IF NOT FOUND OR NEW.signing_singleton_id IS DISTINCT FROM 1\n       OR NEW.installation_id IS DISTINCT FROM identity_record.installation_id\n       OR NEW.identity_epoch IS DISTINCT FROM identity_record.identity_epoch\n       OR NEW.public_key_sha256 IS DISTINCT FROM identity_record.public_key_sha256 THEN\n        RAISE EXCEPTION 'Enrollment requires the active signing identity' USING ERRCODE = '23514';\n    END IF;\n    RETURN NEW;\nEND\n$enrollment$", 'CREATE TRIGGER guard_signing_enrollment BEFORE INSERT OR UPDATE OR DELETE\nON agents.agent_signing_enrollments FOR EACH ROW EXECUTE FUNCTION agents.guard_signing_enrollment()', 'CREATE TRIGGER guard_signing_enrollment_no_truncate BEFORE TRUNCATE\nON agents.agent_signing_enrollments FOR EACH STATEMENT EXECUTE FUNCTION agents.guard_signing_enrollment()')

_CHECKS = [('singleton', 'signing_singleton_id = 1'), ('epoch', 'identity_epoch > 0'), ('fingerprint', "public_key_sha256 ~ '^[0-9a-f]{64}$'")]
