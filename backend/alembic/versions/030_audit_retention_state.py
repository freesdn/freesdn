# SPDX-License-Identifier: AGPL-3.0-only
"""Retain signed audit boundaries and immutable owner UUID snapshots.

Maintenance upgrade with old writers stopped. Old row values/signatures remain
unchanged; the initial marker does not authenticate pre-migration history.
Downgrade is refused because it would discard local seals or rewrite snapshots.
"""

import sqlalchemy as sa
from alembic import op

revision = "030_audit_retention_state"
down_revision = "029_audit_append_order"
branch_labels = None
depends_on = None

_DDL = ('INSERT INTO audit.audit_chain_state (id,revision,state_bytes,state_hmac)\n    VALUES (1,0,convert_to(\'{"state":"uninitialized","v":1}\',\'UTF8\'),NULL)', "CREATE FUNCTION audit.guard_audit_chain_state() RETURNS trigger\n    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$ BEGIN\n      IF TG_OP <> 'UPDATE' THEN\n        RAISE EXCEPTION 'Audit chain state must be retained';\n      END IF;\n      IF NEW.id <> OLD.id OR OLD.revision = 9223372036854775807\n         OR NEW.revision <> OLD.revision + 1 OR NEW.state_hmac IS NULL THEN\n        RAISE EXCEPTION 'Invalid audit state transition';\n      END IF;\n      RETURN NEW;\n    END $$", 'CREATE TRIGGER guard_audit_chain_state BEFORE INSERT OR UPDATE OR DELETE\n    ON audit.audit_chain_state FOR EACH ROW EXECUTE FUNCTION audit.guard_audit_chain_state()', 'CREATE TRIGGER guard_audit_chain_state_truncate BEFORE TRUNCATE\n    ON audit.audit_chain_state FOR EACH STATEMENT EXECUTE FUNCTION audit.guard_audit_chain_state()')


def _online():
    if op.get_context().as_sql or op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("Audit retention migration requires online PostgreSQL inspection")
    connection = op.get_bind()
    policy = connection.execute(sa.text(
        "SELECT current_setting('transaction_isolation'), current_setting('session_replication_role')"
    )).one()
    if tuple(policy) != ("read committed", "origin"):
        raise RuntimeError("Audit retention migration requires READ COMMITTED and origin triggers")
    connection.execute(sa.text("SELECT pg_advisory_xact_lock(779001439)"))
    connection.execute(sa.text("LOCK TABLE audit.audit_logs IN ACCESS EXCLUSIVE MODE"))
    return connection


def _owner_keys(connection):
    keys = sa.inspect(connection).get_foreign_keys("audit_logs", schema="audit")
    return [key for key in keys if set(key["constrained_columns"]) & {"organization_id", "site_id"}]


def _verify(connection):
    columns = connection.execute(sa.text("""
        SELECT a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,
               pg_get_expr(d.adbin,d.adrelid),a.attidentity::text,a.attgenerated::text
        FROM pg_attribute a LEFT JOIN pg_attrdef d
          ON d.adrelid=a.attrelid AND d.adnum=a.attnum
        WHERE a.attrelid='audit.audit_chain_state'::regclass
          AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum
    """)).all()
    if [tuple(row) for row in columns] != [
        ("id","smallint",True,None,"",""), ("revision","bigint",True,None,"",""),
        ("state_bytes","bytea",True,None,"",""),
        ("state_hmac","character varying(64)",False,None,"","")
    ]:
        raise RuntimeError("Unexpected audit state columns")
    relation = connection.execute(sa.text("""
        SELECT relkind::text,relpersistence::text,relrowsecurity,relforcerowsecurity
        FROM pg_class WHERE oid='audit.audit_chain_state'::regclass
    """)).one()
    if tuple(relation) != ("r","p",False,False):
        raise RuntimeError("Unexpected audit state storage or visibility")
    constraints = sa.inspect(connection).get_check_constraints("audit_chain_state", schema="audit")
    # Expressions are normalized only for insignificant SQL whitespace and
    # explicit PostgreSQL literal casts; every complete predicate is retained.
    normalized = {item["name"]: " ".join(item["sqltext"].split()) for item in constraints}
    expected = {
        "ck_audit_chain_state_audit_chain_singleton": "id = 1",
        "ck_audit_chain_state_audit_chain_revision": "revision >= 0",
        "ck_audit_chain_state_audit_chain_size": "octet_length(state_bytes) >= 1 AND octet_length(state_bytes) <= 8192",
        "ck_audit_chain_state_audit_chain_hmac": "state_hmac IS NULL OR state_hmac::text ~ '^[0-9a-f]{64}$'::text",
    }
    if normalized != expected:
        raise RuntimeError("Unexpected audit state constraints")
    flags = connection.execute(sa.text("""
        SELECT bool_and(convalidated AND NOT condeferrable AND NOT condeferred
                        AND COALESCE((to_jsonb(c)->>'conenforced')::boolean,true))
        FROM pg_constraint c WHERE conrelid='audit.audit_chain_state'::regclass AND contype='c'
    """)).scalar()
    if flags is not True or sa.inspect(connection).get_pk_constraint(
            "audit_chain_state", schema="audit")["constrained_columns"] != ["id"]:
        raise RuntimeError("Unexpected audit state constraint enforcement")
    function = connection.execute(sa.text("""
        SELECT p.prosrc,p.proconfig,p.prosecdef,p.proleakproof,p.proisstrict,
               p.provolatile::text,p.proparallel::text,p.prokind::text,p.pronargs,
               p.prorettype::regtype::text,l.lanname
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
          JOIN pg_language l ON l.oid=p.prolang
        WHERE n.nspname='audit' AND p.proname='guard_audit_chain_state'
    """)).all()
    if [tuple(row) for row in function] != [(_DDL[1].split("$$")[1],
            ["search_path=pg_catalog, pg_temp"],False,False,False,"v","u","f",0,"trigger","plpgsql")]:
        raise RuntimeError("Unexpected audit state guard function")
    triggers = connection.execute(sa.text("""
        SELECT t.tgname,t.tgtype,t.tgenabled::text,t.tgdeferrable,t.tginitdeferred,t.tgnargs,
               t.tgattr::text,pg_get_expr(t.tgqual,t.tgrelid),n.nspname,p.proname
        FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
          JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE t.tgrelid='audit.audit_chain_state'::regclass AND NOT t.tgisinternal
        ORDER BY t.tgname
    """)).all()
    if [tuple(row) for row in triggers] != [
        ("guard_audit_chain_state",31,"O",False,False,0,"",None,"audit","guard_audit_chain_state"),
        ("guard_audit_chain_state_truncate",34,"O",False,False,0,"",None,"audit","guard_audit_chain_state")
    ]:
        raise RuntimeError("Unexpected audit state guard triggers")
    indexes = connection.execute(sa.text("""
        SELECT i.indisunique,i.indisvalid,i.indisready,am.amname,
               pg_get_indexdef(i.indexrelid,1,true),pg_get_indexdef(i.indexrelid,2,true),
               pg_get_indexdef(i.indexrelid,3,true),i.indpred IS NULL,i.indnatts,i.indnkeyatts
        FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_am am ON am.oid=c.relam
        WHERE i.indrelid='audit.audit_logs'::regclass AND c.relname='ix_audit_logs_chain_order'
    """)).all()
    if [tuple(row) for row in indexes] != [
            (False,True,True,"btree","COALESCE(append_sequence, 0::bigint)",'"timestamp"',"id",True,3,3)]:
        raise RuntimeError("Unexpected audit append traversal index")
    if _owner_keys(connection):
        raise RuntimeError("Audit owner snapshots must not have mutation cascades")
    values = connection.execute(sa.text(
        "SELECT id,revision,state_bytes,state_hmac FROM audit.audit_chain_state"
    )).all()
    if len(values) != 1 or values[0].id != 1:
        raise RuntimeError("Missing audit state; never recreate genesis on repeated upgrade")
    row = values[0]
    if row.revision == 0 and (bytes(row.state_bytes) != b'{"state":"uninitialized","v":1}'
                              or row.state_hmac is not None):
        raise RuntimeError("Invalid unsealed audit migration marker")
    if row.revision > 0 and row.state_hmac is None:
        raise RuntimeError("Missing audit state signature")
    # HMAC verification requires the deployment key and remains an application
    # operation; DDL never re-signs, repairs or certifies historical values.


def upgrade():
    connection = _online()
    exists = connection.scalar(sa.text("SELECT to_regclass('audit.audit_chain_state') IS NOT NULL"))
    if not exists:
        keys = _owner_keys(connection)
        actual = {(tuple(key["constrained_columns"]),key["referred_schema"],key["referred_table"],
                   tuple(key["referred_columns"]),key.get("options",{}).get("ondelete")) for key in keys}
        expected = {(("organization_id",),"core","organizations",("id",),"SET NULL"),
                    (("site_id",),"core","sites",("id",),"SET NULL")}
        if actual != expected or len(keys) != 2:
            raise RuntimeError("Unexpected predecessor audit owner constraints")
        connection.execute(sa.text("""CREATE TABLE audit.audit_chain_state (
          id smallint PRIMARY KEY, revision bigint NOT NULL, state_bytes bytea NOT NULL,
          state_hmac varchar(64),
          CONSTRAINT ck_audit_chain_state_audit_chain_singleton CHECK (id=1),
          CONSTRAINT ck_audit_chain_state_audit_chain_revision CHECK (revision>=0),
          CONSTRAINT ck_audit_chain_state_audit_chain_size CHECK (octet_length(state_bytes) BETWEEN 1 AND 8192),
          CONSTRAINT ck_audit_chain_state_audit_chain_hmac CHECK (state_hmac IS NULL OR state_hmac ~ '^[0-9a-f]{64}$')
        )"""))
        for statement in _DDL:
            # Driver SQL preserves colons inside the constant JSON seed literal;
            # text() would reinterpret them as named parameter markers.
            connection.exec_driver_sql(statement)
        for key in keys:
            op.drop_constraint(key["name"], "audit_logs", schema="audit", type_="foreignkey")
        connection.execute(sa.text("CREATE INDEX ix_audit_logs_chain_order "
                                   "ON audit.audit_logs (COALESCE(append_sequence,0),timestamp,id)"))
    _verify(connection)


def downgrade():
    _online()
    raise RuntimeError("Refusing downgrade that discards audit retention state and owner snapshots")
