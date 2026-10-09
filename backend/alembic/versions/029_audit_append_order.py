# SPDX-License-Identifier: AGPL-3.0-only
"""Separate new audit append order from event time; preserve all historical bytes.

Maintenance upgrade: stop old writers before applying. New INSERTs without a
signed append position are rejected. Existing rows remain format 1 with NULL
positions; this migration neither re-signs nor certifies their history.
"""

import sqlalchemy as sa

from alembic import op

revision = "029_audit_append_order"
down_revision = "028_remote_write_history"
branch_labels = None
depends_on = None

_DDL = ("CREATE FUNCTION audit.guard_audit_append() RETURNS trigger\n    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$ BEGIN\n      IF NEW.append_sequence IS NULL OR NEW.append_sequence <= 0\n         OR NEW.row_hmac IS NULL OR NEW.row_hmac !~ '^[0-9a-f]{64}$'\n         OR (NEW.prev_hash IS NOT NULL AND NEW.prev_hash !~ '^[0-9a-f]{64}$') THEN\n        RAISE EXCEPTION 'Audit insert requires a signed append sequence';\n      END IF;\n      RETURN NEW;\n    END $$", 'CREATE TRIGGER guard_audit_append BEFORE INSERT ON audit.audit_logs\n    FOR EACH ROW EXECUTE FUNCTION audit.guard_audit_append()')


def _online():
    if op.get_context().as_sql or op.get_bind().dialect.name != 'postgresql':
        raise RuntimeError('Audit append migration requires online PostgreSQL inspection')
    connection = op.get_bind()
    policy = connection.execute(sa.text(
        "SELECT current_setting('transaction_isolation'), current_setting('session_replication_role')"
    )).one()
    if tuple(policy) != ('read committed', 'origin'):
        raise RuntimeError('Audit append migration requires READ COMMITTED and origin triggers')
    connection.execute(sa.text('LOCK TABLE audit.audit_logs IN ACCESS EXCLUSIVE MODE'))
    return connection


def _verify(connection):
    column = connection.execute(sa.text("""
        SELECT format_type(a.atttypid,a.atttypmod),a.attnotnull,
               pg_get_expr(d.adbin,d.adrelid),a.attidentity::text,a.attgenerated::text
        FROM pg_attribute a LEFT JOIN pg_attrdef d
          ON d.adrelid=a.attrelid AND d.adnum=a.attnum
        WHERE a.attrelid='audit.audit_logs'::regclass
          AND a.attname='append_sequence' AND NOT a.attisdropped
    """)).all()
    if [tuple(r) for r in column] != [('bigint',False,None,'','')]:
        raise RuntimeError('Unexpected audit append column; preserve for investigation')
    sequence = connection.execute(sa.text("""
        SELECT data_type::text,start_value,min_value,max_value,increment_by,cycle,cache_size
        FROM pg_sequences WHERE schemaname='audit' AND sequencename='audit_append_sequence'
    """)).all()
    if [tuple(r) for r in sequence] != [('bigint',1,1,9223372036854775807,1,False,1)]:
        raise RuntimeError('Unexpected audit sequence definition')
    persistence = connection.scalar(sa.text(
        "SELECT relpersistence::text FROM pg_class WHERE oid='audit.audit_append_sequence'::regclass"
    ))
    if persistence != 'p':
        raise RuntimeError('Audit sequence must be permanent')
    index = connection.execute(sa.text("""
        SELECT i.indisunique,i.indisvalid,i.indisready,am.amname,
               pg_get_indexdef(i.indexrelid,1,true),pg_get_expr(i.indpred,i.indrelid),
               i.indnatts,i.indnkeyatts,i.indexprs IS NULL,i.indisprimary
        FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
          JOIN pg_am am ON am.oid=c.relam
        WHERE i.indrelid='audit.audit_logs'::regclass
          AND c.relname='ix_audit_logs_append_sequence'
    """)).all()
    if [tuple(r) for r in index] != [(True,True,True,'btree','append_sequence',
                                    '(append_sequence IS NOT NULL)',1,1,True,False)]:
        raise RuntimeError('Unexpected audit sequence index')
    constraint = connection.execute(sa.text("""
        SELECT pg_get_expr(conbin,conrelid),convalidated,condeferrable,condeferred,
               COALESCE((to_jsonb(c)->>'conenforced')::boolean,true)
        FROM pg_constraint c WHERE conrelid='audit.audit_logs'::regclass
          AND conname='ck_audit_logs_audit_append_sequence_positive' AND contype='c'
    """)).all()
    if [tuple(r) for r in constraint] != [('((append_sequence IS NULL) OR (append_sequence > 0))',
                                         True,False,False,True)]:
        raise RuntimeError('Unexpected audit append position constraint')
    functions = connection.execute(sa.text("""
        SELECT p.prosrc,p.proconfig,p.prosecdef,p.proleakproof,p.proisstrict,
               p.provolatile::text,p.proparallel::text,p.prokind::text,p.pronargs,
               p.prorettype::regtype::text,l.lanname
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
          JOIN pg_language l ON l.oid=p.prolang
        WHERE n.nspname='audit' AND p.proname='guard_audit_append'
    """)).all()
    if [tuple(r) for r in functions] != [(_DDL[0].split('$$')[1],
            ['search_path=pg_catalog, pg_temp'],False,False,False,'v','u','f',0,'trigger','plpgsql')]:
        raise RuntimeError('Unexpected audit append guard function')
    triggers = connection.execute(sa.text("""
        SELECT t.tgtype,t.tgenabled::text,t.tgdeferrable,t.tginitdeferred,t.tgnargs,
               t.tgattr::text,pg_get_expr(t.tgqual,t.tgrelid),n.nspname,p.proname
        FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
          JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE t.tgrelid='audit.audit_logs'::regclass AND t.tgname='guard_audit_append'
    """)).all()
    if [tuple(r) for r in triggers] != [(7,'O',False,False,0,'',None,'audit','guard_audit_append')]:
        raise RuntimeError('Unexpected audit append guard trigger')
    last, called = connection.execute(sa.text(
        'SELECT last_value,is_called FROM audit.audit_append_sequence'
    )).one()
    maximum = connection.scalar(sa.text('SELECT max(append_sequence) FROM audit.audit_logs'))
    if maximum is not None and (last < maximum or (last == maximum and not called)):
        raise RuntimeError('Audit append sequence is behind stored history')


def upgrade():
    connection = _online()
    present = connection.scalar(sa.text("""
        SELECT EXISTS(SELECT 1 FROM pg_attribute
          WHERE attrelid='audit.audit_logs'::regclass
            AND attname='append_sequence' AND NOT attisdropped)
    """))
    if not present:
        # Transactional DDL: any conflicting object/refusal rolls this back.
        connection.execute(sa.text('CREATE SEQUENCE audit.audit_append_sequence AS bigint'))
        connection.execute(sa.text('ALTER TABLE audit.audit_logs ADD COLUMN append_sequence bigint'))
        connection.execute(sa.text('ALTER TABLE audit.audit_logs ADD CONSTRAINT '
            'ck_audit_logs_audit_append_sequence_positive '
            'CHECK (append_sequence IS NULL OR append_sequence > 0)'))
        connection.execute(sa.text('CREATE UNIQUE INDEX ix_audit_logs_append_sequence '
            'ON audit.audit_logs (append_sequence) WHERE append_sequence IS NOT NULL'))
        for statement in _DDL:
            connection.execute(sa.text(statement))
    _verify(connection)


def downgrade():
    connection = _online()
    _verify(connection)
    if connection.scalar(sa.text('SELECT EXISTS (SELECT 1 FROM audit.audit_logs '
                                 'WHERE append_sequence IS NOT NULL)')):
        raise RuntimeError('Refusing downgrade that discards signed audit append positions')
    connection.execute(sa.text('DROP TRIGGER guard_audit_append ON audit.audit_logs'))
    connection.execute(sa.text('DROP FUNCTION audit.guard_audit_append()'))
    connection.execute(sa.text('DROP INDEX audit.ix_audit_logs_append_sequence'))
    connection.execute(sa.text('ALTER TABLE audit.audit_logs DROP CONSTRAINT '
                               'ck_audit_logs_audit_append_sequence_positive'))
    connection.execute(sa.text('ALTER TABLE audit.audit_logs DROP COLUMN append_sequence'))
    connection.execute(sa.text('DROP SEQUENCE audit.audit_append_sequence'))
