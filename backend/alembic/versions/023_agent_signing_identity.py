# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Retain installation signing identity independently of private-key storage.

No key files are inspected or generated, and no installation is auto-adopted.
The frozen schema below is independent of future application model edits.
"""

from uuid import uuid4

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "023_agent_signing_identity"
down_revision = "022_sso_binding_unique"
branch_labels = None
depends_on = None

_INTENTS = "agent_signing_intents"
_IDENTITIES = "agent_signing_identities"


def _tables(schema: str, names: tuple[str, str], *, temporary: bool = False):
    metadata = sa.MetaData()
    options = {"prefixes": ["TEMPORARY"], "postgresql_on_commit": "DROP"} if temporary else {}
    intents = sa.Table(
        names[0], metadata,
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("singleton_id", sa.SmallInteger(), nullable=False),
        sa.Column("installation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("identity_epoch", sa.BigInteger(), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("expected_public_sha256", sa.String(64)),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("requested_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("public_key_pem", sa.LargeBinary()),
        sa.Column("public_key_sha256", sa.String(64)),
        sa.Column("prepared_at", sa.DateTime(timezone=True)),
        sa.Column("closed_at", sa.DateTime(timezone=True)),
        sa.Column("closed_by", postgresql.UUID(as_uuid=True)),
        sa.PrimaryKeyConstraint("operation_id", name="pk_agent_signing_intents"),
        *(sa.CheckConstraint(sql, name="ck_agent_signing_intents_" + name)
          for name, sql in _CHECKS["AgentSigningIntent"]),
        schema=schema, **options,
    )
    sa.Index("ix_signing_one_open_intent", intents.c.singleton_id, unique=True,
             postgresql_where=sa.text("state IN ('pending', 'prepared')"))
    identity = sa.Table(
        names[1], metadata,
        sa.Column("singleton_id", sa.SmallInteger(), nullable=False, autoincrement=False),
        sa.Column("format_version", sa.SmallInteger(), nullable=False),
        sa.Column("purpose", sa.String(32), nullable=False),
        sa.Column("installation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("identity_epoch", sa.BigInteger(), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("public_key_pem", sa.LargeBinary(), nullable=False),
        sa.Column("public_key_sha256", sa.String(64), nullable=False),
        sa.Column("activated_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("singleton_id", name="pk_agent_signing_identities"),
        sa.ForeignKeyConstraint(
            ["operation_id"], [intents.c.operation_id], ondelete="RESTRICT",
            name="fk_agent_signing_identities_operation_id_agent_signing_intents",
        ),
        *(sa.CheckConstraint(sql, name="ck_agent_signing_identities_" + name)
          for name, sql in _CHECKS["AgentSigningIdentity"]),
        schema=schema, **options,
    )
    return intents, identity


def _shape(connection, schema, names):
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
        # Only the named lifecycle constraint trigger is compared separately
        # by the mandatory exact trigger/function validator below.
        constraints = connection.execute(sa.text("""
            SELECT CASE WHEN contype='n' THEN '<not-null>' ELSE conname::text END AS constraint_name,
                   contype, conkey::text, confkey::text,
                   pg_get_expr(conbin, conrelid), convalidated, condeferrable, condeferred,
                   confupdtype, confdeltype, confmatchtype,
                   COALESCE((to_jsonb(c)->>'conenforced')::boolean, true) AS enforced
            FROM pg_constraint c WHERE conrelid=to_regclass(:relation)
              AND NOT (contype='t' AND conname='signing_activation_complete')
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
        expected_foreign = [(connection.scalar(sa.text("SELECT nspname FROM pg_namespace WHERE oid=pg_my_temp_schema()"))
                             if schema == "pg_temp" else schema, names[0])] if name == names[1] else []
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


def _verify_guards(connection):
    functions = connection.execute(sa.text("""
        SELECT p.proname, p.prosrc, p.proconfig, p.prosecdef, p.proleakproof,
               p.proisstrict, p.provolatile::text, p.proparallel::text, p.prokind::text,
               p.pronargs, p.prorettype::regtype::text, l.lanname
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        JOIN pg_language l ON l.oid=p.prolang
        WHERE n.nspname='agents' AND p.proname IN
          ('guard_signing_lifecycle','require_activated_signing_identity')
        ORDER BY p.proname
    """)).all()
    expected = [
        (name, statement.split("$signing$")[1], ["search_path=pg_catalog, pg_temp"],
         False, False, False, "v", "u", "f", 0, "trigger", "plpgsql")
        for name, statement in zip(
            ["guard_signing_lifecycle", "require_activated_signing_identity"], _DDL[:2], strict=True,
        )
    ]
    if [tuple(row) for row in functions] != expected:
        raise RuntimeError("Signing schema refused: unexpected lifecycle function")
    triggers = connection.execute(sa.text("""
        SELECT c.relname, t.tgname, t.tgtype, t.tgenabled::text, t.tgdeferrable, t.tginitdeferred,
               t.tgnargs, t.tgattr::text, pg_get_expr(t.tgqual,t.tgrelid),
               n.nspname, p.proname, t.tgconstrrelid
        FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
        JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE t.tgrelid IN ('agents.agent_signing_intents'::regclass,
                            'agents.agent_signing_identities'::regclass) AND NOT t.tgisinternal
        ORDER BY c.relname,t.tgname
    """)).all()
    expected_triggers = sorted([
        (_INTENTS, "signing_intent_guard", 31, "O", False, False, 0, "", None, "agents", "guard_signing_lifecycle", 0),
        (_INTENTS, "signing_intent_no_truncate", 34, "O", False, False, 0, "", None, "agents", "guard_signing_lifecycle", 0),
        (_IDENTITIES, "signing_identity_guard", 31, "O", False, False, 0, "", None, "agents", "guard_signing_lifecycle", 0),
        (_IDENTITIES, "signing_identity_no_truncate", 34, "O", False, False, 0, "", None, "agents", "guard_signing_lifecycle", 0),
        (_INTENTS, "signing_activation_complete", 21, "O", True, True, 0, "", None, "agents", "require_activated_signing_identity", 0),
    ])
    if [tuple(row) for row in triggers] != expected_triggers:
        raise RuntimeError("Signing schema refused: unexpected lifecycle trigger")


def _verify(connection):
    # Temporary reference tables ask this exact PostgreSQL parser to normalize
    # the frozen constraints. They are empty, private to this session, dropped
    # on commit and explicitly dropped on success. They contain no key/user data.
    suffix = uuid4().hex
    names = ("signing_intents_" + suffix, "signing_identity_" + suffix)
    temporary = _tables("pg_temp", names, temporary=True)
    for table in temporary:
        table.create(connection)
    if _shape(connection, "agents", (_INTENTS, _IDENTITIES)) != _shape(connection, "pg_temp", names):
        raise RuntimeError("Signing schema refused: existing tables have unexpected definitions")
    _verify_guards(connection)
    # On refusal Alembic rolls back the transaction, including these tables.
    # Do not mask an original SQL error by issuing DROP in an aborted transaction.
    for table in reversed(temporary):
        table.drop(connection)


def upgrade() -> None:
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    present = [inspector.has_table(name, schema="agents") for name in (_INTENTS, _IDENTITIES)]
    if any(present) and not all(present):
        raise RuntimeError("Signing upgrade refused: partial schema; preserve it for explicit recovery")
    if not any(present):
        for table in _tables("agents", (_INTENTS, _IDENTITIES)):
            table.create(connection)
        for statement in _DDL:
            op.execute(sa.text(statement))
    op.execute("LOCK TABLE agents.agent_signing_intents, agents.agent_signing_identities IN ACCESS EXCLUSIVE MODE")
    _verify(connection)
    # Deliberately no rows, keys, adoption, provenance inference or auto-activation.


def downgrade() -> None:
    connection = op.get_bind()
    op.execute("LOCK TABLE agents.agent_signing_intents, agents.agent_signing_identities IN ACCESS EXCLUSIVE MODE")
    _verify(connection)
    if connection.scalar(sa.text("""
        SELECT EXISTS(SELECT 1 FROM agents.agent_signing_intents)
            OR EXISTS(SELECT 1 FROM agents.agent_signing_identities)
    """)):
        raise RuntimeError(
            "Signing downgrade refused: retained identity or operation history exists; "
            "preserve its recovery copy and use a reviewed migration plan"
        )
    op.drop_table(_IDENTITIES, schema="agents")
    op.drop_table(_INTENTS, schema="agents")
    op.execute("DROP FUNCTION agents.require_activated_signing_identity()")
    op.execute("DROP FUNCTION agents.guard_signing_lifecycle()")

_DDL = ("\nCREATE FUNCTION agents.guard_signing_lifecycle() RETURNS trigger\nLANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $signing$\nDECLARE intent agents.agent_signing_intents%ROWTYPE;\nBEGIN\n    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN\n        RAISE EXCEPTION 'Signing identity and operation history cannot be deleted'\n            USING ERRCODE = 'check_violation';\n    END IF;\n    IF TG_TABLE_NAME = 'agent_signing_identities' THEN\n        IF TG_OP = 'UPDATE' THEN\n            IF NEW IS DISTINCT FROM OLD THEN\n                RAISE EXCEPTION 'Active signing identity is immutable'\n                    USING ERRCODE = 'check_violation';\n            END IF;\n            RETURN NEW;\n        END IF;\n        SELECT * INTO intent FROM agents.agent_signing_intents\n            WHERE operation_id = NEW.operation_id FOR UPDATE;\n        IF NOT FOUND OR intent.state IS DISTINCT FROM 'activated'\n            OR ROW(NEW.installation_id, NEW.identity_epoch, NEW.public_key_pem,\n                   NEW.public_key_sha256, NEW.activated_by, NEW.activated_at)\n               IS DISTINCT FROM\n               ROW(intent.installation_id, intent.identity_epoch, intent.public_key_pem,\n                   intent.public_key_sha256, intent.closed_by, intent.closed_at) THEN\n            RAISE EXCEPTION 'Signing identity does not match its activated intent'\n                USING ERRCODE = 'check_violation';\n        END IF;\n        RETURN NEW;\n    END IF;\n    IF TG_OP = 'INSERT' THEN\n        IF NEW.state IS DISTINCT FROM 'pending' THEN\n            RAISE EXCEPTION 'Signing intent must begin pending'\n                USING ERRCODE = 'check_violation';\n        END IF;\n        RETURN NEW;\n    END IF;\n    IF NEW IS NOT DISTINCT FROM OLD THEN\n        RETURN NEW;\n    END IF;\n    IF ROW(NEW.operation_id, NEW.singleton_id, NEW.installation_id, NEW.identity_epoch,\n           NEW.kind, NEW.expected_public_sha256, NEW.requested_by, NEW.created_at)\n       IS DISTINCT FROM\n       ROW(OLD.operation_id, OLD.singleton_id, OLD.installation_id, OLD.identity_epoch,\n           OLD.kind, OLD.expected_public_sha256, OLD.requested_by, OLD.created_at)\n       OR OLD.state IN ('activated', 'cancelled')\n       OR NOT ((OLD.state = 'pending' AND NEW.state IN ('prepared', 'cancelled'))\n               OR (OLD.state = 'prepared' AND NEW.state IN ('activated', 'cancelled')))\n       OR (OLD.state = 'prepared' AND\n           ROW(NEW.public_key_pem, NEW.public_key_sha256, NEW.prepared_at)\n           IS DISTINCT FROM ROW(OLD.public_key_pem, OLD.public_key_sha256, OLD.prepared_at))\n       OR (OLD.state = 'pending' AND NEW.state = 'cancelled' AND\n           ROW(NEW.public_key_pem, NEW.public_key_sha256, NEW.prepared_at)\n           IS DISTINCT FROM ROW(OLD.public_key_pem, OLD.public_key_sha256, OLD.prepared_at)) THEN\n        RAISE EXCEPTION 'Signing intent transition would rewrite retained history'\n            USING ERRCODE = 'check_violation';\n    END IF;\n    RETURN NEW;\nEND;\n$signing$\n", "\nCREATE FUNCTION agents.require_activated_signing_identity() RETURNS trigger\nLANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $signing$\nDECLARE\n    intent agents.agent_signing_intents%ROWTYPE;\n    deadline text;\nBEGIN\n    deadline := current_setting('freesdn.signing_deadline', true);\n    IF deadline IS NOT NULL AND deadline <> '' THEN\n        IF deadline !~ '^[0-9]{1,12}$' OR\n           clock_timestamp() >= to_timestamp(deadline::double precision) THEN\n            RAISE EXCEPTION 'Fresh signing confirmation expired before deferred commit validation'\n                USING ERRCODE = 'check_violation';\n        END IF;\n    END IF;\n    SELECT * INTO STRICT intent FROM agents.agent_signing_intents\n        WHERE operation_id = NEW.operation_id;\n    IF intent.state = 'activated' AND NOT EXISTS (\n        SELECT 1 FROM agents.agent_signing_identities i\n        WHERE i.operation_id = intent.operation_id\n          AND ROW(i.installation_id, i.identity_epoch, i.public_key_pem,\n                  i.public_key_sha256, i.activated_by, i.activated_at)\n              IS NOT DISTINCT FROM\n              ROW(intent.installation_id, intent.identity_epoch, intent.public_key_pem,\n                  intent.public_key_sha256, intent.closed_by, intent.closed_at)\n    ) THEN\n        RAISE EXCEPTION 'Activated signing intent requires its matching identity at commit'\n            USING ERRCODE = 'check_violation';\n    END IF;\n    RETURN NULL;\nEND;\n$signing$\n", 'CREATE TRIGGER signing_intent_guard\nBEFORE INSERT OR UPDATE OR DELETE ON agents.agent_signing_intents\nFOR EACH ROW EXECUTE FUNCTION agents.guard_signing_lifecycle()', 'CREATE TRIGGER signing_intent_no_truncate\nBEFORE TRUNCATE ON agents.agent_signing_intents\nFOR EACH STATEMENT EXECUTE FUNCTION agents.guard_signing_lifecycle()', 'CREATE TRIGGER signing_identity_guard\nBEFORE INSERT OR UPDATE OR DELETE ON agents.agent_signing_identities\nFOR EACH ROW EXECUTE FUNCTION agents.guard_signing_lifecycle()', 'CREATE TRIGGER signing_identity_no_truncate\nBEFORE TRUNCATE ON agents.agent_signing_identities\nFOR EACH STATEMENT EXECUTE FUNCTION agents.guard_signing_lifecycle()', 'CREATE CONSTRAINT TRIGGER signing_activation_complete\nAFTER INSERT OR UPDATE ON agents.agent_signing_intents\nDEFERRABLE INITIALLY DEFERRED FOR EACH ROW\nEXECUTE FUNCTION agents.require_activated_signing_identity()')

_CHECKS = {'AgentSigningIntent': [('singleton', 'singleton_id = 1'), ('epoch', 'identity_epoch > 0'), ('kind', "kind IN ('initialize', 'adopt')"), ('expected_identity', "(kind = 'initialize' AND expected_public_sha256 IS NULL) OR (kind = 'adopt' AND expected_public_sha256 IS NOT NULL AND expected_public_sha256 ~ '^[0-9a-f]{64}$')"), ('state', "state IN ('pending', 'prepared', 'activated', 'cancelled')"), ('public_binding', "(public_key_pem IS NULL AND public_key_sha256 IS NULL AND prepared_at IS NULL) OR (public_key_pem IS NOT NULL AND public_key_sha256 IS NOT NULL AND prepared_at IS NOT NULL AND octet_length(public_key_pem) BETWEEN 1 AND 4096 AND public_key_sha256 = encode(sha256(public_key_pem), 'hex') AND (kind = 'initialize' OR public_key_sha256 = expected_public_sha256))"), ('phase_fields', "(state = 'pending' AND prepared_at IS NULL AND closed_at IS NULL AND closed_by IS NULL) OR (state = 'prepared' AND prepared_at IS NOT NULL AND closed_at IS NULL AND closed_by IS NULL) OR (state = 'activated' AND prepared_at IS NOT NULL AND closed_at IS NOT NULL AND closed_by IS NOT NULL) OR (state = 'cancelled' AND closed_at IS NOT NULL AND closed_by IS NOT NULL)"), ('time_order', '(prepared_at IS NULL OR prepared_at >= created_at) AND (closed_at IS NULL OR closed_at >= created_at) AND (prepared_at IS NULL OR closed_at IS NULL OR closed_at >= prepared_at)')], 'AgentSigningIdentity': [('singleton', 'singleton_id = 1'), ('format', 'format_version = 1'), ('purpose', "purpose = 'agent-release'"), ('epoch', 'identity_epoch > 0'), ('public_binding', "octet_length(public_key_pem) BETWEEN 1 AND 4096 AND public_key_sha256 = encode(sha256(public_key_pem), 'hex')")]}
