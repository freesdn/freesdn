# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Internal native guard attestation within an already owned short transaction.

Frozen 025/027 expected definitions, not a migration runner. Creates only an
owned temporary comparison table and drops it; no durable schema repair, commit,
file access, authorization or artifact reference grant. Call again after I/O.
"""

from collections.abc import Sequence
from typing import Any, Literal, TypedDict
from uuid import uuid4

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

type CatalogueRows = Sequence[sa.Row[*tuple[Any, ...]]]
type CatalogueShape = tuple[CatalogueRows, CatalogueRows, CatalogueRows, sa.Row[*tuple[Any, ...]]]


class TemporaryTableOptions(TypedDict, total=False):
    prefixes: list[str]
    postgresql_on_commit: Literal["DROP"]


def validate_release_reference_installation(connection: sa.Connection) -> None:
    if connection.dialect.name != "postgresql" or not connection.in_transaction():
        raise RuntimeError("Release reference inspection requires owned PostgreSQL transaction")
    configuration = connection.execute(
        sa.text(
            "SELECT current_setting('transaction_isolation'),current_setting('session_replication_role')"
        )
    ).one()
    if tuple(configuration) != ("read committed", "origin"):
        raise RuntimeError("Release reference inspection requires current origin-trigger state")
    # Qualified catalog lookup avoids a caller-specific search path. This is
    # local to the existing transaction and is not a connection-wide setting.
    connection.execute(sa.text("SET LOCAL search_path = pg_catalog, pg_temp"))
    protected: Sequence[str] = (
        connection.execute(
            sa.text("""
        SELECT relation::regclass::text FROM pg_catalog.pg_locks
        WHERE pid=pg_backend_pid() AND granted AND locktype='relation'
          AND mode IN ('ShareLock','ShareRowExclusiveLock','ExclusiveLock','AccessExclusiveLock')
          AND relation IN ('agents.agent_releases'::regclass,'agents.agent_release_operations'::regclass)
    """)
        )
        .scalars()
        .all()
    )
    if set(protected) != {"agents.agent_releases", "agents.agent_release_operations"}:
        raise RuntimeError("Release reference inspection requires both retained table fences")
    tables = connection.execute(
        sa.text("""
        SELECT c.relname,c.relkind::text,c.relpersistence::text,c.relrowsecurity,c.relforcerowsecurity
        FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='agents' AND c.relname IN ('agent_release_operations','agent_releases')
        ORDER BY c.relname
    """)
    ).all()
    if [tuple(r) for r in tables] != [
        ("agent_release_operations", "r", "p", False, False),
        ("agent_releases", "r", "p", False, False),
    ]:
        raise RuntimeError("Managed reference tables differ from the installed protocol")
    _verify_journal(connection)
    _verify(connection)


_FUNCTIONS = ("lock_release_references", "assert_release_reference", "check_release_references")

_TRIGGERS = (
    "release_reference_writer_fence",
    "operation_reference_writer_fence",
    "release_reference_deferred",
    "operation_reference_deferred",
)


def _function_rows(connection: sa.Connection) -> CatalogueRows:
    return connection.execute(
        sa.text("""
        SELECT p.proname,p.prosrc,p.proconfig,p.prosecdef,p.proleakproof,p.proisstrict,
               p.provolatile::text,p.proparallel::text,p.prokind::text,p.pronargs,
               pg_catalog.pg_get_function_identity_arguments(p.oid),p.prorettype::regtype::text,l.lanname
        FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
        JOIN pg_catalog.pg_language l ON l.oid=p.prolang
        WHERE n.nspname='agents' AND p.proname = ANY(:names) ORDER BY p.proname,p.oid
    """),
        {"names": list(_FUNCTIONS)},
    ).all()


def _trigger_rows(connection: sa.Connection) -> CatalogueRows:
    return connection.execute(
        sa.text("""
        SELECT nc.nspname,c.relname,t.tgname,t.tgtype,t.tgenabled::text,t.tgdeferrable,t.tginitdeferred,
               t.tgnargs,t.tgattr::text,pg_catalog.pg_get_expr(t.tgqual,t.tgrelid),
               nf.nspname,p.proname,t.tgconstrrelid
        FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid
        JOIN pg_catalog.pg_namespace nc ON nc.oid=c.relnamespace
        JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
        JOIN pg_catalog.pg_namespace nf ON nf.oid=p.pronamespace
        WHERE NOT t.tgisinternal AND (t.tgname = ANY(:triggers) OR
              (nf.nspname='agents' AND p.proname = ANY(:functions)))
        ORDER BY nc.nspname,c.relname,t.tgname
    """),
        {"triggers": list(_TRIGGERS), "functions": list(_FUNCTIONS)},
    ).all()


def _verify(connection: sa.Connection) -> None:
    expected_functions = []
    for index, name in enumerate(_FUNCTIONS):
        delimiter = ("$reference_lock$", "$reference_assert$", "$reference_check$")[index]
        expected_functions.append(
            (
                name,
                _DDL[index].split(delimiter)[1],
                ["search_path=pg_catalog, pg_temp"],
                False,
                False,
                False,
                "v",
                "u",
                "f",
                1 if index == 1 else 0,
                "identity uuid" if index == 1 else "",
                "void" if index == 1 else "trigger",
                "plpgsql",
            )
        )
    if [tuple(r) for r in _function_rows(connection)] != sorted(expected_functions):
        raise RuntimeError("Release reference functions differ from frozen definitions")
    expected_triggers = []
    for table, prefix in (("agent_release_operations", "operation"), ("agent_releases", "release")):
        expected_triggers += [
            (
                "agents",
                table,
                prefix + "_reference_deferred",
                29,
                "O",
                True,
                True,
                0,
                "",
                None,
                "agents",
                "check_release_references",
                0,
            ),
            (
                "agents",
                table,
                prefix + "_reference_writer_fence",
                62,
                "O",
                False,
                False,
                0,
                "",
                None,
                "agents",
                "lock_release_references",
                0,
            ),
        ]
    if [tuple(r) for r in _trigger_rows(connection)] != expected_triggers:
        raise RuntimeError("Release reference triggers differ from frozen definitions")


_DDL = (
    "CREATE FUNCTION agents.lock_release_references() RETURNS trigger\nLANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $reference_lock$\nBEGIN\n    IF current_setting('transaction_isolation') <> 'read committed' THEN\n        RAISE EXCEPTION 'Managed release writers require READ COMMITTED' USING ERRCODE = '23514';\n    END IF;\n    -- Direct SQL may already own a release RowExclusive lock. NOWAIT on both\n    -- tables prevents a waiting upgrade/reversed-order cycle with coordinators.\n    LOCK TABLE agents.agent_release_operations IN SHARE ROW EXCLUSIVE MODE NOWAIT;\n    LOCK TABLE agents.agent_releases IN SHARE ROW EXCLUSIVE MODE NOWAIT;\n    IF TG_OP = 'TRUNCATE' AND EXISTS (\n        SELECT 1 FROM agents.agent_release_operations\n        WHERE kind = 'publish' AND storage_kind = 'owned'\n    ) THEN\n        RAISE EXCEPTION 'Managed release history forbids truncation' USING ERRCODE = '23514';\n    END IF;\n    RETURN NULL;\nEND\n$reference_lock$",
    "CREATE FUNCTION agents.assert_release_reference(identity uuid) RETURNS void\nLANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $reference_assert$\nDECLARE\n    publication agents.agent_release_operations%ROWTYPE;\n    live agents.agent_releases%ROWTYPE;\n    owned_found boolean;\n    live_found boolean;\n    deleted boolean;\nBEGIN\n    SELECT * INTO publication FROM agents.agent_release_operations\n    WHERE release_id = identity AND kind = 'publish' AND storage_kind = 'owned';\n    owned_found := FOUND;\n    -- Every owned deletion, including pending/cancelled ones, retains its exact\n    -- original publication. Unknown history is not an artifact identity.\n    IF EXISTS (\n        SELECT 1 FROM agents.agent_release_operations d\n        WHERE d.release_id = identity AND d.kind = 'delete' AND d.storage_kind = 'owned'\n          AND (NOT owned_found OR publication.phase IS DISTINCT FROM 'decided'\n               OR publication.decision IS DISTINCT FROM 'published'\n               OR d.operation_id = publication.operation_id\n               OR ROW(d.organization_id, d.artifact_id, d.expected_sha256, d.expected_size)\n                  IS DISTINCT FROM ROW(publication.organization_id, publication.artifact_id,\n                                       publication.expected_sha256, publication.expected_size))\n    ) THEN\n        RAISE EXCEPTION 'Managed deletion has no exact publication' USING ERRCODE = '23514';\n    END IF;\n    IF NOT owned_found THEN\n        RETURN;\n    END IF;\n    IF EXISTS (\n        SELECT 1 FROM agents.agent_release_operations d\n        WHERE d.release_id = identity AND d.kind = 'delete'\n          AND (d.storage_kind IS DISTINCT FROM 'owned'\n               OR ROW(d.organization_id, d.artifact_id, d.expected_sha256, d.expected_size)\n                  IS DISTINCT FROM ROW(publication.organization_id, publication.artifact_id,\n                                       publication.expected_sha256, publication.expected_size))\n    ) THEN\n        RAISE EXCEPTION 'Managed history has a conflicting deletion' USING ERRCODE = '23514';\n    END IF;\n    SELECT * INTO live FROM agents.agent_releases WHERE id = identity;\n    live_found := FOUND;\n    SELECT EXISTS (\n        SELECT 1 FROM agents.agent_release_operations\n        WHERE release_id = identity AND kind = 'delete' AND decision = 'deleted'\n          AND phase IN ('decided', 'cleaned')\n    ) INTO deleted;\n    IF live_found THEN\n        IF publication.phase IS DISTINCT FROM 'decided'\n           OR publication.decision IS DISTINCT FROM 'published' OR deleted\n           OR live.organization_id IS DISTINCT FROM publication.organization_id\n           OR live.checksum_sha256 IS DISTINCT FROM publication.expected_sha256\n           OR live.file_size IS DISTINCT FROM publication.expected_size\n           OR live.download_url IS DISTINCT FROM '/api/v1/agents/releases/' || identity::text || '/binary'\n           OR live.filename IS NULL OR live.filename = '' THEN\n            RAISE EXCEPTION 'Managed release reference is not live and exact' USING ERRCODE = '23514';\n        END IF;\n    ELSIF publication.phase = 'decided' AND publication.decision = 'published' AND NOT deleted THEN\n        RAISE EXCEPTION 'Managed release removal requires its deletion decision' USING ERRCODE = '23514';\n    END IF;\nEND\n$reference_assert$",
    "CREATE FUNCTION agents.check_release_references() RETURNS trigger\nLANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $reference_check$\nBEGIN\n    -- Deferred row events inspect FINAL transaction state, not an intermediate\n    -- INSERT before its journal publication or DELETE before its decision.\n    IF TG_TABLE_NAME = 'agent_releases' THEN\n        IF TG_OP <> 'INSERT' THEN\n            PERFORM agents.assert_release_reference(OLD.id);\n        END IF;\n        IF TG_OP <> 'DELETE' THEN\n            PERFORM agents.assert_release_reference(NEW.id);\n        END IF;\n    ELSE\n        IF TG_OP <> 'INSERT' THEN\n            PERFORM agents.assert_release_reference(OLD.release_id);\n        END IF;\n        IF TG_OP <> 'DELETE' THEN\n            PERFORM agents.assert_release_reference(NEW.release_id);\n        END IF;\n    END IF;\n    RETURN NULL;\nEND\n$reference_check$",
    "CREATE TRIGGER release_reference_writer_fence BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE\nON agents.agent_releases FOR EACH STATEMENT EXECUTE FUNCTION agents.lock_release_references()",
    "CREATE TRIGGER operation_reference_writer_fence BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE\nON agents.agent_release_operations FOR EACH STATEMENT EXECUTE FUNCTION agents.lock_release_references()",
    "CREATE CONSTRAINT TRIGGER release_reference_deferred AFTER INSERT OR UPDATE OR DELETE\nON agents.agent_releases DEFERRABLE INITIALLY DEFERRED\nFOR EACH ROW EXECUTE FUNCTION agents.check_release_references()",
    "CREATE CONSTRAINT TRIGGER operation_reference_deferred AFTER INSERT OR UPDATE OR DELETE\nON agents.agent_release_operations DEFERRABLE INITIALLY DEFERRED\nFOR EACH ROW EXECUTE FUNCTION agents.check_release_references()",
)


def _table(schema: str | None, name: str, *, temporary: bool = False) -> sa.Table:
    metadata = sa.MetaData()
    options: TemporaryTableOptions = (
        {"prefixes": ["TEMPORARY"], "postgresql_on_commit": "DROP"} if temporary else {}
    )
    table = sa.Table(
        name,
        metadata,
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
        *(
            sa.CheckConstraint(sql, name="ck_agent_release_operations_" + key)
            for key, sql in _JOURNAL_CHECKS
        ),
        schema=schema,
        **options,
    )
    sa.Index(
        "uq_release_operation_unresolved",
        table.c.release_id,
        unique=True,
        postgresql_where=sa.text("phase IN ('reserved', 'prepared')"),
    )
    sa.Index(
        "uq_release_operation_publish_identity",
        table.c.release_id,
        unique=True,
        postgresql_where=sa.text("kind = 'publish'"),
    )
    sa.Index(
        "uq_release_operation_owned_object",
        table.c.artifact_id,
        unique=True,
        postgresql_where=sa.text("kind = 'publish' AND storage_kind = 'owned'"),
    )
    sa.Index(
        "ix_release_operation_scope_phase",
        table.c.organization_id,
        table.c.phase,
        table.c.created_at,
    )
    return table


def _shape(
    connection: sa.Connection,
    schema: str,
    names: tuple[str, ...],
    expected_foreign: list[tuple[str, str]],
) -> list[CatalogueShape]:
    """Compare PostgreSQL-parsed semantics; never erase parentheses or casts."""
    result: list[CatalogueShape] = []
    for name in names:
        target = {
            "relation": connection.dialect.identifier_preparer.quote_schema(schema)
            + "."
            + connection.dialect.identifier_preparer.quote(name)
        }
        columns = connection.execute(
            sa.text("""
            SELECT attname, format_type(atttypid, atttypmod), attnotnull,
                   attidentity, attgenerated, attcollation,
                   pg_get_expr(d.adbin, d.adrelid) AS default_expression
            FROM pg_attribute a LEFT JOIN pg_attrdef d
              ON d.adrelid=a.attrelid AND d.adnum=a.attnum
            WHERE a.attrelid=to_regclass(:relation) AND a.attnum>0 AND NOT a.attisdropped
            ORDER BY a.attnum
        """),
            target,
        ).all()
        # PostgreSQL18 names NOT NULL constraints after each relation. Compare
        # their full column/enforcement contract and multiplicity, not that name.
        # Only the named lifecycle constraint trigger is compared separately
        # by the mandatory exact trigger/function validator below.
        constraints = connection.execute(
            sa.text("""
            SELECT CASE WHEN contype='n' THEN '<not-null>' ELSE conname::text END AS constraint_name,
                   contype, conkey::text, ARRAY(SELECT a.attname FROM unnest(c.confkey) WITH ORDINALITY AS k(attnum, ord) JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.attnum ORDER BY k.ord),
                   pg_get_expr(conbin, conrelid), convalidated, condeferrable, condeferred,
                   confupdtype, confdeltype, confmatchtype,
                   COALESCE((to_jsonb(c)->>'conenforced')::boolean, true) AS enforced
            FROM pg_constraint c WHERE conrelid=to_regclass(:relation)
              AND NOT (contype='t' AND conname='operation_reference_deferred')
            ORDER BY constraint_name, contype, conkey::text
        """),
            target,
        ).all()
        # FK target identity is checked separately: temp and durable relations
        # deliberately have different names, but every action/key must match.
        foreign = connection.execute(
            sa.text("""
            SELECT ns.nspname, cl.relname FROM pg_constraint c
            JOIN pg_class cl ON cl.oid=c.confrelid
            JOIN pg_namespace ns ON ns.oid=cl.relnamespace
            WHERE c.conrelid=to_regclass(:relation) AND c.contype='f' ORDER BY c.conname
        """),
            target,
        ).all()
        if [tuple(row) for row in foreign] != expected_foreign:
            raise RuntimeError("Release operation schema refused: unexpected foreign reference")
        indexes = connection.execute(
            sa.text("""
            SELECT idx.relname, am.amname, i.indisunique, i.indisvalid, i.indisready,
                   i.indimmediate, i.indnatts, i.indnkeyatts, i.indkey::text,
                   i.indclass::text, i.indcollation::text, i.indoption::text,
                   i.indnullsnotdistinct, pg_get_expr(i.indpred,i.indrelid),
                   pg_get_expr(i.indexprs,i.indrelid)
            FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid
            JOIN pg_am am ON am.oid=idx.relam
            WHERE i.indrelid=to_regclass(:relation) ORDER BY idx.relname
        """),
            target,
        ).all()
        table_policy = connection.execute(
            sa.text("""
            SELECT relkind, relrowsecurity, relforcerowsecurity, reloptions,
                   EXISTS(SELECT 1 FROM pg_inherits WHERE inhrelid=c.oid OR inhparent=c.oid),
                   EXISTS(SELECT 1 FROM pg_rewrite WHERE ev_class=c.oid)
            FROM pg_class c WHERE oid=to_regclass(:relation)
        """),
            target,
        ).one()
        result.append((columns, constraints, indexes, table_policy))
    return result


def _verify_journal(connection: sa.Connection) -> None:
    name = "release_operation_expected_" + uuid4().hex
    temporary = _table("pg_temp", name, temporary=True)
    temporary.create(connection)
    persistence: str = connection.execute(
        sa.text(
            "SELECT relpersistence::text FROM pg_class WHERE oid='agents.agent_release_operations'::regclass"
        )
    ).scalar_one()
    if persistence != "p":
        raise RuntimeError("Release operation history must be a logged permanent table")
    if _shape(connection, "agents", ("agent_release_operations",), []) != _shape(
        connection, "pg_temp", (name,), []
    ):
        raise RuntimeError(
            "Release operation schema differs from frozen definition; preserve for recovery"
        )
    functions = connection.execute(
        sa.text("""
        SELECT p.prosrc,p.proconfig,p.prosecdef,p.proleakproof,p.proisstrict,
               p.provolatile::text,p.proparallel::text,p.prokind::text,p.pronargs,p.prorettype::regtype::text,l.lanname
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang
        WHERE n.nspname='agents' AND p.proname='guard_release_operation'
    """)
    ).all()
    expected = [
        (
            _JOURNAL_DDL[0].split("$release_operation$")[1],
            ["search_path=pg_catalog, pg_temp"],
            False,
            False,
            False,
            "v",
            "u",
            "f",
            0,
            "trigger",
            "plpgsql",
        )
    ]
    if [tuple(row) for row in functions] != expected:
        raise RuntimeError("Release operation guard differs from frozen definition")
    triggers = connection.execute(
        sa.text("""
        SELECT t.tgname,t.tgtype,t.tgenabled::text,t.tgdeferrable,t.tginitdeferred,t.tgnargs,
               t.tgattr::text,pg_get_expr(t.tgqual,t.tgrelid),n.nspname,p.proname,t.tgconstrrelid
        FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE t.tgrelid='agents.agent_release_operations'::regclass AND NOT t.tgisinternal
          AND t.tgname NOT IN ('operation_reference_writer_fence','operation_reference_deferred') ORDER BY t.tgname
    """)
    ).all()
    expected_triggers = [
        (
            "guard_release_operation",
            31,
            "O",
            False,
            False,
            0,
            "",
            None,
            "agents",
            "guard_release_operation",
            0,
        ),
        (
            "guard_release_operation_no_truncate",
            34,
            "O",
            False,
            False,
            0,
            "",
            None,
            "agents",
            "guard_release_operation",
            0,
        ),
    ]
    if [tuple(row) for row in triggers] != expected_triggers:
        raise RuntimeError("Release operation trigger differs from frozen definition")
    temporary.drop(connection)


_JOURNAL_CHECKS = (
    ("format", "format_version = 1"),
    ("kind", "kind IN ('publish', 'delete')"),
    (
        "storage",
        "storage_kind IN ('owned', 'external', 'legacy') AND ((storage_kind = 'owned' AND artifact_id IS NOT NULL) OR (storage_kind IN ('external', 'legacy') AND artifact_id IS NULL)) AND (kind = 'delete' OR storage_kind <> 'legacy') AND (kind <> 'publish' OR storage_kind <> 'owned' OR artifact_id = operation_id)",
    ),
    (
        "request_binding",
        "octet_length(request_bytes) BETWEEN 1 AND 65536 AND request_sha256 = encode(sha256(request_bytes), 'hex')",
    ),
    (
        "artifact_binding",
        "expected_sha256 ~ '^[0-9a-f]{64}$' AND expected_size BETWEEN 0 AND 10737418240 AND (storage_kind <> 'owned' OR expected_size <= 524288000)",
    ),
    ("sequence", "transition_sequence BETWEEN 0 AND 3"),
    ("phase", "phase IN ('reserved', 'prepared', 'decided', 'cleaned')"),
    (
        "decision_kind",
        "decision IS NULL OR decision = 'cancelled' OR (kind = 'publish' AND decision = 'published') OR (kind = 'delete' AND decision = 'deleted')",
    ),
    (
        "phase_fields",
        "(phase = 'reserved' AND transition_sequence = 0 AND prepared_at IS NULL AND decision IS NULL AND decided_at IS NULL AND cleaned_at IS NULL) OR (phase = 'prepared' AND transition_sequence = 1 AND prepared_at IS NOT NULL AND decision IS NULL AND decided_at IS NULL AND cleaned_at IS NULL) OR (phase = 'decided' AND decision IS NOT NULL AND decided_at IS NOT NULL AND cleaned_at IS NULL AND ((prepared_at IS NOT NULL AND transition_sequence = 2) OR (prepared_at IS NULL AND transition_sequence = 1 AND decision = 'cancelled'))) OR (phase = 'cleaned' AND decision IS NOT NULL AND decision IN ('deleted', 'cancelled') AND decided_at IS NOT NULL AND cleaned_at IS NOT NULL AND ((prepared_at IS NOT NULL AND transition_sequence = 3) OR (prepared_at IS NULL AND transition_sequence = 2 AND decision = 'cancelled')))",
    ),
    (
        "time_order",
        "(prepared_at IS NULL OR prepared_at >= created_at) AND (decided_at IS NULL OR decided_at >= created_at) AND (prepared_at IS NULL OR decided_at IS NULL OR decided_at >= prepared_at) AND (cleaned_at IS NULL OR cleaned_at >= decided_at)",
    ),
)

_JOURNAL_DDL = (
    "CREATE FUNCTION agents.guard_release_operation() RETURNS trigger\nLANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $release_operation$\nBEGIN\n    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN\n        RAISE EXCEPTION 'Release operation history must be retained' USING ERRCODE = '23514';\n    END IF;\n    IF TG_OP = 'INSERT' THEN\n        IF NEW.phase IS DISTINCT FROM 'reserved' OR NEW.transition_sequence IS DISTINCT FROM 0\n           OR NEW.last_transition_by IS DISTINCT FROM NEW.requested_by THEN\n            RAISE EXCEPTION 'Release operation must begin reserved' USING ERRCODE = '23514';\n        END IF;\n        RETURN NEW;\n    END IF;\n    IF NEW IS NOT DISTINCT FROM OLD THEN\n        RETURN NEW;\n    END IF;\n    IF ROW(NEW.operation_id, NEW.format_version, NEW.kind, NEW.release_id,\n           NEW.organization_id, NEW.requested_by, NEW.storage_kind, NEW.artifact_id,\n           NEW.request_bytes, NEW.request_sha256, NEW.expected_sha256, NEW.expected_size,\n           NEW.created_at)\n       IS DISTINCT FROM\n       ROW(OLD.operation_id, OLD.format_version, OLD.kind, OLD.release_id,\n           OLD.organization_id, OLD.requested_by, OLD.storage_kind, OLD.artifact_id,\n           OLD.request_bytes, OLD.request_sha256, OLD.expected_sha256, OLD.expected_size,\n           OLD.created_at) THEN\n        RAISE EXCEPTION 'Release operation intent is immutable' USING ERRCODE = '23514';\n    END IF;\n    IF NEW.transition_sequence IS DISTINCT FROM OLD.transition_sequence + 1\n       OR (OLD.prepared_at IS NOT NULL AND NEW.prepared_at IS DISTINCT FROM OLD.prepared_at)\n       OR (OLD.decided_at IS NOT NULL AND NEW.decided_at IS DISTINCT FROM OLD.decided_at)\n       OR (OLD.decision IS NOT NULL AND NEW.decision IS DISTINCT FROM OLD.decision)\n       OR (OLD.cleaned_at IS NOT NULL AND NEW.cleaned_at IS DISTINCT FROM OLD.cleaned_at) THEN\n        RAISE EXCEPTION 'Release operation cannot rewind or rewrite a decision' USING ERRCODE = '23514';\n    END IF;\n    IF NOT (\n        (OLD.phase = 'reserved' AND NEW.phase = 'prepared') OR\n        (OLD.phase IN ('reserved', 'prepared') AND NEW.phase = 'decided'\n         AND NEW.decision = 'cancelled') OR\n        (OLD.phase = 'prepared' AND NEW.phase = 'decided'\n         AND ((OLD.kind = 'publish' AND NEW.decision = 'published') OR\n              (OLD.kind = 'delete' AND NEW.decision = 'deleted'))) OR\n        (OLD.phase = 'decided' AND OLD.decision IN ('deleted', 'cancelled')\n         AND NEW.phase = 'cleaned')\n    ) THEN\n        RAISE EXCEPTION 'Release operation transition refused' USING ERRCODE = '23514';\n    END IF;\n    RETURN NEW;\nEND\n$release_operation$",
    "CREATE TRIGGER guard_release_operation BEFORE INSERT OR UPDATE OR DELETE\nON agents.agent_release_operations FOR EACH ROW EXECUTE FUNCTION agents.guard_release_operation()",
    "CREATE TRIGGER guard_release_operation_no_truncate BEFORE TRUNCATE\nON agents.agent_release_operations FOR EACH STATEMENT EXECUTE FUNCTION agents.guard_release_operation()",
)
