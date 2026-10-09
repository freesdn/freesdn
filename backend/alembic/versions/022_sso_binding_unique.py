# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Enforce one nondeleted account per external provider and subject.

No account is selected, reassigned, merged or deleted by this migration. Legacy
duplicates stop the upgrade before its revision is recorded. A read-only audit
identifies account IDs for an operator to reconcile through supported account
management; email equality is not evidence that two accounts have one owner.
"""

import sqlalchemy as sa

from alembic import op

revision = "022_sso_binding_unique"
down_revision = "021_credential_snmp_text"
branch_labels = None
depends_on = None

_NAME = "ix_users_external_binding"
_PREDICATE = "deleted_at IS NULL AND sso_provider_id IS NOT NULL AND external_id IS NOT NULL"


def _verified_existing_index() -> bool:
    row = op.get_bind().execute(sa.text("""
        SELECT i.indisunique, i.indisvalid, i.indisready, i.indnatts,
               am.amname, pg_get_expr(i.indpred, i.indrelid) AS predicate,
               i.indexprs IS NULL AS no_expressions,
               ARRAY(SELECT c FROM unnest(i.indcollation) AS c) AS collations,
               ARRAY(SELECT a.attcollation
                     FROM unnest(i.indkey) WITH ORDINALITY AS k(attnum, ordinal)
                     JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum
                     ORDER BY k.ordinal) AS column_collations,
               (SELECT bool_and(c.opcdefault)
                FROM unnest(i.indclass) AS oc(oid)
                JOIN pg_opclass c ON c.oid=oc.oid) AS default_classes,
               ARRAY(SELECT a.attname::text
                     FROM unnest(i.indkey) WITH ORDINALITY AS k(attnum, ordinal)
                     JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum
                     ORDER BY k.ordinal) AS columns
        FROM pg_index i
        JOIN pg_class idx ON idx.oid=i.indexrelid
        JOIN pg_class tbl ON tbl.oid=i.indrelid
        JOIN pg_namespace ns ON ns.oid=tbl.relnamespace
        JOIN pg_am am ON am.oid=idx.relam
        WHERE ns.nspname='core' AND tbl.relname='users' AND idx.relname=:name
    """), {"name": _NAME}).mappings().one_or_none()
    if row is None:
        return False
    def normalize(value: object) -> str:
        return " ".join(str(value).replace("(", " ").replace(")", " ").lower().split())
    if not (
        row["indisunique"] and row["indisvalid"] and row["indisready"]
        and row["indnatts"] == 2 and row["amname"] == "btree"
        and row["no_expressions"] and row["default_classes"]
        and list(row["collations"]) == list(row["column_collations"])
        and list(row["columns"]) == ["sso_provider_id", "external_id"]
        and normalize(row["predicate"]) == normalize(_PREDICATE)
    ):
        raise RuntimeError(
            "SSO binding migration refused: the existing binding index has an unexpected "
            "definition. Preserve the database and inspect its schema; no index was replaced."
        )
    return True


def upgrade() -> None:
    # Serialize the duplicate preflight with every writer, including old
    # application processes which do not know the lifecycle advisory lock.
    # Keep the lock through index creation and Alembic's revision transaction.
    op.execute("LOCK TABLE core.users IN SHARE ROW EXCLUSIVE MODE")
    if _verified_existing_index():
        return  # The fresh model-built schema already carries this invariant.
    duplicate = op.get_bind().execute(sa.text("""
        SELECT EXISTS (
            SELECT 1 FROM core.users
            WHERE deleted_at IS NULL AND sso_provider_id IS NOT NULL AND external_id IS NOT NULL
            GROUP BY sso_provider_id, external_id HAVING count(*) > 1
        )
    """)).scalar_one()
    if duplicate:
        raise RuntimeError(
            "SSO binding upgrade refused: multiple nondeleted accounts share an external "
            "provider and subject. No accounts or bindings were changed. Preserve a recovery "
            "copy and run python -B scripts/audit_sso_bindings.py for a read-only account-ID "
            "report. Reconcile ownership through supported account management before upgrading; "
            "do not guess from email, delete records automatically, or stamp past this revision."
        )
    op.create_index(_NAME, "users", ["sso_provider_id", "external_id"], unique=True,
                    schema="core", postgresql_where=sa.text(_PREDICATE))


def downgrade() -> None:
    op.execute("LOCK TABLE core.users IN SHARE ROW EXCLUSIVE MODE")
    if not _verified_existing_index():
        raise RuntimeError("SSO binding downgrade refused: the required index is missing.")
    bound = op.get_bind().execute(sa.text("""
        SELECT EXISTS (SELECT 1 FROM core.users
                       WHERE deleted_at IS NULL AND sso_provider_id IS NOT NULL AND external_id IS NOT NULL)
    """)).scalar_one()
    if bound:
        raise RuntimeError(
            "SSO binding downgrade refused while nondeleted external accounts remain. "
            "Removing their uniqueness guard would weaken identity ownership. Keep the "
            "current schema or use a reviewed recovery plan; no bindings were changed."
        )
    op.drop_index(_NAME, table_name="users", schema="core")
