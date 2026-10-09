# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Read-only, bounded legacy binding audit; never prints claims or credentials."""

import json
import sys
from pathlib import Path

from sqlalchemy import create_engine, text

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.migrate import _get_sync_url  # noqa: E402


def main() -> int:
    engine = None
    try:
        engine = create_engine(_get_sync_url(), hide_parameters=True,
                               connect_args={"connect_timeout": 10})
        with engine.connect() as connection:
            connection.execute(text("SET TRANSACTION READ ONLY"))
            connection.execute(text("SET LOCAL statement_timeout = '10s'"))
            rows = connection.execute(text("""
                SELECT sso_provider_id,
                       (array_agg(id ORDER BY id))[1:20] AS account_ids,
                       count(*) AS account_count, count(*) OVER () AS duplicate_groups
                FROM core.users
                WHERE deleted_at IS NULL AND sso_provider_id IS NOT NULL AND external_id IS NOT NULL
                GROUP BY sso_provider_id, external_id
                HAVING count(*) > 1
                ORDER BY sso_provider_id, min(id::text)
                LIMIT 100
            """)).mappings().all()
            connection.rollback()
        groups = int(rows[0]["duplicate_groups"]) if rows else 0
        print(json.dumps({
            "read_only": True,
            "duplicate_groups": groups,
            "groups_truncated": groups > len(rows),
            "groups": [{
                "provider_id": str(row["sso_provider_id"]),
                "account_ids": [str(value) for value in row["account_ids"]],
                "account_count": int(row["account_count"]),
                "account_ids_truncated": int(row["account_count"]) > len(row["account_ids"]),
            } for row in rows],
            "disclosed_fields": "provider and account IDs only; no subjects, emails, credentials or MFA data",
            "action": "Review ownership before using supported account management. Do not merge or reassign by email.",
        }, indent=2))
        return 1 if rows else 0
    except Exception:
        # Connection exceptions can embed private database URLs and values.
        # No database rows or revision were written by this command.
        print("SSO binding audit failed; verify database access and schema. No data was changed.", file=sys.stderr)
        return 2
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
