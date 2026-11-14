# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Store every phone MAC canonically; flag phones that turn out to share one.

Provisioning finds a phone, and names its config file, by the canonical MAC
(``aa:bb:cc:dd:ee:ff``), but the phone API stored the MAC as typed and
``ix_phones_mac_address`` was a full unique index on that raw string. So
``00:0B:82:12:34:56`` and ``000b82123456`` could both exist, in different
sites, sharing one ``cfg000b82123456.xml``. Since 26.12 the API stores the
canonical form; this rewrites the rows written before it.

What it does, under an exclusive lock on voip.phones:

* adds ``mac_review`` (NULL, or ``"duplicate"``);
* rewrites every parseable MAC to the canonical form, soft-deleted rows too
  (a MAC that does not parse is left exactly as stored and counted);
* when two or more LIVE phones end up with the same MAC, keeps all of them and
  flags each ``mac_review = 'duplicate'``. Nothing is merged or deleted:
  which phone is the real one is the operator's call. The API shows the flag,
  and provisioning refuses a phone while a live twin exists, naming it;
* replaces the full unique index with ``UNIQUE (mac_address) WHERE deleted_at
  IS NULL AND mac_review IS NULL``. Every unflagged live phone is unique, a
  soft-deleted phone no longer holds its MAC, and a flagged pair can coexist
  until one is deleted. A FULL unique index cannot be built while a flagged
  pair exists, which is why the predicate carries ``mac_review``.

Idempotent: on an already-canonical database it changes nothing and logs zero
counts. It logs how many rows it changed, flagged and could not parse.

Revision ID: 032_phone_mac_canonical
Revises: 031_device_config_backups
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op
from app.modules.voip.provisioning_auth import normalize_mac

revision: str = "032_phone_mac_canonical"
down_revision: str | Sequence[str] | None = "031_device_config_backups"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

logger = logging.getLogger("alembic.runtime.migration")

_INDEX = "ix_phones_mac_address"
_PREDICATE = "deleted_at IS NULL AND mac_review IS NULL"
_DUPLICATE = "duplicate"

_INDEX_STATE = sa.text(
    """
    SELECT i.indisunique, pg_get_expr(i.indpred, i.indrelid) AS predicate
    FROM pg_index i
    JOIN pg_class ic ON ic.oid = i.indexrelid
    JOIN pg_namespace n ON n.oid = ic.relnamespace
    WHERE n.nspname = 'voip' AND ic.relname = :index
    """
)


def _has_phones(bind: sa.engine.Connection) -> bool:
    return sa.inspect(bind).has_table("phones", schema="voip")


def upgrade() -> None:
    bind = op.get_bind()
    if not _has_phones(bind):
        return
    op.execute("LOCK TABLE voip.phones IN ACCESS EXCLUSIVE MODE")
    op.execute("ALTER TABLE voip.phones ADD COLUMN IF NOT EXISTS mac_review VARCHAR(32)")

    # The raw-string unique index would refuse the rewrite of one spelling
    # onto another; it is rebuilt with the predicate below.
    state = bind.execute(_INDEX_STATE, {"index": _INDEX}).fetchone()
    if state is not None:
        op.execute(f'DROP INDEX voip."{_INDEX}"')

    rows = bind.execute(
        sa.text(
            "SELECT id, mac_address, deleted_at IS NULL AS live, mac_review "
            "FROM voip.phones WHERE mac_address IS NOT NULL"
        )
    ).fetchall()

    changed = unparseable = 0
    live_by_mac: dict[str, list] = defaultdict(list)
    for row in rows:
        canonical = normalize_mac(row.mac_address)
        if canonical is None:
            unparseable += 1
            continue
        if canonical != row.mac_address:
            bind.execute(
                sa.text("UPDATE voip.phones SET mac_address = :mac WHERE id = :id"),
                {"mac": canonical, "id": row.id},
            )
            changed += 1
        if row.live:
            live_by_mac[canonical].append(row)

    flagged = 0
    for group in live_by_mac.values():
        if len(group) < 2:
            continue
        for row in group:
            if row.mac_review != _DUPLICATE:
                bind.execute(
                    sa.text("UPDATE voip.phones SET mac_review = :flag WHERE id = :id"),
                    {"flag": _DUPLICATE, "id": row.id},
                )
            flagged += 1

    op.execute(f'CREATE UNIQUE INDEX "{_INDEX}" ON voip.phones (mac_address) WHERE {_PREDICATE}')

    logger.info(
        "032_phone_mac_canonical: %d phone MAC(s) rewritten to canonical form, "
        "%d phone(s) flagged as sharing a MAC (mac_review='duplicate'), "
        "%d MAC(s) left as stored because they do not parse",
        changed,
        flagged,
        unparseable,
    )


def downgrade() -> None:
    """Drop the flag and restore the full unique index.

    MACs stay canonical (the older code reads them unchanged). Refused while two
    rows share a MAC, live or soft-deleted, because the full index the older
    schema had cannot hold them; delete or re-address one of each pair first.
    """
    bind = op.get_bind()
    if not _has_phones(bind):
        return
    op.execute("LOCK TABLE voip.phones IN ACCESS EXCLUSIVE MODE")
    shared = bind.execute(
        sa.text(
            "SELECT mac_address, count(*) FROM voip.phones WHERE mac_address IS NOT NULL "
            "GROUP BY mac_address HAVING count(*) > 1 ORDER BY mac_address"
        )
    ).fetchall()
    if shared:
        raise RuntimeError(
            "Phone MAC downgrade refused: these MACs are held by more than one phone "
            "row and the older full unique index cannot hold them: "
            + ", ".join(f"{mac} ({count} rows)" for mac, count in shared)
        )
    state = bind.execute(_INDEX_STATE, {"index": _INDEX}).fetchone()
    if state is not None:
        op.execute(f'DROP INDEX voip."{_INDEX}"')
    op.execute(f'CREATE UNIQUE INDEX "{_INDEX}" ON voip.phones (mac_address)')
    op.execute("ALTER TABLE voip.phones DROP COLUMN IF EXISTS mac_review")
