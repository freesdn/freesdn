# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Store the Settings read-only switch in Postgres; seed it from Valkey.

The read-only switch set from Settings lived only in the Valkey key
``freesdn:config:adapter_read_only``. Losing that key (a flush, a lost volume,
a Valkey error) turned the operator's choice back into the environment default,
which the shipped compose file sets to read-write. This adds
``core.platform_settings`` (one row per installation-wide setting) and, when
Valkey holds a value for the switch, copies it into the row, so an upgrade keeps
what the operator chose.

Valkey is asked with short timeouts. If it cannot be read during an upgrade,
the migration still succeeds and saves read-only, because the operator's choice
is unknown and losing a saved read-only later would turn every device
read-write. The operator can switch it off in Settings (unless the environment
enforces read-only). A fresh install has no earlier choice to keep, so it adds
no row. If Valkey answers that nothing was saved, no row is added either.

Revision ID: 033_platform_settings
Revises: 032_phone_mac_canonical
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "033_platform_settings"
down_revision: str | Sequence[str] | None = "032_phone_mac_canonical"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

logger = logging.getLogger("alembic.runtime.migration")

_LEGACY_KEY = "freesdn:config:adapter_read_only"
_SETTING_KEY = "adapter_read_only"


_UNREADABLE = "unreadable"


def _legacy_switch() -> bool | str | None:
    """The switch as Valkey holds it: True/False, None when unset, or ``_UNREADABLE``."""
    try:
        from app.core.redis_client import get_sync_redis

        client = get_sync_redis(decode_responses=True, socket_timeout=2, socket_connect_timeout=2)
        value = client.get(_LEGACY_KEY)
    except Exception as exc:  # noqa: BLE001 - an outage must not block the upgrade
        logger.warning(
            "033: could not read the read-only switch from Valkey (%s)",
            type(exc).__name__,
        )
        return _UNREADABLE
    if value is None:
        logger.info("033: no read-only switch saved in Valkey; nothing to copy")
        return None
    return str(value).strip().lower() == "true"


def upgrade() -> None:
    # 001_initial builds a fresh database from the live models, so on that path
    # the table already exists; create it only where it is missing.
    tables = set(sa.inspect(op.get_bind()).get_table_names(schema="core"))
    if "platform_settings" in tables:
        _seed(fresh_install=True)
        return
    op.create_table(
        "platform_settings",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("value", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("version", sa.BigInteger(), server_default="1", nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.PrimaryKeyConstraint("key", name="pk_platform_settings"),
        schema="core",
    )
    _seed(fresh_install=False)


def _seed(*, fresh_install: bool) -> None:
    legacy = _legacy_switch()
    if legacy == _UNREADABLE:
        if fresh_install:
            return
        logger.warning(
            "033: the saved read-only switch is unknown, so read-only is saved; "
            "switch it off in Settings if this installation should write to devices"
        )
        legacy = True
    if legacy is None:
        return
    op.get_bind().execute(
        sa.text(
            "INSERT INTO core.platform_settings (key, value, version) "
            "VALUES (:key, CAST(:value AS JSONB), 1) ON CONFLICT (key) DO NOTHING"
        ),
        {"key": _SETTING_KEY, "value": '{"read_only": true}' if legacy else '{"read_only": false}'},
    )
    logger.info("033: stored the read-only switch (read_only=%s)", legacy)


def downgrade() -> None:
    op.drop_table("platform_settings", schema="core")
