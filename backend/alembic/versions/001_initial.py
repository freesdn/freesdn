# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN 26.06.1 - single consolidated baseline migration

Creates every PostgreSQL schema, all tables from SQLAlchemy models,
audit columns (created_by/updated_by), unique MAC constraint, and
performance indexes - all in a single migration.

This is THE baseline. The previously linear chain (002-040) was squashed
into this one migration on 2026-06-14; the squashed files are archived
under ``alembic/_archive/pre_26.06.1/`` for historical reference and are
NOT on the active chain. Every schema change those migrations carried is
already captured by ``Base.metadata.create_all()`` reading the current ORM
models, so there is nothing to replay - this revision builds the full
26.06.1 schema in one step. Future releases add new migrations that chain
after ``001_initial``.

For fresh installs ``scripts/migrate.py`` (run by the Docker entrypoint)
uses ``Base.metadata.create_all()`` + ``alembic stamp head`` - building the
full current schema from the ORM models and stamping straight to head.
**This is the supported fresh-install path.** Existing databases stamped at
a now-archived revision are auto-restamped to this baseline by
``scripts/migrate.py`` on next boot (its pre-consolidation path).

A plain ``alembic upgrade head`` against a truly empty database is also
supported now that this is the only revision: ``upgrade()`` derives the
schema set from the live model metadata (so it includes every schema,
``fabric`` included) before ``create_all()``. It does the same work as the
create_all+stamp path; ``scripts/migrate.py`` is still preferred because it
also handles the existing-DB and restamp cases.

Revision ID: 001_initial
Revises:
Create Date: 2026-02-20 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

# revision identifiers, used by Alembic.
revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _model_schemas() -> list[str]:
    """Return every PostgreSQL schema declared by the ORM models.

    Imports every model module for its registration side-effect, then derives
    the schema set straight from ``Base.metadata`` rather than a hand-kept
    list. A hand-kept list silently missed ``fabric`` when that module was
    added; deriving from metadata means a new module that declares a new
    schema is picked up automatically and this class of drift can't recur.
    This mirrors ``scripts/migrate.py``.
    """
    import app.models  # noqa: F401  core + cross-cutting (incl. fabric.connections)
    import app.modules.access_control.models  # noqa: F401
    import app.modules.ai.models  # noqa: F401
    import app.modules.backup.models  # noqa: F401
    import app.modules.cameras.models  # noqa: F401
    import app.modules.collector.models  # noqa: F401
    import app.modules.firewall.models  # noqa: F401
    import app.modules.gateway.models  # noqa: F401
    import app.modules.hypervisor.models  # noqa: F401
    import app.modules.network.models  # noqa: F401
    import app.modules.voip.models  # noqa: F401
    from app.db.base import Base

    return sorted({t.schema for t in Base.metadata.tables.values() if t.schema})


# All schema.table pairs that use AuditMixin (created_by, updated_by)
AUDIT_TABLES = [
    ("core", "organizations"),
    ("core", "sites"),
    ("core", "controllers"),
    ("core", "users"),
    ("core", "user_site_access"),
    ("core", "credentials"),
    ("devices", "devices"),
    ("devices", "auto_adoption_rules"),
    ("devices", "mac_pre_registrations"),
    ("devices", "adoption_jobs"),
    ("devices", "provisioning_profiles"),
    ("enterprise", "site_groups"),
    ("enterprise", "device_groups"),
    ("enterprise", "device_configs"),
    ("enterprise", "config_templates"),
    ("enterprise", "bulk_operations"),
    ("enterprise", "auto_backup_policies"),
    ("analytics", "metric_definitions"),
    ("analytics", "analytics_alerts"),
    ("analytics", "dashboard_widgets"),
    ("events", "correlation_rules"),
    ("events", "incidents"),
    ("events", "alert_rules"),
    ("events", "alerts"),
    ("agents", "remote_agents"),
    ("devices", "firmware_images"),
    ("devices", "device_firmware_status"),
    ("devices", "firmware_upgrade_jobs"),
    ("devices", "firmware_schedules"),
    ("vpn", "vpn_connections"),
    ("vpn", "site_vpn_configs"),
    ("vpn", "vpn_tunnel_templates"),
    ("vpn", "site_to_site_tunnels"),
    ("enterprise", "sla_policies"),
    ("enterprise", "sla_reports"),
    ("enterprise", "sla_report_schedules"),
    ("enterprise", "topology_layouts"),
    ("devices", "poe_schedules"),
    ("core", "sso_providers"),
    ("core", "api_keys"),
    ("core", "oauth2_apps"),
    ("network", "radius_server_profiles"),
    ("network", "dot1x_port_configs"),
    ("network", "dot1x_auth_events"),
    ("events", "webhooks"),
    ("events", "webhook_deliveries"),
    ("core", "export_jobs"),
    ("core", "import_jobs"),
    ("core", "integrations"),
    ("core", "marketplace_plugins"),
    ("core", "plugin_reviews"),
    ("core", "installed_plugins"),
    ("events", "automation_rules"),
]

# Performance indexes for high-cardinality filter columns
PERF_INDEXES = [
    ("ix_devices_is_active", "devices.devices", ["is_active"]),
    ("ix_devices_status", "devices.devices", ["status"]),
    ("ix_devices_device_type", "devices.devices", ["device_type"]),
    ("ix_devices_type_site_deleted", "devices.devices", ["device_type", "site_id", "deleted_at"]),
    ("ix_device_ports_is_enabled", "devices.device_ports", ["is_enabled"]),
    ("ix_device_ports_device_id", "devices.device_ports", ["device_id"]),
    ("ix_device_clients_is_online", "devices.device_clients", ["is_online"]),
    ("ix_device_clients_device_id", "devices.device_clients", ["device_id"]),
    ("ix_devices_credential_id", "devices.devices", ["credential_id"]),
]


def upgrade() -> None:
    # ── 1. Create all PostgreSQL schemas (derived from live model metadata) ──
    for schema in _model_schemas():
        op.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema}"))

    # ── 2. Create every table, column, FK, and model-level index from ORM ──
    from app.db.base import Base

    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)

    # ── 3. Add audit columns (created_by/updated_by) where missing ──
    conn = op.get_bind()
    for schema, table in AUDIT_TABLES:
        # Only add to tables that exist but lack the column
        exists = conn.execute(
            text(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema = :schema AND table_name = :table"
            ),
            {"schema": schema, "table": table},
        )
        if exists.fetchone() is None:
            continue
        has_col = conn.execute(
            text(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_schema = :schema AND table_name = :table "
                "AND column_name = 'created_by'"
            ),
            {"schema": schema, "table": table},
        )
        if has_col.fetchone() is None:
            op.execute(text(f'ALTER TABLE "{schema}"."{table}" ADD COLUMN IF NOT EXISTS created_by UUID'))
            op.execute(text(f'ALTER TABLE "{schema}"."{table}" ADD COLUMN IF NOT EXISTS updated_by UUID'))

    # ── 4. Unique MAC constraint (deduplicate first) ──
    # Empty-string MACs ('') are excluded: adapters that surface a MAC-less
    # "self" device (firewall/gateway) write mac='' for distinct devices, so
    # collapsing them by '' equality would wrongly merge unrelated rows. They
    # are deduped at the app layer (discovery MAC-less fallback) instead.
    op.execute("""
        UPDATE devices.devices d
        SET deleted_at = NOW()
        WHERE d.deleted_at IS NULL
          AND d.mac_address IS NOT NULL
          AND d.mac_address <> ''
          AND d.id != (
            SELECT d2.id FROM devices.devices d2
            WHERE d2.mac_address = d.mac_address
              AND d2.deleted_at IS NULL
            ORDER BY d2.last_seen DESC NULLS LAST
            LIMIT 1
          )
    """)
    op.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_devices_mac_alive
        ON devices.devices (mac_address)
        WHERE deleted_at IS NULL AND mac_address IS NOT NULL AND mac_address <> ''
    """)

    # ── 5. Performance indexes ──
    for name, table, columns in PERF_INDEXES:
        cols = ", ".join(columns)
        op.execute(f'CREATE INDEX IF NOT EXISTS "{name}" ON {table} ({cols})')

    # ── 6. GIN indexes for JSONB containment queries ──
    op.execute('CREATE INDEX IF NOT EXISTS "ix_alert_rules_scope_ids" ON events.alert_rules USING gin (scope_ids)')



def downgrade() -> None:
    import os
    if os.environ.get("ALLOW_DESTRUCTIVE_MIGRATIONS") != "true":
        raise RuntimeError(
            "Refusing to downgrade: this would DROP ALL tables and schemas. "
            "Set ALLOW_DESTRUCTIVE_MIGRATIONS=true to proceed."
        )

    from app.db.base import Base

    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)

    for schema in reversed(_model_schemas()):
        op.execute(text(f"DROP SCHEMA IF EXISTS {schema} CASCADE"))
