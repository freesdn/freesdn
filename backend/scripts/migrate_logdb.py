# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""LogDB (TimescaleDB) migration script.

Creates the time-series schema in the separate TimescaleDB instance.
Converts eligible tables to hypertables and configures compression +
retention policies.

Strategy:
  - Ensure TimescaleDB extension is enabled
  - Create required schemas (analytics, vpn, events, agents)
  - Create tables via raw DDL (no cross-DB FK constraints)
  - Convert to hypertables (idempotent — skips if already a hypertable)
  - Add compression & retention policies (idempotent)

This script is synchronous to avoid asyncio.run() conflicts with
shell entrypoints.
"""

import os
import re
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, text


def _get_sync_logdb_url() -> str | None:
    """Return a synchronous LogDB URL or None if not configured."""
    url = os.environ.get("LOGDB_URL", "")
    if not url:
        return None
    return re.sub(r"postgresql\+asyncpg://", "postgresql+psycopg://", url)


# Tables that should be converted to hypertables.
# Format: (schema, table_name, time_column)
HYPERTABLES = [
    ("analytics", "metric_data", "time"),
    ("vpn", "vpn_health_checks", "time"),
    ("agents", "agent_heartbeats", "timestamp"),
    ("events", "event_records", "timestamp"),
]

# Compression policies: (schema, table, after_interval)
COMPRESSION_POLICIES = [
    ("analytics", "metric_data", "7 days"),
    ("vpn", "vpn_health_checks", "7 days"),
    ("agents", "agent_heartbeats", "3 days"),
    ("events", "event_records", "14 days"),
]

# Retention policies: (schema, table, drop_after)
RETENTION_POLICIES = [
    ("analytics", "metric_data", "90 days"),
    ("vpn", "vpn_health_checks", "90 days"),
    ("agents", "agent_heartbeats", "30 days"),
    ("events", "event_records", "180 days"),
]

# Schemas required in logdb
LOGDB_SCHEMAS = ["analytics", "vpn", "events", "agents"]


def _is_hypertable(conn, schema: str, table: str) -> bool:
    """Check if a table is already a TimescaleDB hypertable."""
    result = conn.execute(
        text(
            "SELECT EXISTS ("
            "  SELECT 1 FROM timescaledb_information.hypertables "
            "  WHERE hypertable_schema = :schema "
            "  AND hypertable_name = :table"
            ")"
        ),
        {"schema": schema, "table": table},
    )
    return result.scalar()


def _has_compression_policy(conn, schema: str, table: str) -> bool:
    """Check if a compression policy already exists."""
    result = conn.execute(
        text(
            "SELECT EXISTS ("
            "  SELECT 1 FROM timescaledb_information.jobs "
            "  WHERE hypertable_schema = :schema "
            "  AND hypertable_name = :table "
            "  AND proc_name = 'policy_compression'"
            ")"
        ),
        {"schema": schema, "table": table},
    )
    return result.scalar()


def _has_retention_policy(conn, schema: str, table: str) -> bool:
    """Check if a retention policy already exists."""
    result = conn.execute(
        text(
            "SELECT EXISTS ("
            "  SELECT 1 FROM timescaledb_information.jobs "
            "  WHERE hypertable_schema = :schema "
            "  AND hypertable_name = :table "
            "  AND proc_name = 'policy_retention'"
            ")"
        ),
        {"schema": schema, "table": table},
    )
    return result.scalar()


def _table_exists(conn, schema: str, table: str) -> bool:
    """Check if a table exists in the given schema."""
    result = conn.execute(
        text(
            "SELECT EXISTS ("
            "  SELECT 1 FROM information_schema.tables "
            "  WHERE table_schema = :schema "
            "  AND table_name = :table"
            ")"
        ),
        {"schema": schema, "table": table},
    )
    return result.scalar()


def _create_logdb_tables(engine) -> None:
    """Create time-series tables using raw DDL (no cross-DB FK constraints)."""
    ddl = {
        ("analytics", "metric_data"): """
            CREATE TABLE IF NOT EXISTS analytics.metric_data (
                time        TIMESTAMPTZ   NOT NULL,
                metric_name VARCHAR(255)  NOT NULL,
                labels_hash VARCHAR(64)   NOT NULL DEFAULT '',
                value       DOUBLE PRECISION NOT NULL,
                labels      JSONB,
                organization_id UUID,
                site_id     UUID,
                device_id   UUID,
                PRIMARY KEY (time, metric_name, labels_hash)
            );
            CREATE INDEX IF NOT EXISTS ix_metric_data_name_time
                ON analytics.metric_data (metric_name, time);
            CREATE INDEX IF NOT EXISTS ix_metric_data_site
                ON analytics.metric_data (site_id, time);
            CREATE INDEX IF NOT EXISTS ix_metric_data_device
                ON analytics.metric_data (device_id, time);
        """,
        ("vpn", "vpn_health_checks"): """
            CREATE TABLE IF NOT EXISTS vpn.vpn_health_checks (
                id            UUID NOT NULL DEFAULT gen_random_uuid(),
                time          TIMESTAMPTZ NOT NULL,
                connection_id UUID,
                site_id       UUID,
                tunnel_id     UUID,
                is_healthy    BOOLEAN NOT NULL DEFAULT FALSE,
                latency_ms    DOUBLE PRECISION,
                status        VARCHAR(20) NOT NULL,
                error_message TEXT,
                rx_bytes      INTEGER NOT NULL DEFAULT 0,
                tx_bytes      INTEGER NOT NULL DEFAULT 0,
                peer_count    INTEGER NOT NULL DEFAULT 0,
                -- PK MUST include the partition column 'time' for the
                -- create_hypertable() conversion (TimescaleDB rule), else the
                -- whole LogDB migration aborts and the container crash-loops on
                -- a real prod/staging deploy. Matches agent_heartbeats.
                PRIMARY KEY (id, time)
            );
            CREATE INDEX IF NOT EXISTS ix_vpn_health_site
                ON vpn.vpn_health_checks (site_id, time);
            CREATE INDEX IF NOT EXISTS ix_vpn_health_conn
                ON vpn.vpn_health_checks (connection_id, time);
            CREATE INDEX IF NOT EXISTS ix_vpn_health_tunnel
                ON vpn.vpn_health_checks (tunnel_id, time);
        """,
        ("agents", "agent_heartbeats"): """
            CREATE TABLE IF NOT EXISTS agents.agent_heartbeats (
                id              UUID NOT NULL DEFAULT gen_random_uuid(),
                agent_id        UUID NOT NULL,
                timestamp       TIMESTAMPTZ NOT NULL DEFAULT now(),
                cpu_percent     DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                memory_percent  DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                disk_percent    DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                status          VARCHAR(50) NOT NULL DEFAULT 'online',
                latency_ms      DOUBLE PRECISION,
                managed_devices INTEGER NOT NULL DEFAULT 0,
                active_tasks    INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (id, timestamp)
            );
            CREATE INDEX IF NOT EXISTS ix_agent_heartbeats_agent_timestamp
                ON agents.agent_heartbeats (agent_id, timestamp);
        """,
        ("events", "event_records"): """
            DO $$ BEGIN
                CREATE TYPE events.event_category_enum AS ENUM (
                    'system','device','site','controller','network',
                    'security','user','task','automation'
                );
            EXCEPTION WHEN duplicate_object THEN NULL;
            END $$;
            DO $$ BEGIN
                CREATE TYPE events.event_priority_enum AS ENUM (
                    'low','normal','high','critical'
                );
            EXCEPTION WHEN duplicate_object THEN NULL;
            END $$;
            CREATE TABLE IF NOT EXISTS events.event_records (
                id              UUID NOT NULL DEFAULT gen_random_uuid(),
                event_type      VARCHAR(255) NOT NULL,
                category        events.event_category_enum NOT NULL DEFAULT 'system',
                priority        events.event_priority_enum NOT NULL DEFAULT 'normal',
                payload         JSONB NOT NULL DEFAULT '{}',
                metadata        JSONB NOT NULL DEFAULT '{}',
                source          VARCHAR(100) NOT NULL DEFAULT 'freesdn',
                correlation_id  UUID,
                causation_id    UUID,
                organization_id UUID,
                site_id         UUID,
                user_id         UUID,
                timestamp       TIMESTAMPTZ NOT NULL DEFAULT now(),
                -- PK MUST include the partition column 'timestamp' for
                -- create_hypertable() (TimescaleDB rule) — else the LogDB
                -- migration aborts and the backend container crash-loops on a
                -- real prod/staging deploy.
                PRIMARY KEY (id, timestamp)
            );
            CREATE INDEX IF NOT EXISTS ix_event_records_event_type
                ON events.event_records (event_type);
            CREATE INDEX IF NOT EXISTS ix_event_records_category
                ON events.event_records (category);
            CREATE INDEX IF NOT EXISTS ix_event_records_correlation_id
                ON events.event_records (correlation_id);
            CREATE INDEX IF NOT EXISTS ix_event_records_source
                ON events.event_records (source);
            CREATE INDEX IF NOT EXISTS ix_event_records_organization_id
                ON events.event_records (organization_id);
            CREATE INDEX IF NOT EXISTS ix_event_records_timestamp_brin
                ON events.event_records USING brin (timestamp);
        """,
    }

    with engine.begin() as conn:
        for (schema, table), sql in ddl.items():
            if _table_exists(conn, schema, table):
                print(f"[logdb] Table {schema}.{table} already exists")
                continue
            conn.execute(text(sql))
            print(f"[logdb] Created table {schema}.{table}")


def main() -> None:
    sync_url = _get_sync_logdb_url()
    if not sync_url:
        import os
        env = os.getenv("ENVIRONMENT", "development")
        if env in ("production", "staging"):
            raise RuntimeError(
                "LOGDB_URL is required in production/staging. "
                "Set LOGDB_URL before running migrations."
            )
        print("[logdb] LOGDB_URL not set — skipping LogDB migration (development mode)")
        return

    engine = create_engine(sync_url)
    try:
        with engine.begin() as conn:
            # 1. Ensure TimescaleDB extension
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE"))
            ts_version = conn.execute(
                text("SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'")
            ).scalar()
            print(f"[logdb] TimescaleDB version: {ts_version}")

            # 2. Create schemas
            for schema in LOGDB_SCHEMAS:
                conn.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema}"))
            print(f"[logdb] Schemas ready: {', '.join(LOGDB_SCHEMAS)}")

        # 3. Create tables via raw DDL.
        # We use explicit DDL instead of ORM table.create() because
        # several models have ForeignKey references to the primary DB
        # (e.g. core.organizations, agents.remote_agents) which cannot
        # resolve in the separate LogDB instance.  The columns are kept
        # as plain UUID / typed columns without FK constraints.
        _create_logdb_tables(engine)

        # 4. Convert to hypertables
        with engine.begin() as conn:
            for schema, table, time_col in HYPERTABLES:
                if not _table_exists(conn, schema, table):
                    print(f"[logdb] Skipping hypertable {schema}.{table} — table not found")
                    continue
                if _is_hypertable(conn, schema, table):
                    print(f"[logdb] {schema}.{table} is already a hypertable")
                    continue

                conn.execute(
                    text(
                        f"SELECT create_hypertable("
                        f"'{schema}.{table}', '{time_col}', "
                        f"migrate_data => true, if_not_exists => true"
                        f")"
                    )
                )
                print(f"[logdb] Converted {schema}.{table} to hypertable (time_column={time_col})")

        # 5. Enable compression
        with engine.begin() as conn:
            for schema, table, after_interval in COMPRESSION_POLICIES:
                if not _is_hypertable(conn, schema, table):
                    continue

                # Enable compression on the hypertable
                conn.execute(
                    text(
                        f"ALTER TABLE {schema}.{table} SET ("
                        f"timescaledb.compress, "
                        f"timescaledb.compress_segmentby = ''"
                        f")"
                    )
                )

                if not _has_compression_policy(conn, schema, table):
                    conn.execute(
                        text(
                            f"SELECT add_compression_policy("
                            f"'{schema}.{table}', "
                            f"INTERVAL '{after_interval}'"
                            f")"
                        )
                    )
                    print(f"[logdb] Compression policy: {schema}.{table} after {after_interval}")
                else:
                    print(f"[logdb] Compression policy already exists: {schema}.{table}")

        # 6. Add retention policies
        with engine.begin() as conn:
            for schema, table, drop_after in RETENTION_POLICIES:
                if not _is_hypertable(conn, schema, table):
                    continue
                if not _has_retention_policy(conn, schema, table):
                    conn.execute(
                        text(
                            f"SELECT add_retention_policy("
                            f"'{schema}.{table}', "
                            f"INTERVAL '{drop_after}'"
                            f")"
                        )
                    )
                    print(f"[logdb] Retention policy: {schema}.{table} drop after {drop_after}")
                else:
                    print(f"[logdb] Retention policy already exists: {schema}.{table}")

        # 7. Create continuous aggregates for common queries
        _create_continuous_aggregates(engine)

        print("[logdb] Migration complete")

    finally:
        engine.dispose()


def _create_continuous_aggregates(engine) -> None:
    """Create continuous aggregates for common dashboard queries."""
    aggregates = [
        {
            "name": "analytics.metric_data_hourly",
            "query": """
                SELECT
                    time_bucket('1 hour', time) AS bucket,
                    metric_name,
                    organization_id,
                    site_id,
                    device_id,
                    AVG(value) AS avg_value,
                    MIN(value) AS min_value,
                    MAX(value) AS max_value,
                    COUNT(*) AS sample_count
                FROM analytics.metric_data
                GROUP BY bucket, metric_name, organization_id, site_id, device_id
            """,
        },
        {
            "name": "vpn.health_checks_hourly",
            "query": """
                SELECT
                    time_bucket('1 hour', time) AS bucket,
                    connection_id,
                    tunnel_id,
                    site_id,
                    AVG(latency_ms) AS avg_latency_ms,
                    MIN(latency_ms) AS min_latency_ms,
                    MAX(latency_ms) AS max_latency_ms,
                    COUNT(*) FILTER (WHERE is_healthy) AS healthy_count,
                    COUNT(*) FILTER (WHERE NOT is_healthy) AS unhealthy_count,
                    SUM(rx_bytes) AS total_rx_bytes,
                    SUM(tx_bytes) AS total_tx_bytes
                FROM vpn.vpn_health_checks
                GROUP BY bucket, connection_id, tunnel_id, site_id
            """,
        },
        {
            "name": "agents.heartbeats_hourly",
            "query": """
                SELECT
                    time_bucket('1 hour', timestamp) AS bucket,
                    agent_id,
                    AVG(cpu_percent) AS avg_cpu,
                    AVG(memory_percent) AS avg_memory,
                    AVG(disk_percent) AS avg_disk,
                    AVG(latency_ms) AS avg_latency_ms,
                    COUNT(*) AS heartbeat_count
                FROM agents.agent_heartbeats
                GROUP BY bucket, agent_id
            """,
        },
    ]

    # TimescaleDB refuses to build a continuous aggregate inside a transaction
    # block — `CREATE MATERIALIZED VIEW ... WITH (timescaledb.continuous)` errors
    # with ActiveSqlTransaction. Use an AUTOCOMMIT connection so each statement
    # runs outside a transaction. (The hypertable/compression/retention steps
    # above are transaction-safe and intentionally keep engine.begin().)
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        for agg in aggregates:
            # Check if the view already exists
            schema, name = agg["name"].split(".")
            exists = conn.execute(
                text(
                    "SELECT EXISTS ("
                    "  SELECT 1 FROM timescaledb_information.continuous_aggregates "
                    "  WHERE view_schema = :schema "
                    "  AND view_name = :name"
                    ")"
                ),
                {"schema": schema, "name": name},
            ).scalar()

            if exists:
                print(f"[logdb] Continuous aggregate {agg['name']} already exists")
                continue

            # Check that the source hypertable exists first
            source_table_exists = True
            if "metric_data" in agg["query"] and not _table_exists(conn, "analytics", "metric_data"):
                source_table_exists = False
            if "vpn_health_checks" in agg["query"] and not _table_exists(conn, "vpn", "vpn_health_checks"):
                source_table_exists = False
            if "agent_heartbeats" in agg["query"] and not _table_exists(conn, "agents", "agent_heartbeats"):
                source_table_exists = False

            if not source_table_exists:
                print(f"[logdb] Skipping aggregate {agg['name']} — source table not found")
                continue

            conn.execute(
                text(
                    f"CREATE MATERIALIZED VIEW {agg['name']} "
                    f"WITH (timescaledb.continuous) AS {agg['query']}"
                )
            )

            # Add refresh policy: refresh every hour, cover the last 3 hours
            conn.execute(
                text(
                    f"SELECT add_continuous_aggregate_policy('{agg['name']}', "
                    f"start_offset => INTERVAL '3 hours', "
                    f"end_offset => INTERVAL '1 hour', "
                    f"schedule_interval => INTERVAL '1 hour')"
                )
            )
            print(f"[logdb] Created continuous aggregate: {agg['name']}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        traceback.print_exc(file=sys.stderr)
        print(f"[logdb] Migration failed: {e}", file=sys.stderr)
        sys.exit(1)
