#!/usr/bin/env bash
# =============================================================================
# Standby bootstrap for the HA-drill Postgres replica.
# =============================================================================
#
# On first boot:
#   1. Verify the primary is reachable.
#   2. Run ``pg_basebackup`` from the primary to seed the standby data dir.
#   3. Write a minimal ``postgresql.auto.conf`` with primary_conninfo so the
#      standby starts streaming WAL on first start.
#   4. Drop a ``standby.signal`` file - Postgres 12+ uses that file (instead
#      of recovery.conf) to know "come up as a hot standby."
#
# On subsequent boots the data dir is already seeded; we just exec postgres.
#
# Env vars expected (set by docker-compose.ha.yml):
#   PRIMARY_HOST, PRIMARY_PORT
#   REPL_USER, REPL_PASSWORD
#   POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB
#
# This script is INTENTIONALLY simple - it's drill infrastructure, not a
# production-grade Patroni setup. For real prod HA use Patroni / repmgr.

set -euo pipefail

DATA_DIR="${PGDATA:-/var/lib/postgresql/data}"

# If the data dir already has a PG_VERSION file the standby has been seeded.
if [ -s "${DATA_DIR}/PG_VERSION" ]; then
    echo "[standby-entrypoint] data dir already seeded - starting postgres"
    exec docker-entrypoint.sh postgres
fi

# First-boot bootstrap. Wait for primary to be reachable before pg_basebackup.
echo "[standby-entrypoint] waiting for primary ${PRIMARY_HOST}:${PRIMARY_PORT}…"
for i in $(seq 1 60); do
    if pg_isready -h "${PRIMARY_HOST}" -p "${PRIMARY_PORT}" -U "${POSTGRES_USER}" >/dev/null 2>&1; then
        echo "[standby-entrypoint] primary reachable"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "[standby-entrypoint] primary never came up; refusing to bootstrap"
        exit 1
    fi
    sleep 2
done

# Ensure the data dir exists and is owned by postgres.
mkdir -p "${DATA_DIR}"
chown -R postgres:postgres "${DATA_DIR}"
chmod 700 "${DATA_DIR}"

# pg_basebackup as the replication user. -X stream pulls WAL during the backup
# so we don't need an archive on the primary for the initial sync.
echo "[standby-entrypoint] running pg_basebackup from ${PRIMARY_HOST}:${PRIMARY_PORT}"
export PGPASSWORD="${REPL_PASSWORD}"
su postgres -c "pg_basebackup \
    --host=${PRIMARY_HOST} \
    --port=${PRIMARY_PORT} \
    --username=${REPL_USER} \
    --pgdata=${DATA_DIR} \
    --wal-method=stream \
    --progress \
    --verbose \
    --write-recovery-conf"

# pg_basebackup --write-recovery-conf already drops standby.signal +
# primary_conninfo into postgresql.auto.conf since Postgres 12. Double-check.
if [ ! -f "${DATA_DIR}/standby.signal" ]; then
    touch "${DATA_DIR}/standby.signal"
    chown postgres:postgres "${DATA_DIR}/standby.signal"
fi

echo "[standby-entrypoint] bootstrap complete - starting postgres"
exec docker-entrypoint.sh postgres
