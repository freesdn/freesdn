#!/bin/sh
# =============================================================================
# PgBouncer entrypoint - generates userlist.txt from environment variables
# then starts PgBouncer with the supplied config.
# =============================================================================
set -e

USERLIST_FILE="/etc/pgbouncer/userlist.txt"
CONFIG_FILE="${PGBOUNCER_CONFIG:-/etc/pgbouncer/pgbouncer.ini}"

# Build userlist from environment
# Format: "username" "password" - PgBouncer hashes as needed for scram-sha-256
echo "\"${PGBOUNCER_USER:-freesdn}\" \"${PGBOUNCER_PASSWORD}\"" > "$USERLIST_FILE"

echo "[pgbouncer-entrypoint] userlist.txt generated for user '${PGBOUNCER_USER:-freesdn}'"

exec pgbouncer "$CONFIG_FILE"
