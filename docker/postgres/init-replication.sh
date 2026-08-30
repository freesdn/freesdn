#!/bin/bash
# =============================================================================
# FreeSDN — create the streaming-replication role on the PRIMARY
# =============================================================================
# Mounted into /docker-entrypoint-initdb.d/ by docker-compose.ha.yml ONLY: it is
# the HA overlay that runs a standby, and a single-node deployment has no use
# for a replication role.
#
# Why this file has to exist. docker-compose.ha.yml's `postgres-standby` runs
# pg_basebackup as ${POSTGRES_REPL_USER:-repl}, and nothing anywhere created
# that role or let it connect. initdb's generated pg_hba.conf permits
# replication only over the local socket and from 127.0.0.1, and the official
# image's entrypoint appends `host all all all <auth>` -- which does NOT cover
# the `replication` pseudo-database. So the standby failed every attempt with
#
#   pg_basebackup: error: connection to server at "postgres" failed:
#   FATAL: no pg_hba.conf entry for replication connection from host
#   "172.30.0.9", user "repl", no encryption
#
# and restart-looped forever. Streaming replication had never worked.
#
# `samenet` rather than `all`: it matches only subnets this server is directly
# attached to, i.e. the compose network, so the replication role is not offered
# to anything that merely reaches the port.
#
# LIMIT WORTH KNOWING: /docker-entrypoint-initdb.d only runs on a FRESH data
# directory. Turning on --ha over an existing single-node install will not
# execute this. Run it by hand on the primary in that case:
#
#   docker compose --env-file .env.max exec \
#       -e REPL_USER=repl -e REPL_PASSWORD="$(grep ^POSTGRES_REPL_PASSWORD \
#           .env.max | cut -d= -f2-)" \
#       postgres bash /docker-entrypoint-initdb.d/20-init-replication.sh
#
# then `docker compose ... restart postgres` so pg_hba.conf is re-read.
# =============================================================================
set -euo pipefail

REPL_USER="${REPL_USER:-repl}"

# Constrain the role NAME to a conservative identifier charset. The SQL below is
# already safe -- psql variables through format() %I/%L are quoted by the server
# -- but this name is ALSO interpolated into two places with different grammars
# where quoting it correctly is fiddly and easy to get wrong:
#   * a grep -E REGEX (the "is it already there" check). A name containing a
#     regex metacharacter changes what that matches: "re.l" matches "reXl", so
#     the check can report the line as already present when it is not, silently
#     skip the append, and leave replication broken with no error.
#   * an UNQUOTED pg_hba.conf field. pg_hba is whitespace-delimited, so a name
#     with a space in it becomes two fields and corrupts the file.
# Refusing the name is better than quoting it twice, in two grammars, correctly.
case "$REPL_USER" in
    *[!A-Za-z0-9_]* | "" | [!A-Za-z_]* )
        echo "[init-replication] REPL_USER='${REPL_USER}' is not a plain identifier." >&2
        echo "[init-replication] Use [A-Za-z_][A-Za-z0-9_]* (the default is 'repl')." >&2
        exit 1
        ;;
esac

if [ -z "${REPL_PASSWORD:-}" ]; then
    echo "[init-replication] REPL_PASSWORD is empty - skipping. The standby will" >&2
    echo "[init-replication] not be able to connect until this role exists." >&2
    exit 0
fi

echo "[init-replication] creating replication role '${REPL_USER}'"

# The role name and password are psql VARIABLES run through format()'s %I/%L, so
# they are quoted by the server rather than pasted into SQL text. \gexec runs the
# generated statement. A DO block would not work here: psql does not interpolate
# :'vars' inside dollar-quoted strings.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v repl_user="$REPL_USER" -v repl_password="$REPL_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE %I WITH REPLICATION LOGIN PASSWORD %L',
              :'repl_user', :'repl_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'repl_user')
\gexec

SELECT format('ALTER ROLE %I WITH REPLICATION LOGIN PASSWORD %L',
              :'repl_user', :'repl_password')
WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'repl_user')
\gexec
SQL

HBA="${PGDATA:-/var/lib/postgresql/data}/pg_hba.conf"
if ! grep -qE "^host[[:space:]]+replication[[:space:]]+${REPL_USER}[[:space:]]" "$HBA"; then
    {
        printf '\n# FreeSDN HA: let the standby stream from this primary.\n'
        printf 'host    replication    %s    samenet    scram-sha-256\n' "$REPL_USER"
    } >> "$HBA"
    echo "[init-replication] pg_hba.conf: replication allowed for '${REPL_USER}' from samenet"
else
    echo "[init-replication] pg_hba.conf already permits replication for '${REPL_USER}'"
fi
