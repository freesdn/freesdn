#!/usr/bin/env bash
# ============================================================================
# FreeSDN - DR restore drill
# ============================================================================
# Proves the encrypted backup pipeline is RECOVERABLE end-to-end, including the
# TimescaleDB (LogDB) path that needs timescaledb_pre_restore/post_restore.
# Fully self-contained: seeds throwaway source DBs, runs the EXACT pg-backup
# pipeline (pg_dump | gzip | gpg --encrypt), then decrypts + restores into fresh
# targets and verifies row counts, the hypertable, and the continuous aggregate
# all survive. "A backup you have never restored is not a backup."
#
#   ./scripts/restore_drill.sh
#
# Requires the project's TimescaleDB image (built by the stack). Override with
# LOGDB_IMAGE=... if yours is tagged differently.
set -euo pipefail

NET=rdrill-net
TS_IMG="${LOGDB_IMAGE:-freesdn-logdb:local}"
CLIENT_IMG="${POSTGRES_IMAGE:-postgres:18.6-trixie}"   # has psql + pg_dump + gpg
PW=drillpw
GREEN=$'\033[92m'; RED=$'\033[91m'; CYAN=$'\033[96m'; RST=$'\033[0m'
ok(){ echo "${GREEN}[PASS]${RST} $*"; }
bad(){ echo "${RED}[FAIL]${RST} $*"; FAILED=1; }
info(){ echo "${CYAN}[..]${RST}  $*"; }
FAILED=0
cx(){ docker exec rdrill-cli "$@"; }

cleanup(){ docker rm -f rdrill-src rdrill-tgt rdrill-cli >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker image inspect "$TS_IMG" >/dev/null 2>&1 || { echo "TimescaleDB image $TS_IMG not found - build the stack first (or set LOGDB_IMAGE)"; exit 1; }

info "Spinning up throwaway source + target TimescaleDB + a client…"
docker network create "$NET" >/dev/null
docker run -d --name rdrill-src --network "$NET" -e POSTGRES_PASSWORD=$PW -e POSTGRES_DB=logs "$TS_IMG" -c shared_preload_libraries=timescaledb >/dev/null
docker run -d --name rdrill-tgt --network "$NET" -e POSTGRES_PASSWORD=$PW -e POSTGRES_DB=logs "$TS_IMG" -c shared_preload_libraries=timescaledb >/dev/null
docker run -d --name rdrill-cli --network "$NET" -e PGPASSWORD=$PW "$CLIENT_IMG" sleep 3600 >/dev/null
for c in rdrill-src rdrill-tgt; do
  for _ in $(seq 1 30); do docker exec "$c" pg_isready -U postgres -d logs >/dev/null 2>&1 && break; sleep 2; done
done

info "Seeding source: a plain DB (app) + a TimescaleDB (logs: hypertable + continuous aggregate)…"
cx psql -h rdrill-src -U postgres -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE app;" >/dev/null
cx psql -h rdrill-src -U postgres -d app -v ON_ERROR_STOP=1 -c "
CREATE SCHEMA core; CREATE TABLE core.users(id serial primary key, email text);
INSERT INTO core.users(email) SELECT 'u'||g||'@x' FROM generate_series(1,250) g;" >/dev/null
cx psql -h rdrill-src -U postgres -d logs -v ON_ERROR_STOP=1 -c "
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE TABLE metrics(ts timestamptz NOT NULL, name text, val double precision);
SELECT create_hypertable('metrics','ts');
INSERT INTO metrics SELECT now()-(g||' min')::interval,'cpu',random()*100 FROM generate_series(1,500) g;" >/dev/null
# Continuous aggregate must be created OUTSIDE a transaction → its own psql -c.
cx psql -h rdrill-src -U postgres -d logs -v ON_ERROR_STOP=1 -c \
  "CREATE MATERIALIZED VIEW metrics_hourly WITH (timescaledb.continuous) AS SELECT time_bucket('1 hour',ts) b, name, avg(val) v FROM metrics GROUP BY b,name WITH NO DATA;" >/dev/null
SRC_APP=$(cx psql -h rdrill-src -U postgres -d app  -tAc "SELECT count(*) FROM core.users")
SRC_TS=$(cx  psql -h rdrill-src -U postgres -d logs -tAc "SELECT count(*) FROM metrics")
ok "seeded app=$SRC_APP users, logs=$SRC_TS metric rows (hypertable + cagg)"

info "Generating a throwaway GPG keypair + running the pg-backup pipeline (pg_dump|gzip|gpg --encrypt)…"
cx bash -c "export GNUPGHOME=/tmp/g; mkdir -p \$GNUPGHOME; chmod 700 \$GNUPGHOME; printf '%s\n' 'Key-Type: RSA' 'Key-Length: 2048' 'Subkey-Type: RSA' 'Subkey-Length: 2048' 'Name-Real: drill' 'Name-Email: drill@freesdn.local' 'Expire-Date: 0' '%no-protection' '%commit' > /tmp/keyparams && gpg --batch --gen-key /tmp/keyparams >/dev/null 2>&1"
for db in app logs; do
  cx bash -c "export GNUPGHOME=/tmp/g; pg_dump -h rdrill-src -U postgres -d $db --no-owner --no-privileges | gzip | gpg --batch --yes --trust-model always --encrypt --recipient drill@freesdn.local --output /tmp/$db.sql.gz.gpg"
done
cx bash -c 'head -c2 /tmp/logs.sql.gz.gpg | od -An -tx1 | grep -q "85" ' && ok "dumps encrypted (OpenPGP magic present)" || bad "dump not GPG-encrypted"

info "Restoring PRIMARY (plain psql) into a fresh DB…"
cx psql -h rdrill-tgt -U postgres -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE app;" >/dev/null
cx bash -c "export GNUPGHOME=/tmp/g; gpg --batch --decrypt /tmp/app.sql.gz.gpg 2>/dev/null | gunzip | psql -h rdrill-tgt -U postgres -d app -q >/tmp/app_restore.log 2>&1"
TGT_APP=$(cx psql -h rdrill-tgt -U postgres -d app -tAc "SELECT count(*) FROM core.users" 2>/dev/null || echo ERR)
[ "$TGT_APP" = "$SRC_APP" ] && ok "primary restored: core.users $TGT_APP == $SRC_APP" || bad "primary mismatch: $TGT_APP vs $SRC_APP"

info "Restoring LOGDB (TimescaleDB: pre_restore → restore → post_restore)…"
cx psql -h rdrill-tgt -U postgres -d logs -v ON_ERROR_STOP=1 -c "CREATE EXTENSION IF NOT EXISTS timescaledb;" >/dev/null
cx psql -h rdrill-tgt -U postgres -d logs -v ON_ERROR_STOP=1 -c "SELECT timescaledb_pre_restore();" >/dev/null
cx bash -c "export GNUPGHOME=/tmp/g; gpg --batch --decrypt /tmp/logs.sql.gz.gpg 2>/dev/null | gunzip | psql -h rdrill-tgt -U postgres -d logs -q >/tmp/logs_restore.log 2>&1"
cx psql -h rdrill-tgt -U postgres -d logs -v ON_ERROR_STOP=1 -c "SELECT timescaledb_post_restore();" >/dev/null
TGT_TS=$(cx   psql -h rdrill-tgt -U postgres -d logs -tAc "SELECT count(*) FROM metrics" 2>/dev/null || echo ERR)
TGT_HYPER=$(cx psql -h rdrill-tgt -U postgres -d logs -tAc "SELECT count(*) FROM timescaledb_information.hypertables WHERE hypertable_name='metrics'" 2>/dev/null || echo 0)
TGT_CAGG=$(cx  psql -h rdrill-tgt -U postgres -d logs -tAc "SELECT count(*) FROM timescaledb_information.continuous_aggregates WHERE view_name='metrics_hourly'" 2>/dev/null || echo 0)
[ "$TGT_TS" = "$SRC_TS" ] && ok "logdb rows restored: metrics $TGT_TS == $SRC_TS" || bad "logdb row mismatch: $TGT_TS vs $SRC_TS"
[ "$TGT_HYPER" = "1" ]    && ok "hypertable 'metrics' survived restore"        || bad "hypertable missing after restore"
[ "$TGT_CAGG" = "1" ]     && ok "continuous aggregate 'metrics_hourly' survived" || bad "continuous aggregate missing after restore"

echo
[ "$FAILED" = 0 ] && echo "${GREEN}RESTORE DRILL PASSED - encrypted backups are recoverable (incl. TimescaleDB).${RST}" \
                  || { echo "${RED}RESTORE DRILL FAILED${RST}"; exit 1; }
