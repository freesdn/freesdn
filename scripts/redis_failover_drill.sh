#!/usr/bin/env bash
# ============================================================================
# FreeSDN - Valkey/Redis Sentinel failover drill
# ============================================================================
# Proves the HA Redis path end-to-end: brings up (or uses) the max+HA stack,
# pauses the Valkey master, and asserts that (1) Sentinel promotes the replica
# and (2) the application follows the promoted master (api redis health stays
# healthy once connections re-resolve).
#
# Usage:
#   ./scripts/redis_failover_drill.sh                 # uses .env.max + ha overlay
#   ENV_FILE=.env.max ./scripts/redis_failover_drill.sh --up   # also bring it up first
#
# Requires the backend image to be built from CURRENT source (the api must have
# app.core.redis_client). Rebuild with: docker compose --env-file .env.max build api
#
# NOTE: on Docker Desktop / WSL2 under heavy load, Sentinel may enter TILT mode
# (clock-jump safety) and refuse to fail over. Run on an idle host / real Linux.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."

ENV_FILE="${ENV_FILE:-.env.max}"
DC=(docker compose --env-file "$ENV_FILE" -f docker-compose.yml -f docker-compose.ha.yml)
PROJECT="$(grep -E '^COMPOSE_PROJECT_NAME=' "$ENV_FILE" | cut -d= -f2- || echo freesdn-max)"
PW="$(grep -E '^REDIS_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
SENT=freesdn-redis-sentinel-1            # explicit container_name in ha.yml
REPLICA=freesdn-redis-replica
API_CTR="${PROJECT}-api-1"
GREEN=$'\033[92m'; RED=$'\033[91m'; CYAN=$'\033[96m'; RST=$'\033[0m'
ok()  { echo "${GREEN}[PASS]${RST} $*"; }
bad() { echo "${RED}[FAIL]${RST} $*"; FAILED=1; }
info(){ echo "${CYAN}[..]${RST}  $*"; }
FAILED=0
sentinel(){ docker exec "$SENT" valkey-cli -p 26379 -a "$PW" "$@" 2>/dev/null; }

if [[ "${1:-}" == "--up" ]]; then
  info "Bringing up the failover set…"
  "${DC[@]}" up -d --no-build redis redis-replica redis-sentinel-1 redis-sentinel-2 redis-sentinel-3 postgres logdb api
  sleep 20
fi

info "Pre-drill checks"
docker exec "$REPLICA" valkey-cli -a "$PW" info replication 2>/dev/null | grep -q 'master_link_status:up' \
  && ok "replica link up" || bad "replica not synced"
[[ "$(sentinel sentinel master freesdn-master | paste - - | grep -A0 'num-other-sentinels' -m1 >/dev/null; sentinel sentinel ckquorum freesdn-master)" == *OK* ]] \
  && ok "sentinel quorum OK" || bad "sentinel quorum NOT reachable"
ORIG_MASTER="$(sentinel sentinel get-master-addr-by-name freesdn-master | head -1)"
info "current master host: $ORIG_MASTER"

# Find which container is CURRENTLY the master (failover may have already moved
# it off the base node), so we always inject the fault at the live master.
MASTER_CTR=""
for c in "${PROJECT}-redis-1" "$REPLICA"; do
  if docker exec "$c" valkey-cli -a "$PW" info replication 2>/dev/null | grep -q '^role:master'; then
    MASTER_CTR="$c"; break
  fi
done
[[ -z "$MASTER_CTR" ]] && { bad "no master container found"; exit 1; }

info "Injecting fault: pausing the master ($MASTER_CTR)…"
docker pause "$MASTER_CTR" >/dev/null
T0=$(date +%s)

info "Waiting for Sentinel to promote (down-after 5s + failover 10s)…"
NEW_MASTER=""
for _ in $(seq 1 20); do
  sleep 2
  NEW_MASTER="$(sentinel sentinel get-master-addr-by-name freesdn-master | head -1)"
  [[ -n "$NEW_MASTER" && "$NEW_MASTER" != "$ORIG_MASTER" ]] && break
done
RTO=$(( $(date +%s) - T0 ))
if [[ -n "$NEW_MASTER" && "$NEW_MASTER" != "$ORIG_MASTER" ]]; then
  ok "Sentinel promoted a new master: $NEW_MASTER (RTO ~${RTO}s)"
  docker exec "$REPLICA" valkey-cli -a "$PW" info replication 2>/dev/null | grep -q '^role:master' \
    && ok "promoted node reports role:master" || bad "promoted node not master"
else
  bad "no promotion within window (TILT mode? heavy host? check: docker logs $SENT | grep tilt)"
fi

info "Asserting the APP follows (api redis health should recover)…"
APP_OK=0
for _ in $(seq 1 10); do
  sleep 3
  if docker exec "$API_CTR" python -c "import urllib.request,json,sys; d=json.load(urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health',timeout=6)); sys.exit(0 if d['components']['redis']['status']=='healthy' else 1)" 2>/dev/null; then
    APP_OK=1; break
  fi
done
[[ $APP_OK == 1 ]] && ok "api redis health recovered → app followed the promoted master" \
  || bad "api redis health did NOT recover (is the api running CURRENT code w/ app.core.redis_client?)"

info "Restoring: unpausing the old master (rejoins as replica)…"
docker unpause "$MASTER_CTR" >/dev/null; sleep 10
docker exec "$MASTER_CTR" valkey-cli -a "$PW" info replication 2>/dev/null | grep -q '^role:slave' \
  && ok "old master rejoined as replica" || info "old master role not yet slave (Sentinel reconfigures async)"

echo
[[ $FAILED == 0 ]] && echo "${GREEN}DRILL PASSED${RST}" || { echo "${RED}DRILL FAILED${RST}"; exit 1; }
