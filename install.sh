#!/usr/bin/env bash
# ============================================================================
# FreeSDN - Non-Interactive Installer (tier-aware)
# ============================================================================
# One command from a freshly cloned repo to a running stack. Picks a deployment
# tier, generates the tier env file with random secrets, and brings the stack
# up. TLS is handled automatically by the Caddy edge (no cert scripts needed).
#
# Usage:
#   ./install.sh                                  # lite tier (homelab), HTTP on :8080
#   ./install.sh --tier pro --domain example.com  # SMB, auto-HTTPS via Let's Encrypt
#   ./install.sh --tier max --domain example.com --email you@ex.com --ha
#   ./install.sh --dev                            # local dev (Vite HMR + reload)
#
# Flags:
#   --tier lite|pro|max  Deployment tier (default: lite). See https://docs.freesdn.org/deploy/deployment-tiers/
#   --dev                Developer mode (dev overlay: source mounts + hot reload)
#   --domain DOMAIN      Public hostname → Caddy auto-HTTPS (Let's Encrypt).
#                        Omit for HTTP on a high port (homelab / behind an LB).
#   --email EMAIL        ACME contact email for Let's Encrypt expiry notices.
#   --ha                 (max only) also start the HA overlay (replica + Sentinel + LB).
#   --no-start           Stop after building images (don't run up).
#   --skip-prereqs       Skip the docker / python checks.
#   -h, --help           Show this message.
#
# Exit codes:
#   0  success - stack is running and the edge /healthz returns 200
#   1  generic failure
#   2  prerequisite missing (docker, python3)
#   3  configuration invalid (bad --tier, --ha without --tier max)
#   4  health check did not pass within the timeout
# ============================================================================

set -euo pipefail

# Generated files may contain database passwords and credential-vault keys.
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Defaults ────────────────────────────────────────────────────────────────
TIER="lite"         # lite | pro | max
DEV=false
DOMAIN=""
EMAIL=""
HA=false
START=true
SKIP_PREREQS=false

# ── Colors ──────────────────────────────────────────────────────────────────
RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
ok()   { printf "${GREEN}[OK]${RESET}    %s\n" "$*"; }
warn() { printf "${YELLOW}[WARN]${RESET}  %s\n" "$*"; }
err()  { printf "${RED}[ERR]${RESET}   %s\n" "$*" >&2; }
info() { printf "${CYAN}[INFO]${RESET}  %s\n" "$*"; }
hdr()  { printf "\n${BOLD}=== %s ===${RESET}\n" "$*"; }
usage() { sed -n '2,/^# ===/p' "$0" | sed 's/^# \?//'; exit "${1:-0}"; }

# ── Parse args ──────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tier)         [[ $# -ge 2 && "$2" != -* && -n "$2" ]] || { err "--tier requires a value"; exit 3; }; TIER="$2"; shift 2 ;;
        --dev)          DEV=true; shift ;;
        --domain)       [[ $# -ge 2 && "$2" != -* && -n "$2" ]] || { err "--domain requires a value"; exit 3; }; DOMAIN="$2"; shift 2 ;;
        --email)        [[ $# -ge 2 && "$2" != -* && -n "$2" ]] || { err "--email requires a value"; exit 3; }; EMAIL="$2"; shift 2 ;;
        --ha)           HA=true; shift ;;
        --no-start)     START=false; shift ;;
        --skip-prereqs) SKIP_PREREQS=true; shift ;;
        -h|--help)      usage ;;
        *) err "unknown flag"; usage 3 ;;
    esac
done

# ── Validate ────────────────────────────────────────────────────────────────
if $DEV; then
    ENV_NAME=".env.dev"
else
    case "$TIER" in
        lite|pro|max) ENV_NAME=".env.$TIER" ;;
        *) err "--tier must be one of: lite, pro, max"; exit 3 ;;
    esac
fi
if $HA && [[ "$TIER" != "max" || "$DEV" == true ]]; then
    err "--ha is only valid with --tier max"
    exit 3
fi
EXAMPLE="${ENV_NAME}.example"

# ── Prereqs ─────────────────────────────────────────────────────────────────
hdr "Prerequisites"
if ! $SKIP_PREREQS; then
    for tool in docker python3; do
        command -v "$tool" >/dev/null 2>&1 || { err "$tool not found in PATH"; exit 2; }
        ok "$tool found"
    done
    docker compose version >/dev/null 2>&1 || { err "'docker compose' v2 not available"; exit 2; }
    ok "docker compose v2 available"
fi

# ── Generate/update private configuration without rotating existing secrets ──
hdr "Configuration ($ENV_NAME)"
CONFIG_ARGS=(--tier "$TIER")
if $DEV; then CONFIG_ARGS+=(--dev); fi
if [[ -n "$DOMAIN" ]]; then CONFIG_ARGS+=(--domain "$DOMAIN"); fi
if [[ -n "$EMAIL" ]]; then CONFIG_ARGS+=(--email "$EMAIL"); fi
python3 "$SCRIPT_DIR/scripts/install_config.py" "${CONFIG_ARGS[@]}"

# ── Compose file selection ───────────────────────────────────────────────────
COMPOSE_ARGS=(--env-file "$ENV_NAME" -f docker-compose.yml)
if $DEV; then
    COMPOSE_ARGS+=(-f docker-compose.dev.yml)
fi
if $HA; then
    COMPOSE_ARGS+=(-f docker-compose.ha.yml)
fi

# ── Build + run ──────────────────────────────────────────────────────────────
hdr "Building images"
docker compose "${COMPOSE_ARGS[@]}" build
ok "Images built"

if ! $START; then
    info "--no-start specified; exiting before container start"
    exit 0
fi

hdr "Starting stack ($([[ $DEV == true ]] && echo dev || echo "$TIER" tier))"
docker compose "${COMPOSE_ARGS[@]}" up -d
ok "Stack started"

# ── Health wait ──────────────────────────────────────────────────────────────
# Read the edge host port from the env file (dev → check the api on 8000).
# An ABSENT key is a NORMAL outcome here, and callers are expected to supply a
# ${VAR:-default} fallback. (An earlier version of this comment claimed EVERY
# caller already did; two did not -- they used `get_env X || echo D`, whose
# branch this `|| true` makes unreachable. Both were converted to value
# fallbacks. If you add a caller, use ${VAR:-default}, never `||`.)
# But `grep` exits 1 when it matches nothing, `pipefail` propagates that through
# the pipeline, and `set -e` then kills the script AT THE ASSIGNMENT, before any
# fallback can run. That is not theoretical: .env.dev.example has no
# CADDY_SITE_ADDRESS, so `./install.sh --dev` exited 1 after starting the
# containers -- no health check, no completion instructions. Trailing `|| true`
# makes "not found" mean empty, for every caller, which is what they all assume.
get_env() { grep -E "^$1=" "$ENV_NAME" 2>/dev/null | tail -1 | cut -d= -f2- || true ; }
SITE_ADDR="$(get_env CADDY_SITE_ADDRESS)"
CURL_RESOLVE=()
# Which URL actually serves the app depends on CADDY_SITE_ADDRESS, and probing
# the wrong one is worse than not probing: Caddy 308s plain HTTP to HTTPS
# whenever the site address is a HOSTNAME, and `curl -sf` returns 0 on a 308
# (--fail only trips on >= 400). So the old fixed http://127.0.0.1:$EDGE_HTTP_PORT
# probe reported "Healthy" on pro and max without ever reaching /healthz -- and a
# bare 308 responder serving nothing at all passes it too. Verified both ways on
# 2026-08-30.
if $DEV; then
    HEALTH_PORT="$(get_env API_HOST_PORT)"; HEALTH_PORT="${HEALTH_PORT:-8000}"
    URL_HEALTH="http://127.0.0.1:${HEALTH_PORT}/api/v1/health"
    APP_URL="http://localhost:${HEALTH_PORT}"
elif [[ -z "$SITE_ADDR" || "$SITE_ADDR" == :* ]]; then
    # ":80" style -> plain HTTP on the mapped edge port (the lite default)
    HEALTH_PORT="$(get_env EDGE_HTTP_PORT)"; HEALTH_PORT="${HEALTH_PORT:-8080}"
    URL_HEALTH="http://127.0.0.1:${HEALTH_PORT}/healthz"
    APP_URL="http://localhost:${HEALTH_PORT}"
else
    # a hostname -> Caddy serves HTTPS there and redirects plain HTTP to it.
    # --resolve so this works before public DNS exists; -k because the cert is
    # either Caddy's internal CA (localhost) or not issued yet (a real domain).
    # 8443, not 443: this fallback has to mirror what COMPOSE publishes, and
    # docker-compose.yml:755 maps "${EDGE_HTTPS_PORT:-8443}:443". With the key
    # absent, compose listens on 8443 while probing 443 finds nothing, so a
    # perfectly healthy edge times the installer out after four minutes (exit 4).
    # The shipped pro/max templates set it to 443 explicitly, so they are
    # unaffected either way; this is the omitted-key path.
    HEALTH_PORT="$(get_env EDGE_HTTPS_PORT)"; HEALTH_PORT="${HEALTH_PORT:-8443}"
    URL_HEALTH="https://${SITE_ADDR}:${HEALTH_PORT}/healthz"
    CURL_RESOLVE=(--resolve "${SITE_ADDR}:${HEALTH_PORT}:127.0.0.1")
    if [[ "$HEALTH_PORT" == "443" ]]; then
        APP_URL="https://${SITE_ADDR}"
    else
        APP_URL="https://${SITE_ADDR}:${HEALTH_PORT}"
    fi
fi

hdr "Waiting for the edge to answer ($URL_HEALTH)"
DEADLINE=$(( $(date +%s) + 240 ))
while true; do
    # Require a real 200. See the note above on why `curl -sf` is not enough.
    HEALTH_CODE="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10         ${CURL_RESOLVE[@]+"${CURL_RESOLVE[@]}"} "$URL_HEALTH" 2>/dev/null || echo 000)"
    if [[ "$HEALTH_CODE" == "200" ]]; then
        ok "Healthy at $URL_HEALTH"
        break
    fi
    if (( $(date +%s) > DEADLINE )); then
        err "Timed out waiting for $URL_HEALTH (4 min; last status: $HEALTH_CODE)"
        docker compose "${COMPOSE_ARGS[@]}" ps
        exit 4
    fi
    printf "."; sleep 3
done
echo

# ── Final report ─────────────────────────────────────────────────────────────
hdr "FreeSDN is up"
if $DEV; then
    # Value fallbacks, NOT `get_env ... || echo`: get_env now ends in `|| true`
    # (so an absent key cannot kill the script under set -e), which means it
    # always exits 0 and the `||` branch is dead. These two printed
    # "http://localhost:" with no port when .env.dev omitted the keys. Reading
    # into a variable also covers an explicitly EMPTY value, which `||` never did.
    DEV_FE_PORT="$(get_env FRONTEND_HOST_PORT)"; DEV_FE_PORT="${DEV_FE_PORT:-5173}"
    DEV_API_PORT="$(get_env API_HOST_PORT)"; DEV_API_PORT="${DEV_API_PORT:-8000}"
    echo "  Frontend (Vite): http://localhost:${DEV_FE_PORT}"
    echo "  API:             http://localhost:${DEV_API_PORT}"
else
    # Print the URL that actually works. This used to print
    # http://localhost:$HEALTH_PORT unconditionally, which on pro and max is a
    # 308 to HTTPS -- and then advised setting CADDY_SITE_ADDRESS=localhost,
    # which those tiers' env files already set.
    echo "  URL:  $APP_URL"
    if [[ -z "$SITE_ADDR" || "$SITE_ADDR" == :* ]]; then
        echo "  (HTTP only. For HTTPS set CADDY_SITE_ADDRESS to localhost or your"
        echo "   domain in $ENV_NAME and re-up.)"
    elif [[ "$SITE_ADDR" == "localhost" ]]; then
        echo "  (HTTPS via Caddy's internal CA, so your browser will warn until you"
        echo "   trust it. Set your domain in $ENV_NAME for a public certificate.)"
    else
        echo "  (Caddy is obtaining the certificate now. This needs port 80 and 443"
        echo "   reachable from the internet and DNS pointing here.)"
    fi
fi
echo
echo "  First-run wizard: open the URL above to create the admin user."
echo
echo "  Useful commands:"
echo "    docker compose ${COMPOSE_ARGS[*]} logs -f      # tail logs"
echo "    docker compose ${COMPOSE_ARGS[*]} ps           # container status"
echo "    docker compose ${COMPOSE_ARGS[*]} down         # stop stack"
echo
echo "  See https://docs.freesdn.org/deploy/deployment-tiers/ for tiers, profiles, and TLS options."
echo
