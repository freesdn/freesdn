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
#   0  success - stack is running and the edge /health returns 200
#   1  generic failure
#   2  prerequisite missing (docker, python3)
#   3  configuration invalid (bad --tier, --ha without --tier max)
#   4  health check did not pass within the timeout
# ============================================================================

set -euo pipefail

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
usage() { sed -n '2,/^# ===/p' "$0" | sed 's/^# \?//'; exit 0; }

# ── Parse args ──────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tier)         TIER="$2"; shift 2 ;;
        --dev)          DEV=true; shift ;;
        --domain)       DOMAIN="$2"; shift 2 ;;
        --email)        EMAIL="$2"; shift 2 ;;
        --ha)           HA=true; shift ;;
        --no-start)     START=false; shift ;;
        --skip-prereqs) SKIP_PREREQS=true; shift ;;
        -h|--help)      usage ;;
        *) err "unknown flag: $1"; usage ;;
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

# ── Generate the tier env file from its template ─────────────────────────────
hdr "Configuration ($ENV_NAME)"
GENERATED=0
if [[ ! -f "$ENV_NAME" ]]; then
    [[ -f "$EXAMPLE" ]] || { err "template $EXAMPLE not found"; exit 1; }
    info "Generating $ENV_NAME from $EXAMPLE with random secrets…"
    SRC="$EXAMPLE" DST="$ENV_NAME" python3 <<'PYEOF'
import os, secrets, string
from pathlib import Path

def rand_pw(n=24):
    alpha = string.ascii_letters + string.digits
    return "".join(secrets.choice(alpha) for _ in range(n))

src = Path(os.environ["SRC"]).read_text(encoding="utf-8")
out = []
for line in src.splitlines():
    s = line.strip()
    if not s or s.startswith("#") or "=" not in s:
        out.append(line); continue
    key, _, val = s.partition("=")
    key, val = key.strip(), val.strip()
    if "__CHANGE_ME__" in val:
        if key == "SECRET_KEY":
            val = secrets.token_urlsafe(48)
        elif key == "FLOWER_BASIC_AUTH":
            val = f"admin:{rand_pw(20)}"
        else:
            val = rand_pw(32)
    out.append(f"{key}={val}")
Path(os.environ["DST"]).write_text("\n".join(out) + "\n", encoding="utf-8")
print(f"Generated {os.environ['DST']} ({len(out)} lines)")
PYEOF
    ok "$ENV_NAME generated with random secrets"
    GENERATED=1
else
    ok "$ENV_NAME already present - leaving it alone"
fi

# ── Apply --domain (Caddy auto-HTTPS) ────────────────────────────────────────
if [[ -n "$DOMAIN" ]]; then
    info "Configuring Caddy auto-HTTPS for $DOMAIN…"
    DOMAIN="$DOMAIN" EMAIL="$EMAIL" ENVF="$ENV_NAME" python3 <<'PYEOF'
import os
from pathlib import Path
d, e, f = os.environ["DOMAIN"], os.environ.get("EMAIL", ""), os.environ["ENVF"]
overrides = {
    "CADDY_SITE_ADDRESS": d,
    "EDGE_HTTP_PORT": "80",
    "EDGE_HTTPS_PORT": "443",
    "PUBLIC_BASE_URL": f"https://{d}",
    "CORS_ORIGINS": f'["https://{d}"]',
}
if e:
    overrides["CADDY_ACME_EMAIL"] = e
p = Path(f)
lines = p.read_text(encoding="utf-8").splitlines()
seen = set(); out = []
for line in lines:
    if "=" in line and not line.lstrip().startswith("#"):
        k = line.split("=", 1)[0].strip()
        if k in overrides:
            out.append(f"{k}={overrides[k]}"); seen.add(k); continue
    out.append(line)
for k, v in overrides.items():
    if k not in seen:
        out.append(f"{k}={v}")
p.write_text("\n".join(out) + "\n", encoding="utf-8")
PYEOF
    ok "Caddy will auto-obtain a Let's Encrypt cert for $DOMAIN (needs ports 80+443 + public DNS)"
elif [[ "$GENERATED" == "1" && "$TIER" != "lite" ]]; then
    # No --domain on a fresh pro/max install: the template ships a placeholder
    # CADDY_SITE_ADDRESS (a real domain) which makes the edge unreachable on
    # localhost (it 308-redirects to HTTPS for a domain that does not match
    # 127.0.0.1). Default to localhost so the box is usable out of the box;
    # the operator sets a real domain (or re-runs with --domain) for production.
    info "No --domain given; defaulting CADDY_SITE_ADDRESS=localhost for this local $TIER install…"
    ENVF="$ENV_NAME" python3 <<'PYEOF'
import os
from pathlib import Path
f = os.environ["ENVF"]
overrides = {
    "CADDY_SITE_ADDRESS": "localhost",
    "PUBLIC_BASE_URL": "https://localhost",
    "CORS_ORIGINS": '["https://localhost"]',
}
p = Path(f)
lines = p.read_text(encoding="utf-8").splitlines()
seen = set(); out = []
for line in lines:
    if "=" in line and not line.lstrip().startswith("#"):
        k = line.split("=", 1)[0].strip()
        if k in overrides:
            out.append(f"{k}={overrides[k]}"); seen.add(k); continue
    out.append(line)
for k, v in overrides.items():
    if k not in seen:
        out.append(f"{k}={v}")
p.write_text("\n".join(out) + "\n", encoding="utf-8")
PYEOF
    ok "CADDY_SITE_ADDRESS=localhost (HTTPS via Caddy internal CA). Set your domain in $ENV_NAME (or re-run with --domain) for production."
fi

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
get_env() { grep -E "^$1=" "$ENV_NAME" 2>/dev/null | tail -1 | cut -d= -f2- ; }
if $DEV; then
    HEALTH_PORT="$(get_env API_HOST_PORT)"; HEALTH_PORT="${HEALTH_PORT:-8000}"
    HEALTH_PATH="/api/v1/health"
else
    HEALTH_PORT="$(get_env EDGE_HTTP_PORT)"; HEALTH_PORT="${HEALTH_PORT:-8080}"
    HEALTH_PATH="/health"
fi
URL_HEALTH="http://127.0.0.1:${HEALTH_PORT}${HEALTH_PATH}"

hdr "Waiting for the edge to answer ($URL_HEALTH)"
DEADLINE=$(( $(date +%s) + 240 ))
while true; do
    if curl -sf "$URL_HEALTH" >/dev/null 2>&1; then
        ok "Healthy at $URL_HEALTH"
        break
    fi
    if (( $(date +%s) > DEADLINE )); then
        err "Timed out waiting for $URL_HEALTH (4 min)"
        docker compose "${COMPOSE_ARGS[@]}" ps
        exit 4
    fi
    printf "."; sleep 3
done
echo

# ── Final report ─────────────────────────────────────────────────────────────
hdr "FreeSDN is up"
if $DEV; then
    echo "  Frontend (Vite): http://localhost:$(get_env FRONTEND_HOST_PORT || echo 5173)"
    echo "  API:             http://localhost:$(get_env API_HOST_PORT || echo 8000)"
elif [[ -n "$DOMAIN" ]]; then
    echo "  URL:  https://$DOMAIN   (Caddy is obtaining the certificate now)"
else
    echo "  URL:  http://localhost:${HEALTH_PORT}"
    echo "  (For HTTPS set CADDY_SITE_ADDRESS=localhost or your domain in $ENV_NAME and re-up.)"
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
