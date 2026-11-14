#!/bin/sh
# FreeSDN Backend - Production Entrypoint
# Runs database migrations, configures Gunicorn for the host machine,
# then starts the application server.
set -e

echo "[entrypoint] Running database migrations..."
python scripts/migrate.py

echo "[entrypoint] Running LogDB (TimescaleDB) migration..."
python scripts/migrate_logdb.py

# ── VPN overlay daemons (OPT-IN; default OFF — the `vpn` SIDECAR owns them) ───
# In the shipped topology a dedicated privileged `vpn` container runs tailscaled
# + the NetBird daemon + the OpenVPN supervisor, and api/worker share its network
# namespace (docker-compose `network_mode: "service:vpn"`) — so these hardened,
# non-root, read-only app containers do NOT run VPN daemons themselves. This block
# only fires if FREESDN_VPN_AUTOSTART=true (an all-in-one single-container deploy
# that has the binaries + NET_ADMIN + /dev/net/tun). Backgrounded + `|| true` so a
# daemon that can't start degrades the VPN feature to "not connected", never a
# crash-loop.
if [ "${FREESDN_VPN_AUTOSTART:-false}" = "true" ]; then
    echo "[entrypoint] Starting supervised tailscaled (userspace-networking)..."
    python -m app.tailscaled_supervisor --detach || true
    if command -v netbird >/dev/null 2>&1; then
        echo "[entrypoint] Starting netbird daemon..."
        ( netbird service run >/var/lib/netbird/netbird.log 2>&1 || true ) &
    fi
elif [ "${TAILSCALE_RUNTIME:-}" = "container" ]; then
    # ── Tailscale runs in its own container (docker-compose `tailscale`) ─────
    # The runtime container owns tailscaled and its node state, starts it once
    # Tailscale is in use, and Docker restarts it. Nothing to start here: this
    # container only has the socket volume, and drives tailscaled through it.
    :
else
    # ── Capless Tailscale in this container (outside the shipped compose) ────
    # Once Tailscale has been started in this deployment its node state lives
    # in the tailscale_state volume, so bring the daemon back on every api
    # start instead of leaving the node offline until someone clicks Connect
    # again. A no-op when never enrolled, in VPN sidecar mode (the vpn
    # container owns tailscaled), or when the binary or volumes are absent.
    # The supervisor detaches, restarts tailscaled if it exits, logs to
    # /var/lib/tailscale/tailscaled.log, and is shared safely with a second
    # api replica (one daemon per state volume, flock).
    python -m app.tailscaled_supervisor --detach --if-enrolled || true
fi

# ── Gunicorn elastic configuration ──────────────────────────────────────────
# All tunables default to conservative values suitable for a small controller.
# Override via environment variables in docker-compose / .env for larger hardware.
export WEB_CONCURRENCY="${WEB_CONCURRENCY:-2}"
export GUNICORN_MAX_REQUESTS="${GUNICORN_MAX_REQUESTS:-1000}"
export GUNICORN_MAX_REQUESTS_JITTER="${GUNICORN_MAX_REQUESTS_JITTER:-50}"
export GUNICORN_GRACEFUL_TIMEOUT="${GUNICORN_GRACEFUL_TIMEOUT:-30}"
export GUNICORN_TIMEOUT="${GUNICORN_TIMEOUT:-120}"
export GUNICORN_KEEP_ALIVE="${GUNICORN_KEEP_ALIVE:-5}"

# SECURITY: Gunicorn only trusts X-Forwarded-* headers from these IPs.
# Anything not in this list cannot spoof X-Forwarded-For to defeat the
# per-IP rate limiter in app/api/v1/endpoints/auth.py. Default is
# loopback-only; docker-compose sets the compose network CIDR so the
# nginx sidecar is trusted. NEVER set to "*" in production.
export FORWARDED_ALLOW_IPS="${FORWARDED_ALLOW_IPS:-127.0.0.1}"

if [ "$FORWARDED_ALLOW_IPS" = "*" ]; then
    echo "[entrypoint] FATAL: FORWARDED_ALLOW_IPS=* is forbidden - it allows"
    echo "[entrypoint]        X-Forwarded-For spoofing and defeats the rate limiter."
    echo "[entrypoint]        Set it to the reverse-proxy IP or CIDR block."
    exit 1
fi

echo "[entrypoint] Gunicorn: workers=$WEB_CONCURRENCY, max-requests=$GUNICORN_MAX_REQUESTS, timeout=$GUNICORN_TIMEOUT"
echo "[entrypoint] Trusting X-Forwarded-* from: $FORWARDED_ALLOW_IPS"
echo "[entrypoint] Starting application..."
exec gunicorn app.main:app \
    -k uvicorn.workers.UvicornWorker \
    -b 0.0.0.0:8000 \
    --workers "$WEB_CONCURRENCY" \
    --max-requests "$GUNICORN_MAX_REQUESTS" \
    --max-requests-jitter "$GUNICORN_MAX_REQUESTS_JITTER" \
    --graceful-timeout "$GUNICORN_GRACEFUL_TIMEOUT" \
    --timeout "$GUNICORN_TIMEOUT" \
    --keep-alive "$GUNICORN_KEEP_ALIVE" \
    --forwarded-allow-ips="$FORWARDED_ALLOW_IPS" \
    --no-control-socket \
    --access-logfile -
