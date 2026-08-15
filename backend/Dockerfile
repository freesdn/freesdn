# FreeSDN Backend Dockerfile
# Enterprise-grade Debian Trixie base - security-first
# Python 3.14 + FastAPI latest + full apt security patches

# ============================================
# Stage 1: Base Python image with Poetry
# ============================================
FROM python:3.14.6-slim-trixie AS python-base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_VERSION=2.4.1 \
    POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1 \
    PYSETUP_PATH="/opt/pysetup" \
    VENV_PATH="/opt/pysetup/.venv"

# The APP venv must precede Poetry's own venv on PATH. The development stage
# copies $POETRY_HOME in (production does not), and every venv ships a `python`
# — so with Poetry first, a bare `python` resolves to Poetry's interpreter,
# which has none of the app's dependencies. That silently broke
# `python scripts/migrate.py` (docker-entrypoint.sh:8) and scripts/ci-gate.sh
# in the development image, while production stayed fine because
# $POETRY_HOME/bin simply does not exist there.
# `poetry` is still resolved from $POETRY_HOME/bin (the app venv has no poetry
# executable), so ordering it second costs nothing.
ENV PATH="$VENV_PATH/bin:$POETRY_HOME/bin:$PATH"

# ============================================
# Stage 2: Builder - Install dependencies
# ============================================
FROM python-base AS builder-base

RUN apt-get update && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y \
    curl \
    build-essential \
    libpq-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry (W06-REL-002): install the pinned version from PyPI into an
# isolated venv at $POETRY_HOME instead of piping an unauthenticated remote
# installer script into the interpreter. The old pipe-to-python approach ran
# whatever the installer host/CDN returned (no hash/signature on the script
# body), which would be build-time RCE that poisons the signed production image.
# pip validates the poetry wheel against PyPI's recorded hashes, and
# POETRY_VERSION (set above) pins the exact version. The venv is copied as
# $POETRY_HOME into the dev stage.
RUN python3 -m venv "$POETRY_HOME" \
    && "$POETRY_HOME/bin/pip" install --no-cache-dir "poetry==${POETRY_VERSION}" \
    && ln -sf "$POETRY_HOME/bin/poetry" /usr/local/bin/poetry

WORKDIR $PYSETUP_PATH
COPY pyproject.toml poetry.lock* ./

# Install runtime dependencies only (poetry.lock ensures deterministic builds)
RUN poetry install --only main --no-root

# ============================================
# Stage 3: Development image
# ============================================
FROM python-base AS development

# Install system deps + Tailscale VPN agent + full security patches
RUN apt-get update && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y \
    libpq5 \
    ffmpeg \
    curl \
    git \
    iptables \
    iproute2 \
    iputils-ping \
    gnupg \
    && curl -fsSL https://pkgs.tailscale.com/stable/debian/trixie.noarmor.gpg | tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null \
    && curl -fsSL https://pkgs.tailscale.com/stable/debian/trixie.tailscale-keyring.list | tee /etc/apt/sources.list.d/tailscale.list \
    && apt-get update \
    && apt-get install --no-install-recommends -y tailscale \
    && rm -rf /var/lib/apt/lists/*

# Tailscale state directory (will be mounted as volume)
RUN mkdir -p /var/lib/tailscale /var/run/tailscale

# Create non-root user for development
RUN addgroup --system --gid 1001 appgroup \
    && adduser --system --uid 1001 --gid 1001 appuser \
    && chown -R appuser:appgroup /var/lib/tailscale /var/run/tailscale

WORKDIR $PYSETUP_PATH

# Copy poetry and venv from builder
COPY --from=builder-base $POETRY_HOME $POETRY_HOME
COPY --from=builder-base $PYSETUP_PATH $PYSETUP_PATH

# Install dev dependencies
RUN poetry install --no-root

WORKDIR /app
COPY . .

# Create directories that need to be writable by appuser
RUN mkdir -p /app/celerybeat /data/freesdn_firmware \
    && chown -R appuser:appgroup /app /data

# Install the project
RUN poetry install --only-root

# NOTE: Non-root user is used in production stage below.
# Development stage runs as root because tailscaled and alembic require it.
# The docker-compose command drops to appuser after init tasks where possible.

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload", "--reload-dir", "/app/app"]

# ============================================
# Stage 4: Production image
# ============================================
FROM python-base AS production

RUN apt-get update && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y \
    libpq5 \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/* \
    && addgroup --system --gid 1001 appgroup \
    && adduser --system --uid 1001 --gid 1001 appuser

# ── VPN overlay binaries — Tailscale + NetBird + OpenVPN ────────────────────
# FreeSDN's site-to-site / remote-agent overlay shells out to these CLIs/daemons
# (app/services/vpn_integration.py). They MUST be in the PRODUCTION image, not
# just the dev stage, or every VPN feature reports "not installed in this
# container".
#
# We DELIBERATELY do NOT setcap these binaries. In the shipped topology the
# privileged `vpn` sidecar runs the daemons AS ROOT (user 0:0 + cap_add
# NET_ADMIN + /dev/net/tun), so they create tun devices without any file
# capabilities. Conversely the api/worker containers run these as plain CLIs
# (`tailscale up`, `netbird status`, …) under `no-new-privileges:true` — and a
# binary carrying file capabilities CANNOT be exec'd there (the kernel returns
# EPERM, "Operation not permitted"). setcap would therefore be both unnecessary
# (the sidecar is root) AND actively break the api's ability to drive the VPN.
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        curl gnupg ca-certificates iproute2 iptables iputils-ping \
        openvpn wireguard-tools \
    && curl -fsSL https://pkgs.tailscale.com/stable/debian/trixie.noarmor.gpg \
        | tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null \
    && curl -fsSL https://pkgs.tailscale.com/stable/debian/trixie.tailscale-keyring.list \
        | tee /etc/apt/sources.list.d/tailscale.list >/dev/null \
    && curl -fsSL https://pkgs.netbird.io/debian/public.key \
        | gpg --dearmor -o /usr/share/keyrings/netbird-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/netbird-archive-keyring.gpg] https://pkgs.netbird.io/debian stable main" \
        | tee /etc/apt/sources.list.d/netbird.list >/dev/null \
    && apt-get update \
    && apt-get install --no-install-recommends -y tailscale netbird \
    && rm -rf /var/lib/apt/lists/*

# VPN state / config / run dirs, owned by the non-root appuser so the daemons
# (started by the entrypoint) and the openvpn processes (spawned by the app) can
# write their state, pidfiles and logs.
RUN mkdir -p \
        /var/lib/tailscale /var/run/tailscale \
        /etc/openvpn/client /run/openvpn-client /var/log/openvpn \
        /etc/wireguard /run/wireguard \
        /etc/netbird /var/lib/netbird \
    && chown -R appuser:appgroup \
        /var/lib/tailscale /var/run/tailscale \
        /etc/openvpn /run/openvpn-client /var/log/openvpn \
        /etc/wireguard /run/wireguard \
        /etc/netbird /var/lib/netbird

COPY --from=builder-base $VENV_PATH $VENV_PATH

WORKDIR /app
COPY --chown=appuser:appgroup app ./app
COPY --chown=appuser:appgroup alembic ./alembic
COPY --chown=appuser:appgroup alembic.ini ./alembic.ini
COPY --chown=appuser:appgroup docker-entrypoint.sh ./docker-entrypoint.sh
# The privileged `vpn` sidecar reuses THIS image but overrides the entrypoint to
# run only the VPN daemons + openvpn supervisor (see docker-compose `vpn` svc).
COPY --chown=appuser:appgroup vpn-sidecar-entrypoint.sh ./vpn-sidecar-entrypoint.sh
COPY --chown=appuser:appgroup scripts/migrate.py ./scripts/migrate.py
# docker-entrypoint.sh runs BOTH migrate.py and migrate_logdb.py under `set -e`;
# omitting migrate_logdb.py made the prod api container crash-loop on startup
# (python: can't open file 'scripts/migrate_logdb.py') before gunicorn ever ran.
COPY --chown=appuser:appgroup scripts/migrate_logdb.py ./scripts/migrate_logdb.py

# Create writable directories for appuser (celerybeat schedule, plus the
# persistent /data subdirs that get backed by named volumes at runtime). Owning
# these in the image is what makes them WRITABLE once a fresh named volume is
# mounted over them: Docker initializes an empty named volume from the image
# directory at the mountpoint, inheriting its appuser:appgroup ownership. Without
# this, the volume root is root-owned and the non-root appuser (uid 1001) cannot
# mkdir/write - e.g. the agent release-signing key store 500s on a fresh deploy.
RUN mkdir -p \
        /app/celerybeat /app/scripts \
        /data/agent-releases /data/proxmox-uploads \
        /data/fabric_artifacts /data/evidence /data/freesdn_firmware \
    && chown -R appuser:appgroup /app/celerybeat /app/scripts /data

# Fix line endings and make entrypoint executable
RUN sed -i 's/\r$//' docker-entrypoint.sh vpn-sidecar-entrypoint.sh \
    && chmod +x docker-entrypoint.sh vpn-sidecar-entrypoint.sh

USER appuser

# ── Reverse-proxy trust (SECURITY) ─────────────────────────────────────────
# Gunicorn only trusts X-Forwarded-* headers from the IPs listed here. If a
# request comes from an untrusted IP, Gunicorn/uvicorn will NOT rewrite
# request.client.host from X-Forwarded-For, which protects the per-IP rate
# limiter (see app/api/v1/endpoints/auth.py) from header-spoofing attacks.
#
# Default is the loopback address, which is safe when running the image
# standalone (no proxy trust). Operators MUST override this to point at the
# actual reverse proxy IP / CIDR in production. NEVER set to "*".
ENV FORWARDED_ALLOW_IPS=127.0.0.1

EXPOSE 8000

ENTRYPOINT ["/app/docker-entrypoint.sh"]

# Entrypoint runs migrations and starts gunicorn with elastic config from env vars.
# CMD is not used - the entrypoint exec's gunicorn directly.
# If you override ENTRYPOINT, this CMD provides a safe fallback that honours
# the FORWARDED_ALLOW_IPS env var (default 127.0.0.1, NEVER "*").
CMD ["sh", "-c", "if [ \"${FORWARDED_ALLOW_IPS}\" = '*' ]; then echo '[cmd] FATAL: FORWARDED_ALLOW_IPS=* is forbidden (X-Forwarded-For spoofing).' >&2; exit 1; fi; exec gunicorn app.main:app -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000 --forwarded-allow-ips=\"${FORWARDED_ALLOW_IPS:-127.0.0.1}\" --no-control-socket --access-logfile -"]
