# FreeSDN Backend Dockerfile
# Patched Alpine runtime; keep build tools out of the deployed image.
# Python 3.14 with the committed Poetry dependency graph

# ============================================
# Stage 1: Base Python image with Poetry
# ============================================
# Tailscale source and its patched module graph are checksum-locked separately.
FROM golang:1.27.3-alpine3.24 AS tailscale-builder
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /build
COPY tailscale-build/go.mod tailscale-build/go.sum ./
RUN go mod download all && go mod verify
RUN go build -mod=readonly -trimpath \
    -ldflags="-s -w -X tailscale.com/version.longStamp=1.102.4-freesdn -X tailscale.com/version.shortStamp=1.102.4" \
    -o /out/ tailscale.com/cmd/tailscale tailscale.com/cmd/tailscaled tailscale.com/cmd/containerboot

# Optional private-access image. No Python, media stack or app credentials.
FROM alpine:3.24 AS tailscale-access
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates iptables ip6tables iproute2
COPY --from=tailscale-builder /out/ /usr/local/bin/
COPY tailscale-build/LICENSE tailscale-build/NOTICE /usr/share/licenses/tailscale/
RUN mkdir -p /var/lib/tailscale /tailscale \
    && ln -s /usr/local/bin/containerboot /tailscale/run.sh
ENTRYPOINT ["/usr/local/bin/containerboot"]

FROM golang:1.27.3-alpine3.24 AS netbird-builder
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /build
COPY netbird-build/go.mod netbird-build/go.sum ./
RUN go mod download all && go mod verify
COPY netbird-build/ ./
# Preserve NetBird routing hooks while using fixed STUN/DTLS dependencies and
# removing the legacy TURN/DTLS v2 path. Patches reject unreviewed source hashes.
# The compiler is only for race detection in this builder; runtime stays static.
RUN apk add --no-cache build-base \
    && go mod vendor && go run -mod=vendor ./prepare.go \
    && CGO_ENABLED=1 go test -mod=vendor -race -count=3 -timeout=120s \
       github.com/netbirdio/netbird/client/internal/relay
RUN go build -mod=vendor -trimpath \
    -ldflags="-s -w -X github.com/netbirdio/netbird/version.version=0.79.0-freesdn" \
    -o /out/netbird github.com/netbirdio/netbird/client

# Signed upstream stable media build; stable Alpine dependencies only.
FROM alpine:3.24 AS ffmpeg-builder
WORKDIR /build
COPY ffmpeg-build/ ./
RUN sh /build/build.sh

FROM python:3.15.0-alpine3.24 AS python-base
# Exact upstream security backports; unknown Python source fails the build.
COPY python-security/ /usr/local/share/freesdn/python-security/
RUN python -B /usr/local/share/freesdn/python-security/apply_backports.py \
    && python -B /usr/local/share/freesdn/python-security/apply_backports.py --verify
RUN apk upgrade --no-cache

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_VERSION=2.5.1 \
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

RUN apk add --no-cache build-base libffi-dev openssl-dev postgresql-dev git

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
COPY pyproject.toml poetry.lock* README ./

# Install runtime dependencies only (poetry.lock ensures deterministic builds)
RUN poetry check --lock \
    && poetry install --only main --no-root

# ============================================
# Stage 3: Development image
# ============================================
FROM python-base AS development

RUN apk add --no-cache libpq curl git iptables ip6tables iproute2 iputils \
    openvpn wireguard-tools bash ca-certificates tzdata openresolv \
    && addgroup -S -g 1001 appgroup \
    && adduser -S -D -H -u 1001 -G appgroup appuser \
    && mkdir -p /var/lib/tailscale /var/run/tailscale \
    && chown -R appuser:appgroup /var/lib/tailscale /var/run/tailscale
COPY --from=tailscale-builder /out/tailscale /out/tailscaled /usr/local/bin/
COPY --from=netbird-builder /out/netbird /usr/local/bin/netbird
COPY --from=ffmpeg-builder /out/ /
RUN sh /usr/share/freesdn-sources/ffmpeg/install-runtime.sh

WORKDIR $PYSETUP_PATH

# Copy poetry and venv from builder
COPY --from=builder-base $POETRY_HOME $POETRY_HOME
COPY --from=builder-base $PYSETUP_PATH $PYSETUP_PATH

# Install dev dependencies
RUN poetry install --no-root

WORKDIR /app
COPY . .

# Create directories that need to be writable by appuser
RUN mkdir -p /app/celerybeat /data/freesdn_firmware /tmp/freesdn-hls \
    && chown -R appuser:appgroup /app /data /tmp/freesdn-hls \
    && chmod 0700 /tmp/freesdn-hls

# Source is imported from /app; the public export omits the private README
# referenced by the package metadata, so do not install the root package here.

# NOTE: Non-root user is used in production stage below.
# Development stage runs as root because tailscaled and alembic require it.
# The docker-compose command drops to appuser after init tasks where possible.

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload", "--reload-dir", "/app/app"]

# ============================================
# Stage 4: Production image
# ============================================
FROM python-base AS production

# Preserve the existing app UID and VPN CLI/socket contract. VPN daemons run
# only in the explicitly privileged sidecar; no binary receives file capabilities.
RUN apk add --no-cache libpq curl iproute2 iptables ip6tables iputils \
    openvpn wireguard-tools bash ca-certificates tzdata openresolv \
    && addgroup -S -g 1001 appgroup \
    && adduser -S -D -H -u 1001 -G appgroup appuser
COPY --from=tailscale-builder /out/tailscale /out/tailscaled /usr/local/bin/
COPY --from=netbird-builder /out/netbird /usr/local/bin/netbird
COPY --from=ffmpeg-builder /out/ /
RUN sh /usr/share/freesdn-sources/ffmpeg/install-runtime.sh
COPY tailscale-build/LICENSE tailscale-build/NOTICE /usr/share/licenses/tailscale/
COPY netbird-build/LICENSE netbird-build/NOTICE /usr/share/licenses/netbird/

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
# Optional plugin installs use the locked uv binary in the app environment.
# Remove pip and its embedded bootstrap wheel from BOTH interpreter locations;
# venv --without-pip still works without ensurepip and does not restore old code.
RUN "$VENV_PATH/bin/python" -m pip uninstall -y pip \
    && /usr/local/bin/python -m pip uninstall -y pip \
    && rm -rf /usr/local/lib/python3.14/ensurepip

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
COPY --chown=appuser:appgroup scripts/migration_lock.py ./scripts/migration_lock.py
COPY --chown=appuser:appgroup scripts/encrypt_vpn_site_configs.py ./scripts/encrypt_vpn_site_configs.py

# Create writable directories for appuser (celerybeat schedule, plus the
# persistent /data subdirs that get backed by named volumes at runtime). Owning
# these in the image is what makes them WRITABLE once a fresh named volume is
# mounted over them: Docker initializes an empty named volume from the image
# directory at the mountpoint, inheriting its appuser:appgroup ownership. Without
# this, the volume root is root-owned and the non-root appuser (uid 1001) cannot
# mkdir/write - e.g. the agent release-signing key store 500s on a fresh deploy.
#
# /tmp/freesdn_data is here for the same reason even though it is not under
# /data: app/services/import_export.py hardcodes it and the compose files mount
# a named volume there (nested under the tmpfs) so the api and the worker share
# one directory. Without this line that volume root is root-owned too.
RUN mkdir -p \
        /app/celerybeat /app/scripts \
        /data/agent-releases /data/proxmox-uploads \
        /data/fabric_artifacts /data/evidence /data/freesdn_firmware \
        /data/plugins /data/backups /data/sla_reports \
        /data/provisioning/voip /tmp/freesdn_data /tmp/freesdn-hls \
    && chown -R appuser:appgroup /app/celerybeat /app/scripts /data /tmp/freesdn_data /tmp/freesdn-hls \
    && chmod 0700 /tmp/freesdn-hls

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
