# FreeSDN Frontend Dockerfile
# Node LTS build; patched Alpine production runtime
# Multi-stage build for development and production

# ============================================
# Stage 1: Base Node image (Trixie)
# ============================================
# Release policy: stay on Node 24 LTS; qualify LTS major migrations explicitly.
FROM node:24.22.1-trixie-slim AS base
RUN npm install -g npm@12.2.0
WORKDIR /app

# ============================================
# Stage 2: Development image
# ============================================
FROM base AS development

# Install dependencies (.npmrc carries legacy-peer-deps=true - see that file)
COPY package.json package-lock.json* .npmrc* ./
RUN npm install --legacy-peer-deps

# Copy source code
COPY . .

EXPOSE 5173

# Start development server
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

# ============================================
# Stage 3: Build stage
# ============================================
FROM base AS builder

# Prevent tsc OOM during build (305k LOC codebase)
ENV NODE_OPTIONS="--max-old-space-size=4096"

# Install dependencies. --legacy-peer-deps (also in .npmrc) because
# openapi-typescript@7.x peer-pins typescript@^5.x while the project tracks
# typescript@^6; the lockfile is resolved under that flag, so a bare `npm ci`
# fails ERESOLVE. Copy .npmrc first so it's honored at install time.
COPY package.json package-lock.json* .npmrc* ./
RUN npm ci --legacy-peer-deps

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Rebuild the released Caddy source with a patched Go toolchain and dependency
# graph. apk upgrade cannot replace libraries compiled into the upstream binary.
# go.sum verifies downloaded modules; -mod=readonly forbids resolution at build.
FROM golang:1.27.3-alpine3.24 AS caddy-builder
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /build
COPY caddy-build/go.mod caddy-build/go.sum ./
RUN go mod download && go mod verify
COPY caddy-build/ ./
# Patch a private, checksum-verified vendor tree. Module versions remain in the
# binary inventory; no shared module-cache files or upstream imports are changed.
RUN go mod vendor && go run -mod=vendor ./prepare.go \
    && go test -mod=vendor . \
    && go build -mod=vendor -trimpath \
       -ldflags="-s -w -X github.com/caddyserver/caddy/v2.CustomVersion=v2.11.4-freesdn" \
       -o /usr/bin/caddy .

# ============================================
# Stage 4: Production image with Nginx (Alpine)
# Uses the official NGINX stable branch with current Alpine security patches.
# Keep the explicit patch version aligned with the upstream stable/security
# advisories and the HA proxy default; do not silently switch release channels.
# Non-root 'nginx' user for security hardening.
# ============================================
# The patched Alpine variant avoids Debian media/system packages that have
# unresolved advisories. Preserve UID/GID 999 for existing Compose tmpfs mounts.
FROM nginx:1.30.6-alpine AS production
RUN apk upgrade --no-cache && apk add --no-cache curl \
    && deluser nginx \
    && delgroup ping \
    && addgroup -S -g 999 nginx \
    && adduser -S -D -H -u 999 -G nginx nginx

# Prepare for non-root operation.
# The nginx.org package creates a 'nginx' user/group automatically.
# We disable the 'user' directive (not needed when master runs as
# non-root) and fix directory ownership so nginx can write temp
# files, PID, and serve content.
RUN sed -i 's/^user  nginx;/# user directive disabled - running as non-root/' /etc/nginx/nginx.conf \
    && mkdir -p /var/cache/nginx/client_temp /var/cache/nginx/proxy_temp \
       /var/cache/nginx/fastcgi_temp /var/cache/nginx/uwsgi_temp \
       /var/cache/nginx/scgi_temp /etc/nginx/ssl \
    && chown -R nginx:nginx /var/cache/nginx /var/log/nginx /usr/share/nginx/html /etc/nginx/ssl \
    && touch /run/nginx.pid && chown nginx:nginx /run/nginx.pid

# Copy nginx config templates (entrypoint selects based on SSL_MODE)
COPY nginx/http-only.conf /etc/nginx/templates/http-only.conf
COPY nginx/ssl.conf /etc/nginx/templates/ssl.conf
COPY nginx/docker-entrypoint.sh /docker-entrypoint.sh

# Default config (overridden by entrypoint at runtime)
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built assets
COPY --from=builder --chown=nginx:nginx /app/dist /usr/share/nginx/html

# Fix line endings (Windows → Unix) and make entrypoint executable
RUN sed -i 's/\r$//' /docker-entrypoint.sh /etc/nginx/templates/*.conf \
    && chmod +x /docker-entrypoint.sh \
    && chown nginx:nginx /etc/nginx/conf.d/default.conf

USER nginx

EXPOSE 8080 8443

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]

# ============================================
# Stage 5: Caddy edge (DEFAULT production edge)
# ============================================
# Reuses the `builder` stage's compiled SPA and serves it through Caddy, which
# also reverse-proxies /api (HTTP + WebSocket + streams) and manages TLS
# automatically (see ./Caddyfile). This single image replaces the nginx
# `production` stage + the certbot container + the cert scripts. The nginx
# stage above is retained as an opt-in escape hatch (`nginx` compose profile)
# for shops that standardize on nginx / terminate TLS upstream.
FROM caddy:2.11.4-alpine AS caddy

# Apply the latest Alpine security patches (openssl libcrypto3/libssl3, etc.) on
# top of the pinned caddy base, so a freshly built edge image picks up CVE fixes
# even before caddy ships a new tag. Replace its compiled binary with the
# versioned, checksum-locked build above; see caddy-build/README.md.
RUN apk upgrade --no-cache
COPY --from=caddy-builder /usr/bin/caddy /usr/bin/caddy
COPY caddy-build/LICENSE /usr/share/licenses/caddy/LICENSE
COPY caddy-build/NOTICE /usr/share/licenses/caddy/NOTICE

# Built SPA assets (fingerprinted) served from /srv.
COPY --from=builder /app/dist /srv
# Edge config (env-driven; TLS follows CADDY_SITE_ADDRESS).
COPY Caddyfile /etc/caddy/Caddyfile

# Caddy validates its own config on start; fail fast on a bad Caddyfile.
RUN caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile

EXPOSE 80 443

# The official caddy image's entrypoint runs `caddy run` with this config.
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
