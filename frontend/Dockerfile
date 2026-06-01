# FreeSDN Frontend Dockerfile
# Debian Trixie base - matches all other FreeSDN containers
# Multi-stage build for development and production

# ============================================
# Stage 1: Base Node image (Trixie)
# ============================================
FROM node:26.4.0-trixie-slim AS base
RUN npm install -g npm@11.17.0
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

# ============================================
# Stage 4: Production image with Nginx (Trixie)
# Uses official nginx.org mainline repo for latest version.
# F5/NGINX recommends mainline for all deployments - it receives
# all bug fixes, performance improvements, and security patches
# immediately (stable only gets critical fixes).
# Non-root 'nginx' user for security hardening.
# ============================================
FROM debian:trixie-slim AS production

# Pre-create nginx user/group with a fixed UID/GID (999) BEFORE installing
# the nginx package. The package detects the existing user and skips creation.
# This ensures the UID matches docker-compose tmpfs uid=999,gid=999 mounts.
RUN groupadd -g 999 nginx && useradd -r -u 999 -g 999 -d /var/cache/nginx -s /sbin/nologin nginx

# Install nginx from the official nginx.org mainline repo (1.29.x)
# Mainline is recommended by NGINX for production - it's the same
# branch used for NGINX Plus (commercial). Stable only receives
# critical-severity fixes and third-party module compat patches.
# curl is kept in the image for Docker healthcheck probes.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y \
       curl gnupg ca-certificates \
    && curl -fsSL https://nginx.org/keys/nginx_signing.key \
       | gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
       https://nginx.org/packages/mainline/debian/ trixie nginx" \
       > /etc/apt/sources.list.d/nginx.list \
    && apt-get update \
    && apt-get install --no-install-recommends -y nginx \
    && apt-get purge -y --auto-remove gnupg \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log

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
# even before caddy ships a new tag. The caddy binary's bundled Go stdlib is
# upstream-gated and updates only when caddy publishes a rebuild.
RUN apk upgrade --no-cache

# Built SPA assets (fingerprinted) served from /srv.
COPY --from=builder /app/dist /srv
# Edge config (env-driven; TLS follows CADDY_SITE_ADDRESS).
COPY Caddyfile /etc/caddy/Caddyfile

# Caddy validates its own config on start; fail fast on a bad Caddyfile.
RUN caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile

EXPOSE 80 443

# The official caddy image's entrypoint runs `caddy run` with this config.
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
