# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Prometheus Metrics
==============================

Exposes a ``/metrics`` endpoint in Prometheus exposition format for scraping
by Prometheus / Grafana / VictoriaMetrics / any OpenMetrics-compatible agent.

Default HTTP metrics (from prometheus-fastapi-instrumentator):
    - ``http_requests_total{method, handler, status}``
    - ``http_request_duration_seconds{method, handler, status}`` (histogram)
    - ``http_requests_in_progress{method, handler}``

Custom business metrics (module-level, always registered once):
    - ``freesdn_devices_total{type, status}``
    - ``freesdn_device_sync_total{vendor, status}``
    - ``freesdn_adapter_request_duration_seconds{adapter, method}``
    - ``freesdn_adapter_errors_total{adapter, error_type}``
    - ``freesdn_celery_queue_depth{queue}``
    - ``freesdn_celery_tasks_total{task, status}``
    - ``freesdn_celery_task_duration_seconds{task}``
    - ``freesdn_websocket_connections`` (no labels)
    - ``freesdn_auth_events_total{event_type, status}``
    - ``freesdn_rate_limit_hits_total{endpoint}``
    - ``freesdn_plugin_operations_total{operation, status}``
    - ``freesdn_info`` (build/version info)

Cardinality is kept bounded by always using templated path handlers,
low-cardinality outcome labels (success/failure), and grouping status codes.

Security: ``/metrics`` can leak tenant identifiers (site UUIDs,
organization UUIDs, version strings) to anyone who can reach the port. We
mitigate in two ways:

  1. High-cardinality tenant labels are removed from this module. The
     ``site`` label was dropped from ``freesdn_devices_total`` and
     ``organization_id`` was dropped from ``freesdn_websocket_connections``
     so scraping no longer enumerates tenants.
  2. When ``settings.METRICS_AUTH_TOKEN`` is set, ``/metrics`` requires an
     ``Authorization: Bearer <token>`` header. Operators should set this in
     production and configure Prometheus with a ``bearer_token_file``. When
     the setting is empty (dev default), ``/metrics`` is exposed publicly
     — acceptable for local/homelab but not for internet-exposed deploys.
"""

from __future__ import annotations

import secrets

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    Counter,
    Gauge,
    Histogram,
    Info,
    generate_latest,
)
from prometheus_fastapi_instrumentator import Instrumentator, metrics

from app.core.config import settings

# ============================================================================
# Custom metrics — business counters & gauges
# ============================================================================

# Device inventory (set by a periodic gauge refresh or on CRUD side-effects).
# the ``site`` label was dropped — it was a UUID, which both
# exploded cardinality and leaked the site inventory to any unauth scraper.
device_count: Gauge = Gauge(
    "freesdn_devices_total",
    "Total number of managed devices by type and status",
    ["type", "status"],
)

# Device sync attempts and outcomes per vendor.
device_sync_total: Counter = Counter(
    "freesdn_device_sync_total",
    "Total device sync attempts by vendor and outcome",
    ["vendor", "status"],
)

# Latency of outbound adapter calls to vendor APIs.
adapter_request_duration: Histogram = Histogram(
    "freesdn_adapter_request_duration_seconds",
    "Latency of adapter calls to vendor APIs",
    ["adapter", "method"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)

# Adapter errors bucketed by error class.
adapter_errors_total: Counter = Counter(
    "freesdn_adapter_errors_total",
    "Total adapter errors by vendor and error type",
    ["adapter", "error_type"],
)

# Adapter request counter (every outbound call, success or not).
adapter_requests_total: Counter = Counter(
    "freesdn_adapter_requests_total",
    "Total adapter calls by vendor, HTTP method, and outcome",
    ["adapter", "method", "outcome"],
)

# High-level staged-change counter — one increment per state
# transition (staged / applied / failed / discarded). Pairs with the
# event bus emissions in :mod:`app.services.adapter_staging` so Grafana
# can graph per-vendor change throughput + failure rate without
# subscribing to the event bus or scanning the audit log.
# Labels:
#   vendor   = "mikrotik" | "unifi" | "omada" | "opnsense" | "pfsense"
#              | "proxmox" | ... (parsed from change.feature prefix)
#   operation = "create" | "update" | "delete"
#   outcome   = "staged" | "applied" | "failed" | "discarded"
staged_changes_total: Counter = Counter(
    "freesdn_staged_changes_total",
    "Pending Changes lifecycle counter: stage / apply / fail / discard",
    ["vendor", "operation", "outcome"],
)

# Critical events that failed to publish to the event bus (Redis down,
# subscriber raised, etc.). The staging path is intentionally
# best-effort about publish so a broken bus never blocks an apply,
# but high/critical events shouldn't disappear silently. Operators
# alert on increases here.
event_publish_failures_total: Counter = Counter(
    "freesdn_event_publish_failures_total",
    "EventBus publish failures for high/critical change events",
    ["vendor", "priority"],
)

# Circuit-breaker state per adapter+host. 0=closed (healthy), 1=open
# (failing-fast), 2=half-open (probing). One series per controller
# instance so dashboards can graph which controller is unhealthy.
adapter_circuit_state: Gauge = Gauge(
    "freesdn_adapter_circuit_state",
    "Circuit breaker state: 0=closed, 1=open, 2=half-open",
    ["adapter", "host"],
)

# Number of staged Omada changes by status (gauge updated by the
# staging service). Operators graph this to see how big the
# pending queue is and how often things fail.
adapter_pending_changes: Gauge = Gauge(
    "freesdn_adapter_pending_changes",
    "Number of staged adapter changes by status",
    ["adapter", "status"],
)

# Celery queue depth (updated by a periodic probe, see app.tasks.metrics).
celery_queue_depth: Gauge = Gauge(
    "freesdn_celery_queue_depth",
    "Number of pending tasks in each Celery queue",
    ["queue"],
)

# Celery task executions and outcomes (wired via celery signals).
celery_tasks_total: Counter = Counter(
    "freesdn_celery_tasks_total",
    "Total Celery task executions by name and outcome",
    ["task", "status"],
)

celery_task_duration: Histogram = Histogram(
    "freesdn_celery_task_duration_seconds",
    "Latency of Celery task execution",
    ["task"],
    buckets=(0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0),
)

# Active WebSocket connections (set by ConnectionManager on connect/disconnect).
# the ``organization_id`` label was dropped — it was a UUID,
# which enumerated every active tenant to any unauth scraper. A single total
# is what Grafana dashboards actually need.
websocket_connections: Gauge = Gauge(
    "freesdn_websocket_connections",
    "Total active WebSocket connections",
)

# Authentication events: login / mfa / logout / password_reset × success|failure.
auth_events_total: Counter = Counter(
    "freesdn_auth_events_total",
    "Authentication event counts by type and outcome",
    ["event_type", "status"],
)

# Audit-write failures: counts audit log rows that failed to
# persist. Any non-zero rate here means the audit trail is incomplete and
# operators must investigate immediately — wire an alert in Prometheus.
audit_write_failures_total: Counter = Counter(
    "freesdn_audit_write_failures_total",
    "Audit log records that failed to persist to the database",
    ["resource_type"],
)

# Rate-limit hits (bounded: use coarse endpoint category, never raw paths).
rate_limit_hits: Counter = Counter(
    "freesdn_rate_limit_hits_total",
    "Requests blocked by rate limiting, bucketed by endpoint category",
    ["endpoint"],
)

# Plugin lifecycle events (install / uninstall / enable / disable × outcome).
plugin_operations_total: Counter = Counter(
    "freesdn_plugin_operations_total",
    "Plugin lifecycle events by operation and outcome",
    ["operation", "status"],
)

# One-shot build / environment info, set once during setup_metrics().
system_info: Info = Info(
    "freesdn",
    "FreeSDN build and environment information",
)


# ============================================================================
# Setup
# ============================================================================


def setup_metrics(app: FastAPI) -> None:
    """Install the Prometheus ``/metrics`` endpoint on the given FastAPI app.

    No-op when ``settings.ENABLE_METRICS`` is False — this also means the
    instrumentation middleware is not installed, so there is zero runtime
    cost for operators who disable metrics entirely.

    The endpoint is mounted at ``GET /metrics`` at the root (NOT under
    ``/api/v1``) so Prometheus scrape configs are trivial and do not
    require the ``api/v1`` prefix. It is excluded from the OpenAPI schema.

    When ``settings.METRICS_AUTH_TOKEN`` is set (recommended in production),
    ``/metrics`` requires an ``Authorization: Bearer <token>`` header;
    requests without or with a mismatched token get a 401. Operators should
    configure Prometheus with a ``bearer_token_file`` pointing at the same
    secret. Without a token, ``/metrics`` is exposed publicly ONLY when
    ``ENVIRONMENT == "development"`` (local/homelab). In staging/production a
    tokenless deploy does NOT mount ``/metrics`` at all (fail-closed,),
    so no unauthenticated telemetry is served there.
    """
    if not settings.ENABLE_METRICS:
        return

    # Set the one-shot build info gauge. Safe to call on every setup —
    # Info().info() replaces the single label set, it does not accumulate.
    system_info.info(
        {
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT,
            "app": settings.APP_NAME,
        }
    )

    instrumentator = Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        should_group_untemplated=True,
        # Exclude noisy / self-referential endpoints so they do not pollute
        # the HTTP histograms with millisecond-resolution scrape traffic.
        excluded_handlers=[
            "/metrics",
            "/health",
            "/api/v1/health",
            "/api/v1/health/",
            "/api/v1/health/ready",
            "/api/v1/health/live",
        ],
        # Respect the same toggle as the rest of the app. The env var name
        # is used by the instrumentator internally to short-circuit when
        # the variable is set to "false"; we always pass ENABLE_METRICS.
        env_var_name="ENABLE_METRICS",
        inprogress_name="http_requests_in_progress",
        inprogress_labels=True,
    )

    # Install the default HTTP metric set (latency histogram, request
    # counter, and in-progress gauge). Our custom metrics above are
    # already registered on the default CollectorRegistry at import time,
    # so they get picked up by the same /metrics endpoint automatically.
    instrumentator.add(metrics.default())

    # Install request instrumentation middleware unconditionally.
    instrumentator.instrument(app)

    metrics_token = settings.METRICS_AUTH_TOKEN
    if metrics_token:
        # Protected endpoint: scrape requests must carry a Bearer token
        # matching METRICS_AUTH_TOKEN. We render through prometheus_client
        # directly instead of Instrumentator.expose() so we can authenticate
        # in the handler before any label data is serialized.
        @app.get("/metrics", include_in_schema=False, tags=["monitoring"])
        async def metrics_endpoint(
            authorization: str | None = Header(default=None),
        ) -> Response:
            if not authorization or not authorization.startswith("Bearer "):
                raise HTTPException(
                    status_code=401,
                    detail="Metrics endpoint requires Bearer token",
                )
            provided = authorization[len("Bearer ") :]
            # constant-time comparison to avoid timing oracle
            if not secrets.compare_digest(provided, metrics_token):
                raise HTTPException(
                    status_code=401,
                    detail="Invalid metrics token",
                )
            return Response(
                content=generate_latest(REGISTRY),
                media_type=CONTENT_TYPE_LATEST,
            )
    elif settings.ENVIRONMENT == "development":
        # No token configured — expose publicly only in development/local
        # environments. This is the fail-closed: outside development a
        # tokenless deploy never serves the unauthenticated endpoint.
        instrumentator.expose(
            app,
            endpoint="/metrics",
            include_in_schema=False,
            tags=["monitoring"],
            should_gzip=False,
        )
    # If ENABLE_METRICS is True but no token is set and ENVIRONMENT is not
    # development, we fall through WITHOUT exposing /metrics at all (fail-closed,
    # ) — no unauthenticated telemetry leak in production/staging. An
    # operator who wants prod scraping sets FREESDN_METRICS_AUTH_TOKEN, which
    # routes to the authenticated branch above; config.py logs a nudge meanwhile.
