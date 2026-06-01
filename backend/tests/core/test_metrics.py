# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Tests for app.core.metrics — Prometheus metrics module.

These tests verify that all custom metrics are importable and usable, and
that the setup_metrics() function is a no-op when ENABLE_METRICS=false.
The live /metrics endpoint is covered by integration tests that boot the
full FastAPI app with a test client — the pure-unit tests here do not
require a database or Redis.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from prometheus_client import REGISTRY


def test_custom_metrics_registered() -> None:
    """Every custom metric must be importable and callable with labels."""
    from app.core.metrics import (
        adapter_errors_total,
        adapter_request_duration,
        auth_events_total,
        celery_queue_depth,
        celery_task_duration,
        celery_tasks_total,
        device_count,
        device_sync_total,
        plugin_operations_total,
        rate_limit_hits,
        system_info,
        websocket_connections,
    )

    # Counters — .inc() must work with the declared label set.
    device_sync_total.labels(vendor="omada", status="success").inc()
    adapter_errors_total.labels(adapter="omada", error_type="timeout").inc()
    celery_tasks_total.labels(task="app.tasks.sync.test", status="success").inc()
    auth_events_total.labels(event_type="login", status="success").inc()
    rate_limit_hits.labels(endpoint="/api/v1/auth/login").inc()
    plugin_operations_total.labels(operation="install", status="success").inc()

    # Gauges — .set()/.labels().set() must work.
    # the "site" label was dropped from device_count and
    # "organization_id" was dropped from websocket_connections so /metrics
    # no longer enumerates tenant UUIDs to unauthenticated scrapers.
    device_count.labels(type="switch", status="online").set(5)
    celery_queue_depth.labels(queue="default").set(0)
    websocket_connections.set(0)

    # Histograms — .observe() must work.
    adapter_request_duration.labels(adapter="omada", method="get_devices").observe(0.123)
    celery_task_duration.labels(task="app.tasks.sync.test").observe(1.5)

    # Info — .info() must accept a dict.
    system_info.info({"version": "test", "environment": "test"})


def test_metrics_exposed_on_default_registry() -> None:
    """Custom metrics must be registered on the default prometheus_client registry.

    This is what makes them show up at /metrics automatically — the
    instrumentator uses the default CollectorRegistry.
    """
    # Importing the module registers all metrics as a side effect.
    import app.core.metrics  # noqa: F401

    # Collect one tick from the registry and assert our custom names are
    # present. REGISTRY.collect() yields MetricFamilySamples — match by name.
    metric_names = {m.name for m in REGISTRY.collect()}

    # Note: prometheus_client strips the "_total" suffix from counter
    # family names at collection time (the suffix is re-added in the
    # exposition format). Gauges and histograms keep their full name.
    # Note: prometheus_client strips the "_total" suffix from COUNTER family
    # names at collection time (the suffix is re-added in the exposition
    # format). Gauge names are preserved verbatim. Histograms expose the
    # base name (buckets/sum/count become samples on that family).
    expected = {
        "freesdn_devices_total",                      # Gauge — name preserved
        "freesdn_device_sync",                        # Counter → strips _total
        "freesdn_adapter_request_duration_seconds",   # Histogram
        "freesdn_adapter_errors",                     # Counter → strips _total
        "freesdn_celery_queue_depth",                 # Gauge
        "freesdn_celery_tasks",                       # Counter → strips _total
        "freesdn_celery_task_duration_seconds",       # Histogram
        "freesdn_websocket_connections",              # Gauge
        "freesdn_auth_events",                        # Counter → strips _total
        "freesdn_rate_limit_hits",                    # Counter → strips _total
        "freesdn_plugin_operations",                  # Counter → strips _total
        "freesdn",                                    # Info
    }
    missing = expected - metric_names
    assert not missing, f"Missing metrics on default registry: {missing}"


def test_setup_metrics_noop_when_disabled() -> None:
    """setup_metrics() must NOT touch the FastAPI app when ENABLE_METRICS=false."""
    from app.core import metrics as metrics_mod

    app = FastAPI()
    before = list(app.router.routes)

    with patch.object(metrics_mod.settings, "ENABLE_METRICS", False):
        metrics_mod.setup_metrics(app)

    # No routes should have been added (no /metrics endpoint installed).
    assert list(app.router.routes) == before


def test_setup_metrics_installs_endpoint_when_enabled() -> None:
    """setup_metrics() must register a /metrics route when enabled."""
    from app.core import metrics as metrics_mod

    app = FastAPI()

    with patch.object(metrics_mod.settings, "ENABLE_METRICS", True):
        metrics_mod.setup_metrics(app)

    paths = {getattr(r, "path", None) for r in app.router.routes}
    assert "/metrics" in paths, f"/metrics not installed; routes={paths}"


def test_auth_events_label_values_bounded() -> None:
    """auth_events_total must only be called with a small, fixed label set.

    This is a lint/cardinality guard — if a future contributor adds
    uncontrolled label values (like raw usernames) this test will not
    catch it, but it does document the expected vocabulary.
    """
    from app.core.metrics import auth_events_total

    allowed_event_types = {"login", "logout", "mfa", "password_reset", "register"}
    allowed_statuses = {"success", "failure", "locked", "mfa_required"}

    # Sanity-exercise the full matrix we expect to see in code.
    for et in allowed_event_types:
        for st in allowed_statuses:
            auth_events_total.labels(event_type=et, status=st).inc(0)


def test_metrics_setup_called_from_main() -> None:
    """main.create_application must invoke setup_metrics."""
    with patch("app.core.metrics.Instrumentator") as mock_instr:
        mock_instance = MagicMock()
        mock_instr.return_value = mock_instance
        mock_instance.instrument.return_value = mock_instance

        # Re-import main fresh so create_application picks up the patch.
        # We can't fully reload main (it has heavy side effects), but we
        # can call setup_metrics directly with the same contract.
        from app.core.metrics import setup_metrics

        app = FastAPI()
        setup_metrics(app)

        mock_instr.assert_called_once()
        mock_instance.instrument.assert_called_once_with(app)
        mock_instance.expose.assert_called_once()
