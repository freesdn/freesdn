# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Celery Application
================================

Celery configuration for background tasks with:
- Multiple task queues
- Beat scheduler for periodic tasks
- Result backend with expiration
- Task routing by priority
"""

import multiprocessing as _mp
import sys as _sys
from datetime import UTC

from celery import Celery
from celery.schedules import crontab
from kombu import Exchange, Queue

from app.core.config import settings

# Python 3.14 changed the default multiprocessing start method on Linux from
# 'fork' to 'forkserver'. The Celery prefork pool + our scan tasks rely on fork
# semantics — children inherit the already-loaded module registry (see
# tasks/sync.py _ensure_modules_loaded), which a clean forkserver process would
# not have. Pin 'fork' on POSIX to preserve 3.13 behavior; this is a no-op on
# pre-3.14 (fork was already the default) and skipped on Windows/macOS (where
# 'fork' isn't the default and dev uses Celery's solo/threads pool anyway).
if _sys.platform.startswith("linux"):
    try:
        _mp.set_start_method("fork", force=True)
    except (RuntimeError, ValueError):  # pragma: no cover - platform-dependent
        pass

# ===========================================
# Exchange and Queue Configuration
# ===========================================

default_exchange = Exchange("default", type="direct")
discovery_exchange = Exchange("discovery", type="direct")
sync_exchange = Exchange("sync", type="direct")
priority_exchange = Exchange("priority", type="direct")

# Define queues with different priorities
task_queues = (
    # Default queue for general tasks
    Queue("default", default_exchange, routing_key="default"),
    # Discovery queue for device discovery tasks
    Queue("discovery", discovery_exchange, routing_key="discovery"),
    # Sync queue for device state synchronization
    Queue("sync", sync_exchange, routing_key="sync"),
    # Priority queue for time-sensitive tasks
    Queue("priority", priority_exchange, routing_key="priority"),
    # Metrics queue for metrics collection
    Queue("metrics", default_exchange, routing_key="metrics"),
)


# ===========================================
# Create Celery Application
# ===========================================

# Use CELERY_BROKER_URL and CELERY_RESULT_BACKEND if set, otherwise fall back to REDIS_URL
broker_url = settings.CELERY_BROKER_URL or str(settings.REDIS_URL)
result_backend = settings.CELERY_RESULT_BACKEND or str(settings.REDIS_URL)

celery_app = Celery(
    "freesdn",
    broker=broker_url,
    backend=result_backend,
    include=[
        "app.tasks.discovery",
        "app.tasks.sync",
        "app.tasks.metrics",
        "app.tasks.maintenance",
        "app.tasks.analytics",
        "app.tasks.vpn",
        "app.tasks.security_audit",
        "app.tasks.import_export",
        "app.tasks.firmware",
        "app.tasks.agents",
        "app.tasks.correlation",
        "app.tasks.alert_rules",
        "app.tasks.sla",
        "app.tasks.backup",
        "app.tasks.reconciliation",
        "app.tasks.bulk_operations",
        "app.modules.gateway.tasks.sync_tasks",
        "app.modules.gateway.tasks.drift_tasks",
        "app.modules.gateway.tasks.distribution_tasks",
        "app.tasks.cameras",
        "app.modules.voip.tasks",
        "app.tasks.adoption",
        "app.tasks.poe",
        "app.tasks.radius",
        # Notification retry queue — re-drives transient SMTP/Slack/5xx
        # failures with exponential backoff before flipping rows to DLQ.
        "app.tasks.notification_retry",
        # TrueNAS storage health monitor — polls appliances + emits
        # storage.* Fabric events on state transitions.
        "app.tasks.storage",
        # Firewall/gateway health monitor — polls OPNsense/pfSense + emits
        # firewall.event.* Fabric events on state transitions.
        "app.tasks.firewall_monitor",
        # Proxmox hypervisor health monitor — polls clusters + emits
        # hypervisor.* Fabric events on node/quorum/reachability transitions.
        "app.tasks.hypervisor",
        # Omada controller monitor — polls Omada controllers + emits omada.event.*
        # Fabric events on alert/reachability transitions (Fabric source).
        "app.tasks.omada_monitor",
        # Overlay-mesh peer monitor — polls Tailscale/NetBird + emits overlay.*
        # Fabric events on peer online/offline/metadata + reachability transitions.
        "app.tasks.overlay_monitor",
    ],
)


# ===========================================
# Worker Heartbeat Task
# ===========================================
# Lightweight task dispatched by beat every 30s. The worker writes a Redis
# key with a 90s TTL so the health endpoint can verify liveness via a
# simple O(1) GET instead of broadcast inspect commands.


@celery_app.task(name="worker.heartbeat", ignore_result=True)  # type: ignore[untyped-decorator]
def worker_heartbeat() -> None:
    """Write a TTL heartbeat key proving this worker is alive and processing."""
    from datetime import datetime

    from app.core.redis_client import get_sync_redis

    # Sentinel-aware (HA): write to the broker DB (1); follows the promoted master.
    r = get_sync_redis(db=1, decode_responses=True)
    try:
        r.setex("freesdn:worker:heartbeat", 90, datetime.now(UTC).isoformat())
    finally:
        r.close()


# ===========================================
# Celery Configuration
# ===========================================

celery_app.conf.update(
    # Serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # Task execution settings
    task_acks_late=True,  # Acknowledge after task completes
    task_reject_on_worker_lost=True,  # Reject tasks if worker dies
    worker_prefetch_multiplier=1,  # Fetch one task at a time
    task_track_started=True,  # Track task start time
    # Result backend configuration
    result_expires=86400,  # Results expire after 24 hours
    result_extended=True,  # Store additional task metadata
    result_backend_transport_options={
        "visibility_timeout": 3600,
    },
    # Time limits (defaults, can be overridden per task)
    task_soft_time_limit=300,  # 5 minutes soft limit
    task_time_limit=600,  # 10 minutes hard limit
    # Retry settings (defaults)
    task_default_retry_delay=60,  # 1 minute initial retry delay
    task_max_retries=3,
    # Queue configuration
    task_queues=task_queues,
    task_default_queue="default",
    task_default_exchange="default",
    task_default_routing_key="default",
    # Task routing
    task_routes={
        "app.tasks.discovery.*": {"queue": "discovery"},
        "app.tasks.sync.*": {"queue": "sync"},
        "app.tasks.metrics.*": {"queue": "metrics"},
        "app.tasks.analytics.*": {"queue": "metrics"},
        "vpn.*": {"queue": "sync"},
        "app.tasks.*.high_priority_*": {"queue": "priority"},
        "cameras.*": {"queue": "metrics"},
        "gateway.*": {"queue": "sync"},
    },
    # Worker configuration
    worker_send_task_events=True,  # Send task events for monitoring
    task_send_sent_event=True,  # Send event when task is sent
    worker_max_tasks_per_child=1000,  # Recycle workers to prevent memory leaks
    worker_cancel_long_running_tasks_on_connection_loss=True,  # Cancel stuck tasks on broker disconnect
    broker_connection_retry_on_startup=True,  # Retry broker connection on startup
    # Rate limits for heavy periodic tasks (max executions per minute per worker)
    # Prevents resource exhaustion when tasks pile up faster than they complete.
    task_annotations={
        "app.tasks.discovery.discover_all_devices": {"rate_limit": "2/m"},
        "app.tasks.sync.sync_all_device_statuses": {"rate_limit": "4/m"},
        "app.tasks.sync.mark_stale_devices_offline": {"rate_limit": "4/m"},
        "app.tasks.metrics.collect_all_device_metrics": {"rate_limit": "2/m"},
        "app.tasks.reconciliation.reconcile_all_devices": {"rate_limit": "2/m"},
        "app.tasks.reconciliation.recompute_all_health": {"rate_limit": "2/m"},
        "cameras.poll_camera_health": {"rate_limit": "4/m"},
        "cameras.ingest_nvr_alerts": {"rate_limit": "4/m"},
        "app.tasks.sla.evaluate_all_sla": {"rate_limit": "2/m"},
        "app.tasks.alert_rules.evaluate_all_alert_rules": {"rate_limit": "3/m"},
        "app.tasks.correlation.correlate_all_events": {"rate_limit": "2/m"},
        "gateway.sync_all_gateways": {"rate_limit": "2/m"},
    },
    # Beat scheduler configuration
    beat_scheduler="celery.beat:PersistentScheduler",
    beat_schedule_filename="celerybeat-schedule",
    # Periodic task schedule
    beat_schedule={
        # Worker heartbeat - every 30 seconds
        # Proves worker is alive for the health endpoint (O(1) Redis GET)
        # Routed to "default" queue so the main worker (which always listens
        # to default) picks it up regardless of queue topology changes.
        "worker-heartbeat": {
            "task": "worker.heartbeat",
            "schedule": 30.0,
            "options": {"queue": "default"},
        },
        # Device discovery - every 5 minutes
        "discover-all-devices": {
            "task": "app.tasks.discovery.discover_all_devices",
            "schedule": crontab(minute="*/5"),
            "options": {"queue": "discovery"},
        },
        # Device status sync - every minute
        "sync-device-statuses": {
            "task": "app.tasks.sync.sync_all_device_statuses",
            "schedule": crontab(minute="*"),
            "options": {"queue": "sync"},
        },
        # Mark stale devices offline - every minute
        "mark-stale-devices": {
            "task": "app.tasks.sync.mark_stale_devices_offline",
            "schedule": crontab(minute="*"),
            "options": {"queue": "sync"},
        },
        # Metrics collection - every 5 minutes
        "collect-device-metrics": {
            "task": "app.tasks.metrics.collect_all_device_metrics",
            "schedule": crontab(minute="*/5"),
            "options": {"queue": "metrics"},
        },
        # Controller health check - every 2 minutes
        "check-controller-health": {
            "task": "sync.check_controller_health",
            "schedule": crontab(minute="*/2"),
            "options": {"queue": "sync"},
        },
        # Cleanup old events - daily at 3 AM
        "cleanup-old-events": {
            "task": "app.tasks.maintenance.cleanup_old_events",
            "schedule": crontab(hour=3, minute=0),
            "options": {"queue": "default"},
        },
        # Cleanup stale task progress - hourly
        "cleanup-task-progress": {
            "task": "app.tasks.maintenance.cleanup_stale_progress",
            "schedule": crontab(minute=0),
            "options": {"queue": "default"},
        },
        # Sweep stale ``applying`` rows in adapter_pending_changes - every
        # minute. The applier marks a row ``applying`` mid-write and
        # flips back to ``applied``/``failed`` on completion; a crashed
        # worker leaves the row stuck and blocks retries on the same
        # gateway (apply endpoint refuses non-pending rows). Opportunistic
        # recovery on stage_change/list_pending only fires when something
        # else hits the service — this task closes that gap.
        "cleanup-stale-applying-changes": {
            "task": "app.tasks.maintenance.cleanup_stale_applying_changes",
            "schedule": crontab(minute="*"),
            "options": {"queue": "default"},
        },
        # Agent: mark stale agents offline - every 2 minutes
        "cleanup-stale-agents": {
            "task": "agents.cleanup_stale",
            "schedule": crontab(minute="*/2"),
            "options": {"queue": "default"},
        },
        # Agent: purge old heartbeats - daily at 4 AM
        "purge-old-heartbeats": {
            "task": "agents.purge_heartbeats",
            "schedule": crontab(hour=4, minute=0),
            "options": {"queue": "default"},
        },
        # Agent: purge orphan heartbeats (cross-DB consistency) - daily at 5 AM
        "purge-orphan-heartbeats": {
            "task": "agents.purge_orphan_heartbeats",
            "schedule": crontab(hour=5, minute=0),
            "options": {"queue": "default"},
        },
        # Agent: health check - every 5 minutes
        "check-agent-health": {
            "task": "agents.health_check",
            "schedule": crontab(minute="*/5"),
            "options": {"queue": "default"},
        },
        # Agent: cleanup stuck tasks - every 10 minutes
        "cleanup-stuck-agent-tasks": {
            "task": "agents.cleanup_stuck_tasks",
            "schedule": crontab(minute="*/10"),
            "options": {"queue": "default"},
        },
        # Analytics: collect metrics from devices - every 5 minutes
        "analytics-collect-device-metrics": {
            "task": "analytics.collect_device_metrics",
            "schedule": crontab(minute="*/5"),
            "options": {"queue": "metrics"},
        },
        # Analytics: purge old metric data - daily at 2 AM
        "analytics-purge-old-metrics": {
            "task": "analytics.purge_old_metrics",
            "schedule": crontab(hour=2, minute=0),
            "options": {"queue": "default"},
        },
        # Analytics: check metric thresholds - every 5 minutes
        "analytics-check-thresholds": {
            "task": "analytics.check_metric_thresholds",
            "schedule": crontab(minute="*/5"),
            "options": {"queue": "metrics"},
        },
        # Analytics: resolve stale alerts - hourly
        "analytics-resolve-stale-alerts": {
            "task": "analytics.resolve_stale_alerts",
            "schedule": crontab(minute=30),
            "options": {"queue": "default"},
        },
        # VPN: sync connections from live state - every 2 minutes
        "vpn-sync-connections": {
            "task": "vpn.sync_vpn_connections",
            "schedule": crontab(minute="*/2"),
            "options": {"queue": "sync"},
        },
        # VPN: record health checks - every 5 minutes
        "vpn-check-health": {
            "task": "vpn.check_vpn_health",
            "schedule": crontab(minute="*/5"),
            "options": {"queue": "sync"},
        },
        # VPN: auto-reconnect failed connections - every 1 minute
        "vpn-auto-reconnect": {
            "task": "vpn.auto_reconnect",
            "schedule": crontab(minute="*/1"),
            "options": {"queue": "sync"},
        },
        # VPN: check S2S tunnel health - every 5 minutes
        "vpn-check-tunnel-health": {
            "task": "vpn.check_tunnel_health",
            "schedule": crontab(minute="*/5"),
            "options": {"queue": "sync"},
        },
        # VPN: purge old health checks - daily at 3:30 AM
        "vpn-purge-old-health-checks": {
            "task": "vpn.purge_old_vpn_health_checks",
            "schedule": crontab(hour=3, minute=30),
            "options": {"queue": "default"},
        },
        # VPN: purge old event log entries - weekly Sunday 4:00 AM
        "vpn-purge-old-events": {
            "task": "vpn.purge_old_vpn_events",
            "schedule": crontab(hour=4, minute=0, day_of_week="sunday"),
            "options": {"queue": "default"},
        },
        "vpn-scan-certificates": {
            "task": "vpn.scan_vpn_certificates",
            "schedule": crontab(hour=6, minute=0),  # daily 6:00 AM
            "options": {"queue": "default"},
        },
        # Security: brute force scan - every 5 minutes
        "security-scan-brute-force": {
            "task": "security.scan_brute_force",
            "schedule": crontab(minute="*/5"),
            "options": {"queue": "default"},
        },
        # Security: expire IP blocks - every 15 minutes
        "security-expire-ip-blocks": {
            "task": "security.expire_ip_blocks",
            "schedule": crontab(minute="*/15"),
            "options": {"queue": "default"},
        },
        # Security: audit data cleanup - daily at 4:30 AM
        "security-cleanup-audit-data": {
            "task": "security.cleanup_audit_data",
            "schedule": crontab(hour=4, minute=30),
            "options": {"queue": "default"},
        },
        # Security: anomaly detection - every 30 minutes
        "security-detect-anomalies": {
            "task": "security.detect_anomalies",
            "schedule": crontab(minute="*/30"),
            "options": {"queue": "default"},
        },
        # Data: cleanup old export/import files - daily at 5:00 AM
        "data-cleanup-old-files": {
            "task": "data.cleanup_old_data_files",
            "schedule": crontab(hour=5, minute=0),
            "options": {"queue": "default"},
        },
        # Firmware: check scheduled upgrades - every 5 minutes
        "firmware-check-scheduled": {
            "task": "firmware.check_scheduled",
            "schedule": crontab(minute="*/5"),
            "options": {"queue": "default"},
        },
        # Firmware: refresh device firmware status - every hour
        "firmware-refresh-status": {
            "task": "firmware.refresh_status",
            "schedule": crontab(minute=15),
            "options": {"queue": "default"},
        },
        # Enterprise: config reconciliation - every 5 minutes
        "enterprise-reconcile-all": {
            "task": "app.tasks.reconciliation.reconcile_all_devices",
            "schedule": crontab(minute="*/5"),
            "options": {"queue": "sync"},
        },
        # Enterprise: health score recomputation - every 5 minutes
        "enterprise-recompute-health": {
            "task": "app.tasks.reconciliation.recompute_all_health",
            "schedule": crontab(minute="*/5"),
            "options": {"queue": "metrics"},
        },
        # Alert Rules: evaluate all rules - every 3 minutes
        "alert-rules-evaluate-all": {
            "task": "app.tasks.alert_rules.evaluate_all_alert_rules",
            "schedule": crontab(minute="*/3"),
            "options": {"queue": "default"},
        },
        # Alert Rules: auto-resolve stale alerts - every 10 minutes
        "alert-rules-auto-resolve": {
            "task": "app.tasks.alert_rules.auto_resolve_all_alerts",
            "schedule": crontab(minute="*/10"),
            "options": {"queue": "default"},
        },
        # Alert Rules: unsuppress expired suppressions - every 5 minutes
        "alert-rules-unsuppress-expired": {
            "task": "app.tasks.alert_rules.unsuppress_expired_alerts",
            "schedule": crontab(minute="*/5"),
            "options": {"queue": "default"},
        },
        # Event Correlation: scan events and create incidents - every 5 minutes
        "correlation-scan-events": {
            "task": "app.tasks.correlation.correlate_all_events",
            "schedule": crontab(minute="*/5"),
            "options": {"queue": "default"},
        },
        # Event Correlation: auto-resolve stale incidents - every 15 minutes
        "correlation-auto-resolve": {
            "task": "app.tasks.correlation.auto_resolve_all",
            "schedule": crontab(minute="*/15"),
            "options": {"queue": "default"},
        },
        # SLA Monitoring: evaluate policies - every 5 minutes
        "sla-evaluate-all": {
            "task": "app.tasks.sla.evaluate_all_sla",
            "schedule": crontab(minute="*/5"),
            "options": {"queue": "metrics"},
        },
        # Backup: run scheduled backups - every 15 minutes
        "backup-run-scheduled": {
            "task": "backup.run_scheduled",
            "schedule": crontab(minute="*/15"),
            "options": {"queue": "default"},
        },
        # Backup: cleanup expired backups - daily at 2:30 AM
        "backup-cleanup-expired": {
            "task": "backup.cleanup_expired",
            "schedule": crontab(hour=2, minute=30),
            "options": {"queue": "default"},
        },
        # Backup: monthly restore validation — 1st of month at 3:30 AM.
        # Picks each org's most recent completed backup and runs a
        # dry-run restore against it (checksum verify + decrypt +
        # JSON parse + plan walk). Catches "the backup looks fine in
        # the dashboard but can't actually be loaded back" silently.
        "backup-validate-restore": {
            "task": "backup.validate_restore",
            "schedule": crontab(hour=3, minute=30, day_of_month=1),
            "options": {"queue": "default"},
        },
        # Gateway: sync all brain gateways - every 5 minutes
        "gateway-sync-all": {
            "task": "gateway.sync_all_gateways",
            "schedule": crontab(minute="*/5"),
            "options": {"queue": "sync"},
        },
        # Gateway: drift detection on all sites - every 15 minutes
        "gateway-drift-check-all": {
            "task": "gateway.check_all_sites_drift",
            "schedule": crontab(minute="*/15"),
            "options": {"queue": "sync"},
        },
        # Gateway: cleanup expired distribution locks - every 10 minutes
        "gateway-cleanup-locks": {
            "task": "gateway.cleanup_distribution_locks",
            "schedule": crontab(minute="*/10"),
            "options": {"queue": "default"},
        },
        # Module device sync (safety-net): full registry reconciliation.
        # Primary sync is event-driven (triggered on CRUD with 5s debounce).
        # This periodic run catches anything the event triggers might miss.
        "sync-module-devices": {
            "task": "sync.sync_module_devices",
            "schedule": crontab(minute="*/15"),
            "options": {"queue": "sync"},
        },
        # Camera: health polling - every 60 seconds
        "camera-poll-health": {
            "task": "cameras.poll_camera_health",
            "schedule": crontab(minute="*"),
            "options": {"queue": "metrics"},
        },
        # Camera: NVR alert ingestion - every 30 seconds
        "camera-ingest-alerts": {
            "task": "cameras.ingest_nvr_alerts",
            "schedule": 30.0,
            "options": {"queue": "metrics"},
        },
        # Camera: cleanup old health snapshots - daily at 3:15 AM
        "camera-cleanup-health-snapshots": {
            "task": "cameras.cleanup_health_snapshots",
            "schedule": crontab(hour=3, minute=15),
            "options": {"queue": "default"},
        },
        # Camera: prune camera_events past the retention window - daily at 3:30 AM
        "camera-cleanup-events": {
            "task": "cameras.cleanup_camera_events",
            "schedule": crontab(hour=3, minute=30),
            "options": {"queue": "default"},
        },
        # Camera: cleanup stale HLS sessions - every 60 seconds
        "camera-cleanup-hls-sessions": {
            "task": "cameras.cleanup_hls_sessions",
            "schedule": crontab(minute="*"),
            "options": {"queue": "default"},
        },
        # Camera: generate daily report - daily at 1:00 AM
        "camera-generate-daily-report": {
            "task": "cameras.generate_daily_report",
            "schedule": crontab(hour=1, minute=0),
            "options": {"queue": "default"},
        },
        # Camera: AI scene labeling - daily at 5:30 AM
        "camera-label-scenes": {
            "task": "cameras.label_camera_scenes",
            "schedule": crontab(hour=5, minute=30),
            "options": {"queue": "default"},
        },
        # ZTP: retry failed adoption jobs - every 10 minutes
        "ztp-retry-failed-adoptions": {
            "task": "adoption.retry_failed",
            "schedule": crontab(minute="*/10"),
            "options": {"queue": "default"},
        },
        # PoE: evaluate schedules - every 1 minute
        "poe-evaluate-schedules": {
            "task": "poe.evaluate_schedules",
            "schedule": crontab(minute="*"),
            "options": {"queue": "default"},
        },
        # RADIUS: sync 802.1X auth events - every 5 minutes
        "radius-sync-dot1x-events": {
            "task": "radius.sync_dot1x_events",
            "schedule": crontab(minute="*/5"),
            "options": {"queue": "default"},
        },
        # RADIUS: health check RADIUS servers - every 2 minutes
        "radius-check-health": {
            "task": "radius.check_health",
            "schedule": crontab(minute="*/2"),
            "options": {"queue": "default"},
        },
        # Enterprise: nightly health daily snapshot - 01:00 UTC
        "enterprise-snapshot-daily-health": {
            "task": "app.tasks.reconciliation.snapshot_daily_health",
            "schedule": crontab(hour=1, minute=0),
            "options": {"queue": "default"},
        },
        # Reap adapter_pending_changes rows stuck in "applying" - every 1 min.
        # If the apply worker is killed mid-call (SIGKILL/OOM/Omada hang),
        # the row stays in "applying" forever; this task flips rows older
        # than 5 min to "failed" so operators can recover.
        "reap-stuck-omada-pending-changes": {
            "task": "app.tasks.maintenance.reap_stuck_omada_pending_changes",
            "schedule": crontab(minute="*/1"),
            "kwargs": {"max_age_minutes": 5},
            "options": {"queue": "default"},
        },
        # Collector retention prune (C5): drop old syslog/SNMP-trap
        # rows and old NetFlow records per the per-org CollectorConfig
        # retention policy. Without this both collector tables grow
        # forever because the receivers append continuously and have
        # no built-in TTL. Daily at 03:00 UTC.
        "prune-collector-logs": {
            "task": "app.tasks.maintenance.prune_collector_logs",
            "schedule": crontab(hour=3, minute=0),
            "options": {"queue": "default"},
        },
        # Storage (TrueNAS): poll appliance health + emit storage.* Fabric
        # events on state transitions (pool degraded/recovered, capacity
        # warning, critical alert, appliance unreachable/online) - every 2 min.
        "storage-poll-health": {
            "task": "storage.poll_health",
            "schedule": crontab(minute="*/2"),
            "options": {"queue": "metrics"},
        },
        # Firewall (OPNsense/pfSense): poll gateway health + emit firewall.event.*
        # on transitions (IDS-critical, WAN up/down, reachability) - every 2 min.
        "firewall-poll-health": {
            "task": "firewall.poll_health",
            "schedule": crontab(minute="*/2"),
            "options": {"queue": "metrics"},
        },
        # Proxmox: poll cluster quorum + node up/down + emit hypervisor.*
        # on transitions (node offline/online, inquorate, unreachable) - every 2 min.
        "hypervisor-poll-health": {
            "task": "hypervisor.poll_health",
            "schedule": crontab(minute="*/2"),
            "options": {"queue": "metrics"},
        },
        # Omada: poll controllers + emit omada.event.* on transitions (new alerts
        # normalized to device_offline/rogue_ap/poe_overload/firmware_available,
        # reachability) - every 2 min.
        "omada-poll-health": {
            "task": "omada.poll_health",
            "schedule": crontab(minute="*/2"),
            "options": {"queue": "metrics"},
        },
        # Overlay mesh: poll Tailscale/NetBird peers + emit overlay.* on transitions
        # (peer online/offline, metadata changed, enumeration reachability) - every
        # 2 min. Self-skips instantly when resolved_vpn_mode == "off" (the default).
        "overlay-poll-health": {
            "task": "overlay.poll_health",
            "schedule": crontab(minute="*/2"),
            "options": {"queue": "metrics"},
        },
    },
)


# ===========================================
# Redis/Valkey Sentinel (HA) broker support
# ===========================================
# When the broker/result URLs use the ``sentinel://`` scheme (set by the HA
# overlay), Celery's redis transport needs the master name (and Sentinel AUTH)
# via transport options so it can resolve + follow the promoted master on a
# failover. Merge — don't clobber the existing visibility_timeout.
if str(broker_url).startswith("sentinel://") or str(result_backend).startswith("sentinel://"):
    _sentinel_opts: dict[str, object] = {"master_name": settings.REDIS_MASTER_NAME}
    if settings.REDIS_PASSWORD:
        _sentinel_opts["sentinel_kwargs"] = {"password": settings.REDIS_PASSWORD}
    celery_app.conf.broker_transport_options = {
        **(celery_app.conf.broker_transport_options or {}),
        **_sentinel_opts,
    }
    celery_app.conf.result_backend_transport_options = {
        **(celery_app.conf.result_backend_transport_options or {}),
        **_sentinel_opts,
    }


# ===========================================
# Task Signals
# ===========================================

import logging
from typing import Any

from celery.signals import (
    before_task_publish,
    task_failure,
    task_postrun,
    task_prerun,
    worker_process_init,
    worker_ready,
    worker_shutdown,
)

from app.core.logging import request_id_var, setup_logging

logger = logging.getLogger(__name__)


@worker_process_init.connect  # type: ignore[untyped-decorator]
def configure_worker_logging(**_: Any) -> None:
    """Install the same structured logging config in each worker process.

    Celery forks worker processes; the parent's handlers are inherited but
    calling setup_logging() explicitly ensures JSONLogFormatter is active
    and respects LOG_LEVEL/LOG_FORMAT from settings.
    """
    setup_logging(
        level=settings.LOG_LEVEL,
        json_format=(settings.LOG_FORMAT.lower() == "json"),
    )


@before_task_publish.connect  # type: ignore[untyped-decorator]
def propagate_request_id_to_task(
    sender: Any = None,
    headers: Any = None,
    body: Any = None,
    **_: Any,
) -> None:
    """Inject the current request_id into outgoing task headers.

    When a task is dispatched from inside an HTTP request, the request_id
    ContextVar is set. We copy it into the Celery task headers so the worker
    can restore it in its own ContextVar for correlated logs across the
    API → worker boundary.
    """
    current_id = request_id_var.get()
    if current_id and headers is not None:
        headers["x-request-id"] = current_id


@task_prerun.connect  # type: ignore[untyped-decorator]
def set_task_request_id(
    sender: Any = None,
    task_id: str | None = None,
    task: Any = None,
    **_: Any,
) -> None:
    """Restore the request_id ContextVar from task headers on the worker.

    Reads ``x-request-id`` from the task request headers (set by the
    before_task_publish signal) or falls back to a task-scoped ID so task
    logs are always correlated even for beat-scheduled tasks.
    """
    req = getattr(task, "request", None) if task is not None else None
    headers = getattr(req, "headers", None) or {}
    req_id = headers.get("x-request-id") or (f"task-{task_id}" if task_id else None)
    if req_id:
        request_id_var.set(req_id)


@task_postrun.connect  # type: ignore[untyped-decorator]
def clear_task_request_id(sender: Any = None, **_: Any) -> None:
    """Clear the request_id ContextVar after the task completes.

    Workers reuse greenlets/threads between tasks — we must not leak the
    previous task's request_id into the next task's log records.
    """
    request_id_var.set(None)


@worker_ready.connect  # type: ignore[untyped-decorator]
def on_worker_ready(sender: Any, **kwargs: Any) -> None:
    """Load module registry so device sync tasks can find device sources."""
    import asyncio

    from app.modules.loader import ModuleLoader
    from app.modules.registry import module_registry

    if not module_registry.modules:
        try:
            loader = ModuleLoader()
            discovered = loader.discover_modules()
            if discovered:
                asyncio.run(loader.load_all_modules())
            logger.info(
                "Celery worker modules loaded: %d (%s)",
                len(module_registry.modules),
                list(module_registry.modules.keys()),
            )
        except Exception:
            logger.warning(
                "Failed to load modules in worker — device sync will be limited", exc_info=True
            )

    logger.info("Celery worker ready: %s", sender)


@worker_shutdown.connect  # type: ignore[untyped-decorator]
def on_worker_shutdown(sender: Any, **kwargs: Any) -> None:
    """Log when worker is shutting down."""
    logger.info("Celery worker shutting down: %s", sender)


@task_prerun.connect  # type: ignore[untyped-decorator]
def on_task_prerun(sender: Any, task_id: str, task: Any, args: Any, kwargs: Any, **_: Any) -> None:
    """Log task start."""
    logger.info("Task starting: %s[%s]", task.name, task_id)


@task_postrun.connect  # type: ignore[untyped-decorator]
def on_task_postrun(
    sender: Any, task_id: str, task: Any, args: Any, kwargs: Any, retval: Any, state: str, **_: Any
) -> None:
    """Log task completion."""
    logger.info("Task finished: %s[%s] state=%s", task.name, task_id, state)


@task_failure.connect  # type: ignore[untyped-decorator]
def on_task_failure(
    sender: Any,
    task_id: str,
    exception: Exception,
    args: Any,
    kwargs: Any,
    traceback: Any,
    einfo: Any,
    **_: Any,
) -> None:
    """Log task failure."""
    logger.error("Task failed: %s[%s] error=%s", sender.name, task_id, exception)


# ===========================================
# Solo-Task Lock (overlap prevention)
# ===========================================
# Use `acquire_solo_lock(task_name, ttl)` inside any periodic task
# to ensure only one instance runs at a time across all workers.
# If the lock is already held, the task should return early.

import redis as _redis

_solo_redis: _redis.Redis | None = None


def _get_solo_redis() -> _redis.Redis:
    """Lazy-init a sync Redis client for solo-task locks (Sentinel-aware in HA)."""
    global _solo_redis
    if _solo_redis is None:
        from app.core.redis_client import get_sync_redis

        _solo_redis = get_sync_redis(db=0, decode_responses=True, socket_timeout=5)
    return _solo_redis


# Per-acquisition lock tokens, so release only deletes a lock THIS run still
# owns. Keyed by task_name → token. Without this, an unconditional DEL let a slow
# run (that outran its TTL) delete a DIFFERENT run's freshly-acquired lock,
# defeating the overlap guard precisely under the slow-run condition it exists
# for. Keeping the bool/str-name signatures means no caller changes.
_solo_lock_tokens: dict[str, str] = {}

# Compare-and-delete: only DEL if the value still matches our token.
_SOLO_RELEASE_LUA = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end"


def acquire_solo_lock(task_name: str, ttl_seconds: int = 300) -> bool:
    """Try to acquire a distributed solo-lock for *task_name*.

    Returns True if the lock was acquired (caller should proceed).
    Returns False if another instance is already running (caller should skip).
    The lock auto-expires after *ttl_seconds* as a safety net, and release is
    owner-checked so a run can never delete a foreign run's lock.
    """
    import uuid

    r = _get_solo_redis()
    key = f"freesdn:solo:{task_name}"
    token = uuid.uuid4().hex
    acquired = r.set(key, token, nx=True, ex=ttl_seconds)
    if acquired:
        _solo_lock_tokens[task_name] = token
    return bool(acquired)


def release_solo_lock(task_name: str) -> None:
    """Release the solo-lock for *task_name* — only if we still own it."""
    token = _solo_lock_tokens.pop(task_name, None)
    if token is None:
        return  # never acquired here, or already released — don't touch the key
    r = _get_solo_redis()
    key = f"freesdn:solo:{task_name}"
    try:
        r.eval(_SOLO_RELEASE_LUA, 1, key, token)
    except Exception:  # pragma: no cover - release must never raise into a task finally
        logger.debug("solo-lock release failed for %s", task_name, exc_info=True)


# ===========================================
# Debug Task
# ===========================================


@celery_app.task(bind=True)  # type: ignore[untyped-decorator]
def debug_task(self: Any) -> dict[str, str]:
    """Debug task to test Celery connectivity."""
    print(f"Request: {self.request!r}")
    return {"status": "ok", "celery": "working", "task_id": self.request.id}
