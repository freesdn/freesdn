# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN - Celery Tasks"""

from app.tasks.alert_rules import (
    auto_resolve_alerts as auto_resolve_alert_rules_alerts,
)
from app.tasks.alert_rules import (
    auto_resolve_all_alerts,
    evaluate_alert_rules,
    evaluate_all_alert_rules,
    unsuppress_expired_alerts,
)
from app.tasks.analytics import (
    check_metric_thresholds,
    purge_old_metrics,
    resolve_stale_alerts,
)
from app.tasks.analytics import (
    collect_device_metrics as analytics_collect_device_metrics,
)
from app.tasks.backup import (
    cleanup_expired_backups,
    run_backup,
    run_scheduled_backups,
)
from app.tasks.base import (
    FreeSDNTask,
    TaskProgress,
    TaskResult,
    TaskStatus,
    async_task,
    freesdn_task,
    get_active_tasks,
    get_task_progress,
    get_task_result,
    revoke_task,
)
from app.tasks.bulk_operations import (
    execute_bulk_operation,
)
from app.tasks.correlation import (
    auto_resolve_all,
    auto_resolve_incidents,
    correlate_all_events,
    correlate_events,
)
from app.tasks.discovery import (
    discover_all_devices,
    discover_devices_for_controller,
    discovery_health_check,
)
from app.tasks.firmware import (
    check_scheduled_upgrades,
    refresh_device_firmware_status,
    run_firmware_upgrade,
)
from app.tasks.import_export import (
    cleanup_old_data_files,
    run_export_job,
    run_import_job,
)
from app.tasks.maintenance import (
    cleanup_old_events,
    cleanup_orphan_sessions,
    cleanup_stale_progress,
    vacuum_database,
)
from app.tasks.metrics import (
    collect_all_device_metrics,
    collect_controller_metrics,
    collect_device_metrics,
    collect_site_metrics,
)
from app.tasks.reconciliation import (
    recompute_all_health,
    recompute_device_health,
    reconcile_all_devices,
    reconcile_device,
)
from app.tasks.security_audit import (
    cleanup_audit_data,
    detect_anomalies,
    expire_ip_blocks,
    scan_brute_force,
)
from app.tasks.sla import (
    evaluate_sla_policies,
)
from app.tasks.sync import (
    mark_stale_devices_offline,
    sync_all_device_statuses,
    sync_device_config,
    sync_device_status,
)
from app.tasks.vpn import (
    auto_reconnect,
    check_tunnel_health,
    check_vpn_health,
    purge_old_vpn_events,
    purge_old_vpn_health_checks,
    scan_vpn_certificates,
    sync_vpn_connections,
)

__all__ = [
    # Base
    "FreeSDNTask",
    "TaskProgress",
    "TaskResult",
    "TaskStatus",
    "freesdn_task",
    "async_task",
    "get_task_progress",
    "get_task_result",
    "get_active_tasks",
    "revoke_task",
    # Discovery
    "discover_devices_for_controller",
    "discover_all_devices",
    "discovery_health_check",
    # Sync
    "sync_device_status",
    "sync_all_device_statuses",
    "mark_stale_devices_offline",
    "sync_device_config",
    # Metrics
    "collect_device_metrics",
    "collect_controller_metrics",
    "collect_all_device_metrics",
    "collect_site_metrics",
    # Maintenance
    "cleanup_old_events",
    "cleanup_stale_progress",
    "cleanup_orphan_sessions",
    "vacuum_database",
    # Analytics
    "analytics_collect_device_metrics",
    "purge_old_metrics",
    "check_metric_thresholds",
    "resolve_stale_alerts",
    # VPN
    "sync_vpn_connections",
    "check_vpn_health",
    "auto_reconnect",
    "check_tunnel_health",
    "purge_old_vpn_health_checks",
    "purge_old_vpn_events",
    "scan_vpn_certificates",
    # Security Audit
    "scan_brute_force",
    "expire_ip_blocks",
    "cleanup_audit_data",
    "detect_anomalies",
    # Data Import/Export
    "run_export_job",
    "run_import_job",
    "cleanup_old_data_files",
    # Firmware
    "run_firmware_upgrade",
    "check_scheduled_upgrades",
    "refresh_device_firmware_status",
    # Backup
    "run_backup",
    "run_scheduled_backups",
    "cleanup_expired_backups",
    # Reconciliation & Health
    "reconcile_device",
    "reconcile_all_devices",
    "recompute_device_health",
    "recompute_all_health",
    # Bulk Operations
    "execute_bulk_operation",
    # Event Correlation
    "correlate_events",
    "correlate_all_events",
    "auto_resolve_incidents",
    "auto_resolve_all",
    # SLA Monitoring
    "evaluate_sla_policies",
    # Alert Rules Engine
    "evaluate_alert_rules",
    "evaluate_all_alert_rules",
    "auto_resolve_alert_rules_alerts",
    "auto_resolve_all_alerts",
    "unsuppress_expired_alerts",
]
