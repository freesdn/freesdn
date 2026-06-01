# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Services
======================

Core business logic services.
"""

from app.services.adapter_factory import get_adapter, get_available_adapter_types
from app.services.analytics import (
    AnalyticsService,
    AnomalyDetector,
    MetricsCollector,
    PersistentAnalyticsService,
)
from app.services.audit import (
    AuditAction,
    AuditEntry,
    AuditQuery,
    AuditService,
    ResourceType,
    SecurityEvent,
    SecurityEventType,
    clear_audit_context,
    set_audit_context,
)
from app.services.auth import (
    AccountDisabledError,
    AccountLockedError,
    AuthError,
    AuthResult,
    AuthService,
    InvalidCredentialsError,
    MFARequiredError,
    TokenPair,
)
from app.services.automation import (
    Action,
    ActionExecutionError,
    ActionResult,
    AutomationEngine,
    AutomationError,
    AutomationRule,
    AutomationService,
    Condition,
    ConditionGroup,
    ConditionOperator,
    RuleEvaluationError,
    RuleExecution,
    RuleStatus,
    TriggerType,
    automation_engine,
)
from app.services.automation import (
    ActionType as AutomationActionType,
)
from app.services.backup import (
    SUPPORTED_STORAGE_TYPES,
    BackupEncryption,
    BackupService,
    BackupStorageBackend,
    DropboxStorageBackend,
    FTPStorageBackend,
    GoogleDriveStorageBackend,
    LocalStorageBackend,
    S3StorageBackend,
    SFTPStorageBackend,
    WebDAVStorageBackend,
    get_storage_backend,
)
from app.services.correlation import EventCorrelationService
from app.services.device_control import (
    ActionRequest,
    ActionResponse,
    DeviceControlService,
)
from app.services.device_control import (
    ActionType as DeviceActionType,
)
from app.services.discovery import DiscoveryError, DiscoveryService
from app.services.enterprise import (
    BulkOperationService,
    HealthService,
    LifecycleService,
    ReconciliationService,
    TemplateResolver,
)
from app.services.firmware import PersistentFirmwareService
from app.services.notification import (
    DeliveryError,
    DeliveryResult,
    DeliveryStatus,
    NotificationCategory,
    NotificationChannel,
    NotificationError,
    NotificationPayload,
    NotificationService,
    NotificationSeverity,
    SlackProvider,
    SMTPProvider,
    TemplateRenderer,
    WebhookProvider,
)
from app.services.organization import (
    MemberRole,
    OrganizationError,
    OrganizationQuota,
    OrganizationService,
    OrganizationStats,
    OrganizationStatus,
    OrganizationTier,
    QuotaExceededError,
)
from app.services.security_audit import PersistentSecurityAuditService
from app.services.sla import SLAMonitoringService
from app.services.sso import (
    SSOAuthError,
    SSOCallbackError,
    SSOConfigError,
    SSOError,
    SSOProviderNotFoundError,
    SSOService,
)
from app.services.topology import TopologyService
from app.services.webhooks import PersistentWebhookService
from app.services.websocket import (
    ConnectionManager,
    WSEventType,
    create_ws_message,
)

__all__ = [
    # Adapter Factory
    "get_adapter",
    "get_available_adapter_types",
    # Discovery
    "DiscoveryService",
    "DiscoveryError",
    # Auth
    "AuthService",
    "AuthError",
    "InvalidCredentialsError",
    "AccountLockedError",
    "AccountDisabledError",
    "MFARequiredError",
    "TokenPair",
    "AuthResult",
    # Device Control
    "DeviceControlService",
    "DeviceActionType",
    "ActionRequest",
    "ActionResponse",
    # WebSocket
    # NOTE: websocket_manager and setup_websocket_event_handlers were
    # removed in they broadcast unfiltered across all
    # organizations. Use app.api.v1.endpoints.websocket (org-scoped).
    "ConnectionManager",
    "WSEventType",
    "create_ws_message",
    # Organization
    "OrganizationService",
    "OrganizationTier",
    "OrganizationStatus",
    "MemberRole",
    "OrganizationQuota",
    "OrganizationStats",
    "OrganizationError",
    "QuotaExceededError",
    # Backup
    "BackupService",
    "BackupEncryption",
    "BackupStorageBackend",
    "LocalStorageBackend",
    "S3StorageBackend",
    "SFTPStorageBackend",
    "FTPStorageBackend",
    "GoogleDriveStorageBackend",
    "DropboxStorageBackend",
    "WebDAVStorageBackend",
    "get_storage_backend",
    "SUPPORTED_STORAGE_TYPES",
    # Notification
    "NotificationService",
    "NotificationChannel",
    "NotificationSeverity",
    "NotificationCategory",
    "DeliveryStatus",
    "NotificationPayload",
    "DeliveryResult",
    "NotificationError",
    "DeliveryError",
    "TemplateRenderer",
    "SMTPProvider",
    "SlackProvider",
    "WebhookProvider",
    # Audit
    "AuditService",
    "AuditAction",
    "ResourceType",
    "SecurityEventType",
    "AuditEntry",
    "SecurityEvent",
    "AuditQuery",
    "set_audit_context",
    "clear_audit_context",
    # Automation
    "AutomationService",
    "AutomationEngine",
    "automation_engine",
    "TriggerType",
    "AutomationActionType",
    "ConditionOperator",
    "RuleStatus",
    "Condition",
    "ConditionGroup",
    "Action",
    "ActionResult",
    "AutomationRule",
    "RuleExecution",
    "AutomationError",
    "RuleEvaluationError",
    "ActionExecutionError",
    # SSO
    "SSOService",
    "SSOError",
    "SSOProviderNotFoundError",
    "SSOConfigError",
    "SSOCallbackError",
    "SSOAuthError",
    # Enterprise
    "TemplateResolver",
    "LifecycleService",
    "HealthService",
    "ReconciliationService",
    "BulkOperationService",
    # Correlation
    "EventCorrelationService",
    # SLA
    "SLAMonitoringService",
    # Topology
    "TopologyService",
    # Firmware
    "PersistentFirmwareService",
    # Webhooks
    "PersistentWebhookService",
    # Analytics
    "AnalyticsService",
    "PersistentAnalyticsService",
    "MetricsCollector",
    "AnomalyDetector",
    # Security Audit
    "PersistentSecurityAuditService",
]
