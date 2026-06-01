# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Models Package
============================

All SQLAlchemy models for the application.
"""

from app.models.agents import (
    AgentHeartbeat,
    AgentRelease,
    AgentStatus,
    AgentTask,
    AgentTaskStatus,
    AgentTaskType,
    AgentType,
    RemoteAgent,
)
from app.models.alert_rules import (
    Alert,
    AlertRule,
    AlertRuleStatus,
    AlertRuleType,
)
from app.models.alert_rules import (
    AlertSeverity as AlertRuleSeverity,
)
from app.models.alert_rules import (
    AlertStatus as AlertRuleAlertStatus,
)
from app.models.analytics import (
    AggregationType,
    AlertSeverity,
    AlertStatus,
    AnalyticsAlert,
    DashboardWidget,
    Granularity,
    MetricDataPoint,
    MetricDefinitionRecord,
    MetricType,
)
from app.models.api_keys import APIKey
from app.models.automation import (
    AutomationExecutionRecord,
    AutomationRuleRecord,
)
from app.models.core import (
    Controller,
    ControllerStatus,
    ControllerType,
    Credential,
    CredentialScope,
    CredentialType,
    Organization,
    Site,
    User,
    UserRole,
    UserSession,
    UserSiteAccess,
)
from app.models.correlation import (
    CorrelationRule,
    CorrelationRuleStatus,
    Incident,
    IncidentEvent,
    IncidentSeverity,
    IncidentStatus,
)
from app.models.custom_roles import CustomRole
from app.models.devices import (
    ConnectionType,
    Device,
    DeviceClient,
    DevicePort,
    DeviceStatus,
    DeviceType,
    PortStatus,
    PortType,
)
from app.models.enterprise import (
    AutoBackupPolicy,
    BulkOperation,
    BulkOperationStatus,
    ConfigPushResult,
    ConfigTemplate,
    ConfigVersion,
    DeviceConfig,
    DeviceGroup,
    DeviceGroupMembership,
    DeviceHealth,
    DeviceLifecycleLog,
    DeviceTag,
    HealthStatus,
    LifecycleState,
    LifecycleTrigger,
    SiteGroup,
    TemplateScope,
)
from app.models.events import (
    EventCategory,
    EventPriority,
    EventRecord,
    EventSubscription,
)
from app.models.fabric import Connection, ConnectionRun
from app.models.firmware import (
    DeviceFirmwareStatus,
    FirmwareImage,
    FirmwareJobStatus,
    FirmwareSchedule,
    FirmwareUpgradeJob,
    ReleaseType,
    ScheduleFrequency,
)
from app.models.import_export import (
    ConflictResolution,
    ExportFormat,
    ExportJob,
    ExportScope,
    ImportJob,
    ImportSource,
    JobStatus,
)
from app.models.integrations import Integration
from app.models.marketplace import MarketplacePlugin, MarketplacePluginVersion, PluginReview
from app.models.notification import (
    InAppNotification,
    NotificationDelivery,
    NotificationPreference,
    NotificationProviderRecord,  # noqa: F401
)
from app.models.oauth2 import OAuth2App, OAuth2AuthorizationCode, OAuth2Token
from app.models.plugins import InstalledPlugin, PluginOrganizationState, PluginSetting
from app.models.poe import PoESchedule
from app.models.radius import (
    Dot1xAuthEvent,
    Dot1xPortConfig,
    RadiusServerProfile,
)
from app.models.security_audit import (
    AnomalyType,
    AuditActionType,
    AuditLogRecord,
    AuditResourceType,
    FailedLoginRecord,
    IPBlockReason,
    IPBlockRecord,
    SecurityAnomalyRecord,
    SecurityEventCategory,
    SecurityEventRecord,
    SecuritySeverity,
)
from app.models.sla import (
    SLABreach,
    SLABreachSeverity,
    SLABreachStatus,
    SLAPolicy,
    SLAPolicyScope,
    SLAPolicyStatus,
    SLAReport,
    SLAReportSchedule,
    SLASnapshot,
)
from app.models.sso import (
    SSOProtocol,
    SSOProvider,
    SSOProviderStatus,
    SSOSession,
)
from app.models.staging import AdapterPendingChange, OmadaPendingChange
from app.models.sync_lock import DeviceSyncLock
from app.models.topology import (
    TopologyLayout,
)
from app.models.vpn import (
    SiteToSiteTunnel,
    SiteVPNConfiguration,
    VPNConnectionRecord,
    VPNEvent,
    VPNHealthCheck,
    VPNReconnectState,
    VPNStatus,
    VPNTunnelTemplate,
    VPNType,
)
from app.models.webhooks import (
    DeliveryStatus,
    Webhook,
    WebhookDeadLetter,
    WebhookDelivery,
)
from app.models.ztp import (
    AdoptionJob,
    AdoptionJobStatus,
    AdoptionTrigger,
    AutoAdoptionRule,
    MACPreRegistration,
    ProvisioningProfile,
)
from app.modules.ai.models import (
    AIConversation,
    AIMessage,
    AIProviderConfig,
)
from app.modules.backup.models import (
    Backup,
    BackupSchedule,
    BackupStatus,
    BackupStorageType,
    BackupType,
    RestoreJob,
    StorageLocation,
)
from app.modules.collector.models import (
    AppCategory,
    ApplicationClassificationRule,
    CollectorConfig,
    CollectorLog,
    FlowRecord,
)

# Import OrganizationModule AFTER core models to resolve relationship
# This must be after Organization is defined to avoid circular import
from app.modules.models import (
    ModuleEvent,
    OrganizationModule,
)
from app.modules.network.models import (
    ClientRoamingEvent,
    LAGMode,
    LinkAggregationGroup,
    Network,
    PortProfile,
    TopologyLink,
    WifiBand,
    WifiNetwork,
    WifiSecurityType,
)

__all__ = [
    # Fabric (universal interconnect)
    "Connection",
    "ConnectionRun",
    # API Keys
    "APIKey",
    # OAuth2
    "OAuth2App",
    "OAuth2AuthorizationCode",
    "OAuth2Token",
    # AI Module
    "AIConversation",
    "AIMessage",
    "AIProviderConfig",
    # Plugins
    "InstalledPlugin",
    "PluginOrganizationState",
    "PluginSetting",
    # Marketplace
    "MarketplacePlugin",
    "MarketplacePluginVersion",
    "PluginReview",
    # Collector
    "CollectorLog",
    "FlowRecord",
    "CollectorConfig",
    "AppCategory",
    "ApplicationClassificationRule",
    # Core
    "Organization",
    "Site",
    "Controller",
    "ControllerType",
    "ControllerStatus",
    "Credential",
    "CredentialType",
    "CredentialScope",
    "User",
    "UserRole",
    "UserSession",
    "UserSiteAccess",
    # Custom Roles
    "CustomRole",
    # Devices
    "Device",
    "DeviceType",
    "DeviceStatus",
    "ConnectionType",
    "DevicePort",
    "PortType",
    "PortStatus",
    "DeviceClient",
    # Events
    "EventRecord",
    "EventSubscription",
    "EventCategory",
    "EventPriority",
    # Agents
    "RemoteAgent",
    "AgentHeartbeat",
    "AgentRelease",
    "AgentTask",
    "AgentType",
    "AgentStatus",
    "AgentTaskStatus",
    "AgentTaskType",
    # Modules
    "OrganizationModule",
    "ModuleEvent",
    # Analytics
    "MetricDefinitionRecord",
    "MetricDataPoint",
    "AnalyticsAlert",
    "DashboardWidget",
    "MetricType",
    "AggregationType",
    "AlertSeverity",
    "AlertStatus",
    "Granularity",
    # VPN
    "VPNConnectionRecord",
    "SiteVPNConfiguration",
    "VPNHealthCheck",
    "VPNEvent",
    "VPNReconnectState",
    "VPNTunnelTemplate",
    "SiteToSiteTunnel",
    "VPNType",
    "VPNStatus",
    # Security Audit
    "AuditLogRecord",
    "SecurityEventRecord",
    "FailedLoginRecord",
    "IPBlockRecord",
    "SecurityAnomalyRecord",
    "AuditActionType",
    "AuditResourceType",
    "SecuritySeverity",
    "SecurityEventCategory",
    "IPBlockReason",
    "AnomalyType",
    # Data Import/Export
    "ExportJob",
    "ImportJob",
    "ExportFormat",
    "ExportScope",
    "ImportSource",
    "ConflictResolution",
    "JobStatus",
    # Device Sync
    "DeviceSyncLock",
    # ZTP & Provisioning
    "AutoAdoptionRule",
    "MACPreRegistration",
    "AdoptionJob",
    "AdoptionJobStatus",
    "AdoptionTrigger",
    "ProvisioningProfile",
    # Firmware
    "FirmwareImage",
    "DeviceFirmwareStatus",
    "FirmwareUpgradeJob",
    "FirmwareSchedule",
    "ReleaseType",
    "FirmwareJobStatus",
    "ScheduleFrequency",
    # Webhooks
    "Webhook",
    "WebhookDelivery",
    "WebhookDeadLetter",
    "DeliveryStatus",
    # Integrations
    "Integration",
    # SSO
    "SSOProvider",
    "SSOProviderStatus",
    "SSOProtocol",
    "SSOSession",
    # Backup
    "Backup",
    "BackupSchedule",
    "BackupStatus",
    "BackupStorageType",
    "BackupType",
    "RestoreJob",
    "StorageLocation",
    # Network (VLANs, WiFi, Profiles, LAGs, Topology)
    "Network",
    "WifiNetwork",
    "WifiSecurityType",
    "WifiBand",
    "PortProfile",
    "LinkAggregationGroup",
    "LAGMode",
    "TopologyLink",
    # Enterprise Config Management
    "SiteGroup",
    "DeviceGroup",
    "DeviceGroupMembership",
    "DeviceTag",
    "DeviceConfig",
    "ConfigTemplate",
    "DeviceLifecycleLog",
    "DeviceHealth",
    "LifecycleState",
    "ConfigPushResult",
    "HealthStatus",
    "TemplateScope",
    "LifecycleTrigger",
    "BulkOperation",
    "BulkOperationStatus",
    "AutoBackupPolicy",
    "ConfigVersion",
    # PoE Scheduling
    "PoESchedule",
    # Notifications
    "InAppNotification",
    "NotificationDelivery",
    "NotificationPreference",
    # Automation
    "AutomationRuleRecord",
    "AutomationExecutionRecord",
    # Event Correlation
    "CorrelationRule",
    "CorrelationRuleStatus",
    "Incident",
    "IncidentEvent",
    "IncidentSeverity",
    "IncidentStatus",
    # SLA Monitoring
    "SLAPolicy",
    "SLAPolicyStatus",
    "SLAPolicyScope",
    "SLABreach",
    "SLABreachSeverity",
    "SLABreachStatus",
    "SLASnapshot",
    # Topology
    "TopologyLayout",
    # RADIUS / 802.1X
    "RadiusServerProfile",
    "Dot1xPortConfig",
    "Dot1xAuthEvent",
    # VPN Orchestration
    "VPNTunnelTemplate",
    "SiteToSiteTunnel",
    # SLA Reports
    "SLAReport",
    "SLAReportSchedule",
    # Client Roaming
    "ClientRoamingEvent",
    # Alert Rules Engine
    "AlertRule",
    "AlertRuleStatus",
    "AlertRuleType",
    "AlertRuleSeverity",
    "AlertRuleAlertStatus",
    "Alert",
    # Adapter staging (read-only / preview pattern)
    "AdapterPendingChange",
    "OmadaPendingChange",  # deprecated alias, kept for backward compat
]
