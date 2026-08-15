// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { api } from './client';
import type {
  SiteGroup, DeviceGroup, ConfigTemplate, DeviceConfig, ResolvedConfig,
  DeviceHealthResponse, SiteHealthSummary, OrgHealthSummary,
  DeviceLifecycleResponse, LifecycleLogEntry, BulkOperation,
  CorrelationRule, Incident, IncidentEvent, CorrelationStats,
  SLAPolicy, SLABreach, SLAComplianceSummary,
  TopologyGraph, TopologyLayout,
  AlertRule, AlertRuleCreate, AlertRuleUpdate, AlertInstance, AlertRuleStats,
  DeviceHealthListResponse, TopIssuesResponse, InfrastructureHealthResponse, ModuleHealthSummary,
  HealthDailySnapshotResponse, WANDeviceHealth, SiteRanking,
} from './types';

// =============================================================================
// Enterprise Config Management
// =============================================================================

export const enterpriseApi = {
  // Site Groups
  listSiteGroups: () =>
    api.get<SiteGroup[]>('/enterprise/site-groups'),

  createSiteGroup: (data: { name: string; description?: string; parent_id?: string }) =>
    api.post<SiteGroup>('/enterprise/site-groups', data),

  getSiteGroup: (id: string) =>
    api.get<SiteGroup>(`/enterprise/site-groups/${id}`),

  updateSiteGroup: (id: string, data: Partial<SiteGroup>) =>
    api.patch<SiteGroup>(`/enterprise/site-groups/${id}`, data),

  deleteSiteGroup: (id: string) =>
    api.delete(`/enterprise/site-groups/${id}`),

  // Device Groups
  listDeviceGroups: (params?: { site_id?: string }) =>
    api.get<DeviceGroup[]>('/enterprise/device-groups', { params }),

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  createDeviceGroup: (data: { name: string; description?: string; site_id: string; match_rules?: Record<string, any> }) =>
    api.post<DeviceGroup>('/enterprise/device-groups', data),

  getDeviceGroup: (id: string) =>
    api.get<DeviceGroup>(`/enterprise/device-groups/${id}`),

  updateDeviceGroup: (id: string, data: Partial<DeviceGroup>) =>
    api.patch<DeviceGroup>(`/enterprise/device-groups/${id}`, data),

  deleteDeviceGroup: (id: string) =>
    api.delete(`/enterprise/device-groups/${id}`),

  addDeviceToGroup: (groupId: string, deviceId: string) =>
    api.post(`/enterprise/device-groups/${groupId}/devices/${deviceId}`),

  removeDeviceFromGroup: (groupId: string, deviceId: string) =>
    api.delete(`/enterprise/device-groups/${groupId}/devices/${deviceId}`),

  // Device Tags
  getDeviceTags: (deviceId: string) =>
    api.get<{ device_id: string; tags: string[] }>(`/enterprise/devices/${deviceId}/tags`),

  updateDeviceTags: (deviceId: string, tags: string[]) =>
    api.put(`/enterprise/devices/${deviceId}/tags`, { tags }),

  // Config Templates
  listTemplates: (params?: { scope?: string; scope_id?: string; device_type?: string }) =>
    api.get<ConfigTemplate[]>('/enterprise/templates', { params }),

  createTemplate: (data: {
    name: string;
    description?: string;
    scope: string;
    scope_id?: string;
    device_type?: string;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    config: Record<string, any>;
    priority?: number;
  }) => api.post<ConfigTemplate>('/enterprise/templates', data),

  getTemplate: (id: string) =>
    api.get<ConfigTemplate>(`/enterprise/templates/${id}`),

  updateTemplate: (id: string, data: Partial<ConfigTemplate>) =>
    api.patch<ConfigTemplate>(`/enterprise/templates/${id}`, data),

  // Server-side clone: copies the real (unredacted) stored config. The client
  // never sees secrets, so a client-side duplicate would copy the redaction
  // placeholder over them.
  duplicateTemplate: (id: string) =>
    api.post<ConfigTemplate>(`/enterprise/templates/${id}/duplicate`),

  deleteTemplate: (id: string) =>
    api.delete(`/enterprise/templates/${id}`),

  // Device Config (Three-State)
  getDeviceConfig: (deviceId: string) =>
    api.get<DeviceConfig>(`/enterprise/devices/${deviceId}/config`),

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  updateDeviceOverrides: (deviceId: string, overrides: Record<string, any>) =>
    api.put(`/enterprise/devices/${deviceId}/config/overrides`, { device_overrides: overrides }),

  updateDeviceConfigSettings: (deviceId: string, settings: { auto_remediate?: boolean; drift_acknowledged?: boolean }) =>
    api.patch(`/enterprise/devices/${deviceId}/config/settings`, settings),

  getResolvedConfig: (deviceId: string) =>
    api.get<ResolvedConfig>(`/enterprise/devices/${deviceId}/config/resolved`),

  // Lifecycle
  getDeviceLifecycle: (deviceId: string) =>
    api.get<DeviceLifecycleResponse>(`/enterprise/devices/${deviceId}/lifecycle`),

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  transitionLifecycle: (deviceId: string, data: { to_state: string; trigger?: string; error_message?: string; details?: Record<string, any> }) =>
    api.post(`/enterprise/devices/${deviceId}/lifecycle`, data),

  getLifecycleHistory: (deviceId: string) =>
    api.get<LifecycleLogEntry[]>(`/enterprise/devices/${deviceId}/lifecycle/history`),

  // Health Scores
  getDeviceHealth: (deviceId: string) =>
    api.get<DeviceHealthResponse>(`/enterprise/devices/${deviceId}/health`),

  getSiteHealth: (siteId: string) =>
    api.get<SiteHealthSummary>(`/enterprise/health/site/${siteId}`),

  getOrgHealth: (params?: { site_id?: string }) =>
    api.get<OrgHealthSummary>('/enterprise/health/organization', { params }),

  // Reconciliation.
  //
  // ``scope_id`` is OPTIONAL for ``scope=organization``, the backend
  // (``services/enterprise.py:reconcile_devices``) ignores it for that
  // scope and falls back to the caller's own org. Sending a placeholder
  // UUID like all-zeros is a footgun if pydantic ever tightens the
  // ``ReconcileRequest`` UUID validation.
  triggerReconcile: (data: { scope: string; scope_id?: string }) =>
    api.post<{
      total: number;
      compliant: number;
      drifted: number;
      errors: number;
      devices: Array<Record<string, unknown>>;
    }>('/enterprise/reconcile', data),

  // Bulk Operations
  createBulkOperation: (data: {
    operation: string;
    target: { scope: string; scope_id?: string; device_type?: string; tag?: string; device_ids?: string[] };
    config?: Record<string, unknown>;
    rollout?: { strategy: string; stages?: Array<{ percent: number; wait_minutes?: number }>; failure_threshold_percent?: number; rollback_on_failure?: boolean };
  }) => api.post<BulkOperation>('/enterprise/bulk-operations', data),

  listBulkOperations: (params?: { status?: string }) =>
    api.get<BulkOperation[]>('/enterprise/bulk-operations', { params }),

  getBulkOperation: (jobId: string) =>
    api.get<BulkOperation>(`/enterprise/bulk-operations/${jobId}`),

  cancelBulkOperation: (jobId: string) =>
    api.post(`/enterprise/bulk-operations/${jobId}/cancel`),

  // ── Health Dashboard (expanded) ───────────────────────────────────────────
  listDeviceHealth: (params?: {
    site_id?: string;
    health_status?: string;
    device_type?: string;
    sort_by?: string;
    sort_dir?: string;
    limit?: number;
    offset?: number;
  }) => api.get<DeviceHealthListResponse>('/enterprise/health/devices', { params }),

  getTopIssues: (params?: { site_id?: string; limit?: number }) =>
    api.get<TopIssuesResponse>('/enterprise/health/top-issues', { params }),

  getInfrastructureHealth: () =>
    api.get<InfrastructureHealthResponse>('/enterprise/health/infrastructure'),

  getModuleHealth: (params?: { site_id?: string }) =>
    api.get<ModuleHealthSummary[]>('/enterprise/health/modules', { params }),

  getHealthHistory: (params?: { range?: string; site_id?: string }) =>
    api.get<HealthDailySnapshotResponse[]>('/enterprise/health/history', { params }),

  getWANHealth: (params?: { site_id?: string }) =>
    api.get<WANDeviceHealth[]>('/enterprise/health/wan', { params }),

  getSiteRanking: (params?: { site_id?: string }) =>
    api.get<SiteRanking[]>('/enterprise/health/site-ranking', { params }),
};

// =============================================================================
// Event Correlation
// =============================================================================

export const correlationApi = {
  // Rules
  listRules: (params?: { status?: string }) =>
    api.get<{ rules: CorrelationRule[]; total: number }>('/correlation/rules', { params }),
  getRule: (ruleId: string) =>
    api.get<CorrelationRule>(`/correlation/rules/${ruleId}`),
  createRule: (data: Partial<CorrelationRule>) =>
    api.post<CorrelationRule>('/correlation/rules', data),
  updateRule: (ruleId: string, data: Partial<CorrelationRule>) =>
    api.patch<CorrelationRule>(`/correlation/rules/${ruleId}`, data),
  deleteRule: (ruleId: string) =>
    api.delete(`/correlation/rules/${ruleId}`),

  // Incidents
  listIncidents: (params?: { status?: string; severity?: string; site_id?: string; limit?: number; offset?: number }) =>
    api.get<{ incidents: Incident[]; total: number }>('/correlation/incidents', { params }),
  getIncident: (incidentId: string) =>
    api.get<Incident>(`/correlation/incidents/${incidentId}`),
  createIncident: (data: { title: string; description?: string; severity?: string; site_id?: string; tags?: string[] }) =>
    api.post<Incident>('/correlation/incidents', data),
  updateIncident: (incidentId: string, data: Partial<Incident>) =>
    api.patch<Incident>(`/correlation/incidents/${incidentId}`, data),
  getIncidentEvents: (incidentId: string) =>
    api.get<IncidentEvent[]>(`/correlation/incidents/${incidentId}/events`),

  // Engine
  getStats: (params?: { site_id?: string }) =>
    api.get<CorrelationStats>('/correlation/stats', { params }),
  trigger: (data: { time_window_minutes?: number; site_id?: string; dry_run?: boolean }) =>
    api.post('/correlation/trigger', data),
};

// =============================================================================
// SLA Monitoring
// =============================================================================

export const slaApi = {
  // Summary
  getSummary: (params?: { site_id?: string }) =>
    api.get<SLAComplianceSummary>('/sla/summary', { params }),

  // Policies
  listPolicies: (params?: { status?: string; scope?: string; limit?: number; offset?: number; site_id?: string }) =>
    api.get<{ policies: SLAPolicy[]; total: number }>('/sla/policies', { params }),
  getPolicy: (policyId: string) =>
    api.get<SLAPolicy>(`/sla/policies/${policyId}`),
  createPolicy: (data: Partial<SLAPolicy>) =>
    api.post<SLAPolicy>('/sla/policies', data),
  updatePolicy: (policyId: string, data: Partial<SLAPolicy>) =>
    api.patch<SLAPolicy>(`/sla/policies/${policyId}`, data),
  deletePolicy: (policyId: string) =>
    api.delete(`/sla/policies/${policyId}`),

  // Breaches
  listBreaches: (params?: { policy_id?: string; status?: string; limit?: number; offset?: number; site_id?: string }) =>
    api.get<{ breaches: SLABreach[]; total: number }>('/sla/breaches', { params }),
  acknowledgeBreach: (breachId: string, data?: { notes?: string }) =>
    api.post<SLABreach>(`/sla/breaches/${breachId}/acknowledge`, data || {}),

  // Evaluate
  evaluate: () =>
    api.post('/sla/evaluate'),
};

// =============================================================================
// Topology
// =============================================================================

export const topologyApi = {
  getGraph: (params?: { site_id?: string; include_health?: boolean }) =>
    api.get<TopologyGraph>('/topology/graph', { params }),
  getLayout: (siteId: string) =>
    api.get<TopologyLayout | null>(`/topology/layout/${siteId}`),
  saveLayout: (siteId: string, data: Partial<TopologyLayout>) =>
    api.put<TopologyLayout>(`/topology/layout/${siteId}`, data),
  deleteLayout: (siteId: string) =>
    api.delete(`/topology/layout/${siteId}`),
  autoLayout: (siteId: string, algorithm: string) =>
    api.post<TopologyGraph>(`/topology/auto-layout/${siteId}`, null, { params: { algorithm } }),
};

// =============================================================================
// Alert Rules Engine
// =============================================================================

export const alertRulesApi = {
  // Stats
  getStats: (params?: { site_id?: string }) =>
    api.get<AlertRuleStats>('/alert-rules/stats', { params }),

  // Rules CRUD
  listRules: (params?: { status?: string; type?: string; site_id?: string }) =>
    api.get<{ rules: AlertRule[]; total: number }>('/alert-rules/rules', { params }),
  getRule: (id: string) =>
    api.get<AlertRule>(`/alert-rules/rules/${id}`),
  createRule: (data: AlertRuleCreate) =>
    api.post<AlertRule>('/alert-rules/rules', data),
  updateRule: (id: string, data: AlertRuleUpdate) =>
    api.patch<AlertRule>(`/alert-rules/rules/${id}`, data),
  deleteRule: (id: string) =>
    api.delete(`/alert-rules/rules/${id}`),

  // Alerts CRUD & lifecycle
  listAlerts: (params?: { status?: string; severity?: string; rule_id?: string; limit?: number; offset?: number; site_id?: string }) =>
    api.get<{ alerts: AlertInstance[]; total: number }>('/alert-rules/alerts', { params }),
  getAlert: (id: string) =>
    api.get<AlertInstance>(`/alert-rules/alerts/${id}`),
  acknowledgeAlert: (id: string, data?: { note?: string }) =>
    api.post<AlertInstance>(`/alert-rules/alerts/${id}/acknowledge`, data || {}),
  resolveAlert: (id: string, data?: { resolution_note?: string }) =>
    api.post<AlertInstance>(`/alert-rules/alerts/${id}/resolve`, data || {}),
  suppressAlert: (id: string, data: { suppress_minutes: number; reason?: string }) =>
    api.post<AlertInstance>(`/alert-rules/alerts/${id}/suppress`, data),

  // Evaluation
  triggerEvaluation: (data?: { organization_id?: string }) =>
    api.post('/alert-rules/evaluate', data || {}),
};
