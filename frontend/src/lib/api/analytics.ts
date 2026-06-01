// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { api } from './client';
import type {
  EnterpriseAnalytics, DashboardSummary, MetricDefinition,
  MetricQueryRequest, MetricQueryResponse, DeviceHealth,
  NetworkOverview, TrafficAnalytics, ClientAnalytics,
  AnalyticsAlert, DashboardWidget,
} from './types';

export const analyticsApi = {
  getEnterpriseAnalytics: (hours?: number, siteId?: string) =>
    api.get<EnterpriseAnalytics>('/analytics/dashboard/enterprise', {
      params: { hours, site_id: siteId },
    }),

  getDashboardSummary: (siteId?: string) =>
    api.get<DashboardSummary>('/analytics/dashboard/summary', { params: { site_id: siteId } }),

  // Cross-site comparison, single batched-query roll-up of devices,
  // phones, alerts, controllers, and firmware compliance per site.
  // Used by the Cross-Site Comparison page.
  getSitesComparison: () =>
    api.get<{
      sites: Array<{
        site_id: string;
        name: string;
        slug: string;
        devices: { total: number; online: number; online_pct: number | null;
          switches: number; access_points: number; cameras: number;
          firewalls: number; phones: number; };
        phones: { total: number; sip_registered: number; managed: number };
        alerts: { open: number; critical_open: number; last_24h: number; last_7d: number };
        controllers: { total: number; connected: number };
        firmware: { tracked: number; compliant: number; compliance_pct: number | null };
      }>;
      summary: {
        total_sites: number;
        total_devices: number;
        total_online_devices: number;
        total_phones: number;
        total_alerts_open: number;
        total_critical_open: number;
        total_controllers: number;
        generated_at: string;
      };
    }>('/analytics/sites/comparison'),

  getMetricDefinitions: (category?: string, isActive?: boolean) =>
    api.get<MetricDefinition[]>('/analytics/metrics/definitions', {
      params: { category, is_active: isActive }
    }),

  getMetricDefinition: (metricName: string) =>
    api.get<MetricDefinition>(`/analytics/metrics/definitions/${metricName}`),

  queryMetrics: (request: MetricQueryRequest) =>
    api.post<MetricQueryResponse>('/analytics/metrics/query', request),

  getLatestMetric: (metricName: string, siteId?: string, deviceId?: string) =>
    api.get(`/analytics/metrics/${metricName}/latest`, {
      params: { site_id: siteId, device_id: deviceId }
    }),

  getDeviceHealth: (deviceId: string) =>
    api.get<DeviceHealth>(`/analytics/devices/${deviceId}/health`),

  getDevicesHealth: (siteId?: string, deviceType?: string, limit?: number) =>
    api.get<DeviceHealth[]>('/analytics/devices/health', {
      params: { site_id: siteId, device_type: deviceType, limit }
    }),

  getNetworkOverview: (siteId: string) =>
    api.get<NetworkOverview>(`/analytics/sites/${siteId}/network`),

  getTrafficAnalytics: (siteId: string, hours?: number) =>
    api.get<TrafficAnalytics>(`/analytics/sites/${siteId}/traffic`, { params: { hours } }),

  getClientAnalytics: (siteId: string, hours?: number) =>
    api.get<ClientAnalytics>(`/analytics/sites/${siteId}/clients`, { params: { hours } }),

  getAlerts: (params?: {
    status?: string; severity?: string; site_id?: string; limit?: number;
  }) => api.get<AnalyticsAlert[]>('/analytics/alerts', { params }),

  getAlert: (alertId: string) =>
    api.get<AnalyticsAlert>(`/analytics/alerts/${alertId}`),

  updateAlert: (alertId: string, data: { status?: string; notes?: string }) =>
    api.patch<AnalyticsAlert>(`/analytics/alerts/${alertId}`, data),

  getWidgets: (dashboardName?: string) =>
    api.get<DashboardWidget[]>('/analytics/widgets', { params: { dashboard_name: dashboardName } }),

  createWidget: (data: Omit<DashboardWidget, 'id' | 'created_at' | 'updated_at'>) =>
    api.post<DashboardWidget>('/analytics/widgets', data),

  updateWidget: (widgetId: string, data: Partial<DashboardWidget>) =>
    api.put<DashboardWidget>(`/analytics/widgets/${widgetId}`, data),

  deleteWidget: (widgetId: string) =>
    api.delete(`/analytics/widgets/${widgetId}`),

  getAggregations: () =>
    api.get('/analytics/aggregations'),

  getTimeRanges: () =>
    api.get('/analytics/time-ranges'),

  getGranularities: () =>
    api.get('/analytics/granularities'),
};
