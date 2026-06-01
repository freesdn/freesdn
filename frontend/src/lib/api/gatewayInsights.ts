// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Gateway insights: pure read-only telemetry.
 */

import { api } from './client';

const prefix = (controllerId: string, siteId: string) =>
  `/gateway-insights/${controllerId}/sites/${siteId}`;

export const gatewayInsightsApi = {
  appTraffic: (
    controllerId: string,
    siteId: string,
    params?: { period?: string; top_n?: number },
  ) => api.get(`${prefix(controllerId, siteId)}/app-traffic`, { params }),

  appTrafficHistory: (
    controllerId: string,
    siteId: string,
    appId: string,
    params?: { granularity?: string; period?: string },
  ) =>
    api.get(`${prefix(controllerId, siteId)}/app-traffic/${appId}/history`, {
      params,
    }),

  topTalkers: (
    controllerId: string,
    siteId: string,
    params?: { period?: string; top_n?: number; kind?: 'client' | 'ssid' | 'ap' },
  ) => api.get(`${prefix(controllerId, siteId)}/top-talkers`, { params }),

  pastConnections: (
    controllerId: string,
    siteId: string,
    params?: { client_mac?: string; limit?: number },
  ) => api.get(`${prefix(controllerId, siteId)}/past-connections`, { params }),

  rfHeatmap: (controllerId: string, siteId: string) =>
    api.get(`${prefix(controllerId, siteId)}/rf-heatmap`),

  wifiSurvey: (controllerId: string, siteId: string, mac: string) =>
    api.get(`${prefix(controllerId, siteId)}/wifi-survey/${mac}`),

  anomalies: (
    controllerId: string,
    siteId: string,
    params?: { period?: string },
  ) => api.get(`${prefix(controllerId, siteId)}/anomalies`, { params }),

  aiSuggestions: (controllerId: string, siteId: string) =>
    api.get(`${prefix(controllerId, siteId)}/ai-suggestions`),

  meshTopology: (controllerId: string, siteId: string) =>
    api.get(`${prefix(controllerId, siteId)}/mesh-topology`),

  cableDiagHistory: (
    controllerId: string,
    siteId: string,
    mac: string,
    params?: { limit?: number },
  ) =>
    api.get(`${prefix(controllerId, siteId)}/cable-diag-history/${mac}`, {
      params,
    }),
};
