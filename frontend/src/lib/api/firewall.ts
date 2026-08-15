// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { api } from './client';

// NOTE: ``firewallsApi`` (plural, external-firewall-device CRUD) used
// to live here pointing at ``/api/v1/firewalls/...`` but those routes
// were removed when the Firewall module absorbed Gateway orchestration.
// Verified: zero remaining consumers and every URL 404s.
// Deleted entirely; if external-firewall CRUD comes back, build it on
// top of ``/api/v1/firewall/gateways/...`` instead.

// Firewall API (local DB -- rules, NAT, VPN, IDS, logs)
export const firewallApi = {
  // Firewall Rules
  getRules: (params?: { device_id?: string; is_enabled?: boolean; action?: string; site_id?: string; limit?: number; offset?: number }) =>
    api.get('/firewall/rules', { params }),

  getRule: (id: string) =>
    api.get(`/firewall/rules/${id}`),

  createRule: (data: Record<string, unknown>) =>
    api.post('/firewall/rules', data),

  updateRule: (id: string, data: Record<string, unknown>) =>
    api.patch(`/firewall/rules/${id}`, data),

  deleteRule: (id: string) =>
    api.delete(`/firewall/rules/${id}`),

  reorderRules: (deviceId: string, ruleIds: string[]) =>
    api.post('/firewall/rules/reorder', ruleIds, { params: { device_id: deviceId } }),

  // NAT Rules
  getNATRules: (params?: { device_id?: string; nat_type?: string; is_enabled?: boolean; site_id?: string; limit?: number; offset?: number }) =>
    api.get('/firewall/nat', { params }),

  getNATRule: (id: string) =>
    api.get(`/firewall/nat/${id}`),

  createNATRule: (data: Record<string, unknown>) =>
    api.post('/firewall/nat', data),

  updateNATRule: (id: string, data: Record<string, unknown>) =>
    api.patch(`/firewall/nat/${id}`, data),

  deleteNATRule: (id: string) =>
    api.delete(`/firewall/nat/${id}`),

  // VPN Tunnels
  getVPNTunnels: (params?: { device_id?: string; vpn_type?: string; vpn_status?: string; site_id?: string; limit?: number; offset?: number }) =>
    api.get('/firewall/vpn', { params }),

  getVPNStats: (params?: { site_id?: string }) =>
    api.get('/firewall/vpn/stats', { params }),

  getVPNTunnel: (id: string) =>
    api.get(`/firewall/vpn/${id}`),

  createVPNTunnel: (data: Record<string, unknown>) =>
    api.post('/firewall/vpn', data),

  updateVPNTunnel: (id: string, data: Record<string, unknown>) =>
    api.patch(`/firewall/vpn/${id}`, data),

  deleteVPNTunnel: (id: string) =>
    api.delete(`/firewall/vpn/${id}`),

  // IDS/IPS Alerts
  getAlerts: (params?: { device_id?: string; severity?: string; is_acknowledged?: boolean; start_time?: string; end_time?: string; site_id?: string; limit?: number }) =>
    api.get('/firewall/ids/alerts', { params }),

  getAlertStats: (params?: { start_time?: string; end_time?: string; site_id?: string }) =>
    api.get('/firewall/ids/alerts/stats', { params }),

  acknowledgeAlert: (id: string) =>
    api.post(`/firewall/ids/alerts/${id}/acknowledge`),

  // Firewall Logs
  getLogs: (params?: { device_id?: string; action?: string; source_ip?: string; dest_ip?: string; start_time?: string; end_time?: string; site_id?: string; limit?: number }) =>
    api.get('/firewall/logs', { params }),
};
