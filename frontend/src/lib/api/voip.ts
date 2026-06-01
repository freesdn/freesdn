// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { api } from './client';

export const voipApi = {
  // Phones
  //
  // NOTE: ``/voip/phones`` without a trailing slash returns a 307 redirect
  // (FastAPI auto-adds the slash because the router is mounted as
  // ``@phones_router.get("/")``). With ``withCredentials: true`` axios
  // can't follow that redirect cross-origin, the browser sees an
  // opaque-redirect response and the React-Query call resolves with
  // ``undefined`` data, leaving the page stuck on its skeleton loader.
  // Always use the trailing slash on collection endpoints.
  getPhones: (params?: { site_id?: string; pbx_id?: string; status?: string; lifecycle_state?: string; vendor?: string; search?: string; limit?: number; offset?: number }) =>
    api.get('/voip/phones/', { params }),
  getPhoneStats: (siteId?: string) =>
    api.get('/voip/phones/stats', { params: { site_id: siteId } }),
  getPhoneById: (id: string) => api.get(`/voip/phones/${id}`),
  createPhone: (data: Record<string, unknown>) => api.post('/voip/phones/', data),
  updatePhone: (id: string, data: Record<string, unknown>) => api.patch(`/voip/phones/${id}`, data),
  deletePhone: (id: string) => api.delete(`/voip/phones/${id}`),

  // PBX Systems
  getPBXSystems: (params?: { site_id?: string; limit?: number; offset?: number }) =>
    api.get('/voip/pbx/', { params }),
  getPBXById: (id: string) => api.get(`/voip/pbx/${id}`),
  // Trailing slash, backend POST handler is at `/voip/pbx/`; FastAPI
  // would 307-redirect from the slashless form but axios doesn't
  // re-send the body on redirect, so we hit the canonical path.
  createPBX: (data: Record<string, unknown>) => api.post('/voip/pbx/', data),
  updatePBX: (id: string, data: Record<string, unknown>) => api.patch(`/voip/pbx/${id}`, data),
  deletePBX: (id: string) => api.delete(`/voip/pbx/${id}`),
  testPBXConnection: (data: {
    pbx_type: string;
    ip_address: string;
    api_port?: number;
    api_username?: string;
    api_password?: string;
    api_key?: string;
  }) => api.post('/voip/pbx/test-connection', data),
  syncPBX: (id: string) => api.post(`/voip/pbx/${id}/sync`),

  // PBX Enterprise Operations
  connectPBX: (id: string) => api.post(`/voip/pbx/${id}/connect`),
  getPBXDashboard: (id: string) => api.get(`/voip/pbx/${id}/dashboard`),
  getPBXSystemInfo: (id: string) => api.get(`/voip/pbx/${id}/system-info`),
  getPBXTrunks: (id: string) => api.get(`/voip/pbx/${id}/trunks`),
  getPBXQueues: (id: string) => api.get(`/voip/pbx/${id}/queues`),
  getPBXIVRs: (id: string) => api.get(`/voip/pbx/${id}/ivrs`),
  getPBXDids: (id: string) => api.get(`/voip/pbx/${id}/dids`),
  getPBXActiveCalls: (id: string) => api.get(`/voip/pbx/${id}/active-calls`),
  getPBXVoicemailBoxes: (id: string) => api.get(`/voip/pbx/${id}/voicemail-boxes`),

  // PBX Rich Data -- new enterprise endpoints
  getPBXFullConfig: (id: string) => api.get(`/voip/pbx/${id}/config`),
  getPBXOutboundRoutes: (id: string) => api.get(`/voip/pbx/${id}/outbound-routes`),
  getPBXFollowMe: (id: string) => api.get(`/voip/pbx/${id}/followme`),
  getPBXAnnouncements: (id: string) => api.get(`/voip/pbx/${id}/announcements`),
  getPBXPagingGroups: (id: string) => api.get(`/voip/pbx/${id}/paging`),
  getPBXDayNight: (id: string) => api.get(`/voip/pbx/${id}/daynight`),
  getPBXBlacklist: (id: string) => api.get(`/voip/pbx/${id}/blacklist`),
  getPBXCertificates: (id: string) => api.get(`/voip/pbx/${id}/certificates`),
  getPBXAdminUsers: (id: string) => api.get(`/voip/pbx/${id}/admin-users`),
  getPBXRingGroups: (id: string, params?: { limit?: number; offset?: number }) =>
    api.get(`/voip/pbx/${id}/ring-groups`, { params }),
  getPBXCallLogs: (id: string, params?: {
    start_date?: string; end_date?: string; src?: string; dst?: string; limit?: number;
  }) => api.get(`/voip/pbx/${id}/call-logs`, { params }),

  // PBX Extension Detail + CRUD
  getPBXExtensionDetail: (pbxId: string, extNumber: string) =>
    api.get(`/voip/pbx/${pbxId}/extensions/${extNumber}`),
  createPBXExtension: (pbxId: string, data: {
    extension_number: string; display_name: string;
    caller_id_name?: string; caller_id_number?: string;
    voicemail_enabled?: boolean; voicemail_pin?: string; password?: string;
  }) => api.post(`/voip/pbx/${pbxId}/extensions`, data),
  updatePBXExtension: (pbxId: string, extNumber: string, data: Record<string, unknown>) =>
    api.patch(`/voip/pbx/${pbxId}/extensions/${extNumber}`, data),
  deletePBXExtension: (pbxId: string, extNumber: string) =>
    api.delete(`/voip/pbx/${pbxId}/extensions/${extNumber}`),

  // PBX Trunk Detail + CRUD
  getPBXTrunkDetail: (pbxId: string, trunkId: string) =>
    api.get(`/voip/pbx/${pbxId}/trunks/${trunkId}`),
  createPBXTrunk: (pbxId: string, data: Record<string, unknown>) =>
    api.post(`/voip/pbx/${pbxId}/trunks`, data),
  updatePBXTrunk: (pbxId: string, trunkId: string, data: Record<string, unknown>) =>
    api.patch(`/voip/pbx/${pbxId}/trunks/${trunkId}`, data),
  deletePBXTrunk: (pbxId: string, trunkId: string) =>
    api.delete(`/voip/pbx/${pbxId}/trunks/${trunkId}`),

  // PBX Call Control
  originateCall: (pbxId: string, data: {
    extension: string; destination: string; caller_id?: string; context?: string;
  }) => api.post(`/voip/pbx/${pbxId}/call/originate`, data),
  hangupCall: (pbxId: string, channel: string) =>
    api.post(`/voip/pbx/${pbxId}/call/hangup`, { channel }),
  transferCall: (pbxId: string, data: {
    channel: string; destination: string; context?: string;
  }) => api.post(`/voip/pbx/${pbxId}/call/transfer`, data),

  // PBX System Operations
  reloadPBXConfig: (id: string) => api.post(`/voip/pbx/${id}/reload`),
  queueAddMember: (pbxId: string, data: {
    queue_name: string; interface: string; member_name?: string;
  }) => api.post(`/voip/pbx/${pbxId}/queue/add-member`, data),
  queueRemoveMember: (pbxId: string, data: {
    queue_name: string; interface: string;
  }) => api.post(`/voip/pbx/${pbxId}/queue/remove-member`, data),

  // Extensions (scoped to a PBX)
  getExtensions: (pbxId: string, params?: { limit?: number; offset?: number }) =>
    api.get(`/voip/pbx/${pbxId}/extensions`, { params }),
  getAllExtensions: (params?: { site_id?: string; limit?: number; offset?: number }) =>
    api.get('/voip/extensions/', { params }),

  // Ring Groups
  getRingGroups: (params?: { site_id?: string; pbx_id?: string; limit?: number; offset?: number }) =>
    api.get('/voip/ring-groups/', { params }),
  createRingGroup: (data: {
    pbx_id: string;
    group_number: string;
    name: string;
    description?: string;
    ring_strategy?: string;
    ring_time?: number;
    members?: string[];
  }) => api.post('/voip/ring-groups/', data),
  deleteRingGroup: (id: string) => api.delete(`/voip/ring-groups/${id}`),

  // Call Logs / CDR
  getCallLogs: (params?: {
    site_id?: string;
    pbx_id?: string;
    start_time?: string;
    end_time?: string;
    direction?: string;
    call_status?: string;
    caller?: string;
    callee?: string;
    limit?: number;
  }) => api.get('/voip/call-logs/', { params }),
  getCallStats: (params?: { site_id?: string; pbx_id?: string; start_time?: string; end_time?: string }) =>
    api.get('/voip/call-logs/stats', { params }),

  // Voicemails
  getVoicemails: (params?: {
    site_id?: string;
    extension_number?: string;
    folder?: string;
    is_read?: boolean;
    limit?: number;
    offset?: number;
  }) => api.get('/voip/voicemails/', { params }),
  getVoicemailStats: (params?: { site_id?: string; extension_number?: string }) =>
    api.get('/voip/voicemails/stats', { params }),
  getVoicemailById: (id: string) => api.get(`/voip/voicemails/${id}`),
  updateVoicemail: (id: string, data: { is_read?: boolean; folder?: string }) =>
    api.patch(`/voip/voicemails/${id}`, data),
  markVoicemailRead: (id: string) => api.post(`/voip/voicemails/${id}/mark-read`),
  deleteVoicemail: (id: string) => api.delete(`/voip/voicemails/${id}`),
  downloadVoicemail: (id: string) => api.get(`/voip/voicemails/${id}/download`),

  // === Fleet Management (GDMS-style) ===

  // Fleet Dashboard
  getFleetDashboard: (siteId?: string) =>
    api.get('/voip/fleet/dashboard', { params: { site_id: siteId } }),

  // Phone Lifecycle
  onboardPhone: (id: string, data: {
    name?: string;
    pbx_id?: string;
    extension_id?: string;
    config_template_id?: string;
    location?: string;
    tags?: string[];
  }) => api.post(`/voip/phones/${id}/onboard`, data),
  decommissionPhone: (id: string) => api.post(`/voip/phones/${id}/decommission`),
  toggleMaintenance: (id: string, enabled?: boolean) =>
    api.post(`/voip/phones/${id}/maintenance`, null, { params: { enabled: enabled ?? true } }),
  provisionPhone: (id: string, data?: { force?: boolean; reboot_after?: boolean }) =>
    api.post(`/voip/phones/${id}/provision`, data ?? {}),
  previewPhoneConfig: (id: string) =>
    api.get(`/voip/phones/${id}/config-preview`, { responseType: 'text' }),

  // Discovery
  triggerDiscoveryScan: (data: {
    site_id?: string;
    scan_type?: string;
    subnet?: string;
    port_range?: string;
    auto_onboard?: boolean;
    config_template_id?: string;
    credentials?: { username: string; password: string } | null;
  }) => api.post('/voip/discovery/scan', data),
  getDiscoveryScans: (params?: { site_id?: string; scan_status?: string; limit?: number; offset?: number }) =>
    api.get('/voip/discovery/scans', { params }),
  getDiscoveryScan: (id: string) => api.get(`/voip/discovery/scans/${id}`),
  getDiscoveryScanStatus: (id: string) => api.get(`/voip/discovery/scans/${id}/status`),
  cancelDiscoveryScan: (id: string) => api.post(`/voip/discovery/scans/${id}/cancel`),
  deleteDiscoveryScan: (id: string) => api.delete(`/voip/discovery/scans/${id}`),

  // Config Templates
  getTemplates: (params?: { site_id?: string; vendor?: string; limit?: number; offset?: number }) =>
    api.get('/voip/templates/', { params }),
  getTemplate: (id: string) => api.get(`/voip/templates/${id}`),
  createTemplate: (data: Record<string, unknown>) => api.post('/voip/templates/', data),
  updateTemplate: (id: string, data: Record<string, unknown>) => api.patch(`/voip/templates/${id}`, data),
  deleteTemplate: (id: string) => api.delete(`/voip/templates/${id}`),

  // Auto-link discovered phones to PBX extensions by sip_user_id + sip_registrar.
  // Idempotent, already-linked phones are skipped.
  autoLinkPhones: (params?: { site_id?: string; onboard?: boolean }) =>
    api.post('/voip/phones/auto-link', null, { params }),

  // Push the bound FreePBX extension's SIP credentials down to the
  // phone via the Grandstream adapter set_config path. Use dry_run=true
  // for a preview without writing to the device.
  pushSipConfigToPhone: (phoneId: string, body: {
    sip_password: string;
    account_index?: number;
    dry_run?: boolean;
  }) => api.post(`/voip/phones/${phoneId}/push-sip-config`, body),

  // Per-phone power actions. All go through the rewritten Grandstream
  // client's /cgi-bin/api-sys_operation endpoint.
  rebootPhone: (phoneId: string) =>
    api.post(`/voip/phones/${phoneId}/reboot`),
  factoryResetPhone: (phoneId: string) =>
    api.post(`/voip/phones/${phoneId}/factory-reset`),

  // Cheap live-state probe, designed for ~5 s polling. Returns
  // phone_state (available/in_call/ringing), per-line activity,
  // and lockout state. Hot path is ~250-600 ms.
  getPhoneLiveStatus: (phoneId: string) =>
    api.get(`/voip/phones/${phoneId}/live-status`),

  // Move a phone to a different site. Idempotent, re-running with
  // the same target site is a no-op.
  //
  // ``follow_links=true`` tries to find an equivalent PBX/extension
  // at the target site (matched by ip_address + extension_number).
  // Otherwise (default) all site-scoped links are cleared and the
  // operator runs auto-link to bind to the new site's PBX.
  migratePhone: (phoneId: string, body: {
    target_site_id: string;
    follow_links?: boolean;
    dry_run?: boolean;
  }) => api.post(`/voip/phones/${phoneId}/migrate`, body),

  // Firmware
  getFirmwareTracks: (params?: { vendor?: string; model?: string; limit?: number }) =>
    api.get('/voip/firmware/', { params }),
  createFirmwareTrack: (data: Record<string, unknown>) => api.post('/voip/firmware/', data),
  getFirmwareCompliance: (siteId?: string) =>
    api.get('/voip/firmware/compliance', { params: { site_id: siteId } }),

  // Bulk Operations
  bulkReboot: (phoneIds: string[]) =>
    api.post('/voip/fleet/bulk/reboot', { phone_ids: phoneIds }),
  bulkProvision: (phoneIds: string[]) =>
    api.post('/voip/fleet/bulk/provision', { phone_ids: phoneIds }),
  bulkFirmware: (phoneIds: string[], targetVersion: string, scheduleAt?: string) =>
    api.post('/voip/fleet/bulk/firmware', {
      phone_ids: phoneIds,
      target_version: targetVersion,
      schedule_at: scheduleAt,
    }),
  bulkConnect: (phoneIds: string[], username: string, password: string) =>
    api.post('/voip/fleet/bulk/connect', {
      phone_ids: phoneIds,
      username,
      password,
    }),

  // Phone Connection Test & Credentials
  testPhoneConnection: (id: string, data: {
    ip_address?: string;
    username?: string;
    password?: string;
    save_credentials?: boolean;
  }) => api.post(`/voip/phones/${id}/test-connection`, data),
  testPhoneConnectionAdhoc: (data: {
    ip_address: string;
    username?: string;
    password?: string;
  }) => api.post('/voip/phones/test-connection', data),
  savePhoneCredentials: (id: string, data: {
    username: string;
    password: string;
  }) => api.put(`/voip/phones/${id}/credentials`, data),

  // Legacy aliases (for backward compatibility)
  getDevices: (params?: Record<string, unknown>) => api.get('/voip/phones/', { params }),
  getCDR: (params?: Record<string, unknown>) => api.get('/voip/call-logs/', { params }),
};
