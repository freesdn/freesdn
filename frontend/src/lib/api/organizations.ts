// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { api } from './client';
import type { Organization, OrganizationQuota, OrganizationMember } from './types';

export const organizationsApi = {
  getCurrent: () =>
    api.get<Organization>('/organizations/current'),

  updateCurrent: (data: { name?: string; settings?: Record<string, unknown> }) =>
    api.patch<Organization>('/organizations/current', data),

  getQuota: () =>
    api.get<OrganizationQuota>('/organizations/current/quota'),

  getUsage: () =>
    api.get<{ organization_id: string; tier: string; resources: Record<string, unknown>[] }>('/organizations/current/usage'),

  listMembers: () =>
    api.get<OrganizationMember[]>('/organizations/current/members'),

  inviteMember: (email: string, role: string) =>
    api.post('/organizations/current/members/invite', { email, role }),

  updateMemberRole: (memberId: string, role: string) =>
    api.patch(`/organizations/current/members/${memberId}/role`, { role }),

  removeMember: (memberId: string) =>
    api.delete(`/organizations/current/members/${memberId}`),

  getTiers: () =>
    api.get<{ tiers: Record<string, unknown>[] }>('/organizations/tiers'),

  checkFeature: (feature: string) =>
    api.post<{ feature: string; has_access: boolean }>('/organizations/current/check-feature', null, { params: { feature } }),

  getSettings: () =>
    api.get('/organizations/current/settings'),

  updateSettings: (settings: Record<string, unknown>) =>
    api.patch('/organizations/current/settings', settings),
};
