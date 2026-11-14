// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Only a super admin may switch an organization off or on: the API answers an
 * org admin's change with a 403, because deactivating signs every member out.
 * The switch was live for org admins, so they found out only on Save.
 */
import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { fireEvent, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { api } from '@/lib/api/client';
import { useAuthStore } from '@/stores/authStore';
import { renderWithProviders } from '@/test-utils';
import OrganizationDetailPage from '../OrganizationDetailPage';

const ORG = '0f0f0f0f-1111-4111-8111-111111111111';
const DASHBOARD = {
  id: ORG, name: 'Branch office', slug: 'branch', description: null, contact_email: null,
  contact_phone: null, is_active: true, settings: {}, created_at: '2026-11-01T00:00:00Z',
  updated_at: '2026-11-01T00:00:00Z', site_count: 0, user_count: 1, controller_count: 0,
  device_count: 0, online_device_count: 0, recent_sites: [],
};
const oldAdapter = api.defaults.adapter;
const oldUser = useAuthStore.getState().user;

beforeEach(() => {
  api.defaults.adapter = async (config: InternalAxiosRequestConfig): Promise<AxiosResponse> => {
    const path = (config.url ?? '').replace(/\/$/, '');
    const data = path === `/organizations/${ORG}/dashboard` ? DASHBOARD : { items: [], total: 0 };
    return { config, data, status: 200, statusText: 'OK', headers: {} };
  };
});

afterEach(() => {
  api.defaults.adapter = oldAdapter;
  useAuthStore.setState({ user: oldUser });
});

function render(isSuperuser: boolean) {
  useAuthStore.setState({
    user: { id: 'u1', email: 'a@example.test', role: isSuperuser ? 'super_admin' : 'org_admin', is_superuser: isSuperuser } as never,
  });
  return renderWithProviders(<OrganizationDetailPage />, {
    initialPath: `/organizations/${ORG}/settings`,
    routePath: '/organizations/:orgId/:tab',
  });
}

describe('Organization status switch', () => {
  it('is disabled for an org admin, with the reason', async () => {
    render(false);
    const toggle = await screen.findByRole('switch', { name: 'Status' });
    expect(toggle).toBeDisabled();

    // The disabled switch takes no focus; its DisabledReason wrapper does.
    fireEvent.focus(toggle.closest('span[tabindex="0"]') as HTMLElement);
    expect((await screen.findAllByText(/Only a super admin can deactivate or reactivate/)).length).toBeGreaterThan(0);
  });

  it('is usable by a super admin', async () => {
    render(true);
    expect(await screen.findByRole('switch', { name: 'Status' })).toBeEnabled();
    expect(screen.queryByText(/Only a super admin can deactivate/)).toBeNull();
  });
});
