// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * A phone that moved can be tested at its new address from the phone page.
 * Discovery never moves a known phone by itself; the connection test at the
 * new address is what records it, and the dialog used to test only the old
 * address (found in review of 26.11.3).
 */
import type { AxiosResponse } from 'axios';
import { cleanup, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { api } from '@/lib/api/client';
import { useAuthStore, type User } from '@/stores/authStore';
import { renderWithProviders } from '@/test-utils';
import PhoneDetailPage from '../PhoneDetailPage';

const PHONE_ID = '7a1b2c3d-1111-4222-8333-444455556666';
const oldAdapter = api.defaults.adapter;
const posts: { url: string; body: Record<string, unknown> }[] = [];

beforeEach(() => {
  posts.length = 0;
  useAuthStore.setState({
    user: { id: 'u1', username: 'u', email: 'u@example.invalid', organization_id: 'o1', role: 'admin', is_active: true, permissions: ['*'], roles: ['admin'] } as unknown as User,
    isAuthenticated: true,
  });
  api.defaults.adapter = async (config) => {
    let data: unknown = {};
    if (config.method === 'post') {
      const body = JSON.parse(String(config.data ?? '{}')) as Record<string, unknown>;
      posts.push({ url: String(config.url), body });
      data = { success: true, status: 'connected', ip_address: body.ip_address ?? '198.51.100.20', authenticated: true, sip_registered: false };
    } else if (config.url === `/voip/phones/${PHONE_ID}`) {
      data = {
        id: PHONE_ID, name: 'Front desk', ip_address: '198.51.100.20', mac_address: '00:0b:82:00:00:01',
        vendor: 'grandstream', status: 'online', lifecycle_state: 'managed', site_id: 's1',
        settings: { discovered_address: { ip: '198.51.100.44', at: '2026-11-20T03:00:00+00:00' } },
      };
    }
    return { config, data, status: 200, statusText: '200', headers: {} } as AxiosResponse;
  };
});

afterEach(() => {
  cleanup();
  api.defaults.adapter = oldAdapter;
});

it('tests a phone at the address discovery last saw it at', async () => {
  const user = userEvent.setup();
  renderWithProviders(<PhoneDetailPage />, { initialPath: `/voip/phones/${PHONE_ID}/network`, routePath: '/voip/phones/:id/:tab' });
  await user.click(await screen.findByRole('button', { name: 'Test there' }));
  expect(screen.getByLabelText('Address (optional)')).toHaveValue('198.51.100.44');
  await user.click(screen.getByRole('button', { name: /Test Connection/ }));
  await screen.findByText(/Connected & Authenticated/);
  const test = posts.find((p) => p.url === `/voip/phones/${PHONE_ID}/test-connection`);
  expect(test?.body.ip_address).toBe('198.51.100.44');
});

it('tests the recorded address when the field is left empty', async () => {
  const user = userEvent.setup();
  renderWithProviders(<PhoneDetailPage />, { initialPath: `/voip/phones/${PHONE_ID}/network`, routePath: '/voip/phones/:id/:tab' });
  await user.click(await screen.findByRole('button', { name: /Test Connection/ }));
  await screen.findByText(/Connected & Authenticated/);
  const test = posts.find((p) => p.url === `/voip/phones/${PHONE_ID}/test-connection`);
  expect(test?.body).not.toHaveProperty('ip_address');
});
