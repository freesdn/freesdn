// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Deleting a PBX that the server refuses says so with the server's reason,
 * and the page stays on the PBX. The delete mutation had no onError.
 */
import type { AxiosResponse } from 'axios';
import { AxiosError } from 'axios';
import { cleanup, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { api } from '@/lib/api/client';
import { useAuthStore, type User } from '@/stores/authStore';
import { renderWithProviders } from '@/test-utils';
import PBXDetailPage from '../PBXDetailPage';

const PBX_ID = '5b6c7d8e-1111-4222-8333-444455556666';
const REASON = 'This PBX still has phones provisioned against it.';
const oldAdapter = api.defaults.adapter;
const deletes: string[] = [];

beforeEach(() => {
  deletes.length = 0;
  useAuthStore.setState({
    user: { id: 'u1', username: 'u', email: 'u@example.invalid', organization_id: 'o1', role: 'admin', is_active: true, permissions: ['*'], roles: ['admin'] } as unknown as User,
    isAuthenticated: true,
  });
  api.defaults.adapter = async (config) => {
    if (config.method === 'delete') {
      deletes.push(String(config.url));
      const response = {
        config, status: 409, statusText: '', headers: {},
        data: { error: { code: 409, message: REASON, request_id: 'r1' } },
      } as AxiosResponse;
      throw new AxiosError('Request failed with status code 409', 'ERR_BAD_REQUEST', config, null, response);
    }
    let data: unknown = {};
    if (config.url === `/voip/pbx/${PBX_ID}`) {
      data = { id: PBX_ID, name: 'Main PBX', pbx_type: 'freepbx', ip_address: '198.51.100.30', api_port: 443, sip_port: 5060, is_active: true };
    }
    return { config, data, status: 200, statusText: '200', headers: {} } as AxiosResponse;
  };
});

afterEach(() => {
  cleanup();
  api.defaults.adapter = oldAdapter;
});

it('says why the PBX could not be deleted', async () => {
  const user = userEvent.setup();
  renderWithProviders(<PBXDetailPage />, { initialPath: `/voip/pbx/${PBX_ID}/settings`, routePath: '/voip/pbx/:id/:tab' });
  await user.click(await screen.findByRole('button', { name: /Delete PBX/ }));
  const dialog = await screen.findByRole('alertdialog');
  await user.click(within(dialog).getByRole('button', { name: 'Delete PBX' }));
  expect(await screen.findByText('Could not delete the PBX')).toBeInTheDocument();
  expect(screen.getByText(REASON)).toBeInTheDocument();
  expect(screen.queryByText('PBX deleted')).not.toBeInTheDocument();
  expect(deletes).toEqual([`/voip/pbx/${PBX_ID}`]);
});
