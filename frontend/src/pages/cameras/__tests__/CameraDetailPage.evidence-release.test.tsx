// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Releasing an evidence hold that the server refuses (409 while it is still
 * archiving, 403 after a role change) says so with the server's reason. The
 * camera page's release mutation had no onError; the multi-playback panel's
 * copy of the same action already reported it.
 */
import type { AxiosResponse } from 'axios';
import { AxiosError } from 'axios';
import { cleanup, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { api } from '@/lib/api/client';
import { useAuthStore, type User } from '@/stores/authStore';
import { renderWithProviders } from '@/test-utils';
import CameraDetailPage from '../CameraDetailPage';

const CAMERA_ID = '0f6c1a52-6d1e-4a4b-9b55-1d2f3c4b5a69';
const HOLD_ID = '7d1f2a33-1111-4222-8333-444455556666';
const REASON = 'The hold is still archiving; release it once it is sealed.';
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
    if (config.url === `/cameras/${CAMERA_ID}`) data = { id: CAMERA_ID, name: 'Dock', status: 'online', vendor: 'hikvision', ip_address: '198.51.100.20' };
    if (config.url === '/cameras/evidence') {
      data = { items: [{ id: HOLD_ID, camera_id: CAMERA_ID, start_time: '2026-11-13T10:00:00Z', end_time: '2026-11-13T10:05:00Z', watermarked: false, status: 'archiving', created_at: '2026-11-13T10:06:00Z' }] };
    }
    return { config, data, status: 200, statusText: '200', headers: {} } as AxiosResponse;
  };
});

afterEach(() => {
  cleanup();
  api.defaults.adapter = oldAdapter;
});

it("says why a hold could not be released", async () => {
  const user = userEvent.setup();
  renderWithProviders(<CameraDetailPage />, { initialPath: `/cameras/${CAMERA_ID}/recordings`, routePath: '/cameras/:id/:tab' });
  await user.click(await screen.findByTitle('Release hold (delete archive)'));
  const dialog = await screen.findByRole('alertdialog');
  await user.click(within(dialog).getByRole('button', { name: 'Release hold' }));
  expect(await screen.findByText('Could not release the evidence hold')).toBeInTheDocument();
  expect(screen.getByText(REASON)).toBeInTheDocument();
  expect(deletes).toEqual([`/cameras/evidence/${HOLD_ID}`]);
});
