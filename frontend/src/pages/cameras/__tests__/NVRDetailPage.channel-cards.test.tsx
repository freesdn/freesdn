// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The NVR channel cards keep their badges inside the card at phone width.
 *
 * At 390 px the grid has two columns, so a card is about 170 px wide. Its
 * meta row ("Ch 1", the IP address, PTZ, Audio, REC) was a single nowrap
 * flex line inside a card that hides its overflow: the line needs about
 * 186 px, so the last badges were cut off by about 16 px. The row now wraps,
 * the address truncates rather than pushing the badges out, and the name
 * gives way to the status badge. Layout itself is not measured here (no CSS
 * engine in the test DOM); the classes that make it wrap are.
 */
import type { AxiosResponse } from 'axios';
import { cleanup, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { api } from '@/lib/api/client';
import { useAuthStore, type User } from '@/stores/authStore';
import { renderWithProviders } from '@/test-utils';
import NVRDetailPage from '../NVRDetailPage';

const NVR_ID = '3c4d5e6f-1111-4222-8333-444455556666';
const oldAdapter = api.defaults.adapter;

beforeEach(() => {
  useAuthStore.setState({
    user: { id: 'u', username: 'u', organization_id: 'o', role: 'admin', is_active: true, permissions: ['*'], roles: ['admin'] } as unknown as User,
    isAuthenticated: true,
  });
  api.defaults.adapter = async (config) => {
    let data: unknown = {};
    if (config.url === `/cameras/nvrs/${NVR_ID}`) data = { id: NVR_ID, name: 'Main NVR', status: 'offline', vendor: 'hikvision', ip_address: '198.51.100.40' };
    if (config.url === `/cameras/nvrs/${NVR_ID}/channels`) {
      data = { items: [{ id: 'c1', name: 'Loading dock north entrance', channel_id: 1, ip_address: '198.51.100.101', status: 'online', has_ptz: true, has_audio: true, is_recording: true }] };
    }
    return { config, data, status: 200, statusText: '200', headers: {} } as AxiosResponse;
  };
});

afterEach(() => {
  cleanup();
  api.defaults.adapter = oldAdapter;
});

it('wraps the channel meta row instead of clipping its badges', async () => {
  renderWithProviders(<NVRDetailPage />, { initialPath: `/cameras/nvrs/${NVR_ID}/channels`, routePath: '/cameras/nvrs/:id/:tab' });
  const meta = await screen.findByTestId('nvr-channel-meta');
  expect(meta.className).toMatch(/\bflex-wrap\b/);
  expect(meta.className).toMatch(/\bmin-w-0\b/);
  expect(within(meta).getByText('PTZ')).toBeInTheDocument();
  const address = within(meta).getByText('198.51.100.101');
  expect(address.className).toMatch(/\btruncate\b/);
  const name = screen.getAllByText('Loading dock north entrance').find((el) => el.closest('[role="button"]'));
  expect(name?.className).toMatch(/\btruncate\b/);
  expect(name?.className).toMatch(/\bmin-w-0\b/);
});
