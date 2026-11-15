// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The Devices header's Export CSV button is the same height as the
 * header's refresh button (h-9), like every other network page's header.
 * It was a small button (h-8) beside the default-size refresh.
 */
import type { AxiosResponse } from 'axios';
import { cleanup, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { api } from '@/lib/api/client';
import { renderWithProviders } from '@/test-utils';
import DevicesPage from '../DevicesPage';

const oldAdapter = api.defaults.adapter;

beforeEach(() => {
  api.defaults.adapter = async (config) =>
    ({ config, data: { items: [], total: 0 }, status: 200, statusText: '200', headers: {} }) as AxiosResponse;
});

afterEach(() => {
  cleanup();
  api.defaults.adapter = oldAdapter;
});

it('gives the header actions one height', async () => {
  renderWithProviders(<DevicesPage />, { initialPath: '/devices', routePath: '/devices' });
  const exportButton = await screen.findByRole('button', { name: /Export CSV/ });
  const refresh = screen.getByRole('button', { name: 'Refresh' });
  expect(exportButton.className).toMatch(/\bh-9\b/);
  expect(exportButton.className).not.toMatch(/\bh-8\b/);
  expect(refresh.className).toMatch(/\bh-9\b/);
});
