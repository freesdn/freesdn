// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The switch list at phone width. Each row put the name, model and site on
 * the left and the status, port count and Manage on the right of one line;
 * at 390 px the name wrapped a word per line ("HQ-Core-" / "SW-01") and the
 * card clipped Manage on a degraded switch by about 16 px. The row now
 * stacks below the sm breakpoint, the name and model truncate (full name on
 * hover), and the decorative icon is hidden on a phone. Layout is not
 * measured here (no CSS engine in the test DOM); the classes that make it
 * stack are. Checked by eye at 390 and 1440 px against the demo data.
 */
import type { AxiosResponse } from 'axios';
import { cleanup, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { api } from '@/lib/api/client';
import { renderWithProviders } from '@/test-utils';
import SwitchesPage from '../SwitchesPage';

const oldAdapter = api.defaults.adapter;
const SWITCH = {
  id: 'sw-1', name: 'HQ-Warehouse-SW-01', model: 'CRS328-24P-4S+RM', vendor: 'mikrotik', site_id: 's1', site_name: 'HQ Campus',
  total_ports: 28, poe_ports: 24, sfp_ports: 4, status: 'degraded', uptime: 1000, cpu_usage: 3, memory_usage: 20,
  ports_up: 8, ports_down: 20, ports_disabled: 0, poe_budget: 500, poe_used: 40,
};

beforeEach(() => {
  api.defaults.adapter = async (config) => {
    let data: unknown = { items: [], total: 0 };
    const path = (config.url ?? '').replace(/\/$/, '');
    if (path === '/switches') data = { items: [SWITCH], total: 1 };
    if (path === '/switches/profiles') data = [];
    return { config, data, status: 200, statusText: '200', headers: {} } as AxiosResponse;
  };
});

afterEach(() => {
  cleanup();
  api.defaults.adapter = oldAdapter;
});

it('stacks a switch row below the sm breakpoint and truncates the name', async () => {
  renderWithProviders(<SwitchesPage />, { initialPath: '/switches', routePath: '/switches' });
  const header = await screen.findByTestId('switch-row-header');
  expect(header.className).toMatch(/\bflex-col\b/);
  expect(header.className).toMatch(/\bsm:flex-row\b/);
  const name = within(header).getByText('HQ-Warehouse-SW-01');
  expect(name.className).toMatch(/\btruncate\b/);
  expect(name).toHaveAttribute('title', 'HQ-Warehouse-SW-01');
  expect(within(header).getByRole('button', { name: 'Manage' })).toBeInTheDocument();
});
