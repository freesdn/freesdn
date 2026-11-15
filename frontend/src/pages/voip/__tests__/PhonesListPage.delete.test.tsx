// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Deleting a single phone from its row menu asks first (it deleted on the
 * click), opening that menu no longer also opens the phone's page, and the
 * bulk-delete toast describes the deletion. It used to read
 * "2 connected, 1 failed, 0 skipped", the bulk-connect sentence.
 * Real page and Axios client; only the network answers are controlled.
 */
import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { AxiosError } from 'axios';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { api } from '@/lib/api/client';
import { renderWithProviders } from '@/test-utils';
import PhonesListPage from '../PhonesListPage';

const phone = (id: string, name: string) => ({
  id, name, vendor: 'grandstream', model: 'GXP2170', mac_address: `00:0b:82:00:00:${id.slice(0, 2)}`,
  status: 'online', lifecycle_state: 'managed', sip_registered: true,
});
const PHONES = [
  phone('11111111-1111-4111-8111-111111111111', 'Front desk'),
  phone('22222222-2222-4222-8222-222222222222', 'Warehouse'),
];
const REFUSED = 'Phone is provisioned; decommission it first.';
const deletes: string[] = [];
const oldAdapter = api.defaults.adapter;

beforeEach(() => {
  deletes.length = 0;
  api.defaults.adapter = async (config: InternalAxiosRequestConfig): Promise<AxiosResponse> => {
    const method = (config.method ?? 'get').toUpperCase();
    const path = (config.url ?? '').replace(/\/$/, '');
    const reply = (status: number, data: unknown): AxiosResponse => ({ config, data, status, statusText: 'OK', headers: {} });
    if (method === 'GET' && path === '/voip/phones') return reply(200, { items: PHONES, total: PHONES.length });
    if (method === 'GET') return reply(200, { items: [], total: 0 });
    if (method === 'DELETE') {
      deletes.push(path);
      if (path.endsWith(PHONES[1].id)) {
        const response = reply(409, { error: { code: 409, message: REFUSED, request_id: 'r' } });
        throw new AxiosError('Request failed with status code 409', 'ERR_BAD_REQUEST', config, null, response);
      }
      return reply(204, null);
    }
    throw new Error(`Unexpected request ${method} ${path}`);
  };
});

afterEach(() => {
  api.defaults.adapter = oldAdapter;
});

describe('PhonesListPage delete', () => {
  it('asks before deleting one phone from its row menu', async () => {
    const user = userEvent.setup();
    // Mounted on its route: a click that also opened the phone's page (the
    // row's own click) would unmount the list and fail the next step.
    renderWithProviders(<PhonesListPage />, { initialPath: '/voip/phones', routePath: '/voip/phones' });
    const row = (await screen.findByText('Front desk')).closest('tr') as HTMLElement;
    await user.click(within(row).getByRole('button', { name: 'Actions for Front desk' }));
    await user.click(await screen.findByRole('menuitem', { name: /Delete/ }));
    let dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByRole('heading', { name: 'Delete Front desk?' })).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).toBeNull());
    expect(deletes).toEqual([]);

    await user.click(within(row).getByRole('button', { name: 'Actions for Front desk' }));
    await user.click(await screen.findByRole('menuitem', { name: /Delete/ }));
    dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Delete phone' }));
    await waitFor(() => expect(deletes).toEqual([`/voip/phones/${PHONES[0].id}`]));
  });

  it('summarises a bulk delete as deletions, with the reason one was refused', async () => {
    const user = userEvent.setup();
    renderWithProviders(<PhonesListPage />);
    await screen.findByText('Front desk');
    // Each checkbox names its phone; they all read "Select row" before.
    for (const name of ['Front desk', 'Warehouse']) await user.click(screen.getByRole('checkbox', { name: `Select ${name}` }));
    const bar = screen.getByText(/phones? selected/).closest('.fixed') as HTMLElement;
    await user.click(within(bar).getByRole('button', { name: 'Delete' }));
    await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Delete phones' }));
    expect(await screen.findByText(`1 deleted, 1 not deleted: ${REFUSED}`)).toBeInTheDocument();
    expect(screen.queryByText(/connected/)).toBeNull();
  });
});
