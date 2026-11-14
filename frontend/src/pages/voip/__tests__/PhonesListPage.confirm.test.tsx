// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Bulk reboot and bulk delete of phones ask in the in-app confirmation dialog.
 *
 * Both used the browser's native confirm() with only "Reboot (3)" or
 * "Bulk Delete (3)" as the question. A bulk reboot drops every call in
 * progress on those phones, so the dialog now names the phones, says so, and
 * nothing is sent until the operator confirms. Real page and Axios client;
 * only the network answers are controlled.
 */
import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { api } from '@/lib/api/client';
import { renderWithProviders } from '@/test-utils';
import PhonesListPage from '../PhonesListPage';

function phone(id: string, name: string) {
  return {
    id,
    name,
    vendor: 'grandstream',
    model: 'GXP2170',
    mac_address: `00:0b:82:00:00:${id.slice(0, 2)}`,
    status: 'online',
    lifecycle_state: 'managed',
    sip_registered: true,
  };
}

const PHONES = [
  phone('11111111-1111-4111-8111-111111111111', 'Front desk'),
  phone('22222222-2222-4222-8222-222222222222', 'Warehouse'),
  phone('33333333-3333-4333-8333-333333333333', 'Lab bench'),
];

interface Sent {
  method: string;
  path: string;
  body: unknown;
}

const sent: Sent[] = [];
const oldAdapter = api.defaults.adapter;

beforeEach(() => {
  sent.length = 0;
  api.defaults.adapter = async (config: InternalAxiosRequestConfig): Promise<AxiosResponse> => {
    const method = (config.method ?? 'get').toUpperCase();
    const path = (config.url ?? '').replace(/\/$/, '');
    sent.push({ method, path, body: typeof config.data === 'string' ? JSON.parse(config.data) : config.data });
    const reply = (status: number, data: unknown): AxiosResponse => ({
      config,
      data,
      status,
      statusText: 'OK',
      headers: {},
    });
    if (method === 'GET' && path === '/voip/phones') return reply(200, { items: PHONES, total: PHONES.length });
    if (method === 'GET') return reply(200, { items: [], total: 0 });
    if (method === 'POST' && path.startsWith('/voip/fleet/bulk/reboot')) return reply(200, { queued: 2 });
    if (method === 'DELETE' && path.startsWith('/voip/phones/')) return reply(204, null);
    throw new Error(`Unexpected request ${method} ${path}`);
  };
});

afterEach(() => {
  api.defaults.adapter = oldAdapter;
});

const writes = () => sent.filter((r) => r.method !== 'GET');

async function selectRows(...indexes: number[]) {
  const user = userEvent.setup();
  await screen.findByText('Front desk');
  for (const i of indexes) {
    // Re-query each time: selecting a row re-renders the table.
    await user.click(screen.getAllByRole('checkbox', { name: 'Select row' })[i]);
  }
  return user;
}

function bulkBar() {
  return screen.getByText(/phones? selected/).closest('.fixed') as HTMLElement;
}

describe('PhonesListPage bulk confirmations', () => {
  it('names the phones a bulk reboot restarts, sends nothing on Cancel, and reboots only on confirm', async () => {
    renderWithProviders(<PhonesListPage />);
    const user = await selectRows(0, 1);

    await user.click(within(bulkBar()).getByRole('button', { name: 'Reboot' }));
    let dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByRole('heading', { name: 'Reboot 2 phones?' })).toBeInTheDocument();
    expect(within(dialog).getByText(/drops any call in progress/)).toBeInTheDocument();
    expect(within(dialog).getByText('This affects 2 items.')).toBeInTheDocument();
    const listed = within(within(dialog).getByRole('list', { name: 'Affected items' })).getAllByRole('listitem');
    expect(listed.map((li) => li.textContent)).toEqual(['Front desk', 'Warehouse']);

    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).toBeNull());
    expect(writes()).toEqual([]);

    await user.click(within(bulkBar()).getByRole('button', { name: 'Reboot' }));
    dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Reboot phones' }));

    await waitFor(() => expect(writes()).toHaveLength(1));
    expect(writes()[0]).toEqual({
      method: 'POST',
      path: '/voip/fleet/bulk/reboot?confirm=true',
      body: { phone_ids: [PHONES[0].id, PHONES[1].id] },
    });
  });

  it('lists the phones a bulk delete removes and deletes each only on confirm', async () => {
    renderWithProviders(<PhonesListPage />);
    const user = await selectRows(2);

    await user.click(within(bulkBar()).getByRole('button', { name: 'Delete' }));
    let dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByRole('heading', { name: 'Delete 1 phone?' })).toBeInTheDocument();
    expect(within(dialog).getByText('This affects 1 item.')).toBeInTheDocument();
    expect(within(dialog).getByText('Lab bench')).toBeInTheDocument();

    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).toBeNull());
    expect(writes()).toEqual([]);

    await user.click(within(bulkBar()).getByRole('button', { name: 'Delete' }));
    dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Delete phones' }));

    await waitFor(() => expect(writes().map((w) => `${w.method} ${w.path}`)).toEqual([`DELETE /voip/phones/${PHONES[2].id}`]));
  });
});
