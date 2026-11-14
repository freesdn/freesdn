// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The PBX list asks before deleting one PBX from its row menu, and the PBX
 * and Extensions bulk-delete toasts describe the deletion. Both read "1
 * connected, 1 failed, 0 skipped", the bulk-connect sentence borrowed from the
 * Phones page. Real pages and Axios client; only the network is controlled.
 */
import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { AxiosError } from 'axios';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { api } from '@/lib/api/client';
import { renderWithProviders } from '@/test-utils';
import PBXPage from '../PBXPage';
import ExtensionsPage from '../ExtensionsPage';

const PBX = [
  { id: 'a1111111-1111-4111-8111-111111111111', name: 'Main PBX', pbx_type: 'freepbx', ip_address: '198.51.100.30', api_port: 443, sip_port: 5060, is_active: true, extension_count: 2 },
  { id: 'b2222222-2222-4222-8222-222222222222', name: 'Branch PBX', pbx_type: 'freepbx', ip_address: '198.51.100.31', api_port: 443, sip_port: 5060, is_active: true, extension_count: 0 },
];
const EXTENSIONS = [
  { id: 'e1', pbx_id: PBX[0].id, extension_number: '101', display_name: 'Reception', status: 'available' },
  { id: 'e2', pbx_id: PBX[0].id, extension_number: '102', display_name: 'Sales', status: 'available' },
];
const REFUSED = 'The PBX refused the change: extension is in a ring group.';
const deletes: string[] = [];
const oldAdapter = api.defaults.adapter;

beforeEach(() => {
  deletes.length = 0;
  api.defaults.adapter = async (config: InternalAxiosRequestConfig): Promise<AxiosResponse> => {
    const method = (config.method ?? 'get').toUpperCase();
    const path = (config.url ?? '').replace(/\/$/, '');
    const reply = (status: number, data: unknown): AxiosResponse => ({ config, data, status, statusText: 'OK', headers: {} });
    if (method === 'GET' && path === '/voip/pbx') return reply(200, { items: PBX, total: PBX.length });
    if (method === 'GET' && path === '/voip/extensions') return reply(200, { items: EXTENSIONS, total: EXTENSIONS.length });
    if (method === 'GET') return reply(200, { items: [], total: 0 });
    if (method === 'DELETE') {
      deletes.push(path);
      if (path.endsWith('/102') || path.endsWith(PBX[1].id)) {
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

describe('PBXPage delete', () => {
  it('asks before deleting one PBX from its row menu', async () => {
    const user = userEvent.setup();
    renderWithProviders(<PBXPage />);
    const row = (await screen.findByText('Main PBX')).closest('tr') as HTMLElement;
    await user.click(within(row).getByRole('button', { name: 'Actions for Main PBX' }));
    await user.click(await screen.findByRole('menuitem', { name: /Delete/ }));
    let dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByRole('heading', { name: 'Delete Main PBX?' })).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).toBeNull());
    expect(deletes).toEqual([]);

    await user.click(within(row).getByRole('button', { name: 'Actions for Main PBX' }));
    await user.click(await screen.findByRole('menuitem', { name: /Delete/ }));
    dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Delete PBX' }));
    await waitFor(() => expect(deletes).toEqual([`/voip/pbx/${PBX[0].id}`]));
  });

  it('summarises a bulk delete as deletions', async () => {
    const user = userEvent.setup();
    renderWithProviders(<PBXPage />);
    await screen.findByText('Main PBX');
    // Each checkbox names its PBX; they all read "Select row" before.
    for (const name of ['Main PBX', 'Branch PBX']) await user.click(screen.getByRole('checkbox', { name: `Select ${name}` }));
    const bar = screen.getByText(/selected/).closest('.fixed') as HTMLElement;
    await user.click(within(bar).getByRole('button', { name: /Delete/ }));
    await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Delete PBX systems' }));
    expect(await screen.findByText(`1 deleted, 1 not deleted: ${REFUSED}`)).toBeInTheDocument();
    expect(screen.queryByText(/connected/)).toBeNull();
  });
});

describe('ExtensionsPage bulk delete', () => {
  it('summarises a bulk delete as deletions', async () => {
    const user = userEvent.setup();
    renderWithProviders(<ExtensionsPage />);
    await screen.findByText('Reception');
    // Each checkbox names its extension; they all read "Select row" before.
    for (const name of ['101 Reception', '102 Sales']) await user.click(screen.getByRole('checkbox', { name: `Select ${name}` }));
    const bar = screen.getByText(/selected/).closest('.fixed') as HTMLElement;
    await user.click(within(bar).getByRole('button', { name: /Delete/ }));
    await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Delete extensions' }));
    expect(await screen.findByText(`1 deleted, 1 not deleted: ${REFUSED}`)).toBeInTheDocument();
    expect(deletes).toEqual([`/voip/pbx/${PBX[0].id}/extensions/101`, `/voip/pbx/${PBX[0].id}/extensions/102`]);
  });
});
