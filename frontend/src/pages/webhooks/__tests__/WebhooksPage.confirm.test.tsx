// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Deleting webhooks asks in the in-app confirmation dialog.
 *
 * Both deletes used the browser's native confirm(), which named neither the
 * webhook nor how many were selected, and which some browsers let the
 * operator suppress for the rest of the session. These tests drive the real
 * page over the real Axios client: the dialog names what is deleted, Cancel
 * sends nothing, and only the confirm button sends the DELETE requests.
 */
import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { api } from '@/lib/api/client';
import { renderWithProviders } from '@/test-utils';
import WebhooksPage from '../WebhooksPage';

function hook(id: string, name: string) {
  return {
    id,
    name,
    url: `https://${id}.example.invalid/hook`,
    event_types: ['device.offline'],
    enabled: true,
    retry_count: 3,
    failure_count: 0,
    success_count: 2,
    created_at: '2026-11-01T00:00:00Z',
    updated_at: '2026-11-01T00:00:00Z',
  };
}

const HOOKS = [
  hook('11111111-1111-4111-8111-111111111111', 'Ops pager'),
  hook('22222222-2222-4222-8222-222222222222', 'Audit sink'),
  hook('33333333-3333-4333-8333-333333333333', 'Chat relay'),
];

const requests: string[] = [];
const oldAdapter = api.defaults.adapter;

beforeEach(() => {
  requests.length = 0;
  api.defaults.adapter = async (config: InternalAxiosRequestConfig): Promise<AxiosResponse> => {
    const method = (config.method ?? 'get').toUpperCase();
    const path = (config.url ?? '').replace(/\/$/, '');
    requests.push(`${method} ${path}`);
    const reply = (status: number, data: unknown): AxiosResponse => ({
      config,
      data,
      status,
      statusText: 'OK',
      headers: {},
    });
    if (method === 'GET' && path === '/webhooks') {
      return reply(200, { items: HOOKS, total: HOOKS.length, page: 1, per_page: 100, pages: 1 });
    }
    if (method === 'DELETE' && path.startsWith('/webhooks/')) return reply(204, null);
    if (method === 'GET') return reply(200, { items: [], total: 0 });
    throw new Error(`Unexpected request ${method} ${path}`);
  };
});

afterEach(() => {
  api.defaults.adapter = oldAdapter;
});

const deletes = () => requests.filter((r) => r.startsWith('DELETE '));

describe('WebhooksPage delete confirmation', () => {
  it('names the webhook, sends nothing on Cancel and deletes on confirm', async () => {
    const user = userEvent.setup();
    renderWithProviders(<WebhooksPage />);

    await user.click(await screen.findByRole('button', { name: 'Actions for Ops pager' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Delete' }));

    let dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByRole('heading', { name: 'Delete webhook "Ops pager"?' })).toBeInTheDocument();
    expect(within(dialog).getByText(/its delivery history is deleted/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).toBeNull());
    expect(deletes()).toEqual([]);

    await user.click(screen.getByRole('button', { name: 'Actions for Ops pager' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Delete' }));
    dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Delete webhook' }));

    await waitFor(() => expect(deletes()).toEqual([`DELETE /webhooks/${HOOKS[0].id}`]));
  });

  it('shows how many webhooks a bulk delete affects and which, and deletes only those', async () => {
    const user = userEvent.setup();
    renderWithProviders(<WebhooksPage />);
    await screen.findByText('Ops pager');

    // Re-query after each click: selecting a row re-renders the table.
    await user.click(screen.getAllByRole('checkbox', { name: 'Select row' })[0]);
    await user.click(screen.getAllByRole('checkbox', { name: 'Select row' })[2]);

    const bar = screen.getByText(/2 webhooks selected/).closest('.fixed') as HTMLElement;
    await user.click(within(bar).getByRole('button', { name: 'Delete' }));

    let dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByRole('heading', { name: 'Delete 2 webhooks?' })).toBeInTheDocument();
    expect(within(dialog).getByText('This affects 2 items.')).toBeInTheDocument();
    const listed = within(within(dialog).getByRole('list', { name: 'Affected items' })).getAllByRole('listitem');
    expect(listed.map((li) => li.textContent)).toEqual(['Ops pager', 'Chat relay']);

    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).toBeNull());
    expect(deletes()).toEqual([]);

    await user.click(within(bar).getByRole('button', { name: 'Delete' }));
    dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Delete webhooks' }));

    await waitFor(() =>
      expect(deletes().sort()).toEqual([`DELETE /webhooks/${HOOKS[0].id}`, `DELETE /webhooks/${HOOKS[2].id}`].sort()),
    );
  });
});
