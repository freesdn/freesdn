// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Bulk-deleting backups asks in the in-app confirmation dialog.
 *
 * The bulk bar's Delete used the browser's native confirm(), which gave only
 * a count. Deleting a backup also deletes its archive file, so the dialog now
 * lists which backups are about to go. Real page and Axios client; only the
 * network answers are controlled (see vaultPageFixture).
 */
import type { InternalAxiosRequestConfig } from 'axios';
import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { renderWithProviders } from '@/test-utils';
import BackupsPage from '../BackupsPage';
import { installPageFixture, row } from './vaultPageFixture';

const fixture = installPageFixture();
const { state, reply } = fixture;

const IDS = [
  '55555555-5555-4555-8555-555555555555',
  '66666666-6666-4666-8666-666666666666',
  '77777777-7777-4777-8777-777777777777',
];

const deletes = () =>
  state.requests
    .filter((config: InternalAxiosRequestConfig) => config.method === 'delete')
    .map((config: InternalAxiosRequestConfig) => config.url);

beforeEach(() => {
  state.backups = IDS.map((id) => row(false, id));
  state.customAnswer = (config) =>
    config.method === 'delete' && /^\/backups\/[0-9a-f-]+$/.test(config.url ?? '')
      ? reply(config, null, 204)
      : undefined;
});

function mountPage() {
  return renderWithProviders(<BackupsPage />, { initialPath: '/backups', routePath: '/backups/:tab?' });
}

async function select(id: string) {
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Select Owned archive ' + id }));
}

function bulkBar() {
  return screen.getByText(/backups selected/).closest('.fixed') as HTMLElement;
}

describe('BackupsPage bulk delete confirmation', () => {
  it('lists the count and the backup names, sends nothing on Cancel, deletes each on confirm', async () => {
    mountPage();
    await select(IDS[0]);
    await select(IDS[2]);

    fireEvent.click(within(bulkBar()).getByRole('button', { name: 'Delete' }));
    let dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByRole('heading', { name: 'Delete 2 backup(s)?' })).toBeInTheDocument();
    expect(within(dialog).getByText('This affects 2 items.')).toBeInTheDocument();
    expect(within(dialog).getByText(/archive file are deleted/)).toBeInTheDocument();
    const listed = within(within(dialog).getByRole('list', { name: 'Affected items' })).getAllByRole('listitem');
    expect(listed.map((li) => li.textContent)).toEqual(['Owned archive ' + IDS[0], 'Owned archive ' + IDS[2]]);

    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).toBeNull());
    expect(deletes()).toEqual([]);
    // Cancel keeps the selection, so the operator can adjust it and try again.
    expect(screen.getByRole('checkbox', { name: 'Select Owned archive ' + IDS[0] })).toBeChecked();

    fireEvent.click(within(bulkBar()).getByRole('button', { name: 'Delete' }));
    dialog = await screen.findByRole('alertdialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete backups' }));

    await waitFor(() => expect(deletes().sort()).toEqual([`/backups/${IDS[0]}`, `/backups/${IDS[2]}`].sort()));
  });
});
