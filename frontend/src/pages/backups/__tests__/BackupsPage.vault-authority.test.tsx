// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { useAuthStore } from '@/stores/authStore';
import { assertNoSecretCache, backupId, completedDownload, confirm, identity, installPageFixture,
  isCreate, isDownload, openDownload, otherId, principals, row, selectArchive, submitCreate } from './vaultPageFixture';

const network = vi.hoisted(() => ({ toast: vi.fn() }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: network.toast }) }));
const fixture = installPageFixture();
const downloaded = () => fixture.state.requests.filter(isDownload);
const created = () => fixture.state.requests.filter(isCreate);

describe('actual archive page authority affordances', () => {
  it.each(principals.flatMap(principal => [false, true].map(secrets => ({ principal, secrets }))))(
    'enables only permitted downloads: $principal secrets=$secrets', async ({ principal, secrets }) => {
      fixture.state.backups = [row(secrets)];
      const { client } = fixture.mount(principal);
      await selectArchive();
      const button = screen.getByRole('button', { name: /^Download$/ });
      const permitted = principal === 'super_admin' || (!secrets && principal === 'org_admin');
      expect(button).toHaveProperty('disabled', !permitted);
      fireEvent.click(button);
      if (permitted) {
        if (secrets) {
          // Vault bulk actions never bypass one-operation account confirmation.
          expect(downloaded()).toHaveLength(0);
          expect(network.toast).toHaveBeenCalledWith(expect.objectContaining({ description: expect.stringContaining('individually') }));
          await openDownload(); await confirm('download');
          assertNoSecretCache(client);
        }
        await waitFor(() => expect(downloaded()).toHaveLength(1));
        await completedDownload(fixture.state);
      } else {
        expect(downloaded()).toHaveLength(0);
        expect(fixture.state.created).not.toHaveBeenCalled();
      }
    },
  );

  it.each(principals)('offers appropriate creation controls for %s', async principal => {
    fixture.mount(principal);
    await screen.findByRole('checkbox', { name: 'Select Owned archive ' + backupId });
    const button = screen.getByRole('button', { name: 'New Backup' });
    const admin = ['super_admin', 'org_admin'].includes(principal);
    expect(button).toHaveProperty('disabled', !admin);
    fireEvent.click(button);
    if (!admin) {
      expect(screen.queryByRole('dialog', { name: 'Create New Backup' })).not.toBeInTheDocument();
      return;
    }
    const dialog = await screen.findByRole('dialog', { name: 'Create New Backup' });
    const toggle = within(dialog).getByRole('switch', { name: /Full (backup|vault)/ });
    expect(toggle).toHaveProperty('disabled', principal !== 'super_admin');
    if (principal === 'org_admin') expect(within(dialog).getByText('Only a super administrator can create or download a full vault.')).toBeInTheDocument();
  });

  it.each(['demotion', 'logout', 'organization change'])('discards a sensitive open form on %s', async change => {
    fixture.mount('super_admin');
    await screen.findByRole('checkbox', { name: 'Select Owned archive ' + backupId });
    fireEvent.click(screen.getByRole('button', { name: 'New Backup' }));
    const dialog = await screen.findByRole('dialog', { name: 'Create New Backup' });
    fireEvent.click(within(dialog).getByRole('switch', { name: /Full (backup|vault)/ }));
    const phrase = within(dialog).getByLabelText('Backup passphrase');
    fireEvent.change(phrase, { target: { value: 'Owned unsent sensitive passphrase' } });
    const next = change === 'logout' ? null : change === 'demotion' ? identity('org_admin') : { ...identity('super_admin')!, organization_id: otherId };
    await act(async () => { useAuthStore.setState({ user: next, isAuthenticated: next !== null }); });
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Create New Backup' })).not.toBeInTheDocument());
    expect(created()).toHaveLength(0);
    expect(fixture.state.requests.filter(request => request.method === 'post')).toHaveLength(0);
    await act(async () => { useAuthStore.setState({ user: identity('super_admin'), isAuthenticated: true }); });
    fireEvent.click(screen.getByRole('button', { name: 'New Backup' }));
    const reopened = await screen.findByRole('dialog', { name: 'Create New Backup' });
    fireEvent.click(within(reopened).getByRole('switch', { name: /Full (backup|vault)/ }));
    expect(within(reopened).getByLabelText('Backup passphrase')).toHaveValue('');
  });

  it.each(['org_admin', 'super_admin'])('handles a mixed configuration/vault selection for %s without partial downloads', async principal => {
    fixture.state.backups = [row(false, backupId), row(true, otherId)];
    fixture.mount(principal);
    await selectArchive(backupId); await selectArchive(otherId);
    const button = screen.getByRole('button', { name: /^Download$/ });
    expect(button).toHaveProperty('disabled', principal !== 'super_admin');
    fireEvent.click(button);
    expect(downloaded()).toHaveLength(0);
    expect(fixture.state.created).not.toHaveBeenCalled();
    if (principal === 'super_admin') expect(network.toast).toHaveBeenCalledWith(expect.objectContaining({ description: expect.stringContaining('individually') }));
  });

  it.each(['create', 'download'] as const)('rechecks current identity after queued %s work', async operation => {
    fixture.state.backups = [row(true)];
    const { client } = fixture.mount('super_admin');
    const gate = fixture.gate(operation === 'create' ? isCreate : isDownload, 'before-dispatch');
    if (operation === 'download') await openDownload(); else await submitCreate();
    await confirm(operation);
    // The real Axios interceptor holds the final archive request after factors.
    // Sensitive inputs never enter a shared QueryClient mutation cache.
    await waitFor(() => expect(gate.reached).toHaveBeenCalledOnce());
    assertNoSecretCache(client);
    await act(async () => { useAuthStore.setState({ user: identity('viewer') }); gate.release(); });
    const dialog = screen.getByRole('dialog', { name: 'Confirm vault export' });
    await within(dialog).findByRole('alert');
    expect(downloaded()).toHaveLength(0); expect(created()).toHaveLength(0);
    expect(fixture.state.created).not.toHaveBeenCalled(); assertNoSecretCache(client);
    expect(within(dialog).getByRole('alert')).toHaveTextContent('outcome is unconfirmed');
    expect(within(dialog).queryByRole('button', { name: /Confirm and (create|download) vault/ })).not.toBeInTheDocument();
  });
});
