// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Real page/transport with synthetic responses. No server factor or browser proof. */
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { AxiosError } from 'axios';
import { describe, expect, it, vi } from 'vitest';
import { useAuthStore } from '@/stores/authStore';
import {
  accountPassword, actorId, archivePassphrase, assertNoSecretCache, backupId, completedDownload,
  confirm, identity, installPageFixture, isCreate, isDownload, mfaCode, openDownload,
  openRowMenu, organizationId, otherId, proof, readRequirements, row, selectArchive, submitCreate,
} from './vaultPageFixture';

const notification = vi.hoisted(() => ({ toast: vi.fn() }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: notification.toast }) }));
const fixture = installPageFixture();
const requests = () => fixture.state.requests;
const downloads = () => requests().filter(isDownload);
const creations = () => requests().filter(isCreate);
const contextChanges = ['user', 'organization', 'unchanged'] as const;
const ended = () => within(screen.getByRole('dialog', { name: 'Confirm vault export' })).findByRole('alert');
function changeIdentity(change: typeof contextChanges[number]) {
  const user = identity('super_admin')!;
  if (change === 'user') user.id = otherId;
  if (change === 'organization') user.organization_id = otherId;
  useAuthStore.setState({ user });
}
function assertBoundOnce() {
  const sensitive = requests().filter(request => request.url?.startsWith('/auth/vault-export/') || isCreate(request) || isDownload(request) || request.url?.endsWith('/vault-observation'));
  expect(sensitive.length).toBeGreaterThan(0);
  for (const request of sensitive) {
    expect(request.headers['X-FreeSDN-Vault-Actor']).toBe(actorId);
    expect(request.headers['X-FreeSDN-Vault-Organization']).toBe(organizationId);
    expect(request).toHaveProperty('_freesdnVaultNoReplay', true);
    if (request.method === 'post') expect(request.headers['X-CSRF-Token']).toBe('synthetic-page-csrf');
  }
  expect(sensitive.filter(request => request.url?.includes('requirements'))).toHaveLength(1);
  expect(sensitive.filter(request => request.url?.includes('/authorize/'))).toHaveLength(1);
}

describe('actual vault page confirmation workflow', () => {
  it.each(['local', 'ldap'] as const)('creates through %s confirmation without caching account or archive secrets', async method => {
    fixture.state.method = method; fixture.state.mfaRequired = true;
    const { client } = fixture.mount();
    useAuthStore.setState({ user: { ...identity('super_admin')!, mfa_enabled: true } });
    await submitCreate();
    expect(screen.queryByRole('dialog', { name: 'Create New Backup' })).not.toBeInTheDocument();
    expect(creations()).toHaveLength(0); assertNoSecretCache(client);
    await confirm('create', false, true);
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Confirm vault export' })).not.toBeInTheDocument());
    expect(creations()).toHaveLength(1); assertBoundOnce(); assertNoSecretCache(client);
    const create = creations()[0];
    expect(create.headers['X-FreeSDN-Vault-Proof']).toBe(proof);
    expect(JSON.parse(create.data)).toMatchObject({ name: 'Owned queued vault', passphrase: archivePassphrase, include_secrets: true, is_encrypted: true });
    expect(JSON.parse(create.data)).not.toHaveProperty('password');
    expect(JSON.parse(create.data)).not.toHaveProperty('mfa_code');
    const passwordRequest = requests().find(request => request.url === (method === 'local' ? '/auth/vault-export/authorize/local' : '/auth/vault-export/identity/ldap'))!;
    expect(JSON.parse(passwordRequest.data).password).toBe(accountPassword);
    const factor = requests().find(request => request.url?.includes('/authorize/'))!;
    expect(JSON.parse(factor.data).mfa_code).toBe(mfaCode);
    expect(fixture.state.created).not.toHaveBeenCalled();
  });

  it.each(['list', 'details', 'history'] as const)('downloads a recorded vault through the %s control after confirmation', async surface => {
    fixture.state.backups = [row(true)]; const { client } = fixture.mount();
    if (surface === 'list') await openDownload();
    if (surface === 'details') {
      const menu = await openRowMenu(); fireEvent.click(within(menu).getByRole('menuitem', { name: 'View Details' }));
      const details = await screen.findByRole('dialog', { name: 'Backup Details' });
      fireEvent.click(within(details).getByRole('button', { name: 'Download' }));
    }
    if (surface === 'history') {
      fireEvent.mouseDown(await screen.findByRole('tab', { name: /History/ }), { button: 0, ctrlKey: false });
      const panel = await screen.findByRole('tabpanel', { name: 'History' });
      const title = await within(panel).findByText('Owned archive ' + backupId);
      const timeline = title.closest('.flex-1')?.parentElement; expect(timeline).not.toBeNull();
      const button = timeline!.querySelector('button:has(svg.lucide-download)'); expect(button).not.toBeNull();
      fireEvent.click(button!);
    }
    expect(downloads()).toHaveLength(0); assertNoSecretCache(client);
    await confirm('download'); await completedDownload(fixture.state);
    expect(downloads()).toHaveLength(1); expect(downloads()[0].method).toBe('get');
    expect(downloads()[0].headers['X-FreeSDN-Vault-Proof']).toBe(proof);
    assertBoundOnce(); assertNoSecretCache(client);
    expect(notification.toast).toHaveBeenCalledWith(expect.objectContaining({ description: expect.stringContaining('does not prove the file was saved') }));
  });

  it('requires explicit legacy acknowledgment before any hint, observation or download', async () => {
    fixture.state.backups = [row(true, backupId, 'legacy_unverified')]; const { client } = fixture.mount();
    await openDownload(); const dialog = await screen.findByRole('dialog', { name: 'Confirm vault export' });
    const next = within(dialog).getByRole('button', { name: 'Check confirmation requirements' });
    expect(next).toBeDisabled(); fireEvent.click(next);
    expect(requests().filter(request => request.url?.includes('/auth/vault-export/') || request.url?.includes('/vault-'))).toHaveLength(0);
    expect(within(dialog).getByText(/cannot prove historical authenticity/)).toBeInTheDocument();
    await confirm('download', true); await completedDownload(fixture.state);
    const observation = requests().filter(request => request.url?.endsWith('/vault-observation'));
    expect(observation).toHaveLength(1); expect(JSON.parse(observation[0].data)).toEqual({ legacy_acknowledged: true });
    expect(downloads()).toHaveLength(1); expect(downloads()[0].url).toBe(`/backups/${backupId}/vault-download`);
    expect(downloads()[0].headers['X-FreeSDN-Vault-Proof']).toBe('synthetic-page-observed');
    expect(JSON.parse(downloads()[0].data)).toEqual({ legacy_acknowledged: true, observed_identity: { version: 1, bytes: 3, sha256: 'a'.repeat(64) } });
    assertBoundOnce(); assertNoSecretCache(client);
  });

  it.each(['org_admin', 'super_admin'])('refuses mixed bulk vault downloads for %s without a partial configuration download', async principal => {
    fixture.state.backups = [row(false, backupId), row(true, otherId)]; const { client } = fixture.mount(principal);
    await selectArchive(backupId); await selectArchive(otherId);
    const download = screen.getByRole('button', { name: /^Download$/ });
    expect(download).toHaveProperty('disabled', principal !== 'super_admin'); fireEvent.click(download);
    expect(downloads()).toHaveLength(0); expect(fixture.state.created).not.toHaveBeenCalled(); assertNoSecretCache(client);
    expect(screen.queryByRole('dialog', { name: 'Confirm vault export' })).not.toBeInTheDocument();
    if (principal === 'super_admin') expect(notification.toast).toHaveBeenCalledWith(expect.objectContaining({ description: expect.stringContaining('individually') }));
  });

  it.each(['create', 'download'].flatMap(operation => contextChanges.map(change => ({ operation, change }))))(
    'keeps confirmed $operation bound across a real Axios interceptor wait: $change', async ({ operation, change }) => {
      fixture.state.backups = [row(true)]; const { client } = fixture.mount();
      const gate = fixture.gate(operation === 'create' ? isCreate : isDownload, 'before-dispatch');
      if (operation === 'create') await submitCreate(); else await openDownload();
      await confirm(operation as 'create' | 'download'); await waitFor(() => expect(gate.reached).toHaveBeenCalledOnce());
      expect(creations()).toHaveLength(0); expect(downloads()).toHaveLength(0); assertNoSecretCache(client);
      await act(async () => { changeIdentity(change); gate.release(); });
      if (change === 'unchanged') {
        await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Confirm vault export' })).not.toBeInTheDocument());
        if (operation === 'create') expect(creations()).toHaveLength(1); else await completedDownload(fixture.state);
      } else {
        await ended();
        expect(creations()).toHaveLength(0); expect(downloads()).toHaveLength(0); expect(fixture.state.created).not.toHaveBeenCalled();
      }
      assertNoSecretCache(client);
    },
  );

  it.each(contextChanges)('does not save an already-issued late download after context change: %s', async change => {
    fixture.state.backups = [row(true)]; const { client } = fixture.mount();
    const gate = fixture.gate(isDownload, 'after-dispatch');
    await openDownload(); await confirm('download'); await waitFor(() => expect(gate.reached).toHaveBeenCalledOnce());
    expect(downloads()).toHaveLength(1); expect(fixture.state.created).not.toHaveBeenCalled();
    await act(async () => { changeIdentity(change); gate.release(); });
    if (change === 'unchanged') await completedDownload(fixture.state);
    else { await ended(); expect(fixture.state.created).not.toHaveBeenCalled(); expect(fixture.state.clicked).not.toHaveBeenCalled(); }
    expect(downloads()).toHaveLength(1); assertNoSecretCache(client);
  });

  it('rechecks current authority immediately before browser save and revokes a created object URL', async () => {
    fixture.state.backups = [row(true)]; const { client } = fixture.mount();
    fixture.state.created.mockImplementation(() => { changeIdentity('organization'); return 'blob:owned-archive'; });
    await openDownload(); await confirm('download'); await ended();
    expect(downloads()).toHaveLength(1); expect(fixture.state.created).toHaveBeenCalledOnce();
    expect(fixture.state.clicked).not.toHaveBeenCalled(); expect(fixture.state.revoked).toHaveBeenCalledWith('blob:owned-archive');
    assertNoSecretCache(client);
  });

  it.each(['close', 'unmount'] as const)('does not save a late response after %s and makes no rollback claim', async end => {
    fixture.state.backups = [row(true)]; const view = fixture.mount(); const gate = fixture.gate(isDownload, 'after-dispatch');
    await openDownload(); await confirm('download'); await waitFor(() => expect(gate.reached).toHaveBeenCalledOnce());
    expect(downloads()).toHaveLength(1);
    if (end === 'close') fireEvent.click(within(screen.getByRole('dialog', { name: 'Confirm vault export' })).getAllByRole('button', { name: /^Close$/ })[0]);
    else view.unmount();
    await act(async () => { gate.release(); await Promise.resolve(); });
    expect(fixture.state.created).not.toHaveBeenCalled(); expect(fixture.state.clicked).not.toHaveBeenCalled();
    expect(downloads()).toHaveLength(1); assertNoSecretCache(view.client);
  });

  it('keeps an uncertain creation visible without refreshing, replaying or disclosing the Axios body', async () => {
    fixture.state.customAnswer = config => {
      if (!isCreate(config)) return undefined;
      const response = fixture.reply(config, { detail: accountPassword + archivePassphrase + proof }, 401);
      throw new AxiosError('Owned rejected response ' + accountPassword, 'ERR_BAD_REQUEST', config, undefined, response);
    };
    const { client } = fixture.mount(); await submitCreate(); await confirm('create');
    const alert = await ended(); expect(alert).toHaveTextContent('outcome is unconfirmed');
    for (const secret of [accountPassword, archivePassphrase, proof]) expect(document.body.textContent).not.toContain(secret);
    expect(creations()).toHaveLength(1); expect(requests().filter(request => request.url?.includes('/refresh'))).toHaveLength(0);
    expect(screen.queryByRole('button', { name: 'Confirm and create vault' })).not.toBeInTheDocument();
    assertNoSecretCache(client);
  });

  it('refuses an invalid catalogue artifact before confirmation or download', async () => {
    fixture.state.backups = [row(true, backupId, 'invalid')]; const { client } = fixture.mount();
    await openDownload();
    expect(screen.queryByRole('dialog', { name: 'Confirm vault export' })).not.toBeInTheDocument();
    expect(requests().filter(request => request.url?.includes('/auth/vault-export/'))).toHaveLength(0);
    expect(downloads()).toHaveLength(0); expect(notification.toast).toHaveBeenCalledWith(expect.objectContaining({ variant: 'destructive' }));
    assertNoSecretCache(client);
  });

  it('clears entered factors when authority changes while the confirmation is open', async () => {
    const { client } = fixture.mount(); await submitCreate(); const dialog = await readRequirements();
    fireEvent.change(within(dialog).getByLabelText('Current account password'), { target: { value: accountPassword } });
    await act(async () => { changeIdentity('user'); }); await ended();
    expect(screen.queryByLabelText('Current account password')).not.toBeInTheDocument();
    expect(requests().filter(request => request.url?.includes('/authorize/'))).toHaveLength(0);
    expect(creations()).toHaveLength(0); assertNoSecretCache(client);
  });
});
