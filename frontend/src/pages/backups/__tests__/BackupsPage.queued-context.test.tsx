// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { act, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { useAuthStore } from '@/stores/authStore';
import { assertNoSecretCache, completedDownload, confirm, identity, installPageFixture,
  isCreate, isDownload, openDownload, otherId, row, submitCreate } from './vaultPageFixture';

const notification = vi.hoisted(() => ({ toast: vi.fn() }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: notification.toast }) }));
const fixture = installPageFixture();
const downloaded = () => fixture.state.requests.filter(isDownload);
const created = () => fixture.state.requests.filter(isCreate);
const changes = ['user', 'organization', 'unchanged'] as const;
function nextIdentity(change: typeof changes[number]) {
  const user = identity('super_admin')!;
  if (change === 'user') user.id = otherId;
  if (change === 'organization') user.organization_id = otherId;
  return user;
}
const ended = () => within(screen.getByRole('dialog', { name: 'Confirm vault export' })).findByRole('alert');

describe('actual archive page initiating account and organization', () => {
  it.each(['create', 'download'].flatMap(operation => changes.map(change => ({ operation, change }))))(
    'keeps queued $operation bound to its initiating context: $change', async ({ operation, change }) => {
      fixture.state.backups = [row(true)]; const { client } = fixture.mount();
      const gate = fixture.gate(operation === 'create' ? isCreate : isDownload, 'before-dispatch');
      if (operation === 'download') await openDownload(); else await submitCreate();
      await confirm(operation as 'create' | 'download');
      await waitFor(() => expect(gate.reached).toHaveBeenCalledOnce());
      expect(downloaded()).toHaveLength(0); expect(created()).toHaveLength(0);
      assertNoSecretCache(client);
      // Equal privilege cannot transfer queued work to another identity or tenant.
      await act(async () => { useAuthStore.setState({ user: nextIdentity(change) }); gate.release(); });
      if (change === 'unchanged') {
        await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Confirm vault export' })).not.toBeInTheDocument());
        if (operation === 'download') {
          expect(downloaded()).toHaveLength(1); await completedDownload(fixture.state);
          expect(created()).toHaveLength(0);
        } else {
          expect(created()).toHaveLength(1);
          expect(created()[0].url).toBe('/backups/');
          expect(JSON.parse(created()[0].data)).toMatchObject({ name: 'Owned queued vault', include_secrets: true, passphrase: 'Owned queued archive passphrase' });
          expect(JSON.parse(created()[0].data)).not.toHaveProperty('actor');
          expect(downloaded()).toHaveLength(0);
        }
      } else {
        await ended(); expect(downloaded()).toHaveLength(0); expect(created()).toHaveLength(0);
        expect(fixture.state.created).not.toHaveBeenCalled();
        expect(screen.queryByRole('button', { name: /Confirm and (create|download) vault/ })).not.toBeInTheDocument();
      }
      assertNoSecretCache(client);
    },
  );

  it.each(changes)('does not save a late download across a context change: %s', async change => {
    fixture.state.backups = [row(true)]; const { client } = fixture.mount();
    const gate = fixture.gate(isDownload, 'after-dispatch');
    await openDownload(); await confirm('download');
    await waitFor(() => expect(gate.reached).toHaveBeenCalledOnce());
    expect(downloaded()).toHaveLength(1); expect(fixture.state.created).not.toHaveBeenCalled();
    await act(async () => { useAuthStore.setState({ user: nextIdentity(change) }); gate.release(); });
    if (change === 'unchanged') await completedDownload(fixture.state);
    else {
      await ended(); expect(fixture.state.created).not.toHaveBeenCalled(); expect(fixture.state.revoked).not.toHaveBeenCalled();
      expect(screen.queryByRole('button', { name: 'Confirm and download vault' })).not.toBeInTheDocument();
    }
    expect(downloaded()).toHaveLength(1); // An already-issued request cannot be undone.
    assertNoSecretCache(client);
  });
});
