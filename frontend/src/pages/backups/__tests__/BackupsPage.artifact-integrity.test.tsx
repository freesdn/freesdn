// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
// Private, unrun component contracts. HTTP transport is stubbed; no browser or backend proof.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import BackupsPage from '../BackupsPage';

const network = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), manifest: vi.fn(), toast: vi.fn() }));
vi.mock('@/lib/api', () => ({
  api: { get: network.get, post: network.post },
  backupApi: { previewManifest: network.manifest },
  getApiErrorMessage: (_error: unknown, fallback: string) => fallback,
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: network.toast }) }));

const backup = {
  id: 'owned-integrity-backup', name: 'Owned integrity archive', backup_type: 'full',
  status: 'completed', progress: 100, storage_type: 'local', file_size: 1024,
  created_at: '2026-09-01T00:00:00Z', is_encrypted: true, include_secrets: false,
};
let currentBackup = { ...backup };
const core = { id: 'core', schema_version: '2.0.0', counts: { sites: 1 }, restorable: true, incompatibility_reason: null };
const verifiedNotice = 'Archive integrity verified for this preview.';
const recordedNotice = 'Archive identity recorded; file not checked for this preview.';
const legacyNotice = 'No recorded archive identity; integrity is unverified.';

beforeEach(() => {
  vi.resetAllMocks();
  currentBackup = { ...backup };
  network.get.mockImplementation(async (path: string) => {
    if (path.startsWith('/backups?')) return { data: { items: [currentBackup], total: 1 } };
    if (path.startsWith('/backups/stats?')) return { data: { total_backups: 1, completed_backups: 1 } };
    if (path === '/sites') return { data: { items: [] } };
    if (path.startsWith('/backups/schedules?') || path === '/backups/storage-locations' || path === '/backups/storage-types') return { data: [] };
    throw new Error('Unexpected owned request: ' + path);
  });
  network.manifest.mockResolvedValue({ data: {
    backup_id: backup.id, format_version: '2.0', contributors: [core], artifact_integrity: 'verified',
  } });
});

async function openRestore() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter><BackupsPage /></MemoryRouter></QueryClientProvider>);
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Select ' + backup.name }));
  fireEvent.click(screen.getByRole('button', { name: /^Restore$/ }));
  const dialog = await screen.findByRole('dialog', { name: 'Restore from Backup' });
  await waitFor(() => expect(network.manifest).toHaveBeenCalledWith(backup.id));
  return dialog;
}

describe('honest archive preview state in the actual backups page', () => {
  it.each(['recorded', 'legacy_unverified'])(
    'explains a sealed vault without claiming its contents were inspected: %s',
    async (integrity) => {
      currentBackup = { ...backup, include_secrets: true };
      network.manifest.mockResolvedValue({ data: {
        backup_id: backup.id, format_version: null, contributors: [],
        requires_passphrase: true, artifact_integrity: integrity,
        reason: 'This archive is sealed under your passphrase.',
      } });
      const dialog = await openRestore();
      expect(await within(dialog).findByText('Passphrase required to preview this vault.')).toBeInTheDocument();
      expect(within(dialog).getByText(integrity === 'recorded' ? recordedNotice : legacyNotice)).toBeInTheDocument();
      expect(within(dialog).queryByText(verifiedNotice)).not.toBeInTheDocument();
      expect(within(dialog).queryByText('All modules')).not.toBeInTheDocument();
      expect(within(dialog).queryByText(/No restorable modules in this backup/)).not.toBeInTheDocument();
      expect(within(dialog).getByPlaceholderText('The passphrase this .fsdnvault was created with')).toHaveAttribute('type', 'password');
      expect(network.post).not.toHaveBeenCalled();
    },
  );

  it.each(['verified', 'legacy_unverified'])(
    'labels the observed config read and preserves contributor selection: %s',
    async (integrity) => {
      network.manifest.mockResolvedValue({ data: {
        backup_id: backup.id, format_version: '2.0', contributors: [core],
        requires_passphrase: false, artifact_integrity: integrity,
      } });
      const dialog = await openRestore();
      expect(await within(dialog).findByRole('checkbox', { name: 'Restore core module' })).toBeChecked();
      expect(within(dialog).getByText(integrity === 'verified' ? verifiedNotice : legacyNotice)).toBeInTheDocument();
      expect(within(dialog).queryByText(recordedNotice)).not.toBeInTheDocument();
      expect(within(dialog).queryByText('Passphrase required to preview this vault.')).not.toBeInTheDocument();
      fireEvent.click(within(dialog).getByRole('checkbox', { name: 'Restore core module' }));
      expect(within(dialog).getByRole('checkbox', { name: 'Restore core module' })).not.toBeChecked();
      expect(network.post).not.toHaveBeenCalled();
    },
  );

  it('keeps a failed manifest request visible without claiming verified integrity or starting restore', async () => {
    network.manifest.mockRejectedValue(new Error('Owned integrity refusal'));
    const dialog = await openRestore();
    expect(await within(dialog).findByText(/Could not read the backup manifest/)).toBeInTheDocument();
    expect(within(dialog).queryByText(verifiedNotice)).not.toBeInTheDocument();
    expect(within(dialog).queryByText(recordedNotice)).not.toBeInTheDocument();
    expect(network.post).not.toHaveBeenCalled();
  });

  it('retains the real incompatible-module refusal rather than confusing it with a sealed manifest', async () => {
    network.manifest.mockResolvedValue({ data: {
      backup_id: backup.id, format_version: '2.0', artifact_integrity: 'verified',
      contributors: [{ ...core, restorable: false, incompatibility_reason: 'Owned schema mismatch' }],
    } });
    const dialog = await openRestore();
    expect(await within(dialog).findByRole('checkbox', { name: 'Restore core module' })).toBeDisabled();
    expect(within(dialog).getByText('Owned schema mismatch')).toBeInTheDocument();
    expect(within(dialog).getByText(/No restorable modules in this backup/)).toBeInTheDocument();
    expect(within(dialog).queryByText('Passphrase required to preview this vault.')).not.toBeInTheDocument();
    expect(network.post).not.toHaveBeenCalled();
  });
});
