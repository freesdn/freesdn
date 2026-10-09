// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
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
  id: 'owned-backup', name: 'Owned recovery snapshot', backup_type: 'full',
  status: 'completed', progress: 100, storage_type: 'local', file_size: 1024,
  created_at: '2026-09-01T00:00:00Z', is_encrypted: true, include_secrets: false,
};

beforeEach(() => {
  vi.resetAllMocks();
  network.get.mockImplementation(async (path: string) => {
    if (path.startsWith('/backups?')) return { data: { items: [backup], total: 1 } };
    if (path.startsWith('/backups/stats?')) return { data: { total_backups: 1, completed_backups: 1 } };
    if (path === '/sites') return { data: { items: [] } };
    if (path.startsWith('/backups/schedules?') || path === '/backups/storage-locations' || path === '/backups/storage-types') return { data: [] };
    throw new Error('Unexpected request: ' + path);
  });
  network.manifest.mockResolvedValue({ data: {
    backup_id: backup.id, format_version: '2', contributors: [
      { id: 'core', schema_version: '1.0.0', counts: { sites: 1 }, restorable: true, incompatibility_reason: null },
    ],
  } });
});

async function openRestore() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter><BackupsPage /></MemoryRouter></QueryClientProvider>);
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Select ' + backup.name }));
  fireEvent.click(screen.getByRole('button', { name: /^Restore$/ }));
  const dialog = await screen.findByRole('dialog', { name: 'Restore from Backup' });
  await within(dialog).findByRole('checkbox', { name: 'Restore core module' });
  return dialog;
}

function response(dryRun: boolean, mode: string) {
  const failed = mode === 'failed' || mode === 'legacy-errors';
  const report = {
    contributors: [{
      contributor_id: 'core', status: failed ? 'error' : mode === 'skipped' ? 'skipped' : dryRun ? 'dry_run_ok' : 'ok',
      created: {}, updated: failed || mode === 'skipped' ? {} : { sites: 1 },
      skipped: mode === 'skipped' ? { sites: 1 } : {},
      errors: failed ? ['Owned recovery section refused'] : [],
      warnings: mode === 'skipped' ? ['Owned section intentionally skipped'] : [],
    }],
    summary: {
      total_created: 0, total_updated: failed || mode === 'skipped' ? 0 : 1,
      total_skipped: mode === 'skipped' ? 1 : 0, total_errors: failed ? 1 : 0,
      contributors_ok: failed || mode === 'skipped' ? 0 : 1, contributors_failed: failed ? 1 : 0,
    },
  };
  return { data: {
    id: 'owned-job', backup_id: backup.id, status: mode === 'failed' ? 'failed' : 'completed',
    progress: 100, dry_run: dryRun, dry_run_report: dryRun ? report : null,
    restore_log: dryRun ? null : report,
    error_message: mode === 'failed' ? 'One module failed; review the report.' : null,
  } };
}

describe('restore outcomes in the actual backups page', () => {
  it.each([false, true].flatMap(dryRun => ['failed', 'legacy-errors', 'success', 'skipped'].map(mode => ({ dryRun, mode }))))(
    'retains the report and announces the actual outcome: preview=$dryRun mode=$mode',
    async ({ dryRun, mode }) => {
      network.post.mockResolvedValue(response(dryRun, mode));
      const dialog = await openRestore();
      if (!dryRun) fireEvent.change(within(dialog).getByPlaceholderText('Type to confirm destructive restore'), { target: { value: 'RESTORE' } });
      fireEvent.click(within(dialog).getByRole('button', { name: dryRun ? 'Preview Changes' : 'Restore Now' }));
      await waitFor(() => expect(network.post).toHaveBeenCalledOnce());
      expect(network.post).toHaveBeenCalledWith('/backups/restore', expect.objectContaining({ backup_id: backup.id, dry_run: dryRun }));
      const failed = mode === 'failed' || mode === 'legacy-errors';
      const title = failed ? dryRun ? 'Dry run found errors' : 'Restore finished with errors' : dryRun ? 'Dry run complete' : 'Restore completed';
      await waitFor(() => expect(network.toast).toHaveBeenCalledWith(expect.objectContaining({ title, ...(failed ? { variant: 'destructive' } : {}) })));
      expect(screen.getByRole('dialog', { name: 'Restore from Backup' })).toBeInTheDocument();
      expect(within(dialog).getByText(dryRun ? 'Dry run preview · nothing applied yet' : 'Restore result · review applied and failed sections')).toBeInTheDocument();
      if (failed) expect(within(dialog).getByText('Owned recovery section refused')).toBeInTheDocument();
      if (mode === 'skipped') expect(within(dialog).getByText('Owned section intentionally skipped')).toBeInTheDocument();
      if (!dryRun) expect(within(dialog).getByPlaceholderText('Type to confirm destructive restore')).toHaveValue('');
      expect(network.toast.mock.calls.some(([notice]) => notice.title === 'Restore Started')).toBe(false);
      if (!failed) expect(network.toast.mock.calls.some(([notice]) => notice.variant === 'destructive')).toBe(false);
    },
  );

  it('reports a transport failure without closing the dialog or claiming success', async () => {
    network.post.mockRejectedValue(new Error('Owned request failure'));
    const dialog = await openRestore();
    fireEvent.change(within(dialog).getByPlaceholderText('Type to confirm destructive restore'), { target: { value: 'RESTORE' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Restore Now' }));
    await waitFor(() => expect(network.toast).toHaveBeenCalledWith(expect.objectContaining({ variant: 'destructive' })));
    expect(screen.getByRole('dialog', { name: 'Restore from Backup' })).toBeInTheDocument();
    expect(network.toast.mock.calls.some(([notice]) => notice.title === 'Restore Started' || notice.title === 'Restore completed')).toBe(false);
  });
});
