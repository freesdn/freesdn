// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { WelcomeStep } from '../WelcomeStep';
import { setupApi } from '@/lib/setup-api';
import { useSetupStore } from '@/stores/setupStore';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/setup-api', () => ({
  setupApi: { getWelcome: vi.fn(), restoreFromVault: vi.fn() },
}));

const passphrase = 'Owned UI recovery passphrase';
const unconfirmed = 'Recovery was not confirmed. Review the server status before retrying.';

function completeRecovery() {
  return {
    success: true, organization_id: 'owned-recovered-organization',
    result: {
      contributors: [{ contributor_id: 'core', status: 'ok', errors: [], warnings: [],
        created: { users: 1, sites: 1 }, updated: {}, skipped: {} }],
      summary: { total_created: 2, total_updated: 0, total_skipped: 0, total_errors: 0,
        contributors_ok: 1, contributors_failed: 0 },
    },
  };
}

function RouteProbe() {
  return <output aria-label="Current route">{useLocation().pathname}</output>;
}

beforeEach(() => {
  vi.resetAllMocks();
  useSetupStore.getState().reset();
  vi.mocked(setupApi.getWelcome).mockResolvedValue({
    app_name: 'FreeSDN', app_version: 'owned-qualification', environment: 'development', requirements: [],
    all_requirements_met: true, can_proceed: true,
  });
});

async function openRecovery() {
  const onNext = vi.fn();
  renderWithProviders(<><WelcomeStep onNext={onNext} /><RouteProbe /></>, { initialPath: '/setup' });
  fireEvent.click(await screen.findByRole('button', { name: 'Restore from a backup instead' }));
  const file = new File(['owned synthetic archive'], 'owned.fsdnvault', { type: 'application/octet-stream' });
  const fileInput = screen.getByLabelText('Backup file (.fsdnvault)');
  const passwordInput = screen.getByLabelText('Backup passphrase');
  fireEvent.change(fileInput, { target: { files: [file] } });
  fireEvent.change(passwordInput, { target: { value: passphrase } });
  return { file, fileInput, passwordInput, onNext,
    submit: screen.getByRole('button', { name: 'Restore this instance' }) };
}

describe('first-install recovery in the actual welcome screen', () => {
  it.each(['complete', 'false-success', 'empty', 'missing-report', 'missing-organization',
    'module-failure', 'record-errors', 'missing-core', 'preview-only'])(
    'only navigates after a confirmed complete recovery: %s', async mode => {
      const response = completeRecovery();
      if (mode === 'false-success') response.success = false;
      if (mode === 'missing-organization') response.organization_id = '';
      if (mode === 'module-failure') response.result.summary.contributors_failed = 1;
      if (mode === 'record-errors') response.result.summary.total_errors = 1;
      if (mode === 'missing-core') response.result.contributors = [];
      if (mode === 'preview-only') response.result.contributors[0].status = 'dry_run_ok';
      const payload = mode === 'empty' ? undefined : mode === 'missing-report'
        ? { success: true, organization_id: response.organization_id } : response;
      vi.mocked(setupApi.restoreFromVault).mockResolvedValue(payload as Awaited<ReturnType<typeof setupApi.restoreFromVault>>);
      const form = await openRecovery();
      fireEvent.click(form.submit);
      await waitFor(() => expect(setupApi.restoreFromVault).toHaveBeenCalledExactlyOnceWith(form.file, passphrase));
      if (mode === 'complete') {
        await waitFor(() => expect(screen.getByLabelText('Current route')).toHaveTextContent('/login'));
      } else {
        expect(await screen.findByText(unconfirmed)).toBeInTheDocument();
        expect(screen.getByLabelText('Current route')).toHaveTextContent('/setup');
      }
      await waitFor(() => expect(form.passwordInput).toHaveValue(''));
      expect(form.onNext).not.toHaveBeenCalled();
    },
  );

  it.each([
    { name: 'standard envelope', data: { error: { message: 'Vault module compatibility needs review.' } }, expected: 'Vault module compatibility needs review.' },
    { name: 'legacy detail', data: { detail: 'The archive passphrase could not be verified.' }, expected: 'The archive passphrase could not be verified.' },
    { name: 'validation details', data: { error: { message: 'Validation error', details: [{ field: 'body.passphrase', message: 'must contain at least 12 characters' }] } }, expected: 'passphrase: must contain at least 12 characters' },
  ])('shows a safe $name without navigating and permits a retry', async ({ data, expected }) => {
    vi.mocked(setupApi.restoreFromVault).mockRejectedValueOnce({ response: { status: 409, data } });
    const form = await openRecovery();
    fireEvent.click(form.submit);
    expect(await screen.findByText(expected)).toBeInTheDocument();
    expect(screen.getByLabelText('Current route')).toHaveTextContent('/setup');
    await waitFor(() => expect(form.passwordInput).toHaveValue(''));
    expect(form.submit).toBeDisabled();
    vi.mocked(setupApi.restoreFromVault).mockResolvedValueOnce(completeRecovery());
    fireEvent.change(form.passwordInput, { target: { value: passphrase } });
    fireEvent.click(form.submit);
    await waitFor(() => expect(screen.getByLabelText('Current route')).toHaveTextContent('/login'));
    expect(setupApi.restoreFromVault).toHaveBeenCalledTimes(2);
  });

  it('blocks duplicate submissions and competing setup actions while recovery is pending', async () => {
    let finish!: (response: ReturnType<typeof completeRecovery>) => void;
    const pending = new Promise<ReturnType<typeof completeRecovery>>(resolve => { finish = resolve; });
    vi.mocked(setupApi.restoreFromVault).mockReturnValueOnce(pending);
    const form = await openRecovery();
    fireEvent.click(form.submit);
    try {
      expect(form.submit).toBeDisabled();
      expect(form.fileInput).toBeDisabled();
      expect(form.passwordInput).toBeDisabled();
      expect(screen.getByRole('button', { name: 'Restore from a backup instead' })).toBeDisabled();
      const next = screen.getByRole('button', { name: /continue/i });
      expect(next).toBeDisabled();
      fireEvent.click(form.submit);
      fireEvent.click(next);
      expect(setupApi.restoreFromVault).toHaveBeenCalledOnce();
      expect(form.onNext).not.toHaveBeenCalled();
      expect(screen.getByLabelText('Current route')).toHaveTextContent('/setup');
    } finally {
      await act(async () => { finish(completeRecovery()); await pending; });
    }
    await waitFor(() => expect(form.passwordInput).toHaveValue(''));
    expect(screen.getByLabelText('Current route')).toHaveTextContent('/login');
  });
});
