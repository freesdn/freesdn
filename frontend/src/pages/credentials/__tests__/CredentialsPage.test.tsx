// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * CredentialsPage feedback, the failure an operator could not see.
 *
 * Every mutation on this page reported through `useNotificationsStore`,
 * a zustand store with an `addNotification` writer and no reader anywhere
 * in the tree (the bell in TopBar renders the server-side
 * `['in-app-notifications']` query instead). So a rejected save produced
 * no toast, no banner and no bell entry, and looked exactly like a
 * successful one.
 *
 * It was worse than "no toast": the MutationCache safety net in
 * `lib/queryClient.ts` skips any mutation that defines its own `onError`,
 * so defining one that wrote to the dead store is what suppressed the
 * generic error toast these pages would otherwise have inherited.
 *
 * These tests drive the real page and assert on rendered text, so they
 * fail if the reporting sink stops being visible again.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import CredentialsPage from '../CredentialsPage';
import { credentialsApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    credentialsApi: {
      list: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
      delete: vi.fn(),
      test: vi.fn(),
    },
  };
});

const mockList = credentialsApi.list as unknown as Mock;
const mockDelete = credentialsApi.delete as unknown as Mock;

const CRED = {
  id: 'cred-1',
  name: 'core-switch-admin',
  credential_type: 'username_password',
  description: 'lab',
  username: 'admin',
  created_at: '2026-08-01T00:00:00Z',
  updated_at: '2026-08-01T00:00:00Z',
};

beforeEach(() => {
  mockList.mockReset();
  mockDelete.mockReset();
  mockList.mockResolvedValue({ data: [CRED] });
});

async function openDeleteConfirm(user: ReturnType<typeof userEvent.setup>) {
  expect(await screen.findByText('core-switch-admin')).toBeInTheDocument();
  await user.click(
    screen.getByRole('button', { name: /actions for core-switch-admin/i }),
  );
  await user.click(await screen.findByRole('menuitem', { name: /^delete$/i }));
  const dialog = await screen.findByRole('alertdialog');
  await user.click(within(dialog).getByRole('button', { name: /^delete$/i }));
}

describe('CredentialsPage surfaces mutation outcomes to the operator', () => {
  // MUTATION GUARD: swap this toast back to addNotification (or to any
  // other write-only sink) and nothing renders, so the assertion fails
  // for the original reason: the operator sees no error.
  it('renders an error toast when a delete is rejected', async () => {
    const user = userEvent.setup();
    mockDelete.mockRejectedValue(new Error('boom'));

    renderWithProviders(<CredentialsPage />);
    await openDeleteConfirm(user);

    await waitFor(() => expect(mockDelete).toHaveBeenCalledWith('cred-1'));
    expect(
      await screen.findByText(/Failed to delete credential/i),
    ).toBeInTheDocument();
  });

  // The success half matters too: without it a passing error test could be
  // satisfied by a page that toasts on absolutely everything.
  it('renders a success toast when a delete succeeds', async () => {
    const user = userEvent.setup();
    mockDelete.mockResolvedValue({ data: {} });

    renderWithProviders(<CredentialsPage />);
    await openDeleteConfirm(user);

    await waitFor(() => expect(mockDelete).toHaveBeenCalledWith('cred-1'));
    expect(
      await screen.findByText(/The credential has been deleted/i),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(/Failed to delete credential/i),
    ).not.toBeInTheDocument();
  });
});


const mockTest = credentialsApi.test as unknown as Mock;

async function openHttpCheck(user: ReturnType<typeof userEvent.setup>) {
  expect(await screen.findByText('core-switch-admin')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: /actions for core-switch-admin/i }));
  await user.click(await screen.findByRole('menuitem', { name: /^test$/i }));
  return screen.findByRole('dialog');
}

async function submitHttpCheck(user: ReturnType<typeof userEvent.setup>) {
  const dialog = await openHttpCheck(user);
  await user.type(within(dialog).getByRole('textbox', { name: /target host/i }), '10.251.9.1');
  await user.click(within(dialog).getByRole('button', { name: /test connection/i }));
  await waitFor(() => expect(mockTest).toHaveBeenCalledWith('cred-1', '10.251.9.1'));
}

describe('CredentialsPage distinguishes HTTP connectivity from authentication', () => {
  beforeEach(() => { mockTest.mockReset(); });

  it('explains before submission that the HTTP check does not verify authentication', async () => {
    renderWithProviders(<CredentialsPage />);
    const dialog = await openHttpCheck(userEvent.setup());
    expect(within(dialog).getByText(/does not verify authentication/i)).toBeInTheDocument();
    expect(within(dialog).getByText(/does not prove that the credential is valid/i)).toBeInTheDocument();
    expect(mockTest).not.toHaveBeenCalled();
  });

  it('shows the successful backend diagnostic without claiming credential validation', async () => {
    const message = 'HTTP connectivity check returned HTTP 204 via HTTPS; authentication was not verified.';
    mockTest.mockResolvedValue({ data: { success: true, message } });
    renderWithProviders(<CredentialsPage />);
    await submitHttpCheck(userEvent.setup());
    expect(await screen.findByText(message)).toBeInTheDocument();
    expect(screen.getByText('HTTP Target Reachable')).toBeInTheDocument();
    expect(screen.queryByText(/credential was validated/i)).not.toBeInTheDocument();
  });

  it('uses an honest fallback when a successful response has no diagnostic', async () => {
    mockTest.mockResolvedValue({ data: { success: true, message: '' } });
    renderWithProviders(<CredentialsPage />);
    await submitHttpCheck(userEvent.setup());
    expect(await screen.findByText('The HTTP target responded; authentication was not verified.')).toBeInTheDocument();
    expect(screen.queryByText(/credential was validated/i)).not.toBeInTheDocument();
  });

  it.each([401, 403, 500])('shows HTTP %i as a failed connectivity check', async (status) => {
    const message = `HTTP connectivity check returned HTTP ${status} via HTTPS; authentication was not verified.`;
    mockTest.mockResolvedValue({ data: { success: false, message } });
    renderWithProviders(<CredentialsPage />);
    await submitHttpCheck(userEvent.setup());
    expect(await screen.findByText(message)).toBeInTheDocument();
    expect(screen.getByText('HTTP Check Failed')).toBeInTheDocument();
    expect(screen.queryByText('HTTP Target Reachable')).not.toBeInTheDocument();
  });

  it('does not claim authentication failed when an unsuccessful response has no diagnostic', async () => {
    mockTest.mockResolvedValue({ data: { success: false, message: '' } });
    renderWithProviders(<CredentialsPage />);
    await submitHttpCheck(userEvent.setup());
    expect(await screen.findByText('The HTTP connectivity check did not succeed; authentication was not verified.')).toBeInTheDocument();
  });

  it('shows a permission rejection without turning it into an authentication result', async () => {
    mockTest.mockRejectedValue({ response: { data: { detail: 'Write permission required for this site' }, status: 403 } });
    renderWithProviders(<CredentialsPage />);
    await submitHttpCheck(userEvent.setup());
    expect(await screen.findByText('Write permission required for this site')).toBeInTheDocument();
    expect(screen.queryByText('HTTP Target Reachable')).not.toBeInTheDocument();
  });
});
