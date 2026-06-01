// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * LoginPage, smoke + flow tests.
 *
 * Asserts the page renders, validates required fields, calls the auth
 * store's `login`, and switches to the MFA panel when the store reports
 * mfaPending.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { LoginPage } from '@/pages/auth/LoginPage';
import { useAuthStore } from '@/stores/authStore';
import { setupApi } from '@/lib/setup-api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/setup-api', () => ({
  setupApi: {
    getStatus: vi.fn(),
  },
}));

vi.mock('@/components/auth/SSOLoginButtons', () => ({
  default: () => null,
}));

const mockedGetStatus = setupApi.getStatus as unknown as Mock;

function resetAuthStore() {
  useAuthStore.setState({
    user: null,
    isAuthenticated: false,
    isLoading: false,
    error: null,
    mfaPending: false,
    mfaToken: null,
    forcePasswordChange: false,
  });
}

beforeEach(() => {
  resetAuthStore();
  mockedGetStatus.mockReset();
  // Pretend setup is complete so the page doesn't redirect.
  mockedGetStatus.mockResolvedValue({
    is_complete: true,
    current_step: 'complete',
    steps_completed: [],
  });
});

describe('LoginPage', () => {
  it('renders the login form with required fields', async () => {
    renderWithProviders(<LoginPage />);

    expect(screen.getByLabelText(/email or username/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^password/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^sign in$/i })).toBeInTheDocument();
  });

  it('shows validation errors when fields are empty', async () => {
    const user = userEvent.setup();
    renderWithProviders(<LoginPage />);

    await user.click(screen.getByRole('button', { name: /^sign in$/i }));

    expect(await screen.findByText(/email or username is required/i)).toBeInTheDocument();
    expect(await screen.findByText(/password is required/i)).toBeInTheDocument();
  });

  it('calls authStore.login with the entered credentials', async () => {
    const user = userEvent.setup();
    const loginSpy = vi.fn().mockResolvedValue({ success: true });
    useAuthStore.setState({ login: loginSpy } as unknown as Parameters<typeof useAuthStore.setState>[0]);

    renderWithProviders(<LoginPage />);

    await user.type(screen.getByLabelText(/email or username/i), 'alice@example.com');
    await user.type(screen.getByLabelText(/^password/i), 'hunter2');
    await user.click(screen.getByRole('button', { name: /^sign in$/i }));

    await waitFor(() =>
      expect(loginSpy).toHaveBeenCalledWith({
        login: 'alice@example.com',
        password: 'hunter2',
      }),
    );
  });

  it('switches to the MFA panel when the store reports mfaPending', async () => {
    useAuthStore.setState({ mfaPending: true, mfaToken: 'mfa-xyz' });
    renderWithProviders(<LoginPage />);

    expect(
      await screen.findByRole('heading', { name: /two-factor authentication/i }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText(/verification code/i)).toBeInTheDocument();
  });

  it('displays the error message from the auth store', async () => {
    useAuthStore.setState({ error: 'Invalid credentials' });
    renderWithProviders(<LoginPage />);
    expect(await screen.findByText(/invalid credentials/i)).toBeInTheDocument();
  });
});
