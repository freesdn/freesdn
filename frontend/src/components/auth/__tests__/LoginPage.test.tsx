// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * LoginPage (the ROUTED one) — smoke + flow tests.
 *
 * This file deliberately targets `@/components/auth/LoginPage`, which is what
 * `App.tsx` actually mounts at /login. A near-identical `src/pages/auth/LoginPage.tsx`
 * used to exist and owned the only login tests, so for a long time the shipped
 * login screen had zero coverage while a component the router never mounted was
 * fully tested. The decoy is gone; if one ever reappears, trust App.tsx's import,
 * not a filename search.
 *
 * Note the routed component differs from the old decoy in three ways that matter
 * here: it probes /api/v1/setup/status with bare `fetch` (not `setupApi`), it
 * gates rendering on the auth store's `_isHydrated` + `_isAuthInitialized` flags,
 * and it uses native `required` inputs rather than zod, so there are no
 * per-field validation messages to assert.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { LoginPage } from '@/components/auth/LoginPage';
import { useAuthStore } from '@/stores/authStore';
import { renderWithProviders } from '@/test-utils';

/**
 * Rendered as a marker rather than null, so a test can assert the routed login
 * screen actually mounts the SSO entry point. In production this component
 * returns null unless an admin has configured an IdP.
 */
const ssoRendered = vi.fn();
vi.mock('@/components/auth/SSOLoginButtons', () => ({
  default: () => {
    ssoRendered();
    return <div data-testid="sso-login-buttons" />;
  },
}));

/** The component renders nothing until hydration + auth-init have both settled. */
function resetAuthStore(overrides: Record<string, unknown> = {}) {
  useAuthStore.setState({
    user: null,
    isAuthenticated: false,
    isLoading: false,
    error: null,
    mfaPending: false,
    mfaToken: null,
    forcePasswordChange: false,
    _isHydrated: true,
    _isAuthInitialized: true,
    ...overrides,
  } as unknown as Parameters<typeof useAuthStore.setState>[0]);
}

beforeEach(() => {
  ssoRendered.mockClear();
  resetAuthStore();
  // Setup already complete, so the page shows the form instead of redirecting.
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ is_complete: true, current_step: 'complete', steps_completed: [] }),
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('LoginPage (routed)', () => {
  it('renders the login form', async () => {
    renderWithProviders(<LoginPage />);

    expect(await screen.findByLabelText(/email or username/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^password$/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^sign in$/i })).toBeInTheDocument();
  });

  it('calls authStore.login with the entered credentials', async () => {
    const user = userEvent.setup();
    const loginSpy = vi.fn().mockResolvedValue({ success: true, mfaRequired: false });
    resetAuthStore({ login: loginSpy });

    renderWithProviders(<LoginPage />);

    await user.type(await screen.findByLabelText(/email or username/i), 'alice@example.com');
    await user.type(screen.getByLabelText(/^password$/i), 'hunter2');
    await user.click(screen.getByRole('button', { name: /^sign in$/i }));

    await waitFor(() =>
      expect(loginSpy).toHaveBeenCalledWith({
        login: 'alice@example.com',
        password: 'hunter2',
        rememberMe: false,
      }),
    );
  });

  it('switches to the MFA panel when the store reports mfaPending', async () => {
    resetAuthStore({ mfaPending: true, mfaToken: 'mfa-xyz' });
    renderWithProviders(<LoginPage />);

    expect(
      await screen.findByRole('heading', { name: /verify your identity/i }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText(/authentication code/i)).toBeInTheDocument();
  });

  it('displays the error message from the auth store', async () => {
    resetAuthStore({ error: 'Invalid credentials' });
    renderWithProviders(<LoginPage />);

    expect(await screen.findByText(/invalid credentials/i)).toBeInTheDocument();
  });

  it('mounts the SSO entry point so single sign-on is reachable from /login', async () => {
    // Regression guard for the defect where SSOLoginButtons was imported only by
    // an unrouted page, leaving /login password-only even with an IdP configured.
    renderWithProviders(<LoginPage />);

    expect(await screen.findByTestId('sso-login-buttons')).toBeInTheDocument();
    expect(ssoRendered).toHaveBeenCalled();
  });

  it('does not mount the SSO entry point on the MFA panel', async () => {
    // The MFA step is a separate early return; SSO buttons there would be a
    // second, unauthenticated entry point mid-flow.
    resetAuthStore({ mfaPending: true, mfaToken: 'mfa-xyz' });
    renderWithProviders(<LoginPage />);

    await screen.findByRole('heading', { name: /verify your identity/i });
    expect(screen.queryByTestId('sso-login-buttons')).not.toBeInTheDocument();
  });
});
