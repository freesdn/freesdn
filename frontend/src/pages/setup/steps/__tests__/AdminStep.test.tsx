// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * AdminStep, behavior tests.
 *
 * The submit handler calls `setupApi.createAdmin`, so we mock the entire
 * `setup-api` module. The store + form are exercised through userEvent.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AdminStep } from '@/pages/setup/steps/AdminStep';
import { useSetupStore } from '@/stores/setupStore';
import { setupApi } from '@/lib/setup-api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/setup-api', () => ({
  setupApi: {
    createAdmin: vi.fn(),
  },
}));

const mockedCreateAdmin = setupApi.createAdmin as unknown as Mock;

const VALID_PASSWORD = 'Abcdef12345!';

beforeEach(() => {
  useSetupStore.getState().reset();
  mockedCreateAdmin.mockReset();
});

async function fillValidForm() {
  const user = userEvent.setup();
  await user.type(screen.getByLabelText(/email address/i), 'admin@example.com');
  await user.type(screen.getByLabelText(/^username/i), 'admin');
  await user.type(screen.getByLabelText(/^password \*/i), VALID_PASSWORD);
  await user.type(screen.getByLabelText(/^confirm password/i), VALID_PASSWORD);
  return user;
}

describe('AdminStep', () => {
  it('renders heading and required form fields', () => {
    renderWithProviders(<AdminStep onNext={vi.fn()} onPrevious={vi.fn()} />);
    expect(screen.getByRole('heading', { name: /create admin account/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/email address/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^username/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^password \*/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^confirm password/i)).toBeInTheDocument();
  });

  it('keeps Continue disabled until every password rule passes and the confirm matches', async () => {
    const user = userEvent.setup();
    renderWithProviders(<AdminStep onNext={vi.fn()} onPrevious={vi.fn()} />);

    const continueBtn = screen.getByRole('button', { name: /continue/i });
    expect(continueBtn).toBeDisabled();

    // Weak password · still disabled
    await user.type(screen.getByLabelText(/^password \*/i), 'short');
    expect(continueBtn).toBeDisabled();

    // Strong password + matching confirm
    await user.clear(screen.getByLabelText(/^password \*/i));
    await user.type(screen.getByLabelText(/^password \*/i), VALID_PASSWORD);
    await user.type(screen.getByLabelText(/^confirm password/i), VALID_PASSWORD);
    await waitFor(() => expect(continueBtn).not.toBeDisabled());
  });

  it('shows the "passwords do not match" indicator when confirm differs', async () => {
    const user = userEvent.setup();
    renderWithProviders(<AdminStep onNext={vi.fn()} onPrevious={vi.fn()} />);

    await user.type(screen.getByLabelText(/^password \*/i), VALID_PASSWORD);
    await user.type(screen.getByLabelText(/^confirm password/i), 'something-else');

    expect(await screen.findByText(/passwords do not match/i)).toBeInTheDocument();
  });

  it('submits the form, advances on success, and stores the admin info', async () => {
    // Seed the org from the previous step.
    useSetupStore.getState().setOrganizationInfo('Acme', 'acme', '', '');

    mockedCreateAdmin.mockResolvedValueOnce({
      success: true,
      user_id: 'user-123',
      organization_id: 'org-1',
      organization_slug: 'acme',
      default_site_id: 'site-1',
    });

    const onNext = vi.fn();
    renderWithProviders(<AdminStep onNext={onNext} onPrevious={vi.fn()} />);

    const user = await fillValidForm();
    await user.click(screen.getByRole('button', { name: /continue/i }));

    await waitFor(() => expect(onNext).toHaveBeenCalledTimes(1));

    // Verify the payload bundles org fields (atomic-org bundle, see AdminStep.tsx).
    expect(mockedCreateAdmin).toHaveBeenCalledWith(
      expect.objectContaining({
        email: 'admin@example.com',
        username: 'admin',
        password: VALID_PASSWORD,
        organization_name: 'Acme',
        organization_slug: 'acme',
      }),
    );

    const s = useSetupStore.getState();
    expect(s.adminEmail).toBe('admin@example.com');
    expect(s.adminUsername).toBe('admin');
    expect(s.adminId).toBe('user-123');
    expect(s.organizationId).toBe('org-1');
    expect(s.siteId).toBe('site-1');
  });

  it('surfaces a backend error and does not advance', async () => {
    mockedCreateAdmin.mockResolvedValueOnce({
      success: false,
      error: 'Email already in use',
    });

    const onNext = vi.fn();
    renderWithProviders(<AdminStep onNext={onNext} onPrevious={vi.fn()} />);

    const user = await fillValidForm();
    await user.click(screen.getByRole('button', { name: /continue/i }));

    expect(await screen.findByText(/email already in use/i)).toBeInTheDocument();
    expect(onNext).not.toHaveBeenCalled();
  });

  it('surfaces a thrown axios error via getApiErrorMessage', async () => {
    mockedCreateAdmin.mockRejectedValueOnce({
      response: { data: { error: { message: 'Backend exploded' } }, status: 500 },
    });

    const onNext = vi.fn();
    renderWithProviders(<AdminStep onNext={onNext} onPrevious={vi.fn()} />);

    const user = await fillValidForm();
    await user.click(screen.getByRole('button', { name: /continue/i }));

    expect(await screen.findByText(/backend exploded/i)).toBeInTheDocument();
    expect(onNext).not.toHaveBeenCalled();
  });

  it('Previous button invokes the onPrevious callback', async () => {
    const user = userEvent.setup();
    const onPrevious = vi.fn();
    renderWithProviders(<AdminStep onNext={vi.fn()} onPrevious={onPrevious} />);

    await user.click(screen.getByRole('button', { name: /previous/i }));
    expect(onPrevious).toHaveBeenCalledTimes(1);
  });
});
