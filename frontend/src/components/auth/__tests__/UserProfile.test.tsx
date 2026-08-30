// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * UserProfile — the profile-save path and the MFA disable path.
 *
 * `PATCH /auth/me` is validated by ProfileUpdateRequest, which declares
 * full_name / username / language. The form PATCHed `{first_name, last_name}`;
 * pydantic drops unknown keys instead of rejecting them, so the handler
 * committed an empty update, answered 200, and the UI said "Profile updated
 * successfully" while nothing had been written. core.users has no first_name
 * column at all — the auth store splits `full_name` for display.
 *
 * `POST /auth/mfa/disable` takes a REQUIRED `password` body field (step-up
 * re-auth before the account's security floor is lowered). This component is
 * the only caller of /auth/mfa/* anywhere in the frontend, and it posted with
 * no second argument — so axios sent an empty body, FastAPI rejected it at
 * request validation with a 422, and the handler (password check, secret and
 * backup-code clearing, token_version bump) never ran. The user saw a generic
 * "Failed to disable MFA" toast with no field to fill in, and MFA could not be
 * turned off from the product at all.
 *
 * Now that /settings/security mounts this component, that path is reachable,
 * so these tests pin it: the request must carry a password the user typed.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { UserProfile } from '@/components/auth/UserProfile';
import { useAuthStore } from '@/stores/authStore';
import { renderWithProviders } from '@/test-utils';

const post = vi.fn();
const patch = vi.fn();

vi.mock('@/lib/api', () => ({
  api: {
    post: (...args: unknown[]) => post(...args),
    patch: (...args: unknown[]) => patch(...args),
  },
}));

const fetchCurrentUser = vi.fn();

/**
 * Store a user the way the auth store really does: `full_name` is the stored
 * column and first/last are derived from it, so a test that sets the halves
 * without the whole would be pinning a shape production never produces.
 */
function setUser(mfaEnabled: boolean, fullName = 'Op Erator') {
  const [first = '', ...rest] = fullName.split(' ');
  useAuthStore.setState({
    user: {
      id: 'user-1',
      email: 'operator@example.com',
      full_name: fullName,
      first_name: first,
      last_name: rest.join(' '),
      organization_id: 'org-1',
      roles: ['admin'],
      mfa_enabled: mfaEnabled,
    },
    isAuthenticated: true,
    logout: vi.fn(),
    fetchCurrentUser,
  } as unknown as Parameters<typeof useAuthStore.setState>[0]);
}

beforeEach(() => {
  post.mockReset();
  post.mockResolvedValue({ data: { message: 'ok' } });
  patch.mockReset();
  patch.mockResolvedValue({ data: { id: 'user-1' } });
  fetchCurrentUser.mockReset();
  fetchCurrentUser.mockResolvedValue(undefined);
  setUser(true);
});

describe('UserProfile save', () => {
  async function typeName(user: ReturnType<typeof userEvent.setup>, first: string, last: string) {
    const firstField = screen.getByLabelText(/first name/i);
    const lastField = screen.getByLabelText(/last name/i);
    await user.clear(firstField);
    await user.clear(lastField);
    if (first) await user.type(firstField, first);
    if (last) await user.type(lastField, last);
    await user.click(screen.getByRole('button', { name: /save changes/i }));
    await waitFor(() => expect(patch).toHaveBeenCalled());
  }

  it('sends the one field the endpoint stores, and nothing it would drop', async () => {
    const user = userEvent.setup();
    renderWithProviders(<UserProfile />);

    await typeName(user, 'Ada', 'Lovelace');

    // Exact equality on purpose: `{first_name, last_name}` — the old payload —
    // is silently discarded by ProfileUpdateRequest, so an assertion that only
    // checked full_name was present would still pass on the broken version.
    expect(patch).toHaveBeenCalledWith('/auth/me', { full_name: 'Ada Lovelace' });
  });

  it('does not report success for a save the server rejected', async () => {
    patch.mockRejectedValueOnce({ response: { data: { detail: 'Name too long' } } });
    const user = userEvent.setup();
    renderWithProviders(<UserProfile />);

    await typeName(user, 'Ada', 'Lovelace');

    expect(await screen.findByText('Name too long')).toBeInTheDocument();
    expect(screen.queryByText('Profile updated successfully')).toBeNull();
  });

  it('clears the stored name when both halves are emptied', async () => {
    const user = userEvent.setup();
    renderWithProviders(<UserProfile />);

    await typeName(user, '', '');

    // `full_name: ''` is set, so ProfileUpdateRequest's exclude_unset dump
    // carries it and the column is cleared. Sending `undefined` instead would
    // put the field back in the "silently ignored" bucket this fix is about.
    expect(patch).toHaveBeenCalledWith('/auth/me', { full_name: '' });
  });

  it('shows the name the server came back with, not the one that was typed', async () => {
    // The refetch is what makes the success message truthful. Model a server
    // that normalises: the operator's stray spacing is not what gets stored.
    fetchCurrentUser.mockImplementation(async () => setUser(true, 'Ada King Lovelace'));

    const user = userEvent.setup();
    renderWithProviders(<UserProfile />);

    await typeName(user, 'Ada', 'King  Lovelace');
    expect(patch).toHaveBeenCalledWith('/auth/me', { full_name: 'Ada King  Lovelace' });

    await waitFor(() =>
      expect(screen.getByLabelText(/last name/i)).toHaveValue('King Lovelace')
    );
    expect(screen.getByLabelText(/first name/i)).toHaveValue('Ada');
    expect(await screen.findByText('Profile updated successfully')).toBeInTheDocument();
  });
});

describe('UserProfile MFA disable', () => {
  it('sends the password the operator typed', async () => {
    const user = userEvent.setup();
    renderWithProviders(<UserProfile />);

    await user.click(screen.getByRole('button', { name: /disable mfa/i }));

    const field = await screen.findByLabelText(/current password/i, {
      selector: '#disable_mfa_password',
    });
    await user.type(field, 'hunter2-correct-horse');

    const submit = screen
      .getAllByRole('button', { name: /disable mfa/i })
      .find((b) => (b as HTMLButtonElement).type === 'submit');
    expect(submit).toBeDefined();
    await user.click(submit!);

    await waitFor(() => expect(post).toHaveBeenCalled());
    // The regression: before the fix this was `post('/auth/mfa/disable')` with
    // no body at all, which the endpoint answers with a 422.
    expect(post).toHaveBeenCalledWith('/auth/mfa/disable', {
      password: 'hunter2-correct-horse',
    });
  });

  it('never fires the request without a password', async () => {
    const user = userEvent.setup();
    renderWithProviders(<UserProfile />);

    // Revealing the form must not itself call the endpoint...
    await user.click(screen.getByRole('button', { name: /disable mfa/i }));
    expect(post).not.toHaveBeenCalled();

    // ...and the submit stays disabled while the field is empty, so an empty
    // `password` (which the schema's min_length=1 also rejects) can't be sent.
    const submit = screen
      .getAllByRole('button', { name: /disable mfa/i })
      .find((b) => (b as HTMLButtonElement).type === 'submit') as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
  });

  it('surfaces the server error instead of a generic failure', async () => {
    post.mockRejectedValueOnce({ response: { data: { detail: 'Incorrect password' } } });
    const user = userEvent.setup();
    renderWithProviders(<UserProfile />);

    await user.click(screen.getByRole('button', { name: /disable mfa/i }));
    await user.type(await screen.findByLabelText(/current password/i, { selector: '#disable_mfa_password' }), 'wrong');
    const submit = screen
      .getAllByRole('button', { name: /disable mfa/i })
      .find((b) => (b as HTMLButtonElement).type === 'submit') as HTMLButtonElement;
    await user.click(submit);

    expect(await screen.findByText('Incorrect password')).toBeInTheDocument();
  });

  it('shows no password prompt when MFA is already off', async () => {
    setUser(false);
    renderWithProviders(<UserProfile />);

    expect(screen.getByRole('button', { name: /enable mfa/i })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /disable mfa/i })).toBeNull();
  });
});
