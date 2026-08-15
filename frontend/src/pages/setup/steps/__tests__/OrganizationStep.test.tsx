// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * OrganizationStep, behavior tests.
 *
 * The step is purely client-state (no backend call), so we drive it with
 * userEvent and assert via the setupStore + the onNext/onPrevious spies.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { OrganizationStep } from '@/pages/setup/steps/OrganizationStep';
import { useSetupStore } from '@/stores/setupStore';
import { renderWithProviders } from '@/test-utils';

beforeEach(() => {
  useSetupStore.getState().reset();
});

describe('OrganizationStep', () => {
  it('renders the heading and form', () => {
    renderWithProviders(<OrganizationStep onNext={vi.fn()} onPrevious={vi.fn()} />);
    expect(screen.getByRole('heading', { name: /create organization/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/organization name/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/url slug/i)).toBeInTheDocument();
  });

  it('auto-generates a URL-safe slug from the organization name', async () => {
    const user = userEvent.setup();
    renderWithProviders(<OrganizationStep onNext={vi.fn()} onPrevious={vi.fn()} />);

    const nameInput = screen.getByLabelText(/organization name/i) as HTMLInputElement;
    await user.type(nameInput, 'Acme  Corp.');

    const slugInput = screen.getByLabelText(/url slug/i) as HTMLInputElement;
    // "Acme  Corp." → strip dot, collapse spaces, lowercase → "acme-corp"
    expect(slugInput.value).toBe('acme-corp');
  });

  it('disables Continue until the name reaches the 2-char minimum', async () => {
    const user = userEvent.setup();
    renderWithProviders(<OrganizationStep onNext={vi.fn()} onPrevious={vi.fn()} />);

    const continueBtn = screen.getByRole('button', { name: /continue/i });
    expect(continueBtn).toBeDisabled();

    await user.type(screen.getByLabelText(/organization name/i), 'A');
    expect(continueBtn).toBeDisabled();

    await user.type(screen.getByLabelText(/organization name/i), 'BC');
    await waitFor(() => expect(continueBtn).not.toBeDisabled());
  });

  it('writes the organization name + slug to the setup store and calls onNext', async () => {
    const user = userEvent.setup();
    const onNext = vi.fn();
    renderWithProviders(<OrganizationStep onNext={onNext} onPrevious={vi.fn()} />);

    await user.type(screen.getByLabelText(/organization name/i), 'My Company');
    await user.click(screen.getByRole('button', { name: /continue/i }));

    await waitFor(() => expect(onNext).toHaveBeenCalledTimes(1));
    const s = useSetupStore.getState();
    expect(s.organizationName).toBe('My Company');
    expect(s.organizationSlug).toBe('my-company');
  });

  it('Previous button invokes the onPrevious callback', async () => {
    const user = userEvent.setup();
    const onPrevious = vi.fn();
    renderWithProviders(<OrganizationStep onNext={vi.fn()} onPrevious={onPrevious} />);

    await user.click(screen.getByRole('button', { name: /previous/i }));
    expect(onPrevious).toHaveBeenCalledTimes(1);
  });

  it('shows a slug validation error when the slug contains illegal characters', async () => {
    const user = userEvent.setup();
    const onNext = vi.fn();
    renderWithProviders(<OrganizationStep onNext={onNext} onPrevious={vi.fn()} />);

    await user.type(screen.getByLabelText(/organization name/i), 'Acme');
    const slugInput = screen.getByLabelText(/url slug/i);
    // Replace the auto-generated slug with something invalid.
    await user.clear(slugInput);
    await user.type(slugInput, 'BAD SLUG!');

    await user.click(screen.getByRole('button', { name: /continue/i }));

    expect(
      await screen.findByText(/lowercase letters, numbers, and hyphens/i),
    ).toBeInTheDocument();
    expect(onNext).not.toHaveBeenCalled();
  });
});
