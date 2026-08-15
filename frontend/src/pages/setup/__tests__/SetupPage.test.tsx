// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * SetupPage, orchestration tests.
 *
 * The page mounts a sidebar + the current step component, decides whether
 * to navigate to /login when setup is already complete, and renders a
 * loader / error state while bootstrapping. We mock the heavy step
 * components so the test exercises only the orchestration logic.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import SetupPage from '@/pages/setup/SetupPage';
import { useSetupStore } from '@/stores/setupStore';
import { setupApi } from '@/lib/setup-api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/setup-api', () => ({
  setupApi: {
    getStatus: vi.fn(),
  },
}));

// Replace the heavy step components with minimal harnesses so we can
// assert which one is mounted without pulling in every dependency.
vi.mock('@/pages/setup/steps/WelcomeStep', () => ({
  WelcomeStep: ({ onNext }: { onNext: () => void }) => (
    <button type="button" onClick={onNext} data-testid="welcome-next">
      WelcomeStep
    </button>
  ),
}));
vi.mock('@/pages/setup/steps/DatabaseStep', () => ({
  DatabaseStep: ({ onNext }: { onNext: () => void }) => (
    <button type="button" onClick={onNext} data-testid="database-next">
      DatabaseStep
    </button>
  ),
}));
vi.mock('@/pages/setup/steps/OrganizationStep', () => ({
  OrganizationStep: () => <div data-testid="organization-step">OrganizationStep</div>,
}));
vi.mock('@/pages/setup/steps/AdminStep', () => ({
  AdminStep: () => <div data-testid="admin-step">AdminStep</div>,
}));
vi.mock('@/pages/setup/steps/ModulesStep', () => ({
  ModulesStep: () => <div data-testid="modules-step">ModulesStep</div>,
}));
vi.mock('@/pages/setup/steps/ControllersStep', () => ({
  ControllersStep: () => <div data-testid="controllers-step">ControllersStep</div>,
}));
vi.mock('@/pages/setup/steps/CompleteStep', () => ({
  CompleteStep: () => <div data-testid="complete-step">CompleteStep</div>,
}));

const mockedGetStatus = setupApi.getStatus as unknown as Mock;

beforeEach(() => {
  useSetupStore.getState().reset();
  mockedGetStatus.mockReset();
});

describe('SetupPage', () => {
  it('shows the welcome step once the status check resolves as incomplete', async () => {
    mockedGetStatus.mockResolvedValueOnce({
      is_complete: false,
      current_step: 'welcome',
      steps_completed: [],
    });

    renderWithProviders(<SetupPage />);

    expect(await screen.findByTestId('welcome-next')).toBeInTheDocument();
  });

  it('advances through the canonical wizard ordering: Welcome → Database → Organization → Admin', async () => {
    mockedGetStatus.mockResolvedValueOnce({
      is_complete: false,
      current_step: 'welcome',
      steps_completed: [],
    });

    renderWithProviders(<SetupPage />);

    const user = userEvent.setup();
    await user.click(await screen.findByTestId('welcome-next'));
    expect(await screen.findByTestId('database-next')).toBeInTheDocument();

    await user.click(screen.getByTestId('database-next'));
    expect(await screen.findByTestId('organization-step')).toBeInTheDocument();

    // The store records each completed step exactly once.
    expect(useSetupStore.getState().stepsCompleted).toEqual([0, 1]);
    expect(useSetupStore.getState().currentStep).toBe(2);
  });

  it('renders the loading spinner before the status promise resolves', () => {
    // Return a never-resolving promise so we stay in the loading branch.
    mockedGetStatus.mockReturnValueOnce(new Promise(() => {}));
    const { container } = renderWithProviders(<SetupPage />);
    // The loader is a Lucide Loader2 svg, we can find it by class.
    expect(container.querySelector('.animate-spin')).not.toBeNull();
  });

  it('shows an error state when the status check fails', async () => {
    mockedGetStatus.mockRejectedValueOnce(new Error('boom'));
    renderWithProviders(<SetupPage />);

    expect(await screen.findByText(/setup error/i)).toBeInTheDocument();
    expect(screen.getByText(/failed to check setup status/i)).toBeInTheDocument();
  });
});
