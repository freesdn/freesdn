// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Tests for `useSetupStore`.
 *
 * The store is plain zustand + sessionStorage persistence, no axios
 * to mock. Each test resets state via `reset()` so persistence from
 * the previous test doesn't leak.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { useSetupStore } from '@/stores/setupStore';

beforeEach(() => {
  useSetupStore.getState().reset();
  try {
    sessionStorage.clear();
  } catch {
    // ignore
  }
});

describe('useSetupStore navigation', () => {
  it('starts on step 0 with no completions', () => {
    const s = useSetupStore.getState();
    expect(s.currentStep).toBe(0);
    expect(s.stepsCompleted).toEqual([]);
  });

  it('setCurrentStep advances the wizard', () => {
    useSetupStore.getState().setCurrentStep(3);
    expect(useSetupStore.getState().currentStep).toBe(3);
  });

  it('markStepCompleted records the step without duplicates', () => {
    useSetupStore.getState().markStepCompleted(0);
    useSetupStore.getState().markStepCompleted(1);
    useSetupStore.getState().markStepCompleted(0); // duplicate
    expect(useSetupStore.getState().stepsCompleted).toEqual([0, 1]);
  });
});

describe('useSetupStore data setters', () => {
  it('setAdminInfo stores email/username/id', () => {
    useSetupStore
      .getState()
      .setAdminInfo('admin@example.com', 'admin', 'user-1');
    const s = useSetupStore.getState();
    expect(s.adminEmail).toBe('admin@example.com');
    expect(s.adminUsername).toBe('admin');
    expect(s.adminId).toBe('user-1');
  });

  it('setOrganizationInfo stores name/slug/orgId/siteId', () => {
    useSetupStore.getState().setOrganizationInfo('Acme', 'acme', 'org-1', 'site-1');
    const s = useSetupStore.getState();
    expect(s.organizationName).toBe('Acme');
    expect(s.organizationSlug).toBe('acme');
    expect(s.organizationId).toBe('org-1');
    expect(s.siteId).toBe('site-1');
  });

  it('setEnabledModules stores the selection', () => {
    useSetupStore.getState().setEnabledModules(['network', 'cameras']);
    expect(useSetupStore.getState().enabledModules).toEqual(['network', 'cameras']);
  });

  it('addController increments counters', () => {
    useSetupStore.getState().addController(5);
    useSetupStore.getState().addController(3);
    const s = useSetupStore.getState();
    expect(s.controllersAdded).toBe(2);
    expect(s.totalDevices).toBe(8);
  });
});

describe('useSetupStore.getSummary', () => {
  it('returns a snapshot of the user-visible fields', () => {
    const s = useSetupStore.getState();
    s.setAdminInfo('admin@example.com', 'admin', 'user-1');
    s.setOrganizationInfo('Acme', 'acme', 'org-1', 'site-1');
    s.setEnabledModules(['network']);
    s.addController(4);

    expect(useSetupStore.getState().getSummary()).toEqual({
      admin_email: 'admin@example.com',
      organization_name: 'Acme',
      enabled_modules: ['network'],
      controllers_added: 1,
      total_devices: 4,
    });
  });
});

describe('useSetupStore.reset', () => {
  it('clears everything back to initial state', () => {
    const s = useSetupStore.getState();
    s.setCurrentStep(4);
    s.setAdminInfo('admin@example.com', 'admin', 'user-1');
    s.setOrganizationInfo('Acme', 'acme', 'org-1', 'site-1');
    s.setEnabledModules(['network']);
    s.markStepCompleted(0);
    s.markStepCompleted(1);

    s.reset();

    const after = useSetupStore.getState();
    expect(after.currentStep).toBe(0);
    expect(after.adminEmail).toBe('');
    expect(after.organizationName).toBe('');
    expect(after.enabledModules).toEqual([]);
    expect(after.stepsCompleted).toEqual([]);
  });
});
