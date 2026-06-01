// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Tests for `useAuthStore`.
 *
 * We stub `axios.create()` once at module-eval time so the shared `api`
 * instance is a vi-mocked object. Each test then `vi.mocked(api.post)`s
 * the calls it cares about. We do NOT exercise the interceptors here
 * (that's `client.test.ts`'s job).
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';

// Mock axios BEFORE importing anything that pulls the shared `api` instance.
vi.mock('axios', async () => {
  const mockInstance = {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
  };
  return {
    default: {
      create: vi.fn(() => mockInstance),
      post: vi.fn(),
    },
  };
});

import axios from 'axios';
import { api } from '@/lib/api';
import { useAuthStore } from '@/stores/authStore';
import { makeUser } from '@/test-utils/factories';

const mockedPost = api.post as unknown as Mock;
const mockedGet = api.get as unknown as Mock;

function resetStore() {
  // Drop the user/auth flags without touching the actions.
  useAuthStore.setState({
    user: null,
    isAuthenticated: false,
    isLoading: false,
    error: null,
    mfaPending: false,
    mfaToken: null,
    forcePasswordChange: false,
  });
  // Clear any persisted slice from localStorage.
  try {
    localStorage.removeItem('auth-store');
  } catch {
    // ignore
  }
}

describe('useAuthStore.login', () => {
  beforeEach(() => {
    resetStore();
    mockedPost.mockReset();
    mockedGet.mockReset();
  });

  it('sets the user and isAuthenticated=true on a successful login', async () => {
    const user = makeUser({ email: 'alice@example.com' });
    mockedPost.mockResolvedValueOnce({ data: { user, force_password_change: false } });

    const result = await useAuthStore.getState().login({
      login: 'alice@example.com',
      password: 'hunter2',
    });

    expect(result).toEqual({ success: true, forcePasswordChange: false });
    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(true);
    expect(state.user?.email).toBe('alice@example.com');
    expect(state.error).toBeNull();
  });

  it('records the error and stays unauthenticated when login fails', async () => {
    mockedPost.mockRejectedValueOnce({
      response: { data: { error: { message: 'Invalid credentials' } }, status: 401 },
    });

    const result = await useAuthStore.getState().login({
      login: 'bob@example.com',
      password: 'wrong',
    });

    expect(result.success).toBe(false);
    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(false);
    expect(state.user).toBeNull();
    expect(state.error).toBe('Invalid credentials');
  });

  it('surfaces an MFA challenge without authenticating', async () => {
    mockedPost.mockResolvedValueOnce({
      data: { require_mfa: true, mfa_token: 'mfa-xyz' },
    });

    const result = await useAuthStore.getState().login({
      login: 'mfa@example.com',
      password: 'hunter2',
    });

    expect(result).toEqual({ success: true, mfaRequired: true });
    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(false);
    expect(state.mfaPending).toBe(true);
    expect(state.mfaToken).toBe('mfa-xyz');
  });

  it('fetches /auth/me when login response omits the user object', async () => {
    mockedPost.mockResolvedValueOnce({ data: { force_password_change: false } });
    const fetchedUser = makeUser({ email: 'fetched@example.com' });
    mockedGet.mockResolvedValueOnce({ data: fetchedUser });

    await useAuthStore.getState().login({ login: 'fetched@example.com', password: 'x' });

    expect(mockedGet).toHaveBeenCalledWith('/auth/me');
    expect(useAuthStore.getState().user?.email).toBe('fetched@example.com');
  });
});

describe('useAuthStore.logout', () => {
  beforeEach(() => {
    resetStore();
    mockedPost.mockReset();
  });

  it('clears user + isAuthenticated even if backend logout throws', async () => {
    useAuthStore.setState({
      user: makeUser(),
      isAuthenticated: true,
      mfaPending: true,
      mfaToken: 'leftover',
    });
    mockedPost.mockRejectedValueOnce(new Error('network down'));

    await useAuthStore.getState().logout();

    const state = useAuthStore.getState();
    expect(state.user).toBeNull();
    expect(state.isAuthenticated).toBe(false);
    expect(state.mfaPending).toBe(false);
    expect(state.mfaToken).toBeNull();
  });

  it('calls POST /auth/logout', async () => {
    mockedPost.mockResolvedValueOnce({ data: {} });
    await useAuthStore.getState().logout();
    expect(mockedPost).toHaveBeenCalledWith('/auth/logout');
  });
});

describe('useAuthStore.verifyMfa', () => {
  beforeEach(() => {
    resetStore();
    mockedPost.mockReset();
    mockedGet.mockReset();
  });

  it('authenticates on a valid MFA code and refetches the user', async () => {
    useAuthStore.setState({ mfaPending: true, mfaToken: 'mfa-xyz' });
    mockedPost.mockResolvedValueOnce({ data: {} });
    const user = makeUser({ email: 'mfa@example.com', mfa_enabled: true });
    mockedGet.mockResolvedValueOnce({ data: user });

    const ok = await useAuthStore.getState().verifyMfa({ mfa_token: 'mfa-xyz', code: '123456' });

    expect(ok).toBe(true);
    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(true);
    expect(state.mfaPending).toBe(false);
    expect(state.user?.email).toBe('mfa@example.com');
  });

  it('returns false and stores the error message when the code is wrong', async () => {
    mockedPost.mockRejectedValueOnce({
      response: { data: { error: { message: 'Invalid MFA code' } }, status: 401 },
    });
    const ok = await useAuthStore.getState().verifyMfa({ mfa_token: 'm', code: '000000' });
    expect(ok).toBe(false);
    expect(useAuthStore.getState().error).toBe('Invalid MFA code');
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
  });
});

describe('useAuthStore permission helpers', () => {
  beforeEach(() => resetStore());

  it('hasPermission returns false when no user is logged in', () => {
    expect(useAuthStore.getState().hasPermission('devices:read')).toBe(false);
  });

  it('hasPermission is true for superusers regardless of explicit perms', () => {
    useAuthStore.setState({
      user: makeUser({ is_superuser: true, permissions: [] }),
    });
    expect(useAuthStore.getState().hasPermission('anything:write')).toBe(true);
  });

  it('hasPermission matches the wildcard *', () => {
    useAuthStore.setState({
      user: makeUser({ is_superuser: false, permissions: ['*'] }),
    });
    expect(useAuthStore.getState().hasPermission('devices:write')).toBe(true);
  });

  it('hasAnyPermission returns true if any permission matches', () => {
    useAuthStore.setState({
      user: makeUser({ is_superuser: false, permissions: ['devices:read'] }),
    });
    const { hasAnyPermission } = useAuthStore.getState();
    expect(hasAnyPermission('devices:read', 'devices:write')).toBe(true);
    expect(hasAnyPermission('devices:write')).toBe(false);
  });

  it('hasAllPermissions requires every permission', () => {
    useAuthStore.setState({
      user: makeUser({ is_superuser: false, permissions: ['devices:read', 'devices:write'] }),
    });
    const { hasAllPermissions } = useAuthStore.getState();
    expect(hasAllPermissions('devices:read', 'devices:write')).toBe(true);
    expect(hasAllPermissions('devices:read', 'devices:delete')).toBe(false);
  });

  // Regression: the helpers must expand resource wildcards the backend grants,
  // or admin (which holds "device:*"/"network:*", not the specific strings)
  // gets UI controls hidden the backend would actually allow.
  it('expands colon-style resource wildcards (resource:* matches resource:action)', () => {
    useAuthStore.setState({
      user: makeUser({ is_superuser: false, permissions: ['device:*', 'network:*'] }),
    });
    const { hasPermission, hasAnyPermission, hasAllPermissions } = useAuthStore.getState();
    expect(hasPermission('device:update')).toBe(true);
    expect(hasPermission('network:write')).toBe(true);
    expect(hasPermission('camera:view')).toBe(false); // unrelated resource → no match
    expect(hasAnyPermission('camera:view', 'network:read')).toBe(true);
    expect(hasAllPermissions('device:read', 'network:write')).toBe(true);
  });

  it('expands dot-style module wildcards (module.* matches module.action)', () => {
    useAuthStore.setState({
      user: makeUser({ is_superuser: false, permissions: ['cameras.*'] }),
    });
    const { hasPermission } = useAuthStore.getState();
    expect(hasPermission('cameras.view')).toBe(true);
    expect(hasPermission('voip.view')).toBe(false);
  });
});

describe('useAuthStore.setMfaPending', () => {
  beforeEach(() => resetStore());

  it('marks the store as awaiting an MFA challenge', () => {
    useAuthStore.getState().setMfaPending('mfa-from-sso');
    const state = useAuthStore.getState();
    expect(state.mfaPending).toBe(true);
    expect(state.mfaToken).toBe('mfa-from-sso');
    expect(state.isAuthenticated).toBe(false);
  });
});

// Sanity check that the axios mock was applied · prevents accidental
// real-network regression if someone removes the vi.mock above.
describe('axios mock', () => {
  it('exposes a vi-mocked default.create', () => {
    expect(vi.isMockFunction(axios.create)).toBe(true);
  });
});
