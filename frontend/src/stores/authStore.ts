// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useCallback } from 'react';
import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';
import { immer } from 'zustand/middleware/immer';
import { api, getCookie, getApiErrorMessage } from '../lib/api';
import type { AxiosError } from 'axios';
import { demoUser } from '@/demo/fixtures';
import { isDemoMode } from '@/demo/mode';

/**
 * Mirror the backend CurrentUser.has_permission wildcard semantics so the UI
 * never hides a control the backend would actually allow. A user granted a
 * resource wildcard ("device:*", "network:*", "cameras.*", …) must satisfy a
 * specific check ("device:update", "cameras.view"): exact + colon-wildcard +
 * dot-wildcard, matching backend/app/core/dependencies.py. Previously these
 * helpers only did exact match, so e.g. admin, which holds "device:*",
 * "network:*", "firewall.*", was locked out of pages gated on the specific
 * permission string.
 */
function permGranted(perms: string[], permission: string): boolean {
  if (perms.includes('*') || perms.includes(permission)) return true;
  const colon = permission.split(':');
  if (colon.length === 2 && perms.includes(`${colon[0]}:*`)) return true;
  const dot = permission.split('.');
  if (dot.length === 2 && perms.includes(`${dot[0]}.*`)) return true;
  return false;
}

// Types
export interface User {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  username: string;
  full_name: string | null;
  role: string;
  organization_id: string | null;
  is_active: boolean;
  is_superuser: boolean;
  is_org_admin: boolean;
  mfa_enabled: boolean;
  permissions: string[];
  roles: string[];
}

/**
 * Normalize a raw user object from the API.
 *
 * The backend `/auth/me` now returns `permissions`, `is_superuser`, and
 * `is_org_admin` directly. We trust those values and only fall back to
 * role-based derivation for backward compatibility with cached/stale data.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function normalizeUser(raw: any): User {
  const role: string = raw.role ?? 'viewer';

  // Trust backend-provided flags; fall back to role derivation for stale cache
  const isSuperuser: boolean = raw.is_superuser ?? (role === 'super_admin');
  const isOrgAdmin: boolean = raw.is_org_admin ?? ['org_admin', 'admin', 'super_admin'].includes(role);

  // Trust backend-provided permissions (populated by /auth/me)
  const permissions: string[] = raw.permissions ?? [];

  // Derive first_name / last_name from full_name if not provided
  const fullName = raw.full_name ?? '';
  const [firstName = '', ...rest] = fullName.split(' ');
  const lastName = rest.join(' ');

  return {
    ...raw,
    first_name: raw.first_name ?? firstName,
    last_name: raw.last_name ?? lastName,
    permissions,
    roles: raw.roles ?? (role ? [role] : []),
    is_superuser: isSuperuser,
    is_org_admin: isOrgAdmin,
    is_active: raw.is_active ?? true,
    mfa_enabled: raw.mfa_enabled ?? false,
  };
}

export interface LoginCredentials {
  login: string;
  password: string;
  /** Opt into a longer-lived ("remember me") session — sent as remember_me. */
  rememberMe?: boolean;
}

export interface RegisterData {
  email: string;
  password: string;
  first_name: string;
  last_name: string;
  organization_name?: string;
}

export interface MfaVerifyData {
  mfa_token: string;
  code: string;
}

interface AuthState {
  // State
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  _isHydrated: boolean;
  _isAuthInitialized: boolean;
  error: string | null;
  mfaPending: boolean;
  mfaToken: string | null;
  forcePasswordChange: boolean;

  // Actions
  login: (credentials: LoginCredentials) => Promise<{ success: boolean; mfaRequired?: boolean; forcePasswordChange?: boolean }>;
  verifyMfa: (data: MfaVerifyData) => Promise<boolean>;
  register: (data: RegisterData) => Promise<boolean>;
  logout: () => Promise<void>;
  refreshSession: () => Promise<boolean>;
  fetchCurrentUser: () => Promise<void>;
  clearError: () => void;
  clearForcePasswordChange: () => void;
  loginWithSSO: (accessToken?: string, refreshToken?: string, user?: User | null) => Promise<void>;
  // Set MFA pending state from an external flow (e.g. SSO callback that
  // returned require_mfa instead of an access token). The LoginPage's
  // inline MFA form picks this up via `mfaPending` and continues with
  // /auth/login/mfa.
  setMfaPending: (mfaToken: string) => void;

  // Permission helpers
  hasPermission: (permission: string) => boolean;
  hasAnyPermission: (...permissions: string[]) => boolean;
  hasAllPermissions: (...permissions: string[]) => boolean;
}

export const useAuthStore = create<AuthState>()(
  devtools(
    persist(
      immer((set, get) => ({
        // Initial state
        user: null,
        isAuthenticated: false,
        isLoading: false,
        _isHydrated: false,
        _isAuthInitialized: false,
        error: null,
        mfaPending: false,
        mfaToken: null,
        forcePasswordChange: false,

        // Login action
        login: async (credentials: LoginCredentials) => {
          set((state) => {
            state.isLoading = true;
            state.error = null;
            state.mfaPending = false;
            state.mfaToken = null;
            state.forcePasswordChange = false;
          });

          try {
            const response = await api.post('/auth/login', {
              login: credentials.login,
              password: credentials.password,
              remember_me: credentials.rememberMe ?? false,
            });

            const data = response.data;

            // Check if MFA is required
            if (data.require_mfa) {
              set((state) => {
                state.isLoading = false;
                state.mfaPending = true;
                state.mfaToken = data.mfa_token;
              });
              return { success: true, mfaRequired: true };
            }

            const forcePasswordChange = data.force_password_change || false;

            // Cookies are set automatically by the backend response.
            // We only need to track auth state in the store.
            set((state) => {
              state.isAuthenticated = true;
              state.isLoading = false;
              state.forcePasswordChange = forcePasswordChange;
            });

            // Fetch user profile if not included in login response
            let user = data.user;
            if (!user) {
              try {
                const meResponse = await api.get('/auth/me');
                user = meResponse.data;
                set((state) => {
                  state.user = normalizeUser(user);
                });
              } catch {
                // User fetch failed but login succeeded
              }
            } else {
              set((state) => {
                state.user = normalizeUser(user);
              });
            }

            return { success: true, forcePasswordChange };
          } catch (error: unknown) {
            const axiosErr = error as AxiosError<{ detail?: string; error?: { message?: string } }>;
            if (import.meta.env.DEV) {
              // Log only the status code, response body can include
              // mfa_token, hints, or other fields that the DevTools
              // console then captures (recordable in browser session
              // replays).
              console.error('Login error:', axiosErr.response?.status);
            }
            const message = getApiErrorMessage(error, 'Login failed');
            set((state) => {
              state.isLoading = false;
              state.error = message;
            });
            return { success: false };
          }
        },

        // Verify MFA code
        verifyMfa: async (data: MfaVerifyData) => {
          set((state) => {
            state.isLoading = true;
            state.error = null;
          });

          try {
            await api.post('/auth/login/mfa', {
              mfa_token: data.mfa_token,
              code: data.code,
            });

            // Cookies set automatically by backend response
            set((state) => {
              state.isAuthenticated = true;
              state.isLoading = false;
              state.mfaPending = false;
              state.mfaToken = null;
            });

            // Fetch user profile after MFA
            try {
              const userResponse = await api.get('/auth/me');
              set((state) => {
                state.user = normalizeUser(userResponse.data);
              });
            } catch {
              // Non-critical
            }

            return true;
          } catch (error: unknown) {
            const message = getApiErrorMessage(error, 'MFA verification failed');
            set((state) => {
              state.isLoading = false;
              state.error = message;
            });
            return false;
          }
        },

        // Register new user
        register: async (data: RegisterData) => {
          set((state) => {
            state.isLoading = true;
            state.error = null;
          });

          try {
            await api.post('/auth/register', data);

            set((state) => {
              state.isLoading = false;
            });

            return true;
          } catch (error: unknown) {
            const message = getApiErrorMessage(error, 'Registration failed');
            set((state) => {
              state.isLoading = false;
              state.error = message;
            });
            return false;
          }
        },

        // Logout
        logout: async () => {
          if (isDemoMode) {
            if (typeof window !== 'undefined') {
              window.dispatchEvent(new CustomEvent('freesdn-demo-write-blocked'));
            }
            set((state) => {
              state.user = normalizeUser(demoUser);
              state.isAuthenticated = true;
              state.isLoading = false;
              state.mfaPending = false;
              state.mfaToken = null;
            });
            return;
          }

          try {
            // Call logout endpoint to invalidate session + clear cookies
            await api.post('/auth/logout');
          } catch {
            // Ignore errors during logout
          }

          // Clear local state
          set((state) => {
            state.user = null;
            state.isAuthenticated = false;
            state.mfaPending = false;
            state.mfaToken = null;
          });

          // Clear persisted state (removes the 'auth-store' entry in localStorage)
          try {
            useAuthStore.persist.clearStorage();
          } catch {
            // Ignore · persist middleware may not be ready
          }

          // Drop ALL cached query data so the next user on a shared browser can't
          // briefly see the previous user's Connections / device lists / run
          // payloads (query keys are not principal-scoped). Lazy import avoids a
          // circular dependency at module load.
          try {
            const { queryClient } = await import('@/lib/queryClient');
            queryClient.clear();
          } catch {
            // Ignore · cache clear is best-effort
          }

          // Clean up legacy localStorage tokens if they exist (migration)
          try {
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
          } catch {
            // Ignore · may not be available
          }
          sessionStorage.removeItem('sso_protocol');
          sessionStorage.removeItem('sso_state');
        },

        // Refresh session
        refreshSession: async () => {
          if (isDemoMode) {
            set((state) => {
              state.user = normalizeUser(demoUser);
              state.isAuthenticated = true;
            });
            return true;
          }

          // Check if we have a CSRF cookie · indicates an active session
          const hasCsrf = !!getCookie('freesdn_csrf');
          if (!hasCsrf) {
            return false;
          }

          try {
            // httpOnly refresh cookie is sent automatically
            await api.post('/auth/refresh', {});

            set((state) => {
              state.isAuthenticated = true;
            });

            return true;
          } catch {
            // Refresh failed, clear auth state
            await get().logout();
            return false;
          }
        },

        // Fetch current user
        fetchCurrentUser: async () => {
          try {
            const response = await api.get('/auth/me');

            set((state) => {
              state.user = normalizeUser(response.data);
            });
          } catch (error: unknown) {
            // If unauthorized, clear auth state
            const axiosErr = error as AxiosError;
            if (axiosErr.response?.status === 401) {
              await get().logout();
            }
          }
        },

        // Clear error
        clearError: () => {
          set((state) => {
            state.error = null;
          });
        },

        // Clear force password change flag (after successful password change)
        clearForcePasswordChange: () => {
          set((state) => {
            state.forcePasswordChange = false;
          });
        },

        // Permission helpers
        hasPermission: (permission: string) => {
          const user = get().user;
          if (!user) return false;
          if (user.is_superuser) return true;
          return permGranted(user.permissions ?? [], permission);
        },

        hasAnyPermission: (...permissions: string[]) => {
          const user = get().user;
          if (!user) return false;
          if (user.is_superuser) return true;
          const perms = user.permissions ?? [];
          return permissions.some((p) => permGranted(perms, p));
        },

        hasAllPermissions: (...permissions: string[]) => {
          const user = get().user;
          if (!user) return false;
          if (user.is_superuser) return true;
          const perms = user.permissions ?? [];
          return permissions.every((p) => permGranted(perms, p));
        },

        // Set MFA pending from SSO callback. The provider
        // returned require_mfa=true + mfa_token instead of access_token;
        // /login will pick this up via mfaPending and complete the
        // challenge via verifyMfa().
        setMfaPending: (mfaToken: string) => {
          set((state) => {
            state.isAuthenticated = false;
            state.isLoading = false;
            state.error = null;
            state.mfaPending = true;
            state.mfaToken = mfaToken;
          });
        },

        // SSO login · cookies already set by SSO callback response
        loginWithSSO: async (_accessToken?: string, _refreshToken?: string, user?: User | null) => {
          set((state) => {
            state.isAuthenticated = true;
            state.isLoading = false;
            state.error = null;
            state.mfaPending = false;
            state.mfaToken = null;
          });

          if (user) {
            set((state) => { state.user = normalizeUser(user); });
          } else {
            // Fetch user profile
            try {
              const meResponse = await api.get('/auth/me');
              set((state) => { state.user = normalizeUser(meResponse.data); });
            } catch {
              // User profile fetch failed but SSO login succeeded
            }
          }
        },
      })),
      {
        name: 'auth-store',
        // SECURITY: Do NOT persist the user object or any permissions/role
        // fields to localStorage. An XSS flaw would otherwise expose role,
        // is_superuser, and permissions to the attacker. The authoritative
        // user profile is re-fetched from /auth/me during useInitAuth(), so
        // only a minimal UX hint is persisted here.
        partialize: (state) => ({
          isAuthenticated: state.isAuthenticated,
        }),
        onRehydrateStorage: () => (state) => {
          if (state) {
            state._isHydrated = true;
          }
        },
      }
    ),
    { name: 'auth-store', enabled: import.meta.env.DEV }
  )
);

// Export a hook to initialize auth on app load.
// Validates persisted tokens against the backend and sets _isAuthInitialized
// so ProtectedRoute / LoginPage can wait before making routing decisions.
export const useInitAuth = () => {
  const initAuth = useCallback(async () => {
    // Guard: only run once
    if (useAuthStore.getState()._isAuthInitialized) return;

    if (isDemoMode) {
      useAuthStore.setState({
        user: normalizeUser(demoUser),
        isAuthenticated: true,
        _isAuthInitialized: true,
      });
      return;
    }

    // Check if we have a CSRF cookie · indicates an active cookie session
    const hasCsrf = !!getCookie('freesdn_csrf');

    if (!hasCsrf) {
      // No session cookies · definitely not authenticated
      useAuthStore.setState({
        isAuthenticated: false,
        _isAuthInitialized: true,
      });
      return;
    }

    // We have cookies. Verify them against the backend.
    try {
      const response = await api.get('/auth/me');
      // Token is valid
      useAuthStore.setState({
        user: normalizeUser(response.data),
        isAuthenticated: true,
        _isAuthInitialized: true,
      });
    } catch {
      // Token invalid · try refresh
      try {
        // httpOnly refresh cookie is sent automatically
        await api.post('/auth/refresh', {});
        // Refresh succeeded · new cookies are set. Fetch user.
        const meResponse = await api.get('/auth/me');
        useAuthStore.setState({
          user: normalizeUser(meResponse.data),
          isAuthenticated: true,
          _isAuthInitialized: true,
        });
        return;
      } catch {
        // Refresh also failed · fall through to clear
      }

      // All attempts failed · clear stale auth state
      useAuthStore.setState({
        user: null,
        isAuthenticated: false,
        _isAuthInitialized: true,
      });
    }
  }, []);

  return { initAuth };
};
