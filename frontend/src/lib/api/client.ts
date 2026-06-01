// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * API Client for FreeSDN Backend
 * Core axios setup, interceptors, and utility functions.
 *
 * Authentication uses httpOnly cookies (set by backend on login/refresh).
 * CSRF protection uses double-submit cookie pattern:
 *   - Backend sets `freesdn_csrf` cookie (JS-readable)
 *   - Frontend sends it back as `X-CSRF-Token` header on mutations
 */
import axios from 'axios';
import { useAuthStore } from '../../stores/authStore';
import { installDemoApi } from '@/demo/mockApi';
import { isDemoMode } from '@/demo/mode';

// Default to the current origin so the SPA uses the same-origin /api
// proxy (Vite's dev proxy in dev, nginx in prod). The previous dev
// fallback ('http://localhost:8000') forced cross-origin requests
// which broke CSRF, the freesdn_csrf cookie is set on :8000 but the
// SPA runs on :5173, so document.cookie couldn't see it and every
// mutation returned 403.
const rawApiUrl = import.meta.env.VITE_API_URL
  || (typeof window !== 'undefined' ? window.location.origin : '');
export const API_URL = rawApiUrl.replace(/\/api\/v1\/?$/, '');

/**
 * Get the WebSocket URL dynamically based on the API configuration.
 * This ensures WebSocket connects to the same backend as the REST API.
 */
export function getWebSocketUrl(): string {
  // First check for explicit WebSocket URL
  const wsUrl = import.meta.env.VITE_WS_URL;
  if (wsUrl) {
    return wsUrl;
  }

  // If API_URL is explicitly set, derive WebSocket URL from it
  const apiUrl = import.meta.env.VITE_API_URL;
  if (apiUrl) {
    // Normalize - strip any existing /api/v1 suffix
    const baseUrl = apiUrl.replace(/\/api\/v1\/?$/, '');
    return baseUrl.replace(/^http/, 'ws') + '/api/v1/ws';
  }

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';

  // Production: same-origin, nginx proxies /api/v1/ws to the backend.
  if (import.meta.env.PROD) {
    return `${protocol}//${window.location.host}/api/v1/ws`;
  }

  // Dev fallback: the backend listens on :8000, separate from Vite's :5173,
  // and Vite's ws-proxy does not reliably forward the upgrade, so we connect
  // to the backend directly. Reuse the PAGE's hostname (not a hardcoded
  // "localhost") so the WS host matches the host the auth cookie was scoped
  // to. Hardcoding "localhost" silently broke realtime whenever the SPA was
  // opened via 127.0.0.1 / a LAN IP / a hostname: the auth cookie (set on
  // that host) was never sent to "localhost", the handshake dropped right
  // after the upgrade, and the UI sat on a permanent "Disconnected" badge.
  return `${protocol}//${window.location.hostname}:8000/api/v1/ws`;
}

/**
 * Read a cookie value by name. Used to read the CSRF token cookie.
 */
export function getCookie(name: string): string | null {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

export const api = axios.create({
  baseURL: `${API_URL}/api/v1`,
  headers: {
    'Content-Type': 'application/json',
  },
  // SECURITY: send httpOnly cookies on every request
  withCredentials: true,
});

// Alias for backwards compatibility
export const apiClient = api;

if (isDemoMode) {
  installDemoApi(api);
}

// Request interceptor: attach CSRF token on state-changing requests
api.interceptors.request.use(
  (config) => {
    const method = (config.method || 'get').toUpperCase();
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      const csrfToken = getCookie('freesdn_csrf');
      if (csrfToken) {
        config.headers['X-CSRF-Token'] = csrfToken;
      }
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor: auto-refresh token on 401
let isRefreshing = false;
let failedQueue: Array<{ resolve: (value?: unknown) => void; reject: (err: unknown) => void }> = [];

const processQueue = (error: unknown, success = false) => {
  failedQueue.forEach((prom) => {
    if (success) prom.resolve();
    else prom.reject(error);
  });
  failedQueue = [];
};

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // Only attempt refresh on 401 and not already retried
    if (error.response?.status !== 401 || originalRequest._retry) {
      return Promise.reject(error);
    }

    // Don't try to refresh auth endpoints themselves (infinite loop)
    const url = originalRequest.url || '';
    if (url.includes('/auth/login') || url.includes('/auth/refresh') || url.includes('/auth/register')) {
      return Promise.reject(error);
    }

    // If already refreshing, queue this request.
    // NOTE: mark this request as already-retried
    // BEFORE we enqueue it. Otherwise a second 401 on the same retried
    // request would re-enter this interceptor with _retry still falsy,
    // trigger another refresh, and potentially loop. With _retry=true
    // set up front, the second 401 short-circuits to Promise.reject at
    // the top of the interceptor (which logs the user out cleanly).
    if (isRefreshing) {
      originalRequest._retry = true;
      return new Promise((resolve, reject) => {
        failedQueue.push({
          resolve: () => resolve(api(originalRequest)),
          reject,
        });
      });
    }

    originalRequest._retry = true;
    isRefreshing = true;

    try {
      const csrfToken = getCookie('freesdn_csrf');
      // Call refresh · the httpOnly refresh cookie is sent automatically
      await axios.post(`${API_URL}/api/v1/auth/refresh`, {}, {
        withCredentials: true,
        headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : undefined,
      });

      processQueue(null, true);

      // Retry original request (new cookies are already set by refresh response)
      return api(originalRequest);
    } catch (refreshError) {
      processQueue(refreshError, false);

      // Refresh failed · clear auth state and redirect to login
      useAuthStore.setState({
        user: null,
        isAuthenticated: false,
      });

      return Promise.reject(refreshError);
    } finally {
      isRefreshing = false;
    }
  }
);

/**
 * Extract a human-readable error message from an API error response.
 * Handles both the standard backend format { error: { message } }
 * and the legacy FastAPI format { detail }.
 */
export function getApiErrorMessage(error: unknown, fallback = 'An error occurred'): string {
  const err = error as { response?: { data?: Record<string, unknown>; status?: number }; message?: string } | null;
  const data = err?.response?.data;
  if (!data) return err?.message || fallback;

  // Standard backend format: { error: { message: "...", details: [...] } }
  //
  // For 422 validation errors the ``details`` array carries the
  // load-bearing information ({ field, message, type } per field).
  // The legacy code returned just ``error.message`` (always
  // "Validation error" for 422s) and threw the field info away,
  // operators saw a useless "Request failed with status code 422"
  // toast even when the backend told them exactly which field was
  // missing.
  const errorObj = data.error as {
    message?: string;
    details?: Array<{ field?: string; message?: string; type?: string }> | unknown;
  } | undefined;
  if (errorObj) {
    if (Array.isArray(errorObj.details) && errorObj.details.length > 0) {
      const fieldMsgs = errorObj.details
        .map((d) => {
          const field = d.field ? d.field.replace(/^body\./, '') : '';
          const msg = d.message || d.type || 'invalid';
          return field ? `${field}: ${msg}` : msg;
        })
        .filter(Boolean);
      if (fieldMsgs.length > 0) {
        const prefix = errorObj.message && errorObj.message !== 'Validation error'
          ? `${errorObj.message}, `
          : '';
        return `${prefix}${fieldMsgs.join('; ')}`;
      }
    }
    if (errorObj.message) return errorObj.message;
  }

  // Legacy/FastAPI format: { detail: "..." } or { detail: [...] }
  if (typeof data.detail === 'string') return data.detail;
  if (Array.isArray(data.detail)) {
    return data.detail.map((e: { msg?: string; message?: string }) => e.msg || e.message || String(e)).join(', ');
  }
  if (data.detail && typeof data.detail === 'object') {
    const detail = data.detail as { msg?: string; message?: string };
    return detail.msg || detail.message || JSON.stringify(data.detail);
  }

  // Direct message field
  if (typeof data.message === 'string') return data.message;

  return err?.message || fallback;
}

/**
 * True when an API error means the upstream controller / device could not be
 * reached, as opposed to a FreeSDN-side fault. The backend's central adapter
 * handlers map an unreachable / auth-rejected controller to 502 Bad Gateway and
 * a controller timeout to 504 Gateway Timeout (see
 * app/core/middleware.setup_exception_handlers). Live-read screens (the gateway
 * config pages) use this to show actionable "controller unreachable" guidance
 * instead of a generic "could not load" error.
 */
export function isControllerUnreachable(error: unknown): boolean {
  const status = (error as { response?: { status?: number } } | null)?.response
    ?.status;
  return status === 502 || status === 504;
}
