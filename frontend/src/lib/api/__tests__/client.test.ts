// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Tests for the axios client helpers in `lib/api/client.ts`.
 *
 * We focus on the pure helpers (`getApiErrorMessage`, `getCookie`) and
 * the websocket-url derivation. The interceptors are exercised indirectly
 * by the auth-store tests · stubbing the entire interceptor chain here
 * would just re-test axios.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { getApiErrorMessage, getCookie, getWebSocketUrl } from '@/lib/api/client';

describe('getApiErrorMessage', () => {
  it('returns the fallback when there is no error object', () => {
    expect(getApiErrorMessage(null)).toBe('An error occurred');
    expect(getApiErrorMessage(undefined, 'oops')).toBe('oops');
  });

  it('falls back to axios message when no response.data is present', () => {
    const err = { message: 'Network Error' };
    expect(getApiErrorMessage(err)).toBe('Network Error');
  });

  it('extracts message from the standard backend shape { error: { message } }', () => {
    const err = {
      response: { data: { error: { message: 'Site not found' } }, status: 404 },
    };
    expect(getApiErrorMessage(err)).toBe('Site not found');
  });

  it('expands 422 validation details into field-level messages', () => {
    const err = {
      response: {
        status: 422,
        data: {
          error: {
            message: 'Validation error',
            details: [
              { field: 'body.email', message: 'is required' },
              { field: 'body.password', message: 'too short' },
            ],
          },
        },
      },
    };
    // "Validation error" prefix is suppressed; field paths have `body.` stripped.
    expect(getApiErrorMessage(err)).toBe('email: is required; password: too short');
  });

  it('keeps a non-generic outer message as a prefix when details exist', () => {
    const err = {
      response: {
        status: 422,
        data: {
          error: {
            message: 'Could not create user',
            details: [{ field: 'body.email', message: 'already taken' }],
          },
        },
      },
    };
    expect(getApiErrorMessage(err)).toBe('Could not create user, email: already taken');
  });

  it('handles the legacy FastAPI { detail: string } shape', () => {
    const err = { response: { data: { detail: 'Forbidden' }, status: 403 } };
    expect(getApiErrorMessage(err)).toBe('Forbidden');
  });

  it('handles the legacy FastAPI { detail: [...] } shape', () => {
    const err = {
      response: {
        data: { detail: [{ msg: 'bad field' }, { message: 'other bad field' }] },
        status: 422,
      },
    };
    expect(getApiErrorMessage(err)).toBe('bad field, other bad field');
  });

  it('handles a top-level message field', () => {
    const err = { response: { data: { message: 'Something went wrong' }, status: 500 } };
    expect(getApiErrorMessage(err)).toBe('Something went wrong');
  });

  it('uses the caller-provided fallback when nothing else matches', () => {
    const err = { response: { data: {}, status: 500 } };
    expect(getApiErrorMessage(err, 'Unknown failure')).toBe('Unknown failure');
  });
});

describe('getCookie', () => {
  beforeEach(() => {
    // Wipe document.cookie between tests. Each `document.cookie = "..."`
    // assignment APPENDS, so we have to expire each cookie explicitly.
    // happy-dom's default `document.cookie` starts empty, so we just
    // overwrite any survivors.
    document.cookie.split(';').forEach((c) => {
      const name = c.split('=')[0]?.trim();
      if (name) {
        document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
      }
    });
  });

  it('returns null when the cookie is missing', () => {
    expect(getCookie('does_not_exist')).toBeNull();
  });

  it('returns the decoded value when present', () => {
    document.cookie = 'freesdn_csrf=abc%20def';
    expect(getCookie('freesdn_csrf')).toBe('abc def');
  });

  it('matches the right cookie when multiple are set', () => {
    document.cookie = 'foo=1';
    document.cookie = 'freesdn_csrf=token123';
    document.cookie = 'bar=2';
    expect(getCookie('freesdn_csrf')).toBe('token123');
    expect(getCookie('foo')).toBe('1');
    expect(getCookie('bar')).toBe('2');
  });
});

describe('getWebSocketUrl', () => {
  it('returns a ws:// or wss:// URL ending in /api/v1/ws', () => {
    const url = getWebSocketUrl();
    expect(url).toMatch(/^wss?:\/\//);
    expect(url.endsWith('/api/v1/ws')).toBe(true);
  });
});
