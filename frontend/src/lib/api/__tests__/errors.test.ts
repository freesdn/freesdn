// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The error reader against the bodies the backend really sends.
 *
 * Every body below is copied from a handler in
 * backend/app/core/middleware.py (setup_exception_handlers, the CSRF and rate
 * limit middleware, the body-size cap) or from a route that builds its own
 * response (backend/app/api/v1/endpoints/vault_export.py, tasks.py). The
 * errors are produced by a real axios instance with a stub adapter, so the
 * AxiosError, AxiosHeaders and status wiring are axios's own, not a hand-made
 * object.
 */
import axios, { AxiosError, AxiosHeaders, type AxiosAdapter, type InternalAxiosRequestConfig } from 'axios';
import { describe, expect, it, afterEach, vi } from 'vitest';
import {
  getApiErrorMessage,
  getApiFieldErrors,
  isReadOnlyRefusal,
  parseApiError,
} from '@/lib/api/errors';

const REQUEST_ID = '6f1c2a9e-3b7d-4e55-9a10-2c8f4d1e7b33';

/** Run one request through axios and return what it rejected with. */
async function failWith(
  status: number,
  data: unknown,
  headers: Record<string, string> = { 'content-type': 'application/json' },
): Promise<unknown> {
  const adapter: AxiosAdapter = async (config: InternalAxiosRequestConfig) => {
    const response = {
      data,
      status,
      statusText: '',
      headers: new AxiosHeaders(headers),
      config,
      request: {},
    };
    throw new AxiosError(
      `Request failed with status code ${status}`,
      status >= 500 ? AxiosError.ERR_BAD_RESPONSE : AxiosError.ERR_BAD_REQUEST,
      config,
      {},
      response,
    );
  };
  return axios.create({ adapter }).get('/api/v1/anything').catch((err: unknown) => err);
}

async function failWithoutResponse(code: string, message: string): Promise<unknown> {
  const adapter: AxiosAdapter = async (config) => {
    throw new AxiosError(message, code, config, {});
  };
  return axios.create({ adapter }).get('/api/v1/anything').catch((err: unknown) => err);
}

describe('parseApiError: the backend envelope', () => {
  it('reads an HTTPException string detail (http_exception_handler)', async () => {
    const err = await failWith(404, {
      error: { code: 404, message: 'Site not found', request_id: REQUEST_ID },
    });
    const info = parseApiError(err, 'Could not load the site');
    expect(info.message).toBe('Site not found');
    expect(info.status).toBe(404);
    expect(info.kind).toBe('http');
    expect(info.requestId).toBe(REQUEST_ID);
    expect(info.type).toBeNull();
  });

  it('reads an HTTPException dict detail and keeps the extra fields (tasks.py)', async () => {
    const err = await failWith(503, {
      error: {
        code: 503,
        message: {
          message: 'Task submission outcome is unknown; inspect this task before retrying',
          task_id: 'task-42',
        },
        request_id: REQUEST_ID,
      },
    });
    const info = parseApiError(err);
    expect(info.message).toBe(
      'Task submission outcome is unknown; inspect this task before retrying',
    );
    expect(info.detail).toEqual(expect.objectContaining({ task_id: 'task-42' }));
  });

  it('reads the adapter read-only refusal with its type (adapter_read_only_handler)', async () => {
    const message =
      'ADAPTER_READ_ONLY is set, Hikvision reboot refused. Set ADAPTER_READ_ONLY=false in the environment AND pass force=true to override.';
    const err = await failWith(403, {
      error: { code: 403, type: 'adapter_read_only', message, request_id: REQUEST_ID },
    });
    const info = parseApiError(err);
    expect(info.message).toBe(message);
    expect(info.type).toBe('adapter_read_only');
    expect(isReadOnlyRefusal(err)).toBe(true);
  });

  it('reads the confirmation-required precondition (409)', async () => {
    const err = await failWith(409, {
      error: {
        code: 409,
        type: 'confirmation_required',
        message: 'Deleting VM 105 is irreversible; resubmit with confirmed=true',
        request_id: REQUEST_ID,
      },
    });
    expect(parseApiError(err).type).toBe('confirmation_required');
    expect(isReadOnlyRefusal(err)).toBe(false);
  });

  it('reads an adapter connection failure (502 from the backend, not the proxy)', async () => {
    const err = await failWith(502, {
      error: {
        code: 502,
        type: 'adapter_connection_error',
        message: 'Cannot connect to 10.0.0.1:443: connection refused',
        request_id: REQUEST_ID,
      },
    });
    expect(getApiErrorMessage(err, 'Sync failed')).toBe(
      'Cannot connect to 10.0.0.1:443: connection refused',
    );
  });

  it('reads CSRF refusals, which carry no request_id', async () => {
    const err = await failWith(403, { error: { code: 403, message: 'CSRF token missing' } });
    expect(getApiErrorMessage(err, 'Save failed')).toBe('CSRF token missing');
  });

  it('reads the out-of-range value guard (dbapi_error_handler)', async () => {
    const err = await failWith(400, {
      error: {
        code: 400,
        type: 'invalid_value',
        message: 'A supplied value is out of range or invalid for this request.',
        request_id: REQUEST_ID,
      },
    });
    const info = parseApiError(err);
    expect(info.type).toBe('invalid_value');
    expect(info.message).toBe('A supplied value is out of range or invalid for this request.');
  });

  it('adds the request ID to a bare internal server error so it can be found in the log', async () => {
    const err = await failWith(500, {
      error: { code: 500, message: 'Internal server error', request_id: REQUEST_ID },
    });
    expect(getApiErrorMessage(err, 'Save failed')).toBe(
      `Internal server error (request ID ${REQUEST_ID})`,
    );
  });
});

describe('parseApiError: validation errors (validation_exception_handler)', () => {
  const body = {
    error: {
      code: 422,
      message: 'Validation error',
      details: [
        { field: 'body.name', message: 'Field required', type: 'missing' },
        {
          field: 'body.vlan_id',
          message: 'Input should be less than or equal to 4094',
          type: 'less_than_equal',
        },
        { field: 'body.subnet', message: 'Value error, 10.0.0.0/33 is not a valid network', type: 'value_error' },
        { field: 'query.page', message: 'Input should be greater than 0', type: 'greater_than' },
      ],
      request_id: REQUEST_ID,
    },
  };

  it('lists every field, without the request location or the pydantic prefix', async () => {
    const err = await failWith(422, body);
    expect(getApiErrorMessage(err, 'Could not save the VLAN')).toBe(
      'name: Field required; vlan_id: Input should be less than or equal to 4094; ' +
        'subnet: 10.0.0.0/33 is not a valid network; page: Input should be greater than 0',
    );
  });

  it('exposes field errors for form wiring', async () => {
    const err = await failWith(422, body);
    expect(parseApiError(err).fieldErrors[0]).toEqual({
      field: 'name',
      message: 'Field required',
      type: 'missing',
    });
    expect(getApiFieldErrors(err)).toEqual({
      name: 'Field required',
      vlan_id: 'Input should be less than or equal to 4094',
      subnet: '10.0.0.0/33 is not a valid network',
      page: 'Input should be greater than 0',
    });
  });

  it("reads FastAPI's own 422 shape (loc/msg) from a route outside the handler", async () => {
    const err = await failWith(422, {
      detail: [
        { type: 'missing', loc: ['body', 'name'], msg: 'Field required', input: {} },
        { type: 'int_parsing', loc: ['path', 'vlan_id'], msg: 'Input should be a valid integer', input: 'x' },
      ],
    });
    expect(getApiErrorMessage(err)).toBe(
      'name: Field required, vlan_id: Input should be a valid integer',
    );
    expect(getApiFieldErrors(err)).toEqual({
      name: 'Field required',
      vlan_id: 'Input should be a valid integer',
    });
  });
});

describe('parseApiError: bare detail bodies', () => {
  it('reads the rate limiter, with its retry hint', async () => {
    const err = await failWith(
      429,
      { detail: 'Rate limit exceeded', retry_after: 60 },
      { 'content-type': 'application/json', 'retry-after': '60' },
    );
    const info = parseApiError(err);
    expect(info.message).toBe('Rate limit exceeded');
    expect(info.retryAfter).toBe(60);
  });

  it('reads the body-size cap', async () => {
    const err = await failWith(413, { detail: 'request body exceeds 1048576-byte limit' });
    expect(getApiErrorMessage(err, 'Upload failed')).toBe('request body exceeds 1048576-byte limit');
  });

  it('reads the vault confirmation routes', async () => {
    const err = await failWith(401, { detail: 'Fresh identity confirmation failed; start again' });
    expect(getApiErrorMessage(err)).toBe('Fresh identity confirmation failed; start again');
  });

  it("reads Starlette's own 404 for an unmatched route", async () => {
    const err = await failWith(404, { detail: 'Not Found' });
    expect(getApiErrorMessage(err, 'Could not load')).toBe('Not Found');
  });

  it('decodes a JSON body that arrived as text', async () => {
    const err = await failWith(
      404,
      JSON.stringify({ error: { code: 404, message: 'Camera not found', request_id: REQUEST_ID } }),
    );
    expect(getApiErrorMessage(err)).toBe('Camera not found');
  });
});

describe('parseApiError: no usable body', () => {
  it('ignores a proxy HTML page and uses the caller fallback', async () => {
    const err = await failWith(
      502,
      '<html><head><title>502 Bad Gateway</title></head><body>nginx</body></html>',
      { 'content-type': 'text/html' },
    );
    expect(getApiErrorMessage(err, 'Sync failed')).toBe('Sync failed');
  });

  it('explains a proxy 502 when the caller gave no fallback', async () => {
    const err = await failWith(502, '<html>502 Bad Gateway</html>', { 'content-type': 'text/html' });
    expect(getApiErrorMessage(err)).toBe(
      'The FreeSDN API is not answering (HTTP 502). It may be restarting; try again shortly.',
    );
  });

  it('keeps a short plain-text body (an ASGI server error page)', async () => {
    const err = await failWith(500, 'Internal Server Error', { 'content-type': 'text/plain' });
    expect(getApiErrorMessage(err, 'Save failed')).toBe('Internal Server Error');
  });

  it('names the status of an empty error response', async () => {
    const err = await failWith(418, '');
    expect(getApiErrorMessage(err)).toBe('The server returned an error (HTTP 418).');
  });
});

describe('parseApiError: requests that never got an answer', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('says the server could not be reached on a network error', async () => {
    const err = await failWithoutResponse(AxiosError.ERR_NETWORK, 'Network Error');
    const info = parseApiError(err, 'Sync failed');
    expect(info.kind).toBe('network');
    expect(info.status).toBeNull();
    expect(info.message).toBe(
      'Could not reach the FreeSDN server. Check your connection and try again.',
    );
  });

  it('says the browser is offline when it is', async () => {
    vi.spyOn(navigator, 'onLine', 'get').mockReturnValue(false);
    const err = await failWithoutResponse(AxiosError.ERR_NETWORK, 'Network Error');
    expect(getApiErrorMessage(err)).toBe(
      'You appear to be offline. Please check your connection.',
    );
  });

  it('says the request timed out', async () => {
    const err = await failWithoutResponse(AxiosError.ECONNABORTED, 'timeout of 30000ms exceeded');
    const info = parseApiError(err);
    expect(info.kind).toBe('timeout');
    expect(info.message).toBe('The server took too long to respond. Try again.');
  });

  it('recognises a cancelled request', async () => {
    const controller = new AbortController();
    controller.abort();
    const adapter: AxiosAdapter = async (config) => ({
      data: {},
      status: 200,
      statusText: 'OK',
      headers: new AxiosHeaders(),
      config,
    });
    const err = await axios
      .create({ adapter })
      .get('/api/v1/anything', { signal: controller.signal })
      .catch((caught: unknown) => caught);
    const info = parseApiError(err);
    expect(info.kind).toBe('cancelled');
    expect(info.message).toBe('The request was cancelled.');
  });
});

describe('parseApiError: hand-built errors', () => {
  it('treats a response without a status as an answer from the server', () => {
    // Older mocks and some wrappers drop the status; the body still counts.
    const err = { response: { data: { error: { message: 'Name already in use' } } } };
    const info = parseApiError(err, 'Save failed');
    expect(info.message).toBe('Name already in use');
    expect(info.kind).toBe('http');
    expect(info.status).toBeNull();
  });

  it('falls back when such a response has no usable body', () => {
    expect(getApiErrorMessage({ response: { data: {} } }, 'Save failed')).toBe('Save failed');
    expect(getApiErrorMessage({ response: {} })).toBe('An error occurred');
  });
});

describe('parseApiError: things that are not request failures', () => {
  it("uses a thrown Error's own message", () => {
    expect(getApiErrorMessage(new Error('No changes'), 'Save failed')).toBe('No changes');
  });

  it('uses a thrown string', () => {
    expect(getApiErrorMessage('Pick a site first')).toBe('Pick a site first');
  });

  it('uses the fallback for anything else', () => {
    expect(getApiErrorMessage(undefined, 'Save failed')).toBe('Save failed');
    expect(getApiErrorMessage(42)).toBe('An error occurred');
    expect(getApiErrorMessage({}, 'Save failed')).toBe('Save failed');
  });
});
