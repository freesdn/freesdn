// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * describeApplyError drives the pending-changes drawer's read-only banner and
 * per-row failure text. The backend's read-only refusal arrives in the
 * { error: { type: 'adapter_read_only', message } } envelope
 * (backend/app/core/middleware.py, adapter_read_only_handler), which the old
 * detail-only reader could not see: the banner stayed dark and the row said
 * "Apply failed".
 */
import { AxiosError, AxiosHeaders } from 'axios';
import { describe, expect, it } from 'vitest';
import { describeApplyError } from '@/lib/api/pendingChanges';

function httpError(status: number, data: unknown): AxiosError {
  const headers = new AxiosHeaders();
  return new AxiosError('Request failed', 'ERR_BAD_REQUEST', { headers }, undefined, {
    status,
    statusText: '',
    headers: {},
    config: { headers },
    data,
  });
}

describe('describeApplyError', () => {
  it('lights the read-only banner from the typed envelope refusal', () => {
    const message =
      'ADAPTER_READ_ONLY is set, OPNsense alias update refused. Set ADAPTER_READ_ONLY=false in the environment AND pass force=true to override.';
    const info = describeApplyError(
      httpError(403, {
        error: { code: 403, type: 'adapter_read_only', message, request_id: 'r-1' },
      }),
    );
    expect(info.isForbidden).toBe(true);
    expect(info.isReadOnly).toBe(true);
    expect(info.message).toBe(message);
  });

  it('shows a permission refusal without calling it read-only', () => {
    const info = describeApplyError(
      httpError(403, {
        error: { code: 403, message: 'Missing permission: gateway.apply', request_id: 'r-2' },
      }),
    );
    expect(info.isForbidden).toBe(true);
    expect(info.isReadOnly).toBe(false);
    expect(info.message).toBe('Missing permission: gateway.apply');
  });

  it('still reads the legacy bare detail', () => {
    const info = describeApplyError(
      httpError(403, { detail: 'OMADA_READ_ONLY=true; refusing to push staged change.' }),
    );
    expect(info.isReadOnly).toBe(true);
    expect(info.message).toBe('OMADA_READ_ONLY=true; refusing to push staged change.');
  });

  it('keeps the vendor rejection on a 502', () => {
    const info = describeApplyError(
      httpError(502, {
        error: { code: 502, type: 'adapter_error', message: 'RouterOS rejected the change' },
        applied_response: { error: 'failure: already have such address' },
      }),
    );
    expect(info.message).toBe('RouterOS rejected the change');
    expect(info.vendorError).toBe('failure: already have such address');
  });

  it('reads a 422 field list instead of "Apply failed"', () => {
    const info = describeApplyError(
      httpError(422, {
        error: {
          code: 422,
          message: 'Validation error',
          details: [{ field: 'body.payload.vlan_id', message: 'Input should be less than or equal to 4094', type: 'less_than_equal' }],
        },
      }),
    );
    expect(info.message).toBe('payload.vlan_id: Input should be less than or equal to 4094');
  });
});
