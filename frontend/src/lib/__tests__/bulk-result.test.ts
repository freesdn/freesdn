// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import i18n from 'i18next';
import { describe, expect, it } from 'vitest';
import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios';
import { summariseBulkDelete } from '@/lib/bulk-result';

const t = i18n.t.bind(i18n);

function refused(message: string): AxiosError {
  const response = {
    status: 409, statusText: '', headers: {}, config: { headers: new AxiosHeaders() },
    data: { error: { code: 409, message, request_id: 'r' } },
  } as AxiosResponse;
  return new AxiosError('Request failed with status code 409', 'ERR_BAD_REQUEST', response.config, null, response);
}

const ok = (): PromiseSettledResult<unknown> => ({ status: 'fulfilled', value: {} });
const no = (message: string): PromiseSettledResult<unknown> => ({ status: 'rejected', reason: refused(message) });

describe('summariseBulkDelete', () => {
  it('says how many were deleted', () => {
    expect(summariseBulkDelete([ok(), ok()], t)).toEqual({ description: '2 deleted.', deleted: 2, failed: 0 });
  });

  it("names the first failure's reason when some were not deleted", () => {
    const summary = summariseBulkDelete([ok(), no('Phone is provisioned'), no('Other')], t);
    expect(summary.description).toBe('1 deleted, 2 not deleted: Phone is provisioned');
    expect(summary.failed).toBe(2);
  });

  it('says nothing was deleted when every row failed', () => {
    expect(summariseBulkDelete([no('Read-only mode is on')], t).description).toBe('Nothing was deleted: Read-only mode is on');
  });

  it('never reads like the bulk-connect summary', () => {
    expect(summariseBulkDelete([ok(), no('x')], t).description).not.toMatch(/connected|skipped/);
  });
});
