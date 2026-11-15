// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Omada raw passthrough, escape hatch for any controller API we
 * haven't typed yet. Power-users / debugging only.
 *
 * Read-only: only GET is forwarded and secrets in the response are
 * masked. Writes are refused (use the staged Omada pages), and users
 * limited to some sites are refused.
 */

import { api } from './client';
import type { ApiSchemas } from './generated';

// Re-exported from the OpenAPI spec so backend signature changes
// fail tsc here. ``method`` is the inline enum on the request schema.
export type RawCallRequest = ApiSchemas['RawCallRequest'];
export type RawCallResponse = ApiSchemas['RawCallResponse'];
export type RawMethod = ApiSchemas['RawCallRequest']['method'];

export const gatewayRawApi = {
  call: (controllerId: string, body: RawCallRequest) =>
    api.post<RawCallResponse>(`/gateway-raw/${controllerId}/call`, body),
};
