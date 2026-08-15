// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Shared types for the gateway-* feature clients.
 *
 * As of 2026-05 these are sourced from the generated OpenAPI types
 * (see ``frontend/src/lib/api/generated/index.ts``). Hand-typed
 * shapes drift; generated types fail tsc when the backend changes
 * its contract. Rerun ``npm run gen:api`` after a backend signature
 * change.
 */

import type { ApiSchemas } from './generated';

// ``ChangeOperation`` / ``ChangeStatus`` are inlined on the response
// schema by Pydantic (Literal types don't get their own schema
// entry), so we project them out via indexed access. The result is
// the same string-union as the manual literal we used to maintain,
// but tsc fails if the backend ever drops or renames a value.
export type ChangeOperation =
  ApiSchemas['PendingChangeResponse']['operation'];
export type ChangeStatus = ApiSchemas['PendingChangeResponse']['status'];
export type PendingChangeRequest = ApiSchemas['PendingChangeRequest'];
export type PendingChangeResponse = ApiSchemas['PendingChangeResponse'];

export interface GatewayCollectionResponse<T = Record<string, unknown>> {
  controller_id: string;
  site_id: string;
  items: T[];
  fetched_at: string;
  [k: string]: unknown;
}

export interface GatewayDetailResponse<T = Record<string, unknown>> {
  controller_id: string;
  site_id: string;
  item: T;
  fetched_at: string;
  [k: string]: unknown;
}
