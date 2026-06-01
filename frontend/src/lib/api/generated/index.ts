// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, Generated OpenAPI types
 * ===================================
 *
 * Re-exports the schemas + paths that ``openapi-typescript`` emits
 * from the backend's ``/api/v1/openapi.json``. Hand-written API
 * clients should ``import type`` from THIS module rather than
 * redeclaring shapes that drift away from the backend.
 *
 * Regeneration::
 *
 *     cd frontend && npm run gen:api
 *
 * That runs ``backend/scripts/export_openapi.py`` to refresh
 * ``openapi.json`` and then ``openapi-typescript`` to refresh
 * ``openapi.d.ts``. Both files are checked in so CI doesn't need
 * a running backend.
 *
 * Usage example::
 *
 *     import type { ApiSchemas } from '@/lib/api/generated';
 *
 *     type PendingChangeResponse = ApiSchemas['PendingChangeResponse'];
 *     type ChangeOperation = ApiSchemas['ChangeOperation'];
 *
 *     const stage = (body: ApiSchemas['PendingChangeRequest']) => ...;
 *
 * Migration plan: each gateway-* API client (gatewayBulk.ts,
 * gatewaySystem.ts, etc.) can be incrementally re-typed against
 * ``ApiSchemas`` to surface drift as a tsc error rather than a
 * runtime surprise.
 */

import type { components, paths } from './openapi';

/** Strongly-typed map of all OpenAPI ``components.schemas``. */
export type ApiSchemas = components['schemas'];

/** Strongly-typed map of every API path → operation. */
export type ApiPaths = paths;

/** Convenience: pull the response body type for a given GET path. */
export type GetResponse<P extends keyof ApiPaths> =
  ApiPaths[P] extends { get: { responses: { 200: { content: { 'application/json': infer R } } } } }
    ? R
    : never;

/** Convenience: pull the request body type for a given POST path. */
export type PostBody<P extends keyof ApiPaths> =
  ApiPaths[P] extends { post: { requestBody: { content: { 'application/json': infer B } } } }
    ? B
    : never;
