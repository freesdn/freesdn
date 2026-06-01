// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTik tab shared type-narrowing helpers.
 *
 * RouterOS rows arrive as `Record<string, unknown>` (or interfaces with
 * `[key: string]: unknown`). Reading those rows safely across all 9
 * tabs led to ~30 repetitions of `(row['.id'] as string | undefined) ?? ''`
 * patterns. These helpers centralise the narrow so a future shape change
 * (or a stricter API contract) only needs to touch one file.
 */

/**
 * RouterOS rows ship a `.id` field. We narrow it to `string`; if it's
 * missing or has the wrong shape, we return the empty string so call
 * sites can branch on truthiness rather than UB.
 */
export function getRouterId(row: { '.id'?: unknown }): string {
  const v = row['.id'];
  return typeof v === 'string' ? v : '';
}

/**
 * Narrow an arbitrary key on a RouterOS row to a string. Returns
 * `defaultValue` (default empty string) if the value is missing or
 * not a string.
 */
export function getRouterStr(
  row: Record<string, unknown>,
  key: string,
  defaultValue = '',
): string {
  const v = row[key];
  return typeof v === 'string' ? v : defaultValue;
}

/**
 * RouterOS booleans are usually serialised as `"true"` / `"false"` or
 * `"yes"` / `"no"` strings, but the JS side already sees `boolean` for
 * some payload shapes. Accept either.
 */
export function getRouterBool(row: Record<string, unknown>, key: string): boolean {
  const v = row[key];
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string') return v === 'true' || v === 'yes';
  return false;
}
