// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * `gatewaySwitchAdvancedApi` URLs, pinned to the generated OpenAPI paths.
 *
 * `scripts/check_api_contract.py` reports "every frontend api call
 * resolves", but its `_CALL` regex only matches calls whose path literal
 * begins with `/`. Every function in the twelve `gateway*.ts` modules opens
 * with a `${prefix(...)}` template hole, so roughly 120 calls, this whole
 * family included, are invisible to that gate. `getPerPortJumbo` built
 * `.../switches/{mac}/per-port-jumbo`, which the backend has never served
 * (the real route is `.../switches/{mac}/ports/{port_id}/jumbo-frame`), and
 * the gate stayed green.
 *
 * These tests close the hole for this module by running the client, then
 * folding the concrete ids back into `{placeholder}` form and asserting the
 * result against `keyof ApiPaths`, which is generated from the live backend
 * schema. A typo'd segment fails the runtime assertion; a route that no
 * longer exists fails `tsc` on the `keyof ApiPaths` annotation.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';

import { gatewaySwitchAdvancedApi } from '../gatewaySwitchAdvanced';
import type { ApiPaths } from '../generated';

vi.mock('../client', () => ({
  api: {
    get: vi.fn(() => Promise.resolve({ data: {} })),
    post: vi.fn(() => Promise.resolve({ data: {} })),
    put: vi.fn(() => Promise.resolve({ data: {} })),
    delete: vi.fn(() => Promise.resolve({ data: {} })),
  },
  API_URL: '',
}));

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const api = (await import('../client')).api as any;

const CID = '11111111-1111-1111-1111-111111111111';
const SID = '22222222-2222-2222-2222-222222222222';
const MAC = 'AA-BB-CC-DD-EE-FF';
const PORT = 7;

/** Fold the concrete ids back into the OpenAPI `{placeholder}` template. */
function toTemplate(url: string): string {
  return `/api/v1${url}`
    .replace(CID, '{controller_id}')
    .replace(SID, '{site_id}')
    .replace(MAC, '{mac}')
    .replace(`/${PORT}/`, '/{port_id}/');
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('gatewaySwitchAdvancedApi paths resolve against the generated schema', () => {
  it('getPerPortJumbo targets the ports/{port_id}/jumbo-frame route', () => {
    gatewaySwitchAdvancedApi.getPerPortJumbo(CID, SID, MAC, PORT);

    // Annotated `keyof ApiPaths`: tsc rejects the literal if the backend
    // ever drops or renames the route.
    const expected: keyof ApiPaths =
      '/api/v1/gateway-switch-advanced/{controller_id}/sites/{site_id}/switches/{mac}/ports/{port_id}/jumbo-frame';
    expect(toTemplate(api.get.mock.calls[0][0])).toBe(expected);
  });

  it('getSwitchConfig and listMirrorSessions resolve too', () => {
    gatewaySwitchAdvancedApi.getSwitchConfig(CID, SID, MAC, 'sflow');
    gatewaySwitchAdvancedApi.listMirrorSessions(CID, SID, MAC);

    const configPath: keyof ApiPaths =
      '/api/v1/gateway-switch-advanced/{controller_id}/sites/{site_id}/switches/{mac}/configs/{config_name}';
    const mirrorPath: keyof ApiPaths =
      '/api/v1/gateway-switch-advanced/{controller_id}/sites/{site_id}/switches/{mac}/mirror-sessions';

    expect(toTemplate(api.get.mock.calls[0][0]).replace('/sflow', '/{config_name}')).toBe(
      configPath,
    );
    expect(toTemplate(api.get.mock.calls[1][0])).toBe(mirrorPath);
  });
});
