// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The SNMP trap-target wire contract, which the UI had wrong in both
 * directions.
 *
 * READ: `GET /gateway-mikrotik-security/{cid}/snmp/trap-targets` declares
 * `response_model=list[MikroTikSnmpTrapTarget]` and that model is
 * `extra="forbid"` with a single required `host`. The client typed it as
 * `MikroTikListResponse<T>` and the tab read `.data.items`, which on an
 * Array is `undefined`, so `?? []` rendered an empty table on a router
 * that really had trap targets configured.
 *
 * WRITE: RouterOS has no per-target row. `trap-target` is a comma-list on
 * the `/snmp` singleton, so there is no `.id` to address and no per-target
 * community / version / port. The applier
 * (`adapter_mikrotik_security.py`, the `_SNMP_TRAP_TARGET_FEATURE` branch)
 * reads `payload.host` (or the legacy `payload.address`) and raises 400
 * without it, for delete as much as for create. The old `removeSnmpTrapTarget`
 * sent `target_id` and no payload at all, so every staged delete was
 * guaranteed to 400 at apply time.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';

import { mikrotikApi } from '../mikrotik';

vi.mock('../client', () => ({
  api: {
    get: vi.fn(() => Promise.resolve({ data: [] })),
    post: vi.fn(() => Promise.resolve({ data: {} })),
    put: vi.fn(() => Promise.resolve({ data: {} })),
    delete: vi.fn(() => Promise.resolve({ data: {} })),
  },
  API_URL: '',
}));

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const api = (await import('../client')).api as any;

const CID = '11111111-1111-1111-1111-111111111111';

beforeEach(() => {
  vi.clearAllMocks();
});

describe('SNMP trap-target staged writes carry the host in the payload', () => {
  it('stages a create with payload.host', () => {
    mikrotikApi.addSnmpTrapTarget(CID, '10.0.0.100');

    const [url, body, config] = api.post.mock.calls[0];
    expect(url).toBe(
      `/gateway-mikrotik-security/${CID}/changes/mikrotik.security.snmp.trap_target`,
    );
    expect(config.params.operation).toBe('create');
    // MUTATION GUARD: the applier reads payload.host. Moving the host to
    // target_id, or nesting it under address/port/version as the old form
    // did, makes this fail.
    expect(body.payload).toEqual({ host: '10.0.0.100' });
  });

  it('stages a delete with payload.host, not a bare target_id', () => {
    mikrotikApi.removeSnmpTrapTarget(CID, '10.0.0.100');

    const [url, body, config] = api.post.mock.calls[0];
    expect(url).toBe(
      `/gateway-mikrotik-security/${CID}/changes/mikrotik.security.snmp.trap_target`,
    );
    expect(config.params.operation).toBe('delete');
    // MUTATION GUARD: reverting to `{ target_id: host }` leaves payload
    // empty and the applier 400s with
    // "requires payload {host: str} or {address: str}".
    expect(body.payload).toEqual({ host: '10.0.0.100' });
  });

  it('exposes no update verb for trap targets', () => {
    // The backend maps ("...trap_target", "update") onto the SAME
    // idempotent append as "create", and there is no row id to address, so
    // an "edit" would add the new host and silently leave the old one
    // forwarding traps. Add + delete is the whole surface.
    expect('updateSnmpTrapTarget' in mikrotikApi).toBe(false);
  });
});

describe('list reads that the backend answers with a bare array', () => {
  it('asks for the trap-target and LLDP collections at the documented paths', () => {
    mikrotikApi.getSnmpTrapTargets(CID);
    mikrotikApi.getLldpInterfaces(CID);

    expect(api.get.mock.calls[0][0]).toBe(
      `/gateway-mikrotik-security/${CID}/snmp/trap-targets`,
    );
    expect(api.get.mock.calls[1][0]).toBe(
      `/gateway-mikrotik-system/${CID}/lldp`,
    );
  });
});
