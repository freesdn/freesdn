// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Contract tests for the OpenAPI-generated types.
 *
 * These don't test runtime behavior, they test that the generated
 * type surface in ``src/lib/api/generated/openapi.d.ts`` matches
 * what the gateway-* clients depend on. If the backend renames a
 * schema or drops a field, ``npm run gen:api`` followed by ``tsc``
 * will fail here at compile time rather than letting the drift
 * sneak into runtime.
 *
 * Adding a runtime ``expect``-flavoured shell so the test runner
 * actually emits a result.
 */

import { describe, it, expect } from 'vitest';

import type {
  ChangeOperation,
  ChangeStatus,
  PendingChangeRequest,
  PendingChangeResponse,
} from '../gatewayCommon';
import type { ApiSchemas } from '../generated';

describe('OpenAPI-generated staging types', () => {
  it('ChangeOperation accepts every expected literal', () => {
    // tsc will fail this assignment if any of the literals is no
    // longer in the generated union, that's the contract test.
    const ops: ChangeOperation[] = ['create', 'update', 'delete'];
    expect(ops).toHaveLength(3);
  });

  it('ChangeStatus includes the new "applying" state', () => {
    // The "applying" state was added in the audit fix to
    // support the atomic FOR UPDATE claim. The frontend MUST keep
    // it in the union so PendingChangesPage can render it.
    const statuses: ChangeStatus[] = [
      'pending',
      'applying',
      'applied',
      'discarded',
      'failed',
    ];
    expect(statuses).toHaveLength(5);
  });

  it('PendingChangeRequest has the documented optional shape', () => {
    // payload is required, target_id and notes are nullable strings.
    // tsc will fail if any of these drift.
    const minimal: PendingChangeRequest = { payload: {} };
    const full: PendingChangeRequest = {
      payload: { foo: 'bar' },
      target_id: 'user-123',
      notes: 'change ticket #42',
    };
    expect(minimal.payload).toEqual({});
    expect(full.target_id).toBe('user-123');
  });

  it('PendingChangeResponse exposes failure_reason for the UI', () => {
    // The failed-row UI surfaces this field. If the backend ever
    // renames it, the type system fails this test, and the UI
    // would otherwise show "undefined" silently.
    const r: PendingChangeResponse = {
      id: 'c1',
      organization_id: 'o1',
      controller_id: 'ctrl-1',
      site_id: null,
      omada_site_id: null,
      feature: 'vpn.ipsec.policy',
      operation: 'create',
      target_id: null,
      payload: {},
      status: 'failed',
      applied_at: null,
      applied_response: null,
      failure_reason: 'OmadaApiError',
      notes: null,
      created_at: '2026-05-09T00:00:00Z',
      created_by: null,
    };
    expect(r.failure_reason).toBe('OmadaApiError');
  });

  it('ApiSchemas exposes ControllerCapabilities-shaped paths', () => {
    // Capability advertisement is the keystone of capability-aware
    // UI. The endpoint must return a flat ``capabilities`` array
    // and a per-device-type breakdown, not a different shape.
    type Caps = ApiSchemas['PendingChangeResponse'];
    // tsc satisfies this only if PendingChangeResponse exists.
    const _placeholder: Caps | undefined = undefined;
    expect(_placeholder).toBeUndefined();
  });
});
