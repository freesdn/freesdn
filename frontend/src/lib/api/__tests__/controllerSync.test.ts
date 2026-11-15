// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, expect, it } from 'vitest';
import { readControllerDelete } from '@/lib/api/controllerSync';

describe('readControllerDelete', () => {
  it('reads a confirmed delete, and an answer with no controller fields, as deleted', () => {
    expect(readControllerDelete({ success: true, controller_synced: true, controller_warning: null })).toEqual({ kind: 'deleted' });
    expect(readControllerDelete({ success: true })).toEqual({ kind: 'deleted' });
    expect(readControllerDelete(undefined)).toEqual({ kind: 'deleted' });
  });

  it("reads today's unconfirmed delete: the record went, the controller did not confirm", () => {
    const body = { success: true, controller_synced: false, controller_warning: 'Omada answered -1001 (VLAN in use)' };
    expect(readControllerDelete(body)).toEqual({ kind: 'removed-unconfirmed', warning: 'Omada answered -1001 (VLAN in use)' });
    expect(readControllerDelete({ data: body, status: 200 })).toEqual({ kind: 'removed-unconfirmed', warning: 'Omada answered -1001 (VLAN in use)' });
  });

  it('reads the documented refusal: the record is kept', () => {
    expect(readControllerDelete({ success: false, controller_synced: false, controller_warning: 'refused' })).toEqual({ kind: 'kept', warning: 'refused' });
    expect(readControllerDelete({ deleted: false, controller_synced: false, message: 'kept' })).toEqual({ kind: 'kept', warning: 'kept' });
    expect(readControllerDelete({ kept: true, controller_synced: false })).toEqual({ kind: 'kept', warning: null });
  });
});
