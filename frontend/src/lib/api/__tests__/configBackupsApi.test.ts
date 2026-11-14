// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { configBackupApi } from '../configBackups';
import { api } from '../client';

vi.mock('../client', () => ({ api: { patch: vi.fn() } }));

beforeEach(() => vi.clearAllMocks());

describe('configBackupApi.update', () => {
  it('patches the target (no trailing slash: the route is /config-backups/{id}) and returns the body', async () => {
    const updated = { id: 'target/1', enabled: false, interval_hours: 24 };
    vi.mocked(api.patch).mockResolvedValue({ data: updated });
    await expect(configBackupApi.update('target/1', { enabled: false })).resolves.toEqual(updated);
    expect(api.patch).toHaveBeenCalledWith('/config-backups/target%2F1', { enabled: false });
  });

  it('sends only the fields that changed', async () => {
    vi.mocked(api.patch).mockResolvedValue({ data: {} });
    await configBackupApi.update('t', { interval_hours: 6 });
    expect(vi.mocked(api.patch).mock.calls[0][1]).toEqual({ interval_hours: 6 });
  });
});
