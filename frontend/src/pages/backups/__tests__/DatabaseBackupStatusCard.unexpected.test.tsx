// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The database-backup card printed raw keys ("DatabaseBackupStatus.title.
 * undefined") when the status body had no state it knew: the demo served its
 * generic empty list for /backups/database-status, and an older backend or a
 * proxy error page parsed as JSON would do the same. Such a body is an unknown
 * status and is now shown as one; the demo serves a real status body.
 */
import type { ReactNode } from 'react';
import type { AxiosResponse } from 'axios';
import { cleanup, render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { api } from '@/lib/api/client';
import { demoAxiosAdapter } from '@/demo/mockApi';
import { useAuthStore, type User } from '@/stores/authStore';
import { DatabaseBackupStatusCard } from '../DatabaseBackupStatusCard';

const oldAdapter = api.defaults.adapter;

function renderWithClient(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

function serve(body: unknown) {
  api.defaults.adapter = async (config) =>
    ({ config, data: body, status: 200, statusText: '200', headers: {} }) as AxiosResponse;
}

beforeEach(() => {
  useAuthStore.setState({
    user: { id: 'u', is_active: true, is_superuser: true, is_org_admin: true, permissions: [] } as unknown as User,
    isAuthenticated: true,
  });
});

afterEach(() => {
  cleanup();
  api.defaults.adapter = oldAdapter;
});

describe('DatabaseBackupStatusCard with an unexpected body', () => {
  it.each([
    ['a list envelope', { items: [], total: 0 }],
    ['an unknown state', { state: 'rebuilding', severity: 'critical', setup_command: { cmd: 'x' } }],
  ])('shows %s as an unknown status, not raw keys', async (_label, body) => {
    serve(body);
    renderWithClient(<DatabaseBackupStatusCard />);
    const card = await screen.findByTestId('database-backup-status');
    expect(card.dataset.state).toBe('unknown');
    expect(screen.getByText('Database backups: status unknown')).toBeTruthy();
    expect(card.textContent).not.toMatch(/undefined|DatabaseBackupStatus\./);
    expect(card.textContent).not.toContain('[object Object]');
  });

  it('gets a real status from the demo API', async () => {
    api.defaults.adapter = demoAxiosAdapter;
    renderWithClient(<DatabaseBackupStatusCard />);
    const card = await screen.findByTestId('database-backup-status');
    expect(card.dataset.state).toBe('healthy');
    expect(screen.getByText('Database backups: working')).toBeTruthy();
  });
});
