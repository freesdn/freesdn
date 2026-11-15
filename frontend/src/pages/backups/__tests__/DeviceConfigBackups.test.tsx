// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Database-backup status and device config history, over the real Axios client. */
import type { ReactNode } from 'react';
import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ToastProvider } from '@/components/ui/toast';
import { api } from '@/lib/api/client';
import { useAuthStore, type User } from '@/stores/authStore';
import { DatabaseBackupStatusCard } from '../DatabaseBackupStatusCard';
import { DeviceConfigBackupsSection } from '../DeviceConfigBackupsSection';

const target = {
  id: '55555555-5555-4555-8555-555555555555',
  source_kind: 'gateway',
  source_id: '66666666-6666-4666-8666-666666666666',
  vendor: 'opnsense',
  display_name: 'fw-office',
  site_id: null,
  enabled: true,
  interval_hours: 24,
  retention_versions: 30,
  next_due_at: '2026-11-14T03:00:00Z',
  last_attempt_at: '2026-11-13T03:00:00Z',
  last_success_at: '2026-11-13T03:00:00Z',
  last_changed_at: '2026-11-13T03:00:00Z',
  last_status: 'changed',
  last_error_code: null,
  consecutive_failures: 0,
  capture_running: false,
  latest_version: 2,
  latest_captured_at: '2026-11-13T03:00:00Z',
};

function user(role: string): User {
  return {
    id: '11111111-1111-4111-8111-111111111111',
    username: 'u',
    email: 'u@example.invalid',
    first_name: 'U',
    last_name: 'U',
    full_name: 'U U',
    organization_id: '22222222-2222-4222-8222-222222222222',
    role,
    is_active: true,
    is_superuser: role === 'super_admin',
    is_org_admin: ['org_admin', 'super_admin'].includes(role),
    mfa_enabled: false,
    permissions: [],
    roles: [role],
  } as User;
}

type Handler = (config: InternalAxiosRequestConfig) => [number, unknown];
let routes: Record<string, Handler> = {};
const requests: string[] = [];
const oldAdapter = api.defaults.adapter;

function renderWithClient(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>{node}</ToastProvider>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  requests.length = 0;
  routes = {};
  useAuthStore.setState({ user: user('super_admin'), isAuthenticated: true });
  document.cookie = 'freesdn_csrf=synthetic-csrf; path=/';
  api.defaults.adapter = async (config) => {
    const key = `${config.method?.toUpperCase()} ${config.url}`;
    requests.push(key);
    const handler = routes[key];
    const [status, data] = handler ? handler(config) : [404, { detail: 'not found' }];
    const response = { config, data, status, statusText: String(status), headers: {} } as AxiosResponse;
    if (status >= 400) {
      throw Object.assign(new Error('Request failed'), { isAxiosError: true, response, config });
    }
    return response;
  };
});

afterEach(() => {
  cleanup();
  api.defaults.adapter = oldAdapter;
});

describe('DatabaseBackupStatusCard', () => {
  it('says plainly that a fresh install has no database backups, with the setup command', async () => {
    routes['GET /backups/database-status'] = () => [
      200,
      {
        state: 'disabled',
        severity: 'critical',
        enabled: false,
        encrypted: false,
        reason: 'no_key',
        last_success_at: null,
        max_age_seconds: 93600,
        checked_at: '2026-11-13T00:00:00Z',
        setup_command: './scripts/backup-keygen.sh > /path/off/this/host/freesdn-backup-private.asc',
      },
    ];
    renderWithClient(<DatabaseBackupStatusCard />);
    const card = await screen.findByTestId('database-backup-status');
    expect(card.dataset.state).toBe('disabled');
    expect(screen.getByText('Database backups: OFF')).toBeTruthy();
    expect(screen.getByText(/NO database backups/)).toBeTruthy();
    expect(screen.getByText(/No public key is installed yet/)).toBeTruthy();
    expect(screen.getByText(/backup-keygen\.sh/)).toBeTruthy();
    expect(screen.getByText(/never stored by FreeSDN/)).toBeTruthy();
  });

  it('is not even requested for a non-admin', async () => {
    useAuthStore.setState({ user: user('viewer') });
    renderWithClient(<DatabaseBackupStatusCard />);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(requests).toEqual([]);
    expect(screen.queryByTestId('database-backup-status')).toBeNull();
  });
});

describe('DeviceConfigBackupsSection', () => {
  it('lists devices and shows the REDACTED diff of the newest version', async () => {
    routes['GET /config-backups/'] = () => [200, [target]];
    routes[`GET /config-backups/${target.id}/versions/`] = () => [
      200,
      [
        { id: 'v2', version: 2, captured_at: '2026-11-13T03:00:00Z', format: 'opnsense-config-xml', size_bytes: 10, trigger: 'scheduled', summary: { added: 1, removed: 1 } },
        { id: 'v1', version: 1, captured_at: '2026-11-12T03:00:00Z', format: 'opnsense-config-xml', size_bytes: 10, trigger: 'scheduled', summary: null },
      ],
    ];
    routes[`GET /config-backups/${target.id}/versions/2/diff`] = () => [
      200,
      {
        target_id: target.id,
        from_version: 1,
        to_version: 2,
        redacted: true,
        truncated: false,
        added: 1,
        removed: 1,
        lines: [
          '--- v1',
          '+++ v2',
          '@@ -1 +1 @@',
          '-<password>[redacted:aaaaaaaaaa]</password>',
          '+<password>[redacted:bbbbbbbbbb]</password>',
        ],
      },
    ];
    renderWithClient(<DeviceConfigBackupsSection />);
    expect(await screen.findByText('fw-office')).toBeTruthy();
    expect(screen.getByText('Changed')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: /History/ }));
    const diff = await screen.findByTestId('config-diff');
    expect(diff.textContent).toContain('[redacted:bbbbbbbbbb]');
    expect(screen.getByText(/1 added, 1 removed/)).toBeTruthy();
  });

  it('asks the server for one export and never retries on refusal', async () => {
    routes['GET /config-backups/'] = () => [200, [target]];
    routes[`POST /config-backups/${target.id}/capture`] = () => [
      429,
      { detail: 'This device was exported less than 10 minutes ago; try again later' },
    ];
    renderWithClient(<DeviceConfigBackupsSection />);
    fireEvent.click(await screen.findByRole('button', { name: /Back up now/ }));
    await waitFor(() => expect(requests).toContain(`POST /config-backups/${target.id}/capture`));
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(requests.filter((r) => r.startsWith('POST')).length).toBe(1);
  });

  it('renders nothing for a user who may not view firewall data', async () => {
    routes['GET /config-backups/'] = () => [403, { detail: 'Missing permissions: firewall.view' }];
    renderWithClient(<DeviceConfigBackupsSection />);
    await waitFor(() => expect(requests).toContain('GET /config-backups/'));
    await waitFor(() => expect(screen.queryByTestId('device-config-backups')).toBeNull());
  });
});
