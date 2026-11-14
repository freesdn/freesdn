// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The Backups page showed each device's configuration-backup schedule but
 * could not change it, although the backend has always accepted
 * PATCH /config-backups/{id} with `enabled` and `interval_hours` (6 to 168)
 * for users with `firewall.manage_rules`. These tests drive the new schedule
 * dialog over the real Axios client: it sends only what changed, offers only
 * intervals the backend accepts, and is unavailable (with the reason) to a
 * user without the permission, as is "Back up now", which needs the same one.
 */
import type { ReactNode } from 'react';
import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ToastProvider } from '@/components/ui/toast';
import { api } from '@/lib/api/client';
import { useAuthStore, type User } from '@/stores/authStore';
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

function user(role: string, permissions: string[], superuser = false): User {
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
    is_superuser: superuser,
    is_org_admin: false,
    mfa_enabled: false,
    permissions,
    roles: [role],
  } as User;
}

type Handler = (config: InternalAxiosRequestConfig) => [number, unknown];
let routes: Record<string, Handler> = {};
const requests: { key: string; body: unknown }[] = [];
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
  routes = { 'GET /config-backups/': () => [200, [target]] };
  document.cookie = 'freesdn_csrf=synthetic-csrf; path=/';
  api.defaults.adapter = async (config) => {
    const key = `${config.method?.toUpperCase()} ${config.url}`;
    requests.push({ key, body: config.data ? JSON.parse(config.data as string) : undefined });
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

const patchKey = `PATCH /config-backups/${target.id}`;

describe('config backup schedule', () => {
  it('shows the interval and turns the schedule off with a PATCH of only that field', async () => {
    useAuthStore.setState({ user: user('site_admin', ['firewall.view', 'firewall.manage_rules']), isAuthenticated: true });
    routes[patchKey] = (config) => [200, { ...target, ...JSON.parse(config.data as string) }];
    renderWithClient(<DeviceConfigBackupsSection />);
    expect(await screen.findByTestId(`config-schedule-${target.id}`)).toHaveTextContent('Daily (every 24 hours)');

    fireEvent.click(screen.getByRole('button', { name: /Schedule/ }));
    const dialog = await screen.findByRole('dialog');
    const toggle = within(dialog).getByRole('switch', { name: 'Scheduled backups' });
    expect(toggle).toBeChecked();
    expect(within(dialog).getByRole('button', { name: 'Save schedule' })).toBeDisabled();
    fireEvent.click(toggle);
    expect(within(dialog).getByText(/Back up now still works/)).toBeTruthy();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save schedule' }));

    await waitFor(() => expect(requests.map((r) => r.key)).toContain(patchKey));
    expect(requests.find((r) => r.key === patchKey)?.body).toEqual({ enabled: false });
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('offers only intervals from 6 to 168 hours, keeps a custom one, and sends the new interval', async () => {
    useAuthStore.setState({ user: user('site_admin', ['firewall.view', 'firewall.manage_rules']), isAuthenticated: true });
    routes['GET /config-backups/'] = () => [200, [{ ...target, interval_hours: 36 }]];
    routes[patchKey] = (config) => [200, { ...target, ...JSON.parse(config.data as string) }];
    const ue = userEvent.setup();
    renderWithClient(<DeviceConfigBackupsSection />);
    expect(await screen.findByTestId(`config-schedule-${target.id}`)).toHaveTextContent('Every 36 hours');
    await ue.click(screen.getByRole('button', { name: /Schedule/ }));
    const dialog = await screen.findByRole('dialog');
    await ue.click(within(dialog).getByRole('combobox'));
    const options = screen.getAllByRole('option').map((o) => o.textContent);
    expect(options).toEqual([
      'Every 6 hours',
      'Every 12 hours',
      'Daily (every 24 hours)',
      'Every 36 hours',
      'Every 48 hours',
      'Every 72 hours',
      'Weekly (every 168 hours)',
    ]);
    await ue.click(screen.getByRole('option', { name: 'Every 6 hours' }));
    await ue.click(within(dialog).getByRole('button', { name: 'Save schedule' }));
    await waitFor(() => expect(requests.find((r) => r.key === patchKey)?.body).toEqual({ interval_hours: 6 }));
  });

  it('says why the controls are off for a user without firewall.manage_rules, and sends nothing', async () => {
    useAuthStore.setState({ user: user('operator', ['firewall.view']), isAuthenticated: true });
    renderWithClient(<DeviceConfigBackupsSection />);
    const schedule = await screen.findByRole('button', { name: /Schedule/ });
    const capture = screen.getByRole('button', { name: /Back up now/ });
    expect(schedule).toBeDisabled();
    expect(capture).toBeDisabled();
    await act(async () => {
      fireEvent.focus(schedule.parentElement as HTMLElement);
    });
    expect((await screen.findAllByText(/need the firewall\.manage_rules permission/)).length).toBeGreaterThan(0);
    expect(requests.filter((r) => r.key !== 'GET /config-backups/')).toEqual([]);
  });

  it('cannot schedule a device that is gone', async () => {
    useAuthStore.setState({ user: user('site_admin', ['firewall.view', 'firewall.manage_rules']), isAuthenticated: true });
    routes['GET /config-backups/'] = () => [200, [{ ...target, last_status: 'source_removed', enabled: false }]];
    renderWithClient(<DeviceConfigBackupsSection />);
    expect(await screen.findByRole('button', { name: /Schedule/ })).toBeDisabled();
  });
});
