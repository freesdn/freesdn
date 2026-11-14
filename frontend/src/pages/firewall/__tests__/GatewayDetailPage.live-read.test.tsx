// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The gateway page while the gateway is busy: a remembered answer reads
 * "as of", a device-busy 503 is waited out rather than shown as a failure,
 * a skipped sync is labelled a skip, and a busy Sync is not "Sync failed".
 * Synthetic responses shaped like backend/app/services/device_live_read.py.
 */
import { beforeEach, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { AxiosError, AxiosHeaders, type InternalAxiosRequestConfig } from 'axios';
import GatewayDetailPage from '../GatewayDetailPage';
import { formatAsOf } from '@/components/ui/live-read-status';
import { renderWithProviders } from '@/test-utils';

const ID = '12345678-1234-4123-8123-123456789abc';
const BUSY = 'Device busy: gateway full sync since 14:02:10 UTC (35s). Nothing was sent to it; try again in a few seconds.';
const api = vi.hoisted(() => ({
  summary: vi.fn(),
  firmware: vi.fn(),
  sync: vi.fn(),
  gateway: {} as Record<string, unknown>,
  toast: vi.fn(),
}));

function busy503(): AxiosError {
  const config = { headers: new AxiosHeaders() } as InternalAxiosRequestConfig;
  return new AxiosError('Request failed with status code 503', AxiosError.ERR_BAD_RESPONSE, config, {}, {
    data: { error: { code: 503, message: BUSY } },
    status: 503,
    statusText: '',
    headers: new AxiosHeaders({ 'retry-after': '1' }),
    config,
  });
}

vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: api.toast }) }));
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  const getById = vi.fn(async (id: string) => ({ data: {
    id, name: 'Busy gateway', vendor: 'opnsense', host: 'gateway.example.test', port: 443,
    is_online: true, capabilities: [], settings: {}, sync_enabled: true, sync_status: 'success',
    sync_interval_seconds: 300, created_at: '2026-11-01T00:00:00Z', updated_at: '2026-11-01T00:00:00Z',
    ...api.gateway,
  } }));
  const empty = vi.fn().mockResolvedValue({ data: {} });
  const methods = {
    getById,
    getDeviceSummary: api.summary,
    getFirmware: api.firmware,
    getGatewayHealth: vi.fn(async (id: string) => ({ data: { gateway_id: id, gateways: [], count: 0 } })),
    triggerSync: api.sync,
  };
  return {
    ...actual,
    gatewayApi: new Proxy(methods, { get: (target, name) => (name in target ? target[name as keyof typeof target] : empty) }),
    sitesApiV2: { list: vi.fn().mockResolvedValue({ data: { items: [] } }) },
  };
});

const summary = { gateway_id: ID, vendor: 'opnsense', summary: {
  hostname: 'busy-host', version: '26.1', interface_count: 2, interfaces_up: 2, interfaces_down: 0, wan_status: 'up', uptime: '3 days',
} };
const firmware = { gateway_id: ID, vendor: 'opnsense', firmware: { current_version: 'fw-remembered', latest_version: null, update_available: null } };

beforeEach(() => {
  api.gateway = {};
  api.toast.mockReset();
  api.sync.mockReset();
  api.summary.mockReset().mockResolvedValue({ data: summary });
  api.firmware.mockReset().mockResolvedValue({ data: firmware });
});

const render = () =>
  renderWithProviders(<GatewayDetailPage />, { initialPath: `/firewall/gateways/${ID}/overview`, routePath: '/firewall/gateways/:id/:tab' });

it('says a remembered answer is as of its read time, without hiding it', async () => {
  const asOf = '2026-11-13T14:02:10Z';
  api.firmware.mockResolvedValue({ data: { ...firmware, as_of: asOf, cached: true, cache_reason: 'device_busy' } });
  render();
  expect((await screen.findAllByText('fw-remembered', { selector: 'dd' })).length).toBeGreaterThan(0);
  expect(await screen.findByTestId('live-read-as-of')).toHaveTextContent(`As of ${formatAsOf(asOf)}, device busy`);
});

it('shows nothing extra when every read is live', async () => {
  api.firmware.mockResolvedValue({ data: { ...firmware, as_of: new Date().toISOString(), cached: false, cache_reason: null } });
  render();
  await screen.findAllByText('fw-remembered', { selector: 'dd' });
  expect(screen.queryByTestId('live-read-as-of')).not.toBeInTheDocument();
  expect(screen.queryByTestId('live-read-busy')).not.toBeInTheDocument();
});

it('waits out a device-busy 503 calmly and then shows the read', async () => {
  api.summary.mockRejectedValueOnce(busy503());
  render();
  const panel = (await screen.findByText('Live device summary')).closest('[class*="rounded-lg"]') as HTMLElement;
  expect(await within(panel).findByText(/The gateway is busy with another request/)).toBeInTheDocument();
  expect(screen.getByTestId('live-read-busy')).toHaveTextContent('Device busy, retrying');
  expect(screen.queryByText(/Gateway status is unavailable/)).not.toBeInTheDocument();
  expect(screen.queryByText(/Some live data could not be loaded/i)).not.toBeInTheDocument();
  expect(await screen.findByText('3 days', undefined, { timeout: 3000 })).toBeInTheDocument();
  expect(api.summary).toHaveBeenCalledTimes(2);
});

it('labels a sync skipped for a busy gateway as a skip, not an error', async () => {
  api.gateway = { last_sync_error: 'Device busy: firewall health poll since 10:01:00 UTC (3s)' };
  render();
  const label = await screen.findByText('Last Sync Skipped', { selector: 'dt' });
  expect(label.nextElementSibling).toHaveTextContent('Device busy: firewall health poll');
  expect(screen.queryByText('Last Error', { selector: 'dt' })).not.toBeInTheDocument();
});

it('keeps "Last Error" for a real sync failure', async () => {
  api.gateway = { last_sync_error: 'connect: ConnectTimeout' };
  render();
  expect(await screen.findByText('Last Error', { selector: 'dt' })).toBeInTheDocument();
});

it('reports a Sync that found the gateway busy without calling it a failure', async () => {
  api.sync.mockRejectedValue(busy503());
  render();
  await screen.findAllByText('Busy gateway');
  fireEvent.click(screen.getByRole('button', { name: /^Sync$/ }));
  await waitFor(() => expect(api.toast).toHaveBeenCalled());
  const [{ title, description, variant }] = api.toast.mock.calls[0];
  expect(title).toBe('Gateway busy');
  expect(description).toBe(BUSY);
  expect(variant).toBeUndefined();
});
