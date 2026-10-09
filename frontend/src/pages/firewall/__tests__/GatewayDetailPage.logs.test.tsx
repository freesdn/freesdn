// SPDX-License-Identifier: AGPL-3.0-only
/** Actual page/query/table; vendor and identity responses are synthetic. */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import GatewayDetailPage from '../GatewayDetailPage';
import { renderWithProviders } from '@/test-utils';

const state = vi.hoisted(() => ({ system: vi.fn(), firewall: vi.fn() }));
const ID = '12345678-1234-4123-8123-123456789abc';
const row = { __timestamp__: '2026-09-26T00:00:00Z', process_name: 'owned-process', message: 'owned-log-message' };
const body = { gateway_id: ID, vendor: 'opnsense', logs: [row] };
const unavailable = /Logs are unavailable/;
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  const getById = vi.fn(async (id: string) => ({ data: { id, name: 'Owned log gateway', vendor: 'opnsense', host: 'gateway.example.test', port: 443, is_online: true, capabilities: [], settings: {} } }));
  const empty = vi.fn().mockResolvedValue({ data: {} });
  return { ...actual, gatewayApi: new Proxy({ getById, getSystemLog: state.system, getFirewallLog: state.firewall }, { get: (target, name) => name in target ? target[name as keyof typeof target] : empty }), sitesApiV2: { list: vi.fn().mockResolvedValue({ data: { items: [] } }) } };
});
beforeEach(() => {
  state.system.mockReset().mockResolvedValue({ data: body });
  state.firewall.mockReset().mockResolvedValue({ data: body });
});
async function show(kind: 'system' | 'firewall') {
  const view = renderWithProviders(<GatewayDetailPage />, { initialPath: `/firewall/gateways/${ID}/logs`, routePath: '/firewall/gateways/:id/:tab' });
  await screen.findByText('Owned log gateway');
  if (kind === 'system') fireEvent.click(await screen.findByRole('button', { name: 'System' }));
  await waitFor(() => expect(view.queryClient.getQueryState(['gateways', ID, 'logs-'+kind])?.fetchStatus).toBe('idle'));
  return view;
}
for (const kind of ['system', 'firewall'] as const) describe(kind+' gateway log availability', () => {
  it.each([
    ['missing body', undefined], ['null body', null], ['missing rows', { ...body, logs: undefined }],
    ['null rows', { ...body, logs: null }], ['object rows', { ...body, logs: { message: 'wrong-shape' } }],
    ['wrong gateway', { ...body, gateway_id: 'other-gateway' }], ['wrong vendor', { ...body, vendor: 'pfsense' }],
    ['missing gateway', { ...body, gateway_id: undefined }], ['missing vendor', { ...body, vendor: undefined }],
    ['null row', { ...body, logs: [null] }], ['string row', { ...body, logs: ['wrong-shape'] }],
    ['array row', { ...body, logs: [[]] }], ['nested message', { ...body, logs: [{ ...row, message: { secret: 'private-nested-message' } }] }],
    ['nested timestamp', { ...body, logs: [{ ...row, timestamp: { secret: 'private-nested-time' } }] }],
    ['nested process', { ...body, logs: [{ ...row, process_name: { secret: 'private-nested-process' } }] }],
    ['too many rows', { ...body, logs: Array.from({ length: 201 }, () => row) }],
  ] as [string, unknown][])('does not report %s as available logs', async (_name, data) => {
    state[kind].mockResolvedValue({ data });
    await show(kind);
    expect(await screen.findByText(unavailable)).toBeInTheDocument();
    expect(screen.queryByText(row.message)).not.toBeInTheDocument();
    expect(screen.queryByText(/private-nested/)).not.toBeInTheDocument();
  });
  it('shows a generic unavailable state for a failed read', async () => {
    state[kind].mockRejectedValue(new Error('private-device-log-diagnostic'));
    await show(kind);
    expect(await screen.findByText(unavailable)).toBeInTheDocument();
    expect(screen.queryByText(/private-device-log-diagnostic/)).not.toBeInTheDocument();
  });
  it('keeps a successful empty result distinct from failure', async () => {
    state[kind].mockResolvedValue({ data: { ...body, logs: [] } });
    await show(kind);
    expect(screen.queryByText(unavailable)).not.toBeInTheDocument();
    expect(screen.queryByText(row.message)).not.toBeInTheDocument();
  });
  it('renders current rows and the OPNsense timestamp', async () => {
    await show(kind);
    expect(await screen.findByText(row.message)).toBeInTheDocument();
    expect(screen.getByText(row.__timestamp__)).toBeInTheDocument();
    expect(screen.getByText(row.process_name)).toBeInTheDocument();
  });
  it('renders returned log text as text, never as HTML', async () => {
    state[kind].mockResolvedValue({ data: { ...body, logs: [{ message: '<img src=x onerror=alert(1)>' }] } });
    const view = await show(kind);
    expect(await screen.findByText('<img src=x onerror=alert(1)>')).toBeInTheDocument();
    expect(view.container.querySelector('img[src="x"]')).toBeNull();
  });
  it('retries only the selected log read and recovers', async () => {
    state[kind].mockRejectedValueOnce(new Error('unavailable'));
    await show(kind);
    fireEvent.click(await screen.findByRole('button', { name: 'Retry logs' }));
    expect(await screen.findByText(row.message)).toBeInTheDocument();
    expect(state[kind]).toHaveBeenCalledTimes(2);
    expect(state[kind === 'system' ? 'firewall' : 'system']).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(unavailable)).not.toBeInTheDocument();
  });
  it('hides cached rows throughout a refresh and after failure', async () => {
    const view = await show(kind);
    await screen.findByText(row.message);
    let fail!: (error: Error) => void;
    state[kind].mockReturnValue(new Promise((_resolve, reject) => { fail = reject; }));
    let request!: Promise<void>;
    await act(async () => { request = view.queryClient.refetchQueries({ queryKey: ['gateways', ID, 'logs-'+kind], exact: true }); });
    await waitFor(() => expect(screen.queryByText(row.message)).not.toBeInTheDocument());
    await act(async () => { fail(new Error('private-refresh-diagnostic')); await request; });
    expect(await screen.findByText(unavailable)).toBeInTheDocument();
    expect(screen.queryByText(row.message)).not.toBeInTheDocument();
  });
  it('rejects a wrong-gateway replacement of cached data', async () => {
    const view = await show(kind);
    await screen.findByText(row.message);
    await act(async () => { view.queryClient.setQueryData(['gateways', ID, 'logs-'+kind], { data: { ...body, gateway_id: 'other-gateway' } }); });
    expect(await screen.findByText(unavailable)).toBeInTheDocument();
    expect(screen.queryByText(row.message)).not.toBeInTheDocument();
  });
});
