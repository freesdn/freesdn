// SPDX-License-Identifier: AGPL-3.0-only
/** Actual page/query/lifecycle panel; device and identity data are synthetic. */
import { beforeEach, expect, it, vi } from 'vitest';
import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import GatewayDetailPage from '../GatewayDetailPage';
import { renderWithProviders } from '@/test-utils';

const state = vi.hoisted(() => ({ expiry: vi.fn() }));
const ID = '12345678-1234-4123-8123-123456789abc';
const healthy = { gateway_id: ID, days_threshold: 30, total_certificates: 1, valid_count: 1, expired: [], expiring_soon: [], unknown: [], unknown_count: 0, needs_attention: false };
const unknown = { name: 'Owned unknown certificate', common_name: 'unknown.example.test', status: 'unknown', expires: null, days_remaining: null };
const unavailable = /Certificate status is unavailable/;
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  const getById = vi.fn(async (id: string) => ({ data: { id, name: 'Owned certificate gateway', vendor: 'opnsense', host: 'gateway.example.test', port: 443, is_online: true, capabilities: [], settings: {} } }));
  const empty = vi.fn().mockResolvedValue({ data: {} });
  return { ...actual, gatewayApi: new Proxy({ getById, getCertificateExpiry: state.expiry }, { get: (target, name) => name in target ? target[name as keyof typeof target] : empty }), sitesApiV2: { list: vi.fn().mockResolvedValue({ data: { items: [] } }) } };
});
beforeEach(() => { state.expiry.mockReset().mockResolvedValue({ data: healthy }); });
async function show() {
  const view = renderWithProviders(<GatewayDetailPage />, { initialPath: `/firewall/gateways/${ID}/system`, routePath: '/firewall/gateways/:id/:tab' });
  await screen.findByText('Owned certificate gateway');
  await waitFor(() => expect(view.queryClient.getQueryState(['gateways', ID, 'cert-expiry'])?.fetchStatus).toBe('idle'));
  return view;
}

it.each([
  ['missing', undefined], ['null', null], ['empty object', {}], ['wrong gateway', { ...healthy, gateway_id: 'other-gateway' }],
  ['missing total', { ...healthy, total_certificates: undefined }], ['negative total', { ...healthy, total_certificates: -1 }],
  ['invalid count', { ...healthy, valid_count: '1' }], ['inconsistent count', { ...healthy, total_certificates: 2 }],
  ['missing unknown count', { ...healthy, unknown_count: undefined }], ['missing attention', { ...healthy, needs_attention: undefined }],
  ['null expired list', { ...healthy, expired: null }], ['invalid list row', { ...healthy, expired: [null] }],
  ['nested private identity', { ...healthy, valid_count: 0, unknown_count: 1, unknown: [{ ...unknown, name: { secret: 'owned-private-certificate' } }], needs_attention: true }],
  ['unknown count mismatch', { ...healthy, unknown_count: 1 }], ['hidden warning', { ...healthy, valid_count: 0, unknown_count: 1, unknown: [unknown] }],
  ['malformed expiry', { ...healthy, valid_count: 0, expired: [{ ...unknown, status: 'expired', expires: 'not-a-date', days_remaining: -3 }], needs_attention: true }],
] as [string, unknown][])('does not show %s data as healthy', async (_kind, data) => {
  state.expiry.mockResolvedValue({ data });
  await show();
  expect(await screen.findByText(unavailable)).toBeInTheDocument();
  expect(screen.queryByText('All certificates are valid')).not.toBeInTheDocument();
  expect(screen.queryByText(/owned-private-certificate/)).not.toBeInTheDocument();
});

it.each([501, 502])('shows failed or unsupported status %s without private diagnostics', async (status) => {
  state.expiry.mockRejectedValue(Object.assign(new Error('owned-private-certificate'), { response: { status } }));
  await show();
  expect(await screen.findByText(unavailable)).toBeInTheDocument();
  expect(screen.queryByText('All certificates are valid')).not.toBeInTheDocument();
  expect(screen.queryByText(/owned-private-certificate/)).not.toBeInTheDocument();
});

it('shows confirmed valid certificates', async () => {
  await show();
  expect(await screen.findByText('All certificates are valid')).toBeInTheDocument();
  expect(screen.queryByText(unavailable)).not.toBeInTheDocument();
  expect(state.expiry).toHaveBeenCalledWith(ID, 30);
});

it('distinguishes a confirmed empty inventory from valid certificates', async () => {
  state.expiry.mockResolvedValue({ data: { ...healthy, total_certificates: 0, valid_count: 0 } });
  await show();
  expect(await screen.findByText('No certificates were returned.')).toBeInTheDocument();
  expect(screen.queryByText('All certificates are valid')).not.toBeInTheDocument();
});

it('shows unknown expiry as attention without inventing a date', async () => {
  state.expiry.mockResolvedValue({ data: { ...healthy, valid_count: 0, unknown_count: 1, unknown: [unknown], needs_attention: true } });
  await show();
  expect(await screen.findByText(unknown.name)).toBeInTheDocument();
  expect(screen.getByText('Some certificate expiry dates could not be read. Verify them on the gateway.')).toBeInTheDocument();
  expect(screen.queryByText('All certificates are valid')).not.toBeInTheDocument();
  expect(screen.queryByText(/Invalid Date|1\/1\/1970/)).not.toBeInTheDocument();
});

it('renders expired and soon-expiring warnings', async () => {
  state.expiry.mockResolvedValue({ data: { ...healthy, total_certificates: 2, valid_count: 0, expired: [{ name: 'Owned expired', common_name: 'old.example.test', expires: '2026-01-01T00:00:00Z', days_remaining: -10, status: 'expired' }], expiring_soon: [{ name: 'Owned expiring', common_name: 'soon.example.test', expires: '2026-10-01T00:00:00Z', days_remaining: 5, status: 'expiring_soon' }], needs_attention: true } });
  await show();
  expect(await screen.findByText('Owned expired')).toBeInTheDocument();
  expect(screen.getByText('Owned expiring')).toBeInTheDocument();
  expect(screen.queryByText('All certificates are valid')).not.toBeInTheDocument();
});

it('retries the certificate query and recovers', async () => {
  state.expiry.mockRejectedValueOnce(new Error('unavailable'));
  await show();
  fireEvent.click(await screen.findByRole('button', { name: 'Retry certificate check' }));
  expect(await screen.findByText('All certificates are valid')).toBeInTheDocument();
  expect(state.expiry).toHaveBeenCalledTimes(2);
});

it('hides cached health throughout refresh and after failure', async () => {
  const view = await show();
  await screen.findByText('All certificates are valid');
  let fail!: (error: Error) => void;
  state.expiry.mockReturnValue(new Promise((_resolve, reject) => { fail = reject; }));
  let request!: Promise<void>;
  await act(async () => { request = view.queryClient.refetchQueries({ queryKey: ['gateways', ID, 'cert-expiry'], exact: true }); });
  await waitFor(() => expect(screen.queryByText('All certificates are valid')).not.toBeInTheDocument());
  await act(async () => { fail(new Error('owned-private-certificate')); await request; });
  expect(await screen.findByText(unavailable)).toBeInTheDocument();
  expect(screen.queryByText('All certificates are valid')).not.toBeInTheDocument();
});

it('rejects a wrong-gateway replacement in the query cache', async () => {
  const view = await show();
  await screen.findByText('All certificates are valid');
  await act(async () => { view.queryClient.setQueryData(['gateways', ID, 'cert-expiry'], { data: { ...healthy, gateway_id: 'other' } }); });
  expect(await screen.findByText(unavailable)).toBeInTheDocument();
  expect(screen.queryByText('All certificates are valid')).not.toBeInTheDocument();
});
