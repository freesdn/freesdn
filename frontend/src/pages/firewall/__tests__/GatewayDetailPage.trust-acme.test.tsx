// SPDX-License-Identifier: AGPL-3.0-only
/** Real page/query panels; device data and transport are synthetic. */
import { beforeEach, expect, it, vi } from 'vitest';
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import GatewayDetailPage from '../GatewayDetailPage';
import { renderWithProviders } from '@/test-utils';

const state = vi.hoisted(() => ({ trust: vi.fn(), acme: vi.fn() }));
const ID = '12345678-1234-4123-8123-123456789abc';
const emptyTrust = { gateway_id: ID, trust: { certificates: [], certificate_authorities: [], crls: [], cert_count: 0, ca_count: 0, crl_count: 0 } };
const emptyACME = { gateway_id: ID, acme: { settings: { enabled: false, auto_renewal: true }, certificates: [], accounts: [], validations: [], actions: [], cert_count: 0, account_count: 0 } };
const panel = (kind: string) => screen.getByText(kind === 'trust' ? 'Certificate Management' : "ACME / Let's Encrypt").closest('[class*="rounded-lg"]') as HTMLElement;

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  const getById = vi.fn(async (id: string) => ({ data: { id, name: 'Owned trust gateway', vendor: 'opnsense', host: 'gateway.example.test', port: 443, is_online: true, capabilities: [], settings: {} } }));
  const empty = vi.fn().mockResolvedValue({ data: {} });
  return { ...actual, gatewayApi: new Proxy({ getById, getTrustOverview: state.trust, getACMEOverview: state.acme }, { get: (target, name) => name in target ? target[name as keyof typeof target] : empty }), sitesApiV2: { list: vi.fn().mockResolvedValue({ data: { items: [] } }) } };
});

beforeEach(() => {
  state.trust.mockReset().mockResolvedValue({ data: structuredClone(emptyTrust) });
  state.acme.mockReset().mockResolvedValue({ data: structuredClone(emptyACME) });
});
async function show(kind: string) {
  const view = renderWithProviders(<GatewayDetailPage />, { initialPath: `/firewall/gateways/${ID}/system`, routePath: '/firewall/gateways/:id/:tab' });
  await screen.findByText('Owned trust gateway');
  await waitFor(() => expect(view.queryClient.getQueryState(['gateways', ID, `${kind}-overview`])?.fetchStatus).toBe('idle'));
  return view;
}

it.each(['trust', 'acme'] as const)('renders only confirmed empty %s inventories', async (kind) => {
  await show(kind);
  expect(within(panel(kind)).getByText(kind === 'trust' ? /No certificates/ : /No ACME/)).toBeInTheDocument();
  expect(state[kind]).toHaveBeenCalledWith(ID);
});

it.each(['trust', 'acme'] as const)('does not show failed %s reads as empty and can retry', async (kind) => {
  state[kind].mockRejectedValueOnce(new Error('owned-private-trust-device-error'));
  await show(kind);
  expect(within(panel(kind)).getByText(/inventory is unavailable/)).toBeInTheDocument();
  expect(screen.queryByText(/owned-private-trust-device-error/)).not.toBeInTheDocument();
  fireEvent.click(within(panel(kind)).getByRole('button', { name: /Retry/ }));
  await waitFor(() => expect(state[kind]).toHaveBeenCalledTimes(2));
  expect(await within(panel(kind)).findByText(kind === 'trust' ? /No certificates/ : /No ACME/)).toBeInTheDocument();
});

it.each(['trust', 'acme'] as const)('does not retain stale %s counts during refresh or after failure', async (kind) => {
  const view = await show(kind);
  let fail!: (error: Error) => void;
  state[kind].mockReturnValue(new Promise((_resolve, reject) => { fail = reject; }));
  let request!: Promise<void>;
  await act(async () => { request = view.queryClient.refetchQueries({ queryKey: ['gateways', ID, `${kind}-overview`], exact: true }); });
  await waitFor(() => expect(within(panel(kind)).queryAllByText('0')).toHaveLength(0));
  await act(async () => { fail(new Error('owned-private-trust-device-error')); await request; });
  expect(await within(panel(kind)).findByText(/inventory is unavailable/)).toBeInTheDocument();
  expect(within(panel(kind)).queryAllByText('0')).toHaveLength(0);
});

it.each(['trust', 'acme'] as const)('rejects malformed %s data instead of showing zero counts', async (kind) => {
  state[kind].mockResolvedValue({ data: {} });
  await show(kind);
  expect(within(panel(kind)).getByText(/inventory is unavailable/)).toBeInTheDocument();
  expect(within(panel(kind)).queryAllByText('0')).toHaveLength(0);
});

it.each(['trust', 'acme'] as const)('rejects data for a different gateway in the %s panel', async (kind) => {
  state[kind].mockResolvedValue({ data: { ...(kind === 'trust' ? emptyTrust : emptyACME), gateway_id: 'other' } });
  await show(kind);
  expect(within(panel(kind)).getByText(/inventory is unavailable/)).toBeInTheDocument();
});

it.each((['trust', 'acme'] as const).flatMap((kind) =>
  ['missing-list', 'non-list', 'null-row', 'nested-field', 'negative-count', 'bool-count', 'missing-count'].map((bad) => [kind, bad] as const)
))('rejects %s inventory with %s', async (kind, bad) => {
  const data = structuredClone(kind === 'trust' ? emptyTrust : emptyACME);
  const inventory = (kind === 'trust' ? (data as typeof emptyTrust).trust : (data as typeof emptyACME).acme) as Record<string, unknown>;
  if (bad === 'missing-list') delete inventory.certificates;
  else if (bad === 'non-list') inventory.certificates = {};
  else if (bad === 'null-row' || bad === 'nested-field') {
    inventory.certificates = bad === 'null-row' ? [null] : [{ uuid: 'owned', enabled: true, name: { secret: 'owned-private-trust-device-error' } }];
    inventory.cert_count = 1;
  } else if (bad === 'negative-count') inventory.cert_count = -1;
  else if (bad === 'bool-count') inventory.cert_count = false;
  else delete inventory.cert_count;
  state[kind].mockResolvedValue({ data });
  await show(kind);
  expect(within(panel(kind)).getByText(/inventory is unavailable/)).toBeInTheDocument();
  expect(screen.queryByText(/owned-private-trust-device-error/)).not.toBeInTheDocument();
});

it('uses the normalized CRL field and count', async () => {
  state.trust.mockResolvedValue({ data: { ...emptyTrust, trust: { ...emptyTrust.trust, crls: [{ uuid: 'owned', caref: 'owned', descr: 'Owned CRL' }], crl_count: 1 } } });
  await show('trust');
  expect(within(panel('trust')).getByText('1')).toBeInTheDocument();
  expect(within(panel('trust')).queryByText(/No certificates/)).not.toBeInTheDocument();
});

it('renders normalized ACME domains and timestamps', async () => {
  state.acme.mockResolvedValue({ data: { ...emptyACME, acme: { ...emptyACME.acme, certificates: [{ uuid: 'owned', name: 'Owned certificate', enabled: true, alt_names: 'owned.example.test', last_update: 'owned-last-update' }], cert_count: 1 } } });
  await show('acme');
  expect(within(panel('acme')).getByText('owned.example.test')).toBeInTheDocument();
  expect(within(panel('acme')).getByText('owned-last-update')).toBeInTheDocument();
});
