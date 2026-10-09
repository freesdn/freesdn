/** Actual overview query and cards with synthetic read-only normalized responses. */
import { beforeEach, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import GatewayDetailPage from '../GatewayDetailPage';
import { validatedAggregate } from '../gateway-tabs/gatewayAggregateRead';
import { renderWithProviders } from '@/test-utils';

const state = vi.hoisted(() => ({ summary: vi.fn() }));
const ID = '12345678-1234-4123-8123-123456789abc';
const body = (): Record<string, unknown> => ({
  hostname: 'owned-summary-host', version: 'owned-summary-version', wan_status: 'online',
  interface_count: 3, interfaces_up: 1, interfaces_down: 1, interfaces_unknown: 1,
  uptime_text: 'owned-summary-uptime', wan_ip: '198.51.100.2',
});
const envelope = (summary: Record<string, unknown>) => ({ data: { gateway_id: ID, vendor: 'opnsense', summary } });
const card = (label: string) => screen.getByText(label).closest('[class*="rounded-lg"]') as HTMLElement;

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  const getById = vi.fn(async (id: string) => ({ data: {
    id, name: 'Owned summary gateway', vendor: 'opnsense', host: 'gateway.example.test',
    port: 443, is_online: true, capabilities: [], settings: {},
  } }));
  const empty = vi.fn().mockResolvedValue({ data: {} });
  const methods = { getById, getDeviceSummary: state.summary,
    getFirmware: vi.fn(async (id: string) => ({ data: { gateway_id: id, vendor: 'opnsense', firmware: { current_version: 'owned-firmware-version', update_available: null } } })),
    getGatewayHealth: vi.fn(async (id: string) => ({ data: { gateway_id: id, vendor: 'opnsense', gateways: [], count: 0 } })),
  };
  return { ...actual, gatewayApi: new Proxy(methods, {
    get: (target, name) => name in target ? target[name as keyof typeof target] : empty,
  }), sitesApiV2: { list: vi.fn().mockResolvedValue({ data: { items: [] } }) } };
});

beforeEach(() => state.summary.mockReset());
async function show(summary: Record<string, unknown>) {
  state.summary.mockResolvedValue(envelope(summary));
  const view = renderWithProviders(<GatewayDetailPage />, {
    initialPath: `/firewall/gateways/${ID}/overview`, routePath: '/firewall/gateways/:id/:tab',
  });
  await screen.findAllByText('Owned summary gateway');
  await waitFor(() => expect(state.summary).toHaveBeenCalledWith(ID));
  await waitFor(() => expect(view.queryClient.getQueryState(['gateways', ID, 'device-summary'])?.fetchStatus).toBe('idle'));
  return view;
}
const legacyBody = () => ({ ...body(), interface_count: 2, interfaces_unknown: undefined });

it('admits unknown interfaces without rewriting the normalized response', () => {
  const value = envelope(body());
  expect(validatedAggregate(value, ID, 'device-summary')).toBe(value);
  expect(value.data.summary.interfaces_unknown).toBe(1);
});
it('accepts legacy summaries without the optional unknown count', () => {
  const value = envelope(legacyBody());
  expect(validatedAggregate(value, ID, 'device-summary')).toBe(value);
});
it.each([null, true, '1', -1, 0.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1])('rejects invalid unknown interface count %s', unknown => {
  const summary = { ...legacyBody(), interfaces_unknown: unknown };
  expect(() => validatedAggregate(envelope(summary), ID, 'device-summary')).toThrow('Gateway status is unavailable');
});
it('rejects an unknown count inconsistent with the total', () => {
  expect(() => validatedAggregate(envelope({ ...legacyBody(), interfaces_unknown: 1 }), ID, 'device-summary')).toThrow('Gateway status is unavailable');
});
it.each(['interface_count', 'interfaces_up', 'interfaces_down'])('rejects unsafe integer %s', field => {
  const value = { ...legacyBody(), interface_count: 2 ** 53, interfaces_up: 2 ** 53, interfaces_down: 0, [field]: 2 ** 53 };
  expect(() => validatedAggregate(envelope(value), ID, 'device-summary')).toThrow('Gateway status is unavailable');
});
it('renders an actual query with an unknown interface instead of an unavailable panel', async () => {
  await show(body());
  expect(screen.getByText('owned-summary-uptime')).toBeInTheDocument();
  expect(screen.queryByText(/Gateway status is unavailable/)).not.toBeInTheDocument();
});
it('does not admit an inconsistent unknown count to the overview', async () => {
  await show({ ...legacyBody(), interfaces_unknown: 1 });
  expect(await screen.findByText(/Gateway status is unavailable/)).toBeInTheDocument();
  expect(screen.queryByText('owned-summary-uptime')).not.toBeInTheDocument();
});
it('renders measured zero WAN latency and loss', async () => {
  await show({ ...legacyBody(), wan_delay_ms: 0, wan_loss_pct: 0 });
  expect(within(card('WAN IP')).getByText('Latency: 0 ms, Loss: 0%')).toBeInTheDocument();
});
it.each([undefined, null])('shows unknown for absent WAN samples %s', missing => {
  return show({ ...legacyBody(), wan_delay_ms: missing, wan_loss_pct: missing }).then(() => {
    expect(within(card('WAN IP')).getByText('Latency: Unknown, Loss: Unknown')).toBeInTheDocument();
    expect(card('WAN IP').textContent).not.toContain('0%');
  });
});
it('keeps measured nonzero latency independent of an unknown loss sample', async () => {
  await show({ ...legacyBody(), wan_delay_ms: 12.5 });
  expect(within(card('WAN IP')).getByText('Latency: 12.5 ms, Loss: Unknown')).toBeInTheDocument();
});
it('keeps measured zero loss independent of an unknown latency sample', async () => {
  await show({ ...legacyBody(), wan_loss_pct: 0 });
  expect(within(card('WAN IP')).getByText('Latency: Unknown, Loss: 0%')).toBeInTheDocument();
});
it('renders numeric zero uptime', async () => {
  await show({ ...legacyBody(), uptime_text: undefined, uptime: 0 });
  expect(within(card('Uptime')).getByText('0')).toBeInTheDocument();
});
it.each(['services_running', 'services_stopped'])('does not invent the other half of %s', async field => {
  await show({ ...legacyBody(), [field]: 3 });
  expect(screen.queryByText(/^\d+ running$/)).not.toBeInTheDocument();
  expect(screen.queryByText(/^\d+ stopped$/)).not.toBeInTheDocument();
});
it.each(['vpn_tunnels_up', 'vpn_tunnels_total'])('does not invent the other half of %s', async field => {
  await show({ ...legacyBody(), [field]: 3 });
  expect(screen.queryByText('VPN Tunnels')).not.toBeInTheDocument();
});
it('retains complete zero service and VPN counters', async () => {
  await show({ ...legacyBody(), services_running: 0, services_stopped: 0, vpn_tunnels_up: 0, vpn_tunnels_total: 0 });
  expect(screen.getByText('0 running')).toBeInTheDocument();
  expect(screen.getByText('0 stopped')).toBeInTheDocument();
  expect(within(card('VPN Tunnels')).getByText('0 / 0')).toBeInTheDocument();
});
it('retains complete nonzero counters', async () => {
  await show({ ...legacyBody(), services_running: 7, services_stopped: 2, vpn_tunnels_up: 2, vpn_tunnels_total: 3 });
  expect(screen.getByText('7 running')).toBeInTheDocument();
  expect(screen.getByText('2 stopped')).toBeInTheDocument();
  expect(within(card('VPN Tunnels')).getByText('2 / 3')).toBeInTheDocument();
});
