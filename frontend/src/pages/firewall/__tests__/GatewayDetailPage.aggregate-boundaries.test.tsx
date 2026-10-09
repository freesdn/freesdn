/** Actual page/query panels with synthetic read-only gateway responses. */
import { beforeEach, expect, it, vi } from 'vitest';
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import GatewayDetailPage from '../GatewayDetailPage';
import { renderWithProviders } from '@/test-utils';

const state = vi.hoisted(() => ({
  vpn: vi.fn(), tailscale: vi.fn(), haproxy: vi.fn(), proxy: vi.fn(),
  crowdsec: vi.fn(), monit: vi.fn(), telegraf: vi.fn(), netflow: vi.fn(), summary: vi.fn(),
}));
const ID = '12345678-1234-4123-8123-123456789abc';
const kinds = ['vpn', 'tailscale', 'haproxy', 'proxy', 'crowdsec', 'monit', 'telegraf', 'netflow'] as const;
type Kind = typeof kinds[number];
const definitions: Record<Kind, { tab: string; heading: string }> = {
  vpn: { tab: 'vpn', heading: 'VPN Raw Status' },
  tailscale: { tab: 'vpn', heading: 'Tailscale' },
  haproxy: { tab: 'services', heading: 'HAProxy · Load Balancer' },
  proxy: { tab: 'services', heading: 'Web Proxy (Squid)' },
  crowdsec: { tab: 'ids', heading: 'CrowdSec IPS' },
  monit: { tab: 'monitoring', heading: 'Monit' },
  telegraf: { tab: 'monitoring', heading: 'Telegraf' },
  netflow: { tab: 'monitoring', heading: 'NetFlow / sFlow' },
};
const payloads: Record<Kind, Record<string, unknown>> = {
  vpn: { tunnels: { wireguard: { status: {}, peers: [], servers: [] }, openvpn: { providers: [], instances: [] }, ipsec: {} } },
  tailscale: { tailscale: { settings: { enabled: true, use_exit_node: [], listen_port: '41641' }, running: true } },
  haproxy: { haproxy: { servers: [], backends: [], frontends: [], acls: [], actions: [], server_count: 0, backend_count: 0, frontend_count: 0 } },
  proxy: { proxy: { enabled: true, running: true, ssl_inspection: false, transparent_mode: false, cache_enabled: false, logging: true, port: '3128' } },
  crowdsec: { crowdsec: { running: true, alerts: [], decisions: [], alert_count: 0, decision_count: 0 } },
  monit: { monit: { running: true, services: [], tests: [], alerts: [], service_count: 0, test_count: 0, alert_count: 0 } },
  telegraf: { telegraf: { enabled: true, running: true, output_influxdb: true, output_graphite: false, output_prometheus: false, influx_url: 'https://metrics.example.test' } },
  netflow: { netflow: { enabled: true, running: true, collect_enabled: true, interfaces: 'owned-interface', version: '9' } },
};
const envelope = (kind: Kind): Record<string, unknown> => ({ gateway_id: ID, vendor: 'opnsense', ...structuredClone(payloads[kind]) });
const panel = (kind: Kind) => screen.getByText(definitions[kind].heading).closest('[class*="rounded-lg"]') as HTMLElement;

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  const getById = vi.fn(async (id: string) => ({ data: { id, name: 'Owned aggregate gateway', vendor: 'opnsense', host: 'gateway.example.test', port: 443, is_online: true, capabilities: [], settings: {} } }));
  const empty = vi.fn().mockResolvedValue({ data: {} });
  const methods = { getById,
    getFirmware: vi.fn(async (id: string) => ({ data: { gateway_id: id, vendor: 'opnsense', firmware: { current_version: 'owned-independent-firmware-version', update_available: null } } })),
    getGatewayHealth: vi.fn(async (id: string) => ({ data: { gateway_id: id, vendor: 'opnsense', gateways: [], count: 0 } })),
    getDeviceSummary: state.summary, getVPN: state.vpn, getTailscaleStatus: state.tailscale, getHAProxyStatus: state.haproxy, getProxySettings: state.proxy, getCrowdSecStatus: state.crowdsec, getMonitStatus: state.monit, getTelegrafStatus: state.telegraf, getNetFlowStatus: state.netflow };
  return { ...actual, gatewayApi: new Proxy(methods, { get: (target, name) => name in target ? target[name as keyof typeof target] : empty }), sitesApiV2: { list: vi.fn().mockResolvedValue({ data: { items: [] } }) } };
});

const summary = () => ({ gateway_id: ID, vendor: 'opnsense', summary: { hostname: 'owned-summary-host', version: 'owned-summary-version', wan_status: 'online', interface_count: 2, interfaces_up: 1, interfaces_down: 1, uptime_text: 'owned-summary-uptime' } });

beforeEach(() => {
  state.summary.mockReset().mockResolvedValue({ data: summary() });
  for (const kind of kinds) state[kind].mockReset().mockResolvedValue({ data: envelope(kind) });
});

async function show(kind: Kind) {
  const view = renderWithProviders(<GatewayDetailPage />, { initialPath: `/firewall/gateways/${ID}/${definitions[kind].tab}`, routePath: '/firewall/gateways/:id/:tab' });
  await screen.findByText('Owned aggregate gateway');
  await waitFor(() => expect(state[kind]).toHaveBeenCalledWith(ID));
  await waitFor(() => expect(view.queryClient.getQueryState(['gateways', ID, kind])?.fetchStatus).toBe('idle'));
  return view;
}


async function showSummary() {
  const view = renderWithProviders(<GatewayDetailPage />, { initialPath: `/firewall/gateways/${ID}/overview`, routePath: '/firewall/gateways/:id/:tab' });
  await screen.findAllByText('Owned aggregate gateway');
  await waitFor(() => expect(view.queryClient.getQueryState(['gateways', ID, 'device-summary'])?.fetchStatus).toBe('idle'));
  return view;
}

it('renders admitted device-summary values', async () => {
  await showSummary();
  expect(screen.getAllByText('owned-summary-version').length).toBeGreaterThan(0);
  expect(screen.getByText('owned-summary-uptime')).toBeInTheDocument();
  expect(screen.queryByText(/Gateway status is unavailable/)).not.toBeInTheDocument();
});

it('retries an unavailable device summary without showing provider diagnostics', async () => {
  state.summary.mockRejectedValueOnce(new Error('owned-summary-private-diagnostic'));
  await showSummary();
  expect(screen.getByText(/Gateway status is unavailable/)).toBeInTheDocument();
  expect(screen.queryByText(/owned-summary-private-diagnostic/)).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: /Retry/ }));
  await screen.findByText('owned-summary-uptime');
  expect(state.summary).toHaveBeenCalledTimes(2);
});

it('hides prior summary values throughout a pending and failed refresh', async () => {
  const view = await showSummary();
  let fail!: (reason: Error) => void;
  state.summary.mockReturnValue(new Promise((_resolve, reject) => { fail = reject; }));
  let request!: Promise<void>;
  await act(async () => { request = view.queryClient.refetchQueries({ queryKey: ['gateways', ID, 'device-summary'], exact: true }); });
  expect(await screen.findByText(/Loading gateway status/)).toBeInTheDocument();
  expect(screen.queryByText('owned-summary-uptime')).not.toBeInTheDocument();
  expect(screen.queryByText('owned-summary-version')).not.toBeInTheDocument();
  await act(async () => { fail(new Error('owned-summary-private-diagnostic')); await request; });
  expect(await screen.findByText(/Gateway status is unavailable/)).toBeInTheDocument();
  expect(screen.queryByText('owned-summary-uptime')).not.toBeInTheDocument();
});

it.each(['wrong-gateway', 'missing', 'null', 'negative-count', 'fraction-count', 'wrong-sum', 'string-count', 'object-hostname'])('rejects device-summary %s', async bad => {
  const data: Record<string, unknown> = summary();
  const body = data.summary as Record<string, unknown>;
  if (bad === 'wrong-gateway') data.gateway_id = 'wrong-gateway';
  else if (bad === 'missing') delete data.summary;
  else if (bad === 'null') data.summary = null;
  else if (bad === 'negative-count') body.interface_count = -1;
  else if (bad === 'fraction-count') body.interface_count = 2.5;
  else if (bad === 'wrong-sum') body.interfaces_up = 2;
  else if (bad === 'string-count') body.interface_count = '2';
  else body.hostname = {};
  state.summary.mockResolvedValue({ data });
  await showSummary();
  expect(screen.getByText(/Gateway status is unavailable/)).toBeInTheDocument();
  expect(screen.queryByText('owned-summary-uptime')).not.toBeInTheDocument();
});

it.each(['tailscale', 'proxy', 'crowdsec', 'monit', 'telegraf', 'netflow'] as const)('refuses a string instead of %s running boolean', async kind => {
  const data = envelope(kind);
  (data[kind] as Record<string, unknown>).running = 'false';
  state[kind].mockResolvedValue({ data });
  await show(kind);
  expect(within(panel(kind)).getByText(/Gateway status is unavailable/)).toBeInTheDocument();
});

it.each([['haproxy', 'servers', 'server_count'], ['crowdsec', 'alerts', 'alert_count'], ['monit', 'services', 'service_count']] as const)('refuses mismatched %s %s counts', async (kind, _rows, count) => {
  const data = envelope(kind);
  (data[kind] as Record<string, unknown>)[count] = 1;
  state[kind].mockResolvedValue({ data });
  await show(kind);
  expect(within(panel(kind)).getByText(/Gateway status is unavailable/)).toBeInTheDocument();
});

it.each([['haproxy', 'servers', 'server_count'], ['crowdsec', 'alerts', 'alert_count'], ['monit', 'services', 'service_count']] as const)('refuses nested %s %s row data', async (kind, rows, count) => {
  const data = envelope(kind);
  const body = data[kind] as Record<string, unknown>;
  body[rows] = [{ name: { nested: 'owned-nested-payload' } }]; body[count] = 1;
  state[kind].mockResolvedValue({ data });
  await show(kind);
  expect(within(panel(kind)).getByText(/Gateway status is unavailable/)).toBeInTheDocument();
});

it.each(['string', 'array', 'object', 'deep'])('redacts %s VPN secret values while retaining public keys', async shape => {
  const marker = 'owned-private-vpn-marker';
  let nested: Record<string, unknown> = { private_key: shape === 'array' ? [marker] : shape === 'object' ? { value: marker } : marker };
  if (shape === 'deep') for (let depth = 0; depth < 15; depth++) nested = { child: nested };
  state.vpn.mockResolvedValue({ data: { gateway_id: ID, tunnels: { public_key: 'owned-public-vpn-key', nested } } });
  await show('vpn');
  expect(panel('vpn').textContent).toContain('owned-public-vpn-key');
  expect(panel('vpn').textContent).not.toContain(marker);
});
