/** Actual page/query panels with synthetic read-only gateway responses. */
import { beforeEach, expect, it, vi } from 'vitest';
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import GatewayDetailPage from '../GatewayDetailPage';
import { renderWithProviders } from '@/test-utils';

const state = vi.hoisted(() => ({
  vpn: vi.fn(), tailscale: vi.fn(), haproxy: vi.fn(), proxy: vi.fn(),
  crowdsec: vi.fn(), monit: vi.fn(), telegraf: vi.fn(), netflow: vi.fn(),
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
const envelope = (kind: Kind) => ({ gateway_id: ID, vendor: 'opnsense', ...structuredClone(payloads[kind]) });
const panel = (kind: Kind) => screen.getByText(definitions[kind].heading).closest('[class*="rounded-lg"]') as HTMLElement;

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  const getById = vi.fn(async (id: string) => ({ data: { id, name: 'Owned aggregate gateway', vendor: 'opnsense', host: 'gateway.example.test', port: 443, is_online: true, capabilities: [], settings: {} } }));
  const empty = vi.fn().mockResolvedValue({ data: {} });
  const methods = { getById, getVPN: state.vpn, getTailscaleStatus: state.tailscale, getHAProxyStatus: state.haproxy, getProxySettings: state.proxy, getCrowdSecStatus: state.crowdsec, getMonitStatus: state.monit, getTelegrafStatus: state.telegraf, getNetFlowStatus: state.netflow };
  return { ...actual, gatewayApi: new Proxy(methods, { get: (target, name) => name in target ? target[name as keyof typeof target] : empty }), sitesApiV2: { list: vi.fn().mockResolvedValue({ data: { items: [] } }) } };
});

beforeEach(() => {
  for (const kind of kinds) state[kind].mockReset().mockResolvedValue({ data: envelope(kind) });
});

async function show(kind: Kind) {
  const view = renderWithProviders(<GatewayDetailPage />, { initialPath: `/firewall/gateways/${ID}/${definitions[kind].tab}`, routePath: '/firewall/gateways/:id/:tab' });
  await screen.findByText('Owned aggregate gateway');
  await waitFor(() => expect(state[kind]).toHaveBeenCalledWith(ID));
  await waitFor(() => expect(view.queryClient.getQueryState(['gateways', ID, kind])?.fetchStatus).toBe('idle'));
  return view;
}

it.each(kinds)('renders confirmed %s status without an unavailable warning', async (kind) => {
  await show(kind);
  expect(within(panel(kind)).queryByText(/Gateway status is unavailable/)).not.toBeInTheDocument();
  expect(within(panel(kind)).queryByText(/Loading gateway status/)).not.toBeInTheDocument();
});

it.each(kinds)('shows unavailable %s reads and retries without exposing diagnostics', async (kind) => {
  state[kind].mockRejectedValueOnce(new Error('owned-private-aggregate-device-error'));
  await show(kind);
  expect(await within(panel(kind)).findByText(/Gateway status is unavailable/)).toBeInTheDocument();
  expect(screen.queryByText(/owned-private-aggregate-device-error/)).not.toBeInTheDocument();
  fireEvent.click(within(panel(kind)).getByRole('button', { name: /Retry/ }));
  await waitFor(() => expect(state[kind]).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(within(panel(kind)).queryByText(/Gateway status is unavailable|Loading gateway status/)).not.toBeInTheDocument());
});

it.each(kinds)('hides stale %s status while refresh is pending and after failure', async (kind) => {
  const view = await show(kind);
  let reject!: (error: Error) => void;
  state[kind].mockReturnValue(new Promise((_resolve, fail) => { reject = fail; }));
  let request!: Promise<void>;
  await act(async () => { request = view.queryClient.refetchQueries({ queryKey: ['gateways', ID, kind], exact: true }); });
  expect(await within(panel(kind)).findByText(/Loading gateway status/)).toBeInTheDocument();
  expect(within(panel(kind)).queryAllByText(/^(Running|Stopped|Enabled|Disabled|On|Off|0)$/)).toHaveLength(0);
  await act(async () => { reject(new Error('owned-private-aggregate-device-error')); await request; });
  expect(await within(panel(kind)).findByText(/Gateway status is unavailable/)).toBeInTheDocument();
  expect(within(panel(kind)).queryAllByText(/^(Running|Stopped|Enabled|Disabled|On|Off|0)$/)).toHaveLength(0);
});

it.each(kinds.flatMap(kind => ['missing', 'null', 'wrong-gateway', 'wrong-shape'].map(bad => [kind, bad] as const)))('rejects %s %s responses', async (kind, bad) => {
  let data: unknown;
  if (bad === 'missing') data = {};
  else if (bad === 'null') data = null;
  else if (bad === 'wrong-gateway') data = { ...envelope(kind), gateway_id: 'another-gateway' };
  else data = { gateway_id: ID, vendor: 'opnsense', [kind === 'vpn' ? 'tunnels' : kind]: [] };
  state[kind].mockResolvedValue({ data });
  await show(kind);
  expect(await within(panel(kind)).findByText(/Gateway status is unavailable/)).toBeInTheDocument();
});

it('renders normalized Monit service rows and boolean enabled values', async () => {
  state.monit.mockResolvedValue({ data: { gateway_id: ID, vendor: 'opnsense', monit: { running: true, services: [{ uuid: 'owned', name: 'Owned monitored service', enabled: true }], tests: [], alerts: [], service_count: 1, test_count: 0, alert_count: 0 } } });
  await show('monit');
  expect(within(panel('monit')).getByText('Owned monitored service')).toBeInTheDocument();
  expect(within(panel('monit')).getByText('Yes')).toBeInTheDocument();
});

it('renders normalized Telegraf output details', async () => {
  await show('telegraf');
  expect(within(panel('telegraf')).getByText('https://metrics.example.test')).toBeInTheDocument();
  expect(within(panel('telegraf')).getByText('Running')).toBeInTheDocument();
});

it('renders normalized NetFlow interface and version fields', async () => {
  await show('netflow');
  expect(within(panel('netflow')).getByText('owned-interface')).toBeInTheDocument();
  expect(within(panel('netflow')).getByText('v9')).toBeInTheDocument();
});

it('renders normalized CrowdSec decision fields', async () => {
  state.crowdsec.mockResolvedValue({ data: { gateway_id: ID, vendor: 'opnsense', crowdsec: { running: true, alerts: [], decisions: [{ id: 'owned', value: '192.0.2.25', type: 'ban', scope: 'Ip', origin: 'owned-origin', duration: '4h' }], alert_count: 0, decision_count: 1 } } });
  await show('crowdsec');
  expect(within(panel('crowdsec')).getByText('192.0.2.25')).toBeInTheDocument();
  expect(within(panel('crowdsec')).getByText('4h')).toBeInTheDocument();
});
