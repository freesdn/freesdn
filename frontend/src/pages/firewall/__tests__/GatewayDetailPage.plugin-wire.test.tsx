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


function crowdsecWindow(field: 'alerts' | 'decisions', total: number) {
  const count = Math.min(total, 50);
  const body = { running: true, alerts: [] as Record<string, unknown>[], decisions: [] as Record<string, unknown>[], alert_count: 0, decision_count: 0, alert_total: 0, decision_total: 0, alert_truncated: false, decision_truncated: false };
  body[field] = Array.from({ length: count }, (_, id) => ({ id, value: '192.0.2.1', scope: 'Ip', origin: 'owned-source', type: 'ban', duration: '4h' }));
  if (field === 'alerts') { body.alert_count = count; body.alert_total = total; body.alert_truncated = total > count; }
  else { body.decision_count = count; body.decision_total = total; body.decision_truncated = total > count; }
  return { gateway_id: ID, vendor: 'opnsense', crowdsec: body };
}

it.each((['alerts', 'decisions'] as const).flatMap(field => [0, 1, 75].map(total => [field, total] as const)))('shows truthful %s totals and bounded-window context at %s', async (field, total) => {
  state.crowdsec.mockResolvedValue({ data: crowdsecWindow(field, total) });
  await show('crowdsec');
  const card = within(panel('crowdsec'));
  if (total) expect(card.getByText(String(total), { exact: true })).toBeInTheDocument();
  if (total > 50) expect(card.getByText(`Showing 50 of ${total} ${field}. Only the first 50 records are retrieved.`)).toBeInTheDocument();
  else expect(card.queryByText(/Only the first 50/)).not.toBeInTheDocument();
});

it('labels CrowdSec origin as Source', async () => {
  state.crowdsec.mockResolvedValue({ data: crowdsecWindow('decisions', 1) });
  await show('crowdsec');
  expect(within(panel('crowdsec')).getByRole('columnheader', { name: /^Source$/ })).toBeInTheDocument();
});

it('displays the sanitized InfluxDB v2 endpoint', async () => {
  state.telegraf.mockResolvedValue({ data: { gateway_id: ID, vendor: 'opnsense', telegraf: { enabled: true, running: true, output_influxdb: true, output_graphite: false, output_prometheus: false, output_influxdb_v2: true, influx_v2_url: 'https://owned-v2.example.test/metrics' } } });
  await show('telegraf');
  expect(within(panel('telegraf')).getByText('InfluxDB v2 URL')).toBeInTheDocument();
  expect(within(panel('telegraf')).getByText('https://owned-v2.example.test/metrics')).toBeInTheDocument();
});

it.each(['alerts', 'decisions'] as const)('hides stale %s totals and window notices on refresh failure', async field => {
  state.crowdsec.mockResolvedValue({ data: crowdsecWindow(field, 75) });
  const view = await show('crowdsec');
  expect(within(panel('crowdsec')).getByText(/Only the first 50/)).toBeInTheDocument();
  let reject!: (error: Error) => void;
  state.crowdsec.mockReturnValue(new Promise((_resolve, fail) => { reject = fail; }));
  let pending!: Promise<void>;
  await act(async () => { pending = view.queryClient.refetchQueries({ queryKey: ['gateways', ID, 'crowdsec'], exact: true }); });
  expect(await within(panel('crowdsec')).findByText(/Loading gateway status/)).toBeInTheDocument();
  expect(within(panel('crowdsec')).queryByText(/Only the first 50/)).not.toBeInTheDocument();
  await act(async () => { reject(new Error('owned-private-error')); await pending; });
  expect(await within(panel('crowdsec')).findByText(/Gateway status is unavailable/)).toBeInTheDocument();
  expect(within(panel('crowdsec')).queryByText('75', { exact: true })).not.toBeInTheDocument();
  expect(screen.queryByText(/owned-private-error/)).not.toBeInTheDocument();
  fireEvent.click(within(panel('crowdsec')).getByRole('button', { name: /Retry/ }));
});

it('refuses contradictory window metadata before rendering totals', async () => {
  const data = crowdsecWindow('decisions', 75); data.crowdsec.decision_truncated = false;
  state.crowdsec.mockResolvedValue({ data });
  await show('crowdsec');
  expect(await within(panel('crowdsec')).findByText(/Gateway status is unavailable/)).toBeInTheDocument();
  expect(within(panel('crowdsec')).queryByText('75', { exact: true })).not.toBeInTheDocument();
});
