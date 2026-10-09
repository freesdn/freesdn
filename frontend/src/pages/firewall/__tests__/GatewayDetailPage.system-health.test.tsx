/** Actual overview queries; synthetic responses, no device/authentication claim. */
import { beforeEach, expect, it, vi } from 'vitest';
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import GatewayDetailPage from '../GatewayDetailPage';
import { renderWithProviders } from '@/test-utils';

const state = vi.hoisted(() => ({ firmware: vi.fn(), health: vi.fn() }));
const ID = '12345678-1234-4123-8123-123456789abc';
const kinds = ['firmware', 'health'] as const;
type Kind = typeof kinds[number];
const firmware = () => ({ current_version: 'owned-live-version', latest_version: null, update_available: null });
const health = () => ({ name: 'owned-live-gateway', status: 'online', status_text: 'En ligne', loss_pct: 0, delay_ms: 0, stddev_ms: 0, default_gateway: true });
const envelope = (kind: Kind) => ({ gateway_id: ID, vendor: 'opnsense', ...(kind === 'firmware' ? { firmware: firmware() } : { gateways: [health()], count: 1 }) });
const panel = (kind: Kind) => screen.getByText(kind === 'firmware' ? 'Firmware & Sync' : 'WAN Gateway Health').closest('[class*="rounded-lg"]') as HTMLElement;
const field = (label: string) => within(panel('firmware')).getByText(label, { selector: 'dt' }).nextElementSibling;
const marker = (kind: Kind) => kind === 'firmware' ? 'owned-live-version' : 'owned-live-gateway';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  const getById = vi.fn(async (id: string) => ({ data: {
    id, name: 'Owned health gateway', vendor: 'opnsense', host: 'gateway.example.test', port: 443,
    is_online: true, capabilities: [], settings: {}, sync_enabled: true, sync_status: 'owned-sync',
    detected_version: 'owned-stored-version',
  } }));
  const getDeviceSummary = vi.fn().mockResolvedValue({ data: { gateway_id: '12345678-1234-4123-8123-123456789abc', vendor: 'opnsense', summary: {
    hostname: 'owned-host', version: 'owned-summary-version', interface_count: 0, interfaces_up: 0, interfaces_down: 0, wan_status: 'unknown',
  } } });
  const empty = vi.fn().mockResolvedValue({ data: {} });
  const methods = { getById, getDeviceSummary, getFirmware: state.firmware, getGatewayHealth: state.health };
  return { ...actual, gatewayApi: new Proxy(methods, { get: (target, name) => name in target ? target[name as keyof typeof target] : empty }), sitesApiV2: { list: vi.fn().mockResolvedValue({ data: { items: [] } }) } };
});
beforeEach(() => { for (const kind of kinds) state[kind].mockReset().mockResolvedValue({ data: envelope(kind) }); });
function render() { return renderWithProviders(<GatewayDetailPage />, { initialPath: `/firewall/gateways/${ID}/overview`, routePath: '/firewall/gateways/:id/:tab' }); }
async function show(kind: Kind) {
  const view = render();
  await screen.findAllByText('Owned health gateway');
  await waitFor(() => expect(state[kind]).toHaveBeenCalledWith(ID));
  await waitFor(() => expect(view.queryClient.getQueryState(['gateways', ID, kind])?.fetchStatus).toBe('idle'));
  return view;
}

it.each(kinds)('shows a valid %s read', async kind => {
  await show(kind);
  expect(within(panel(kind)).getByText(marker(kind))).toBeInTheDocument();
  expect(within(panel(kind)).queryByText(/Gateway status is unavailable/)).not.toBeInTheDocument();
});
it.each(kinds)('reports %s failure and retries without private diagnostics', async kind => {
  state[kind].mockRejectedValueOnce(new Error('owned-private-health-error'));
  await show(kind);
  expect(await within(panel(kind)).findByText(/Gateway status is unavailable/)).toBeInTheDocument();
  expect(screen.queryByText(/owned-private-health-error/)).not.toBeInTheDocument();
  fireEvent.click(within(panel(kind)).getByRole('button', { name: /Retry/ }));
  expect(await within(panel(kind)).findByText(marker(kind))).toBeInTheDocument();
  expect(state[kind]).toHaveBeenCalledTimes(2);
});
it.each(kinds)('hides stale %s data during refresh and after failure', async kind => {
  const view = await show(kind);
  let reject!: (error: Error) => void;
  state[kind].mockReturnValue(new Promise((_resolve, fail) => { reject = fail; }));
  let pending!: Promise<void>;
  await act(async () => { pending = view.queryClient.refetchQueries({ queryKey: ['gateways', ID, kind], exact: true }); });
  expect(await within(panel(kind)).findByText(/Loading gateway status/)).toBeInTheDocument();
  expect(within(panel(kind)).queryByText(marker(kind))).not.toBeInTheDocument();
  if (kind === 'firmware') expect(screen.queryByText('owned-stored-version')).not.toBeInTheDocument();
  await act(async () => { reject(new Error('owned-private-health-error')); await pending; });
  expect(await within(panel(kind)).findByText(/Gateway status is unavailable/)).toBeInTheDocument();
  expect(within(panel(kind)).queryByText(marker(kind))).not.toBeInTheDocument();
  expect(within(panel('firmware')).getByText('owned-sync')).toBeInTheDocument();
});
it.each(kinds)('shows initial %s loading without definitive state', async kind => {
  state[kind].mockReturnValue(new Promise(() => {}));
  render();
  await screen.findAllByText('Owned health gateway');
  expect(await within(panel(kind)).findByText(/Loading gateway status/)).toBeInTheDocument();
  expect(within(panel(kind)).queryByText(marker(kind))).not.toBeInTheDocument();
});
it.each(kinds.flatMap(kind => ['missing', 'null', 'wrong-id', 'wrong-shape'].map(bad => [kind, bad] as const)))('rejects %s %s envelope', async (kind, bad) => {
  const data = bad === 'null' ? null : bad === 'missing' ? {} : bad === 'wrong-id' ? { ...envelope(kind), gateway_id: 'another-gateway' }
    : { gateway_id: ID, vendor: 'opnsense', ...(kind === 'firmware' ? { firmware: [] } : { gateways: {}, count: 0 }) };
  state[kind].mockResolvedValue({ data });
  await show(kind);
  expect(await within(panel(kind)).findByText(/Gateway status is unavailable/)).toBeInTheDocument();
  expect(within(panel(kind)).queryByText(marker(kind))).not.toBeInTheDocument();
});
it.each([[null, 'Unknown'], [false, 'No'], [true, 'Yes (?)']] as const)('preserves firmware availability %s', async (available, expected) => {
  state.firmware.mockResolvedValue({ data: { ...envelope('firmware'), firmware: { ...firmware(), update_available: available } } });
  await show('firmware');
  expect(field('Update Available')).toHaveTextContent(expected);
});
it('does not invent a latest firmware version from the current version', async () => {
  await show('firmware');
  expect(field('Latest Version')).toHaveTextContent('Unknown');
});
it.each(['delay_ms', 'loss_pct', 'stddev_ms'])('renders measured zero %s', async fieldName => {
  await show('health');
  const label = { delay_ms: 'Latency:', loss_pct: 'Loss:', stddev_ms: 'Jitter:' }[fieldName]!;
  expect(within(panel('health')).getByText(label).textContent).toContain(fieldName === 'loss_pct' ? '0.0%' : '0.0 ms');
});
it.each(['delay_ms', 'loss_pct', 'stddev_ms'])('renders missing %s as unknown', async fieldName => {
  state.health.mockResolvedValue({ data: { ...envelope('health'), gateways: [{ ...health(), [fieldName]: null }] } });
  await show('health');
  const label = { delay_ms: 'Latency:', loss_pct: 'Loss:', stddev_ms: 'Jitter:' }[fieldName]!;
  expect(within(panel('health')).getByText(label).textContent).toContain('Unknown');
});
it.each([['none', 'Unmonitored'], ['pending', 'Pending'], ['loss', 'Packet loss'], ['delay', 'High latency'], ['future', 'Unknown']])('does not color %s as online because of a translated label', async (status, label) => {
  state.health.mockResolvedValue({ data: { ...envelope('health'), gateways: [{ ...health(), status, status_text: 'Online', loss_pct: null, delay_ms: null, stddev_ms: null }] } });
  await show('health');
  const badge = within(panel('health')).getByText(label, { selector: 'div' });
  expect(badge).not.toHaveClass('text-primary');
  expect(within(panel('health')).queryByText('Online')).not.toBeInTheDocument();
});
it('distinguishes a confirmed empty inventory from an unavailable inventory', async () => {
  state.health.mockResolvedValue({ data: { ...envelope('health'), gateways: [], count: 0 } });
  await show('health');
  expect(within(panel('health')).getByText('No WAN gateways reported')).toBeInTheDocument();
});
it.each(['count', 'measurement', 'identity', 'default'])('rejects malformed health %s', async bad => {
  const row = { ...health(), ...(bad === 'measurement' ? { loss_pct: 101 } : bad === 'identity' ? { name: '' } : bad === 'default' ? { default_gateway: 'false' } : {}) };
  state.health.mockResolvedValue({ data: { ...envelope('health'), gateways: [row], count: bad === 'count' ? 2 : 1 } });
  await show('health');
  expect(await within(panel('health')).findByText(/Gateway status is unavailable/)).toBeInTheDocument();
});
it('rejects string firmware availability rather than treating it as true', async () => {
  state.firmware.mockResolvedValue({ data: { ...envelope('firmware'), firmware: { ...firmware(), update_available: 'false' } } });
  await show('firmware');
  expect(await within(panel('firmware')).findByText(/Gateway status is unavailable/)).toBeInTheDocument();
});
