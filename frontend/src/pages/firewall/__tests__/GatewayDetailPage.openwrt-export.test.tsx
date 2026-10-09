// SPDX-License-Identifier: AGPL-3.0-only
/** Actual OpenWRT page/tab; synthetic identity, API replies and file APIs. */
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { useNavigate } from 'react-router-dom';
import GatewayDetailPage from '../GatewayDetailPage';
import { renderWithProviders } from '@/test-utils';
import { useAuthStore } from '@/stores/authStore';
import { gatewayApi } from '@/lib/api';

const state = vi.hoisted(() => ({ toast: vi.fn(), download: vi.fn(), sync: vi.fn() }));
const ID = '12345678-1234-4123-8123-123456789abc';
const NEXT = '12345678-1234-4123-8123-123456789def';
const PRIVATE = 'owned-openwrt-private-diagnostic';
const bytes = Uint8Array.from([31, 139, 0, 255, 128, 65, 0]);
const originalAuth = useAuthStore.getState();
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: state.toast }) }));
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  const getById = vi.fn(async (id: string) => ({ data: { id, name: 'Owned OpenWRT', vendor: 'openwrt', host: 'gateway.example.test', port: 443, is_online: true, capabilities: [], settings: {} } }));
  const empty = vi.fn().mockResolvedValue({ data: {} });
  return { ...actual, gatewayApi: new Proxy({ getById, downloadConfig: state.download, triggerSync: state.sync }, {
    get: (target, key) => key in target ? target[key as keyof typeof target] : empty,
  }), sitesApiV2: { list: vi.fn().mockResolvedValue({ data: { items: [] } }) } };
});
vi.mock('@/lib/api/openwrt', () => ({ openwrtApi: new Proxy({}, { get: () => vi.fn().mockResolvedValue({ data: { items: [] } }) }) }));

function identity(role: string | null, permissions = ['controller:write'], superuser = false) {
  useAuthStore.setState({ user: role ? { id: ID, email: 'owned@example.test', first_name: 'Owned', last_name: '', username: 'owned', full_name: 'Owned', role, organization_id: ID, is_active: true, is_superuser: superuser, is_org_admin: superuser, mfa_enabled: false, permissions, roles: [role] } : null });
}
function response(gateway = ID) {
  return { data: { gateway_id: gateway, vendor: 'openwrt', config: { backup_data: btoa(String.fromCharCode(...bytes)), encoding: 'base64', format: 'tar.gz', scope: 'sysupgrade' } } };
}
let created: ReturnType<typeof vi.fn>;
let clicks: string[];
beforeEach(() => {
  vi.clearAllMocks();
  identity('super_admin');
  state.download.mockReset().mockResolvedValue(response());
  state.sync.mockReset().mockResolvedValue({ data: { success: true } });
  created = vi.fn().mockReturnValue('blob:owned-openwrt-export');
  vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: created, revokeObjectURL: vi.fn() }));
  clicks = [];
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) { clicks.push(this.download); });
});
afterEach(() => {
  vi.restoreAllMocks(); vi.unstubAllGlobals(); useAuthStore.setState(originalAuth, true);
});
function Navigator() {
  const navigate = useNavigate();
  return <button onClick={() => navigate(`/firewall/gateways/${NEXT}/system`)}>Other gateway</button>;
}
async function show() {
  const view = renderWithProviders(<><Navigator /><GatewayDetailPage /></>, { initialPath: `/firewall/gateways/${ID}/system`, routePath: '/firewall/gateways/:id/:tab' });
  await screen.findByText('Owned OpenWRT');
  return view;
}
function button() { return screen.getByRole('button', { name: 'Download Config' }); }

it.each([false, true])('offers export to an authorized super administrator (superuser=%s)', async (superuser) => {
  identity('super_admin', superuser ? [] : ['controller:write'], superuser);
  await show(); expect(button()).toBeEnabled(); expect(state.download).not.toHaveBeenCalled();
});
it.each(['viewer', 'org_admin', 'missing-permission', 'anonymous'])('does not offer full-secret export for %s', async (kind) => {
  identity(kind === 'anonymous' ? null : kind === 'missing-permission' ? 'super_admin' : kind, kind === 'missing-permission' ? [] : ['controller:write']);
  await show(); expect(screen.queryByRole('button', { name: 'Download Config' })).not.toBeInTheDocument(); expect(state.download).not.toHaveBeenCalled();
});
it('downloads original archive bytes through the real OpenWRT page without caching them', async () => {
  const view = await show(); fireEvent.click(button());
  await waitFor(() => expect(created).toHaveBeenCalledOnce());
  const blob = created.mock.calls[0][0] as Blob;
  const contents = await new Promise<Uint8Array>((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer)); reader.onerror = () => reject(reader.error); reader.readAsArrayBuffer(blob); });
  expect(contents).toEqual(bytes); expect(blob.type).toBe('application/gzip');
  expect(clicks).toEqual([`freesdn-gateway-${ID}-config.tar.gz`]);
  expect(state.download.mock.calls[0][0]).toBe(ID); expect(state.download.mock.calls[0][1]).toBeInstanceOf(AbortSignal);
  expect(JSON.stringify(view.queryClient.getQueryCache().getAll().map((q) => q.state.data))).not.toContain(response().data.config.backup_data);
  expect(view.queryClient.getMutationCache().getAll()).toHaveLength(0);
});
it('disables the export control and refuses duplicate clicks while pending', async () => {
  let resolve!: (value: unknown) => void;
  state.download.mockReturnValue(new Promise((done) => { resolve = done; })); await show(); const control = button();
  fireEvent.click(control); fireEvent.click(control); expect(state.download).toHaveBeenCalledOnce(); expect(control).toBeDisabled(); expect(control).toHaveAttribute('aria-busy', 'true');
  await act(async () => { resolve(response()); }); expect(control).toBeEnabled();
});
it('shows a fixed error without provider diagnostics', async () => {
  state.download.mockRejectedValue({ response: { data: { detail: PRIVATE } } }); await show(); fireEvent.click(button());
  await waitFor(() => expect(state.toast).toHaveBeenCalled()); expect(JSON.stringify(state.toast.mock.calls)).not.toContain(PRIVATE); expect(created).not.toHaveBeenCalled();
  expect(state.toast).toHaveBeenLastCalledWith(expect.objectContaining({ title: 'Configuration download failed', variant: 'destructive' }));
});
it('rejects an archive for another gateway', async () => {
  state.download.mockResolvedValue(response(NEXT)); await show(); fireEvent.click(button()); await waitFor(() => expect(state.toast).toHaveBeenCalled()); expect(created).not.toHaveBeenCalled();
});
it.each(['resolve', 'reject'])('aborts and ignores a late %s after unmount', async (outcome) => {
  let resolve!: (value: unknown) => void; let reject!: (reason: unknown) => void;
  state.download.mockReturnValue(new Promise((done, fail) => { resolve = done; reject = fail; })); const view = await show(); fireEvent.click(button()); const signal = state.download.mock.calls[0][1] as AbortSignal; view.unmount();
  await act(async () => { if (outcome === 'resolve') resolve(response()); else reject(new Error(PRIVATE)); }); expect(signal.aborted).toBe(true); expect(created).not.toHaveBeenCalled(); expect(state.toast).not.toHaveBeenCalled();
});
it('does not download after navigation to another gateway', async () => {
  let resolve!: (value: unknown) => void; state.download.mockReturnValue(new Promise((done) => { resolve = done; })); await show(); fireEvent.click(button()); fireEvent.click(screen.getByRole('button', { name: 'Other gateway' })); await waitFor(() => expect(gatewayApi.getById).toHaveBeenCalledWith(NEXT));
  await act(async () => { resolve(response()); }); expect(created).not.toHaveBeenCalled(); expect(state.toast).not.toHaveBeenCalled();
});
it('does not request configuration when the page is opened', async () => { await show(); expect(state.download).not.toHaveBeenCalled(); });
it('preserves the existing sync control without starting an export', async () => {
  await show(); fireEvent.click(screen.getByRole('button', { name: 'Sync' })); await waitFor(() => expect(state.sync).toHaveBeenCalled()); expect(state.download).not.toHaveBeenCalled();
});
