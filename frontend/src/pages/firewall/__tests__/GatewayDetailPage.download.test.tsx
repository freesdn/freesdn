// SPDX-License-Identifier: AGPL-3.0-only
/** Real page and tabs; API outcomes and browser file APIs are controlled. */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { useNavigate } from 'react-router-dom';
import GatewayDetailPage from '../GatewayDetailPage';
import { gatewayApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

const state = vi.hoisted(() => ({ toast: vi.fn(), download: vi.fn() }));
const ID = '12345678-1234-4123-8123-123456789abc';
const NEXT = '12345678-1234-4123-8123-123456789def';
const PRIVATE = 'private-fixture-error-body';
const XML = '\ufeff<?xml version="1.0"?>\n<opnsense>α\nowned</opnsense>\n';

vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: state.toast }) }));
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  const getById = vi.fn(async (id: string) => ({ data: {
    id, name: 'Owned gateway', vendor: 'opnsense', host: 'gateway.example.test',
    port: 443, is_online: true, capabilities: [], settings: {},
  } }));
  const empty = vi.fn().mockResolvedValue({ data: {} });
  return {
    ...actual,
    gatewayApi: new Proxy({ getById, downloadConfig: state.download }, {
      get: (target, key) => key in target ? target[key as keyof typeof target] : empty,
    }),
    sitesApiV2: { list: vi.fn().mockResolvedValue({ data: { items: [] } }) },
  };
});

let created: ReturnType<typeof vi.fn>;
let revoked: ReturnType<typeof vi.fn>;
let clicks: { href: string; filename: string }[];

beforeEach(() => {
  vi.clearAllMocks();
  state.download.mockReset();
  state.download.mockResolvedValue({ data: { gateway_id: ID, vendor: 'opnsense', config: { config_xml: XML } } });
  created = vi.fn().mockReturnValue('blob:owned-download');
  revoked = vi.fn();
  vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: created, revokeObjectURL: revoked }));
  clicks = [];
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
    clicks.push({ href: this.href, filename: this.download });
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function Navigator() {
  const navigate = useNavigate();
  return <button onClick={() => navigate(`/firewall/gateways/${NEXT}/system`)}>Other gateway</button>;
}

async function show(tab = 'system') {
  const result = renderWithProviders(<><Navigator /><GatewayDetailPage /></>, {
    initialPath: `/firewall/gateways/${ID}/${tab}`, routePath: '/firewall/gateways/:id/:tab',
  });
  await screen.findByText('Owned gateway');
  return result;
}

async function button() {
  return screen.findByRole('button', { name: 'Download Config' });
}

function readBlob(blob: Blob): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(blob);
  });
}

describe('gateway configuration file download', () => {
  it('saves exact XML from the real system button without a write-success flag', async () => {
    const view = await show();
    fireEvent.click(await button());
    await waitFor(() => expect(state.toast).toHaveBeenCalled());
    expect(created).toHaveBeenCalledOnce();
    expect(clicks).toEqual([{ href: 'blob:owned-download', filename: `freesdn-gateway-${ID}-config.xml` }]);
    const blob = created.mock.calls[0][0] as Blob;
    expect(blob.type).toBe('application/xml');
    expect(await readBlob(blob)).toEqual(new TextEncoder().encode(XML));
    expect(state.toast).toHaveBeenLastCalledWith(expect.objectContaining({ title: 'Configuration download started' }));
    expect(JSON.stringify(view.queryClient.getQueryCache().getAll().map((q) => q.state.data))).not.toContain('owned</opnsense>');
    expect(view.queryClient.getMutationCache().getAll()).toHaveLength(0);
    expect(document.querySelector('a[download]')).toBeNull();
  });

  it('decodes a binary archive and saves its original bytes', async () => {
    const bytes = Uint8Array.from([31, 139, 0, 255, 128, 65, 0]);
    state.download.mockResolvedValue({ data: { gateway_id: ID, vendor: 'openwrt', config: {
      backup_data: btoa(String.fromCharCode(...bytes)), encoding: 'base64', format: 'tar.gz', scope: '/etc/config/',
    } } });
    await show();
    fireEvent.click(await button());
    await waitFor(() => expect(state.toast).toHaveBeenCalled());
    expect(created).toHaveBeenCalledOnce();
    expect(await readBlob(created.mock.calls[0][0] as Blob)).toEqual(bytes);
    expect(clicks[0].filename).toBe(`freesdn-gateway-${ID}-config.tar.gz`);
  });

  it('suppresses duplicate clicks while an export request is pending', async () => {
    let resolve!: (value: unknown) => void;
    state.download.mockReturnValue(new Promise((done) => { resolve = done; }));
    await show();
    const download = await button();
    fireEvent.click(download);
    fireEvent.click(download);
    expect(state.download).toHaveBeenCalledOnce();
    expect(download).toBeDisabled();
    await act(async () => { resolve({ data: { gateway_id: ID, config: { config_xml: '<opnsense/>' } } }); });
    expect(download).not.toBeDisabled();
  });

  it('supplies an abort signal to the configuration request', async () => {
    await show();
    fireEvent.click(await button());
    await waitFor(() => expect(state.download).toHaveBeenCalled());
    expect(state.download.mock.calls[0][0]).toBe(ID);
    expect(state.download.mock.calls[0][1]).toBeInstanceOf(AbortSignal);
  });

  it.each(['resolve', 'reject'])('ignores a late %s after unmount', async (outcome) => {
    let resolve!: (value: unknown) => void;
    let reject!: (reason: unknown) => void;
    state.download.mockReturnValue(new Promise((done, fail) => { resolve = done; reject = fail; }));
    const view = await show();
    fireEvent.click(await button());
    const signal = state.download.mock.calls[0][1] as AbortSignal | undefined;
    view.unmount();
    await act(async () => {
      if (outcome === 'resolve') resolve({ data: { gateway_id: ID, config: { config_xml: XML } } });
      else reject(new Error(PRIVATE));
    });
    expect(created).not.toHaveBeenCalled();
    expect(state.toast).not.toHaveBeenCalled();
    expect(signal?.aborted).toBe(true);
  });

  it('ignores a response after navigation to a different gateway', async () => {
    let resolve!: (value: unknown) => void;
    state.download.mockReturnValue(new Promise((done) => { resolve = done; }));
    await show();
    fireEvent.click(await button());
    fireEvent.click(screen.getByRole('button', { name: 'Other gateway' }));
    await waitFor(() => expect(gatewayApi.getById).toHaveBeenCalledWith(NEXT));
    await act(async () => { resolve({ data: { gateway_id: ID, config: { config_xml: XML } } }); });
    expect(created).not.toHaveBeenCalled();
    expect(state.toast).not.toHaveBeenCalled();
  });

  it('shows a fixed failure without reflecting server diagnostics', async () => {
    state.download.mockRejectedValue({ response: { data: { detail: PRIVATE } } });
    await show();
    fireEvent.click(await button());
    await waitFor(() => expect(state.toast).toHaveBeenCalled());
    expect(JSON.stringify(state.toast.mock.calls)).not.toContain(PRIVATE);
    expect(state.toast).toHaveBeenLastCalledWith(expect.objectContaining({ title: 'Configuration download failed', variant: 'destructive' }));
    expect(created).not.toHaveBeenCalled();
  });

  it('has one export action even when there is no backup history', async () => {
    await show('backups');
    fireEvent.click(await screen.findByRole('button', { name: 'Export configuration' }));
    await waitFor(() => expect(state.download).toHaveBeenCalledOnce());
    await waitFor(() => expect(created).toHaveBeenCalledOnce());
  });

  it.each([{}, { gateway_id: ID, config: {} }, { gateway_id: NEXT, config: { config_xml: XML } }])('does not save an incomplete or mismatched response %#', async (data) => {
    state.download.mockResolvedValue({ data });
    await show();
    fireEvent.click(await button());
    await waitFor(() => expect(state.toast).toHaveBeenCalled());
    expect(created).not.toHaveBeenCalled();
    expect(clicks).toHaveLength(0);
  });

  it('does not fetch an export just because the page is opened', async () => {
    await show();
    expect(state.download).not.toHaveBeenCalled();
  });
});
