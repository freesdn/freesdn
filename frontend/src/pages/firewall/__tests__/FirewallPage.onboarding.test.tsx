// SPDX-License-Identifier: AGPL-3.0-only
/** Exercise real onboarding interactions; API responses and device I/O are doubles. */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import FirewallPage from '../FirewallPage';
import { gatewayApi } from '@/lib/api';
import { useSiteStore } from '@/stores/siteStore';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    gatewayApi: {
      getAll: vi.fn().mockResolvedValue({ data: [] }),
      getSummary: vi.fn().mockResolvedValue({ data: null }),
      create: vi.fn(),
      update: vi.fn(),
      delete: vi.fn(),
      triggerSync: vi.fn(),
      testConnection: vi.fn(),
      testExisting: vi.fn(),
    },
    firewallApi: {
      getRules: vi.fn().mockResolvedValue({ data: [] }),
      getNATRules: vi.fn().mockResolvedValue({ data: [] }),
      getVPNTunnels: vi.fn().mockResolvedValue({ data: [] }),
      getVPNStats: vi.fn().mockResolvedValue({ data: {} }),
      getAlerts: vi.fn().mockResolvedValue({ data: [] }),
      getAlertStats: vi.fn().mockResolvedValue({ data: {} }),
      getLogs: vi.fn().mockResolvedValue({ data: [] }),
    },
    sitesApiV2: { list: vi.fn().mockResolvedValue({ data: { items: [] } }) },
  };
});

const testConnection = vi.mocked(gatewayApi.testConnection);
const create = vi.mocked(gatewayApi.create);
const vendors = ['OPNsense', 'pfSense', 'MikroTik RouterOS', 'OpenWRT'] as const;
const success = { data: { success: true, message: 'Verified synthetic gateway connection' } };

beforeEach(() => {
  vi.clearAllMocks();
  testConnection.mockReset();
  create.mockReset();
  testConnection.mockResolvedValue(success as never);
  create.mockResolvedValue({ data: { id: 'owned-gateway' } } as never);
  useSiteStore.setState({ selectedSiteId: null });
});

async function openDialog(user: ReturnType<typeof userEvent.setup>) {
  await user.click((await screen.findAllByRole('button', { name: 'Add Gateway' }))[0]);
  return within(await screen.findByRole('dialog', { name: 'Add Firewall Gateway' }));
}

async function fillGateway(user: ReturnType<typeof userEvent.setup>, vendor: typeof vendors[number] = 'OPNsense') {
  const dialog = await openDialog(user);
  await user.type(dialog.getByLabelText('Name'), 'Owned gateway');
  await user.type(dialog.getByLabelText('Host / IP'), 'gateway.example.test');
  await user.click(dialog.getAllByRole('combobox')[0]);
  await user.click(await screen.findByRole('option', { name: vendor }));
  if (vendor === 'MikroTik RouterOS' || vendor === 'OpenWRT') {
    await user.type(dialog.getByLabelText('Username'), 'fixture-operator');
    await user.type(dialog.getByLabelText('Password'), 'fixture-secret');
  } else {
    await user.type(dialog.getByLabelText('API Key'), 'fixture-key');
    await user.type(dialog.getByLabelText('API Secret'), 'fixture-secret');
  }
  return dialog;
}

describe('Firewall gateway onboarding certificate policy', () => {
  it.each(vendors)('verifies certificates by default for %s test and creation requests', async (vendor) => {
    const user = userEvent.setup();
    renderWithProviders(<FirewallPage />, { initialPath: '/firewall/gateways' });
    const dialog = await fillGateway(user, vendor);
    await user.click(dialog.getByRole('button', { name: 'Test Connection' }));
    await waitFor(() => expect(testConnection).toHaveBeenCalledOnce());
    expect(testConnection.mock.calls[0][0]).toMatchObject({ host: 'gateway.example.test', port: 443, verify_ssl: true });
    await user.click(dialog.getByRole('button', { name: 'Add Gateway' }));
    await waitFor(() => expect(create).toHaveBeenCalledOnce());
    expect(create.mock.calls[0][0]).toMatchObject({ name: 'Owned gateway', host: 'gateway.example.test', verify_ssl: true });
  });

  it.each(vendors)('requires a visible opt-out and warning for an unverified %s connection', async (vendor) => {
    const user = userEvent.setup();
    renderWithProviders(<FirewallPage />, { initialPath: '/firewall/gateways' });
    const dialog = await fillGateway(user, vendor);
    const verify = dialog.getByRole('checkbox', { name: 'Verify SSL certificate' });
    expect(verify).toBeChecked();
    await user.click(verify);
    expect(dialog.getByRole('alert')).toHaveTextContent(/credentials.*interception/i);
    await user.click(dialog.getByRole('button', { name: 'Test Connection' }));
    await waitFor(() => expect(testConnection).toHaveBeenCalledOnce());
    expect(testConnection.mock.calls[0][0].verify_ssl).toBe(false);
    await user.click(dialog.getByRole('button', { name: 'Add Gateway' }));
    await waitFor(() => expect(create).toHaveBeenCalledOnce());
    expect(create.mock.calls[0][0].verify_ssl).toBe(false);
  });

  it('clears credentials and restores the safe default after successful creation closes the dialog', async () => {
    const user = userEvent.setup();
    renderWithProviders(<FirewallPage />, { initialPath: '/firewall/gateways' });
    const dialog = await fillGateway(user);
    await user.click(dialog.getByRole('button', { name: 'Add Gateway' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    const next = await openDialog(user);
    expect(next.getByLabelText('Name')).toHaveValue('');
    expect(next.getByLabelText('Host / IP')).toHaveValue('');
    expect(next.getByRole('checkbox', { name: 'Verify SSL certificate' })).toBeChecked();
    expect(next.queryByDisplayValue('fixture-secret')).not.toBeInTheDocument();
  });

  it('does not silently weaken verification after a failed connection test', async () => {
    testConnection.mockResolvedValue({ data: { success: false, message: 'Synthetic certificate trust failure' } } as never);
    const user = userEvent.setup();
    renderWithProviders(<FirewallPage />, { initialPath: '/firewall/gateways' });
    const dialog = await fillGateway(user);
    await user.click(dialog.getByRole('button', { name: 'Test Connection' }));
    expect(await dialog.findByText('Synthetic certificate trust failure')).toBeInTheDocument();
    await user.click(dialog.getByRole('button', { name: 'Add Gateway' }));
    await waitFor(() => expect(create).toHaveBeenCalledOnce());
    expect(create.mock.calls[0][0].verify_ssl).toBe(true);
  });

  it('hides a prior successful test after connection fields change', async () => {
    const user = userEvent.setup();
    renderWithProviders(<FirewallPage />, { initialPath: '/firewall/gateways' });
    const dialog = await fillGateway(user);
    await user.click(dialog.getByRole('button', { name: 'Test Connection' }));
    expect(await dialog.findByText(success.data.message)).toBeInTheDocument();
    await user.type(dialog.getByLabelText('Host / IP'), '.changed');
    expect(dialog.queryByText(success.data.message)).not.toBeInTheDocument();
  });

  it('does not carry a test result into the next dialog', async () => {
    const user = userEvent.setup();
    renderWithProviders(<FirewallPage />, { initialPath: '/firewall/gateways' });
    const dialog = await fillGateway(user);
    await user.click(dialog.getByRole('button', { name: 'Test Connection' }));
    expect(await dialog.findByText(success.data.message)).toBeInTheDocument();
    await user.click(dialog.getByRole('button', { name: 'Close dialog' }));
    const next = await openDialog(user);
    expect(next.queryByText(success.data.message)).not.toBeInTheDocument();
  });

  it('ignores a late connection response after the dialog was closed and reopened', async () => {
    let resolve!: (value: never) => void;
    testConnection.mockImplementation(() => new Promise((done) => { resolve = done; }));
    const user = userEvent.setup();
    renderWithProviders(<FirewallPage />, { initialPath: '/firewall/gateways' });
    const dialog = await fillGateway(user);
    await user.click(dialog.getByRole('button', { name: 'Test Connection' }));
    await waitFor(() => expect(testConnection).toHaveBeenCalledOnce());
    await user.click(dialog.getByRole('button', { name: 'Close dialog' }));
    const next = await fillGateway(user);
    await act(async () => { resolve(success as never); });
    await waitFor(() => expect(next.getByRole('button', { name: 'Test Connection' })).toBeEnabled());
    expect(next.queryByText(success.data.message)).not.toBeInTheDocument();
  });

  it('ignores a pending response after the connection fields changed', async () => {
    let resolve!: (value: never) => void;
    testConnection.mockImplementation(() => new Promise((done) => { resolve = done; }));
    const user = userEvent.setup();
    renderWithProviders(<FirewallPage />, { initialPath: '/firewall/gateways' });
    const dialog = await fillGateway(user);
    await user.click(dialog.getByRole('button', { name: 'Test Connection' }));
    await waitFor(() => expect(testConnection).toHaveBeenCalledOnce());
    await user.type(dialog.getByLabelText('Host / IP'), '.changed');
    await act(async () => { resolve(success as never); });
    await waitFor(() => expect(dialog.getByRole('button', { name: 'Test Connection' })).toBeEnabled());
    expect(dialog.queryByText(success.data.message)).not.toBeInTheDocument();
  });

  it('requires another test after changing certificate verification policy', async () => {
    const user = userEvent.setup();
    renderWithProviders(<FirewallPage />, { initialPath: '/firewall/gateways' });
    const dialog = await fillGateway(user);
    await user.click(dialog.getByRole('button', { name: 'Test Connection' }));
    expect(await dialog.findByText(success.data.message)).toBeInTheDocument();
    await user.click(dialog.getByRole('checkbox', { name: 'Verify SSL certificate' }));
    expect(dialog.queryByText(success.data.message)).not.toBeInTheDocument();
    expect(dialog.getByRole('alert')).toHaveTextContent(/credentials.*interception/i);
  });

  it('reports a rejected test request without retaining success or weakening TLS', async () => {
    const user = userEvent.setup();
    renderWithProviders(<FirewallPage />, { initialPath: '/firewall/gateways' });
    const dialog = await fillGateway(user);
    await user.click(dialog.getByRole('button', { name: 'Test Connection' }));
    expect(await dialog.findByText(success.data.message)).toBeInTheDocument();
    testConnection.mockRejectedValueOnce(new Error('Synthetic test transport failure'));
    await user.click(dialog.getByRole('button', { name: 'Test Connection' }));
    expect(await screen.findByText('Synthetic test transport failure')).toBeInTheDocument();
    await waitFor(() => expect(dialog.getByRole('button', { name: 'Test Connection' })).toBeEnabled());
    expect(dialog.queryByText(success.data.message)).not.toBeInTheDocument();
    expect(dialog.getByRole('checkbox', { name: 'Verify SSL certificate' })).toBeChecked();
  });

  it('does not contact or create a gateway when the user cancels an untested form', async () => {
    const user = userEvent.setup();
    renderWithProviders(<FirewallPage />, { initialPath: '/firewall/gateways' });
    const dialog = await fillGateway(user);
    await user.click(dialog.getByRole('button', { name: 'Close dialog' }));
    expect(create).not.toHaveBeenCalled();
    expect(testConnection).not.toHaveBeenCalled();
  });

  it('preserves submitted gateway identity and credentials through explicit creation', async () => {
    const user = userEvent.setup();
    renderWithProviders(<FirewallPage />, { initialPath: '/firewall/gateways' });
    const dialog = await fillGateway(user);
    await user.click(dialog.getByRole('button', { name: 'Add Gateway' }));
    await waitFor(() => expect(create).toHaveBeenCalledOnce());
    expect(create.mock.calls[0][0]).toMatchObject({ name: 'Owned gateway', host: 'gateway.example.test', vendor: 'opnsense', api_key: 'fixture-key', api_secret: 'fixture-secret' });
  });
});
