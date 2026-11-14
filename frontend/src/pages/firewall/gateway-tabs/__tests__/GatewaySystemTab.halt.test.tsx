// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Halt powers the gateway off and needs someone at the device to bring it
 * back, so it must ask first, say so, and run only on an explicit confirm.
 */
import { describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { GatewaySystemTab, type GatewaySystemTabProps } from '../GatewaySystemTab';
import { renderWithProviders } from '@/test-utils';

function renderTab(onHaltGateway: () => void) {
  const props: GatewaySystemTabProps = {
    gatewayId: 'gw-1',
    packagesData: null,
    packagesLoading: false,
    pluginsData: null,
    cronData: null,
    cronLoading: false,
    trustData: null,
    trustLoading: false,
    trustError: false,
    onRetryTrust: vi.fn(),
    acmeData: null,
    acmeLoading: false,
    acmeError: false,
    onRetryAcme: vi.fn(),
    syslogData: null,
    syslogLoading: false,
    haStatusData: null,
    haStatusLoading: false,
    certExpiryData: null,
    certExpiryLoading: false,
    certExpiryError: false,
    onRetryCertificateExpiry: vi.fn(),
    onCheckUpdates: vi.fn(),
    onDownloadConfig: vi.fn(),
    onHaltGateway,
  };
  return renderWithProviders(<GatewaySystemTab {...props} />);
}

describe('GatewaySystemTab halt confirmation', () => {
  it('explains the power-off and does not halt on Cancel', async () => {
    const user = userEvent.setup();
    const onHalt = vi.fn();
    renderTab(onHalt);

    await user.click(screen.getByRole('button', { name: 'Halt' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByRole('heading', { name: 'Halt this gateway?' })).toBeInTheDocument();
    expect(within(dialog).getByText(/powers off right away/)).toBeInTheDocument();
    expect(within(dialog).getByText(/FreeSDN cannot turn it back on/)).toBeInTheDocument();

    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(onHalt).not.toHaveBeenCalled();
  });

  it('halts exactly once after the operator confirms', async () => {
    const user = userEvent.setup();
    const onHalt = vi.fn();
    renderTab(onHalt);

    await user.click(screen.getByRole('button', { name: 'Halt' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Halt gateway' }));

    await waitFor(() => expect(onHalt).toHaveBeenCalledTimes(1));
  });
});
