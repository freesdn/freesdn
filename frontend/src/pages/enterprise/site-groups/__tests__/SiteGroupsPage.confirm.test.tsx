// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import SiteGroupsPage from '../SiteGroupsPage';
import { enterpriseApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api')>()),
  enterpriseApi: {
    listSiteGroups: vi.fn(),
    listDeviceGroups: vi.fn(),
    createSiteGroup: vi.fn(),
    updateSiteGroup: vi.fn(),
    deleteSiteGroup: vi.fn(),
    createDeviceGroup: vi.fn(),
    updateDeviceGroup: vi.fn(),
    deleteDeviceGroup: vi.fn(),
  },
}));

const group = (id: string, name: string) => ({
  id, organization_id: 'org-1', name, description: null, parent_id: null,
  created_at: '2026-11-01T00:00:00Z', updated_at: '2026-11-01T00:00:00Z',
});

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(enterpriseApi.listSiteGroups).mockResolvedValue({
    data: [group('sg-1', 'Campus'), group('sg-2', 'Branch')],
  } as never);
  vi.mocked(enterpriseApi.listDeviceGroups).mockResolvedValue({ data: [] } as never);
  vi.mocked(enterpriseApi.deleteSiteGroup).mockResolvedValue({ data: undefined } as never);
});

function renderPage() {
  const user = userEvent.setup();
  renderWithProviders(<SiteGroupsPage />, { initialPath: '/groups', routePath: '/groups' });
  return user;
}

function rowOf(name: string): HTMLElement {
  const row = screen.getByText(name).closest('tr');
  if (!row) throw new Error(`no row for ${name}`);
  return row;
}

describe('SiteGroupsPage delete confirmation', () => {
  it('deletes one group only after the operator confirms, and nothing on Cancel', async () => {
    const user = renderPage();
    await screen.findByText('Campus');
    // The row's last button is the trash icon.
    const trash = () => {
      const buttons = within(rowOf('Campus')).getAllByRole('button');
      return buttons[buttons.length - 1];
    };

    await user.click(trash());
    let dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText('Delete site group "Campus"?')).toBeInTheDocument();
    expect(within(dialog).getByText(/unlinked from the group, not deleted/i)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(enterpriseApi.deleteSiteGroup).not.toHaveBeenCalled();

    await user.click(trash());
    dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Delete site group' }));
    await waitFor(() => expect(enterpriseApi.deleteSiteGroup).toHaveBeenCalledTimes(1));
    expect(vi.mocked(enterpriseApi.deleteSiteGroup).mock.calls[0][0]).toBe('sg-1');
  });

  it('bulk delete shows the count and the selected names, then deletes each one', async () => {
    const user = renderPage();
    await screen.findByText('Campus');
    await user.click(within(rowOf('Campus')).getByRole('checkbox'));
    await user.click(within(rowOf('Branch')).getByRole('checkbox'));
    await user.click(screen.getByRole('button', { name: /^delete$/i }));

    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText('Delete 2 site group(s)?')).toBeInTheDocument();
    expect(within(dialog).getByTestId('confirm-count')).toHaveTextContent('This affects 2 items.');
    const items = within(dialog).getByRole('list', { name: 'Affected items' });
    expect(within(items).getByText('Campus')).toBeInTheDocument();
    expect(within(items).getByText('Branch')).toBeInTheDocument();
    expect(enterpriseApi.deleteSiteGroup).not.toHaveBeenCalled();

    await user.click(within(dialog).getByRole('button', { name: 'Delete site groups' }));
    await waitFor(() => expect(enterpriseApi.deleteSiteGroup).toHaveBeenCalledTimes(2));
    expect(vi.mocked(enterpriseApi.deleteSiteGroup).mock.calls.map((c) => c[0]).sort()).toEqual(['sg-1', 'sg-2']);
  });
});
