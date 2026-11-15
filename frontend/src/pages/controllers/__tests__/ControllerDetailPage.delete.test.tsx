// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Deleting a controller asks through the in-app confirmation dialog and says
 * what really happens: FreeSDN drops the controller and its devices from its
 * own records and changes nothing on the controller. A Cancel sends nothing;
 * a confirm sends the delete.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import ControllerDetailPage from '../ControllerDetailPage';
import { controllersApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api/controllers', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api/controllers')>('@/lib/api/controllers');
  return {
    ...actual,
    controllersApi: {
      ...actual.controllersApi,
      getById: vi.fn(),
      getMetadata: vi.fn(),
      delete: vi.fn(),
      sync: vi.fn(),
      test: vi.fn(),
    },
  };
});

const controller = {
  id: 'c-1',
  name: 'HQ Omada',
  description: null,
  controller_type: 'omada',
  host: 'omada.example.invalid',
  port: 8043,
  status: 'connected',
  last_sync: null,
  last_error: null,
  is_active: true,
  use_ssl: true,
  verify_ssl: true,
  sync_enabled: true,
  sync_interval_seconds: 300,
  site_id: 's-1',
  created_at: '2026-11-01T00:00:00Z',
  updated_at: '2026-11-01T00:00:00Z',
};

function mount(deviceTotal: number | null) {
  vi.mocked(controllersApi.getMetadata).mockResolvedValue({
    data: deviceTotal == null ? { devices: [] } : { devices: [], device_counts: { total: deviceTotal } },
  } as never);
  return renderWithProviders(<ControllerDetailPage />, {
    initialPath: '/controllers/c-1/settings',
    routePath: '/controllers/:id/:tab',
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(controllersApi.getById).mockResolvedValue({ data: controller } as never);
  vi.mocked(controllersApi.delete).mockResolvedValue({ data: null } as never);
});

describe('ControllerDetailPage delete confirmation', () => {
  it('names the controller and its device count, and Cancel deletes nothing', async () => {
    const user = userEvent.setup();
    mount(12);
    await user.click(await screen.findByRole('button', { name: 'Delete Controller' }));

    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByRole('heading', { name: 'Delete controller "HQ Omada"?' })).toBeInTheDocument();
    expect(within(dialog).getByText(/removes its 12 devices from FreeSDN/)).toBeInTheDocument();
    expect(within(dialog).getByText(/Nothing is changed on the controller itself/)).toBeInTheDocument();

    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(controllersApi.delete).not.toHaveBeenCalled();
  });

  it('does not claim "0 devices" when the count is unknown, and deletes on confirm', async () => {
    const user = userEvent.setup();
    mount(null);
    await user.click(await screen.findByRole('button', { name: 'Delete Controller' }));

    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText(/removes every device it manages from FreeSDN/)).toBeInTheDocument();
    expect(within(dialog).queryByText(/\b0 devices\b/)).not.toBeInTheDocument();

    await user.click(within(dialog).getByRole('button', { name: 'Delete Controller' }));
    await waitFor(() => expect(controllersApi.delete).toHaveBeenCalledWith('c-1'));
  });
});
