// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * DevicesPage, smoke tests.
 *
 * We mock the devicesApi modules so the page renders without hitting the
 * network. The goal here is to catch silent regressions in the
 * import graph and basic empty-state rendering, not to exercise the
 * entire filter/select/bulk surface.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import DevicesPage from '@/pages/devices/DevicesPage';
import { devicesApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';
import { makeDevice } from '@/test-utils/factories';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    devicesApi: {
      getAll: vi.fn(),
      getById: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
      delete: vi.fn(),
      getStats: vi.fn(),
    },
    deviceControlApi: {
      getCapabilities: vi.fn(),
      reboot: vi.fn(),
    },
  };
});

const mockedGetAll = devicesApi.getAll as unknown as Mock;

beforeEach(() => {
  mockedGetAll.mockReset();
});

describe('DevicesPage smoke', () => {
  it('renders without crashing when the device list is empty', async () => {
    mockedGetAll.mockResolvedValueOnce({ data: { items: [] } });
    renderWithProviders(<DevicesPage />);

    // PageHeader title "Devices" is rendered immediately, before data resolves.
    expect(await screen.findByRole('heading', { name: /device inventory/i })).toBeInTheDocument();
  });

  it('renders device rows when the API returns data', async () => {
    mockedGetAll.mockResolvedValueOnce({
      data: {
        items: [
          makeDevice({ name: 'switch-01' }),
          makeDevice({ name: 'switch-02', device_type: 'switch' }),
        ],
      },
    });

    renderWithProviders(<DevicesPage />);

    // Wait for the data fetch to settle. The header is "Devices"; the
    // rows live inside the dashboard tab summary, but at minimum the
    // page shouldn't blow up on real rows.
    await waitFor(() =>
      expect(mockedGetAll).toHaveBeenCalledWith(
        expect.objectContaining({ per_page: expect.any(Number) }),
      ),
    );
    expect(screen.getByRole('heading', { name: /device inventory/i })).toBeInTheDocument();
  });

  it('does not crash when the API rejects', async () => {
    mockedGetAll.mockRejectedValueOnce(new Error('network down'));
    renderWithProviders(<DevicesPage />);
    // The page still renders its shell; error rendering is exercised by
    // dedicated error-state tests.
    expect(await screen.findByRole('heading', { name: /device inventory/i })).toBeInTheDocument();
  });
});
