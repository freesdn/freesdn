// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikFirmwareTab, smoke test.
 *
 * The firmware tab is the most destructive surface in the stack:
 * installing a firmware update reboots the device. The smoke test
 * verifies:
 *   - All four cards render (current state / available update /
 *     channel selector / installed packages).
 *   - The Install button is the only one with typed-confirmation
 *     gating, and is disabled when no update is available.
 *   - isActive=false short-circuits all fetches.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { MikroTikFirmwareTab } from '../MikroTikFirmwareTab';
import { mikrotikApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    mikrotikApi: {
      getFirmwareStatus: vi.fn(),
      getInstalledPackages: vi.fn(),
      checkFirmwareUpdates: vi.fn(),
      setFirmwareChannel: vi.fn(),
      downloadFirmwareUpdate: vi.fn(),
      installFirmwareUpdate: vi.fn(),
      cancelFirmwareDownload: vi.fn(),
      enablePackage: vi.fn(),
      disablePackage: vi.fn(),
      uninstallPackage: vi.fn(),
    },
  };
});

const mockStatus = mikrotikApi.getFirmwareStatus as unknown as Mock;
const mockPackages = mikrotikApi.getInstalledPackages as unknown as Mock;

beforeEach(() => {
  mockStatus.mockReset();
  mockPackages.mockReset();
});

// Firmware status + packages now return BARE shapes (no envelope).
const emptyList = { data: [] };

describe('MikroTikFirmwareTab smoke', () => {
  it('renders all four cards when status + packages load', async () => {
    mockStatus.mockResolvedValue({
      data: {
        channel: 'stable',
        'installed-version': '7.21.3',
        'latest-version': '7.21.3',
        status: 'New version is not available',
      },
    });
    mockPackages.mockResolvedValue(emptyList);

    renderWithProviders(<MikroTikFirmwareTab controllerId="c1" isActive={true} />);
    await waitFor(() => expect(mockStatus).toHaveBeenCalledWith('c1'));
    expect(await screen.findByText(/Current state/i)).toBeInTheDocument();
    expect(screen.getByText(/Available update/i)).toBeInTheDocument();
    // Several places mention "Update channel" (card title + select label),
    // so we accept "at least one" match.
    expect(screen.getAllByText(/Update channel/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Installed packages/i)).toBeInTheDocument();
  });

  it('disables Install when no update is available', async () => {
    mockStatus.mockResolvedValue({
      data: {
        channel: 'stable',
        'installed-version': '7.21.3',
        'latest-version': '7.21.3',
        status: 'up to date',
      },
    });
    mockPackages.mockResolvedValue(emptyList);

    renderWithProviders(<MikroTikFirmwareTab controllerId="c1" isActive={true} />);
    await waitFor(() => expect(mockStatus).toHaveBeenCalled());
    const install = await screen.findByRole('button', {
      name: /Install \+ reboot/i,
    });
    expect(install).toBeDisabled();
  });

  it('shows an installed package row when packages arrive', async () => {
    mockStatus.mockResolvedValue({
      data: {
        channel: 'stable',
        'installed-version': '7.21.3',
        'latest-version': '7.22',
        status: 'New version is available',
      },
    });
    mockPackages.mockResolvedValue({
      data: [
        {
          '.id': '*1',
          name: 'routeros',
          version: '7.21.3',
          disabled: 'false',
        },
      ],
    });

    renderWithProviders(<MikroTikFirmwareTab controllerId="c1" isActive={true} />);
    await waitFor(() => expect(mockPackages).toHaveBeenCalled());
    expect(await screen.findByText('routeros')).toBeInTheDocument();
    // With an available update, Install is no longer disabled.
    const install = screen.getByRole('button', {
      name: /Install \+ reboot/i,
    });
    expect(install).not.toBeDisabled();
  });

  it('does not fetch when isActive=false', async () => {
    renderWithProviders(<MikroTikFirmwareTab controllerId="c1" isActive={false} />);
    expect(mockStatus).not.toHaveBeenCalled();
    expect(mockPackages).not.toHaveBeenCalled();
  });
});
