// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikBackupTab, smoke test.
 *
 * Backup is a destructive surface, restore reboots the device. The
 * smoke test verifies:
 *   - Action bar + backups table render in the empty case.
 *   - A backup row renders with the correct kind badge when data arrives.
 *   - isActive=false short-circuits the fetch.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { MikroTikBackupTab } from '../MikroTikBackupTab';
import { mikrotikApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    mikrotikApi: {
      listMikrotikBackups: vi.fn(),
      downloadBackupContent: vi.fn(),
      createBinaryBackup: vi.fn(),
      exportTextConfig: vi.fn(),
      uploadBackupContent: vi.fn(),
      deleteMikrotikBackup: vi.fn(),
      restoreMikrotikBackup: vi.fn(),
    },
  };
});

const mockList = mikrotikApi.listMikrotikBackups as unknown as Mock;

beforeEach(() => {
  mockList.mockReset();
});

describe('MikroTikBackupTab smoke', () => {
  it('renders action bar + empty backups card', async () => {
    // Backend returns a bare backups array (no envelope).
    mockList.mockResolvedValue({ data: [] });

    renderWithProviders(<MikroTikBackupTab controllerId="c1" isActive={true} />);
    await waitFor(() => expect(mockList).toHaveBeenCalledWith('c1'));
    expect(
      await screen.findByRole('button', { name: /Create binary backup/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /Export config/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /Upload backup/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/Saved backups/i)).toBeInTheDocument();
    expect(
      screen.getByText(/No backups on the device/i),
    ).toBeInTheDocument();
  });

  it('renders a backup row with Restore for .backup files', async () => {
    mockList.mockResolvedValue({
      data: [
        {
          '.id': '*1',
          name: 'pre-upgrade.backup',
          size: '32768',
          'creation-time': '2026-05-20 10:00:00',
        },
        {
          '.id': '*2',
          name: 'snapshot.rsc',
          size: '8192',
          'creation-time': '2026-05-20 11:00:00',
        },
      ],
    });

    renderWithProviders(<MikroTikBackupTab controllerId="c1" isActive={true} />);
    await waitFor(() => expect(mockList).toHaveBeenCalled());
    expect(await screen.findByText('pre-upgrade.backup')).toBeInTheDocument();
    expect(screen.getByText('snapshot.rsc')).toBeInTheDocument();
    // Restore button appears on binary backups only.
    const restoreButtons = screen.getAllByRole('button', { name: /Restore/i });
    expect(restoreButtons.length).toBe(1);
  });

  it('does not fetch when isActive=false', async () => {
    renderWithProviders(<MikroTikBackupTab controllerId="c1" isActive={false} />);
    expect(mockList).not.toHaveBeenCalled();
  });
});
