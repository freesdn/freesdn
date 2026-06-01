// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikSystemTab, interaction test.
 *
 * The system tab loads identity / time / resource info via
 * `getSystemInfo` and stages identity / NTP edits through dedicated
 * mutation endpoints. The interaction test below opens the NTP edit
 * dialog, fills in primary + secondary servers, submits, and asserts
 * the staging mutation was called with the right arguments.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MikroTikSystemTab } from '../MikroTikSystemTab';
import { mikrotikApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    mikrotikApi: {
      getSystemInfo: vi.fn(),
      stageIdentityUpdate: vi.fn(),
      stageNtpUpdate: vi.fn(),
    },
  };
});

const mockGet = mikrotikApi.getSystemInfo as unknown as Mock;
const mockNtp = mikrotikApi.stageNtpUpdate as unknown as Mock;
const mockIdentity = mikrotikApi.stageIdentityUpdate as unknown as Mock;

beforeEach(() => {
  mockGet.mockReset();
  mockNtp.mockReset();
  mockIdentity.mockReset();
});

const ok = {
  data: {
    identity: { name: 'edge-rtr-1' },
    resource: {
      version: '7.13',
      'board-name': 'RB3011',
      'cpu-load': 5,
      'total-memory': 1024,
      'free-memory': 512,
      uptime: '1w',
    },
    routerboard: {},
    clock: {},
    health: [],
  },
};

describe('MikroTikSystemTab', () => {
  it('does not fetch when isActive=false', () => {
    renderWithProviders(<MikroTikSystemTab controllerId="c1" isActive={false} />);
    expect(mockGet).not.toHaveBeenCalled();
  });

  it('stages an NTP update with primary + secondary servers', async () => {
    const user = userEvent.setup();
    mockGet.mockResolvedValue(ok);
    mockNtp.mockResolvedValue({ data: { staged: true } });

    renderWithProviders(
      <MikroTikSystemTab controllerId="c1" isActive={true} gatewayName="edge-rtr-1" />,
    );
    await waitFor(() => expect(mockGet).toHaveBeenCalled());

    await user.click(await screen.findByRole('button', { name: /Edit NTP/i }));
    const primary = await screen.findByLabelText(/Primary NTP server/i);
    const secondary = await screen.findByLabelText(/Secondary NTP server/i);
    await user.type(primary, '0.pool.ntp.org');
    await user.type(secondary, '1.pool.ntp.org');

    await user.click(screen.getByRole('button', { name: /Stage change/i }));

    await waitFor(() =>
      expect(mockNtp).toHaveBeenCalledWith('c1', '0.pool.ntp.org', '1.pool.ntp.org'),
    );
  });
});
