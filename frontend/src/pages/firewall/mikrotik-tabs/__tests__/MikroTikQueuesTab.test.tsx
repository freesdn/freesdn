// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikQueuesTab, smoke test.
 *
 * Verifies the simple-queues table + tree-view sub-pane both render,
 * and that the table populates rows when data arrives.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { MikroTikQueuesTab } from '../MikroTikQueuesTab';
import { mikrotikApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    mikrotikApi: {
      getSimpleQueues: vi.fn(),
      getQueueTree: vi.fn(),
      createSimpleQueue: vi.fn(),
      updateSimpleQueue: vi.fn(),
      deleteSimpleQueue: vi.fn(),
    },
  };
});

const mockSimple = mikrotikApi.getSimpleQueues as unknown as Mock;
const mockTree = mikrotikApi.getQueueTree as unknown as Mock;

beforeEach(() => {
  mockSimple.mockReset();
  mockTree.mockReset();
});

const emptyList = {
  data: { controller_id: 'c1', items: [], fetched_at: '', limit: 200, offset: 0, total: 0 },
};

describe('MikroTikQueuesTab smoke', () => {
  it('renders both sub-panes with empty data', async () => {
    mockSimple.mockResolvedValue(emptyList);
    mockTree.mockResolvedValue(emptyList);

    renderWithProviders(<MikroTikQueuesTab controllerId="c1" isActive={true} />);
    await waitFor(() => expect(mockSimple).toHaveBeenCalled());
    // Card title + empty-state title both contain the same phrase.
    expect(
      (await screen.findAllByText(/Simple queues/i)).length,
    ).toBeGreaterThan(0);
    expect(screen.getAllByText(/Queue tree/i).length).toBeGreaterThan(0);
  });

  it('renders a simple queue row when data arrives', async () => {
    mockSimple.mockResolvedValue({
      data: {
        controller_id: 'c1',
        items: [
          {
            '.id': '*1',
            name: 'guest-cap',
            target: '192.168.88.0/24',
            'max-limit': '5M/10M',
            priority: '8',
          },
        ],
        fetched_at: '',
        limit: 200,
        offset: 0,
        total: 1,
      },
    });
    mockTree.mockResolvedValue(emptyList);

    renderWithProviders(<MikroTikQueuesTab controllerId="c1" isActive={true} />);
    await waitFor(() => expect(mockSimple).toHaveBeenCalled());
    expect(await screen.findByText('guest-cap')).toBeInTheDocument();
    expect(screen.getByText('5M/10M')).toBeInTheDocument();
  });

  it('does not fetch when isActive=false', async () => {
    renderWithProviders(<MikroTikQueuesTab controllerId="c1" isActive={false} />);
    expect(mockSimple).not.toHaveBeenCalled();
    expect(mockTree).not.toHaveBeenCalled();
  });
});
