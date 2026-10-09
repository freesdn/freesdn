// SPDX-License-Identifier: AGPL-3.0-only
import { screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { enterpriseApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';
import { TopIssuesPanel } from './TopIssuesPanel';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return { ...actual, enterpriseApi: { ...actual.enterpriseApi, getTopIssues: vi.fn() } };
});

describe('top issue component observations', () => {
  it.each([
    [null, null, 'N/A', null],
    ['latency', 0, 'latency: 0', 'text-red-500'],
    ['reachability', 100, 'reachability: 100', 'text-green-500'],
  ])('renders component %s with score %s truthfully', async (name, score, label, color) => {
    vi.mocked(enterpriseApi.getTopIssues).mockResolvedValue({ data: { issues: [{
      device_id: 'owned-device', device_name: 'Measured device', device_type: 'gateway',
      site_name: 'Main Site', site_id: 'owned-site', health_score: 0, health_status: 'critical',
      worst_component: name, worst_component_score: score,
    }] } } as Awaited<ReturnType<typeof enterpriseApi.getTopIssues>>);
    renderWithProviders(<TopIssuesPanel />);
    const badge = await screen.findByText(label as string);
    if (color) expect(badge).toHaveClass(color as string);
    else {
      expect(badge).not.toHaveClass('text-green-500');
      expect(badge).not.toHaveClass('text-red-500');
    }
    expect(screen.getByText('0', { exact: true })).toHaveClass('text-red-500');
  });
});
