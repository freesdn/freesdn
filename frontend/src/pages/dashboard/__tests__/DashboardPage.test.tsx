// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * DashboardPage, smoke test.
 *
 * The dashboard fans out to ~7 API endpoints. We mock every consumed
 * client at the module boundary so the page renders against empty data
 * without making real network calls. The goal is to catch import-graph
 * regressions and ensure the dashboard shell doesn't blow up on a brand
 * new tenant.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { screen } from '@testing-library/react';
import DashboardPage from '@/pages/dashboard/DashboardPage';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    analyticsApi: {
      getDashboardSummary: vi.fn().mockResolvedValue({ data: {} }),
      getEnterpriseAnalytics: vi.fn().mockResolvedValue({ data: {} }),
      getAlerts: vi.fn().mockResolvedValue({ data: { items: [], total: 0 } }),
    },
    systemApi: {
      getHealth: vi.fn().mockResolvedValue({ data: { status: 'ok', checks: [] } }),
      getInfo: vi.fn().mockResolvedValue({ data: {} }),
    },
    camerasApi: {
      getAll: vi.fn().mockResolvedValue({ data: { items: [] } }),
    },
    enterpriseApi: {
      getOrgHealth: vi.fn().mockResolvedValue({ data: {} }),
    },
  };
});

vi.mock('@/lib/api/sites', () => ({
  sitesApiV2: {
    getAll: vi.fn().mockResolvedValue({ data: { items: [] } }),
  },
}));

beforeEach(() => {
  vi.clearAllMocks();
});

describe('DashboardPage smoke', () => {
  it('renders the page header without crashing on empty data', async () => {
    renderWithProviders(<DashboardPage />);
    // The header always renders, even before queries settle.
    expect(
      await screen.findByRole('heading', { name: /dashboard/i }),
    ).toBeInTheDocument();
  });
});
