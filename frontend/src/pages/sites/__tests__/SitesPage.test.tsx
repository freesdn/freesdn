// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * SitesPage, smoke tests.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import SitesPage from '@/pages/sites/SitesPage';
import { sitesApi, api } from '@/lib/api';
import { useAuthStore } from '@/stores/authStore';
import { renderWithProviders } from '@/test-utils';
import { makeSite, makeUser } from '@/test-utils/factories';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    sitesApi: {
      getAll: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
      delete: vi.fn(),
    },
    api: {
      get: vi.fn(),
      post: vi.fn(),
      put: vi.fn(),
      patch: vi.fn(),
      delete: vi.fn(),
    },
  };
});

const mockedGetAll = sitesApi.getAll as unknown as Mock;
const mockedApiGet = api.get as unknown as Mock;

beforeEach(() => {
  mockedGetAll.mockReset();
  mockedApiGet.mockReset();
  // Default org_admin (non-super) so the org filter query is disabled.
  useAuthStore.setState({
    user: makeUser({ is_superuser: false }),
    isAuthenticated: true,
  });
});

describe('SitesPage smoke', () => {
  it('renders the page header with an empty list', async () => {
    mockedGetAll.mockResolvedValueOnce({ data: { items: [] } });
    renderWithProviders(<SitesPage />);
    expect(await screen.findByRole('heading', { name: /^sites$/i })).toBeInTheDocument();
  });

  it('renders site rows when the API returns data', async () => {
    mockedGetAll.mockResolvedValueOnce({
      data: {
        items: [
          makeSite({ name: 'HQ', slug: 'hq' }),
          makeSite({ name: 'Branch', slug: 'branch' }),
        ],
      },
    });
    renderWithProviders(<SitesPage />);

    await waitFor(() => expect(mockedGetAll).toHaveBeenCalled());
    expect(await screen.findByText(/^HQ$/)).toBeInTheDocument();
    expect(screen.getByText(/^Branch$/)).toBeInTheDocument();
  });

  it('does not crash when the sites API rejects', async () => {
    mockedGetAll.mockRejectedValueOnce(new Error('boom'));
    renderWithProviders(<SitesPage />);
    expect(await screen.findByRole('heading', { name: /^sites$/i })).toBeInTheDocument();
  });
});
