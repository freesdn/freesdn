// SPDX-License-Identifier: AGPL-3.0-only
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { api } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';
import MarketplacePage from '../MarketplacePage';

vi.mock('@/stores/authStore', () => ({
  useAuthStore: (selector: (s: { user: { is_superuser: boolean } }) => unknown) =>
    selector({ user: { is_superuser: true } }),
}));
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return { ...actual, api: { ...actual.api, get: vi.fn(), post: vi.fn() } };
});

beforeEach(() => {
  vi.mocked(api.get).mockReset();
  vi.mocked(api.post).mockReset();
  vi.mocked(api.get).mockImplementation(async (url) => ({
    data: url === '/plugins' ? [] : url.endsWith('/categories') ? { categories: [] }
      : { plugins: [], total: 0, page: 1, per_page: 20, pages: 0 },
  } as Awaited<ReturnType<typeof api.get>>));
});

describe('marketplace catalog feedback', () => {
  it.each([
    'Marketplace catalog rollback refused: serial is older than the accepted catalog.',
    'Marketplace catalog has expired. Sync a newly signed catalog.',
  ])('shows the backend refusal: %s', async (message) => {
    vi.mocked(api.post).mockRejectedValue({ response: { status: 409, data: { error: { message } } } });
    renderWithProviders(<MarketplacePage />);
    await userEvent.click(await screen.findByRole('button', { name: 'Sync Registry' }));
    expect(await screen.findByText(message)).toBeInTheDocument();
  });

  it('shows that an offline sync retained the old snapshot', async () => {
    const message = 'Registry unavailable; retained the accepted catalog without changes.';
    vi.mocked(api.post).mockResolvedValue({ data: { message } });
    renderWithProviders(<MarketplacePage />);
    await userEvent.click(await screen.findByRole('button', { name: 'Sync Registry' }));
    expect(await screen.findByText(message)).toBeInTheDocument();
  });
});
