// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Dashboard and List are two tabs of one Cameras page.
 *
 * Switching between `/cameras` and `/cameras/list` used to remount the page,
 * which threw away the search box, the filters and the selection. The page now
 * stays mounted, so these tests pin what it must do with the state it keeps:
 * the search survives, the dashboard view you left is the one you come back
 * to, and the list's checkboxes follow the page's selection (a bulk-bar clear
 * unticks them).
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { api } from '@/lib/api/client';
import { demoAxiosAdapter } from '@/demo/mockApi';
import { ToastProvider } from '@/components/ui/toast';
import { TooltipProvider } from '@/components/ui/tooltip';
import CamerasPage from '../CamerasPage';

const oldAdapter = api.defaults.adapter;

function Where() {
  const location = useLocation();
  return <output data-testid="where">{`${location.pathname}${location.search}`}</output>;
}

function renderAt(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <ToastProvider>
          <TooltipProvider>
            <Where />
            <Routes>
              <Route path="/cameras" element={<CamerasPage />} />
              <Route path="/cameras/list" element={<CamerasPage />} />
            </Routes>
          </TooltipProvider>
        </ToastProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function tab(name: RegExp) {
  return screen.getByRole('tab', { name });
}

async function selectTab(name: RegExp) {
  await act(async () => {
    fireEvent.mouseDown(tab(name), { button: 0 });
    fireEvent.click(tab(name));
  });
}

beforeEach(() => {
  api.defaults.adapter = demoAxiosAdapter;
});

afterEach(() => {
  api.defaults.adapter = oldAdapter;
});

describe('Cameras Dashboard and List tabs', () => {
  it('keeps the search and returns to the dashboard view you left', async () => {
    renderAt('/cameras?view=health');
    const search = await screen.findByPlaceholderText('Search cameras...');
    fireEvent.change(search, { target: { value: 'lobby' } });

    await selectTab(/^List/);
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/cameras/list'));
    expect(screen.getByPlaceholderText('Search cameras...')).toHaveValue('lobby');

    await selectTab(/^Dashboard/);
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/cameras?view=health'));
    expect(screen.getByPlaceholderText('Search cameras...')).toHaveValue('lobby');
    expect(tab(/^Dashboard/)).toHaveAttribute('data-state', 'active');
  }, 20_000);

  it('unticks list rows when the bulk bar clears the selection', async () => {
    renderAt('/cameras/list');
    const table = await screen.findByRole('table');
    const rowBoxes = await within(table).findAllByRole('checkbox', { name: 'Select row' });
    fireEvent.click(rowBoxes[0]);
    await waitFor(() => expect(rowBoxes[0]).toBeChecked());

    fireEvent.click(await screen.findByRole('button', { name: 'Clear selection' }));
    await waitFor(() =>
      expect(within(screen.getByRole('table')).getAllByRole('checkbox', { name: 'Select row' })[0]).not.toBeChecked(),
    );
  }, 20_000);
});
