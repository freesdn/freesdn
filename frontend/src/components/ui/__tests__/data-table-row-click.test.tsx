// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * A clickable row opens only from its own content. React bubbles events from
 * a portal through the component tree, so choosing an item in a row's
 * actions menu (rendered in a portal) reached the row's onClick and opened
 * the row as well, and so did a click on the menu's trigger. Pages worked
 * around it one by one with stopPropagation; the Phones list did not, and
 * every menu action there also navigated to the phone's page.
 */
import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';

interface Row { id: string; name: string }
const data: Row[] = [{ id: 'a', name: 'Alpha' }];

function renderTable(onRowClick: (row: Row) => void, onAction: () => void) {
  const columns: DataTableColumn<Row>[] = [
    { id: 'name', header: 'Name', accessorKey: 'name' },
    {
      id: 'actions',
      header: '',
      cell: () => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button aria-label="Row actions">...</Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem onClick={onAction}>Reboot</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    },
  ];
  return render(<DataTable data={data} columns={columns} searchable={false} onRowClick={onRowClick} />);
}

describe('DataTable row click', () => {
  it('opens the row from its content', async () => {
    const onRowClick = vi.fn();
    renderTable(onRowClick, vi.fn());
    await userEvent.setup().click(screen.getByText('Alpha'));
    expect(onRowClick).toHaveBeenCalledWith(data[0]);
  });

  it('does not open the row from its actions menu or the menu trigger', async () => {
    const onRowClick = vi.fn();
    const onAction = vi.fn();
    renderTable(onRowClick, onAction);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Row actions' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Reboot' }));
    expect(onAction).toHaveBeenCalledTimes(1);
    expect(onRowClick).not.toHaveBeenCalled();
  });
});

describe('DataTable scroller', () => {
  it('contains absolutely positioned header labels, so a screen-reader-only header cannot widen the page', () => {
    const columns: DataTableColumn<Row>[] = [
      { id: 'name', header: 'Name', accessorKey: 'name' },
      { id: 'actions', header: <span className="sr-only">Actions</span>, cell: () => null },
    ];
    render(<DataTable data={data} columns={columns} searchable={false} />);
    // The access-point list at 390 px: the sr-only "Actions" header was placed
    // at the far right of the wide table, outside the scroller, and the page
    // scrolled sideways by 729 px.
    expect(screen.getByTestId('data-table-scroller').className).toMatch(/\brelative\b/);
    expect(screen.getByTestId('data-table-scroller').className).toMatch(/\boverflow-x-auto\b/);
  });
});
