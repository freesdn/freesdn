// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * DataTable behaviours added for the network pages:
 *  - `selectedRows` keeps the checkboxes in step with the parent. Clearing the
 *    parent's selection (BulkActionsBar "clear", a finished bulk action) used
 *    to hide the bar while every checkbox stayed ticked.
 *  - column `className` / `headerClassName` reach the cells (they were ignored).
 *  - clickable rows open from the keyboard.
 *  - the opt-in column picker hides and restores columns.
 */
import { useState } from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DataTable, type DataTableColumn } from '../data-table';

interface Row {
  id: string;
  name: string;
  status: string;
}

const data: Row[] = [
  { id: '1', name: 'Alpha', status: 'online' },
  { id: '2', name: 'Beta', status: 'offline' },
];

const columns: DataTableColumn<Row>[] = [
  { id: 'name', header: 'Name', accessorKey: 'name', className: 'cell-name', headerClassName: 'head-name' },
  { id: 'status', header: 'Status', accessorKey: 'status' },
];

// Whether or not the test run loads the locale files, the picker's name is
// either the English string or its key.
const COLUMNS_BUTTON = /choose columns|DataTable\.columns\.button/i;

function rowCheckboxes() {
  // The first checkbox is the header's select-all.
  return screen.getAllByRole('checkbox').slice(1) as HTMLInputElement[];
}

function ControlledTable() {
  const [selected, setSelected] = useState<Row[]>([]);
  return (
    <>
      <span data-testid="count">{selected.length}</span>
      <button type="button" onClick={() => setSelected([])}>
        clear
      </button>
      <DataTable
        data={data}
        columns={columns}
        selectable
        searchable={false}
        paginated={false}
        onSelectionChange={setSelected}
        selectedRows={selected}
      />
    </>
  );
}

describe('DataTable selectedRows', () => {
  it('unticks the checkboxes when the parent clears its selection', async () => {
    const user = userEvent.setup();
    render(<ControlledTable />);
    await user.click(rowCheckboxes()[0]);
    await user.click(rowCheckboxes()[1]);
    expect(screen.getByTestId('count')).toHaveTextContent('2');
    expect(rowCheckboxes().every((c) => c.checked)).toBe(true);

    await user.click(screen.getByRole('button', { name: 'clear' }));
    expect(screen.getByTestId('count')).toHaveTextContent('0');
    expect(rowCheckboxes().some((c) => c.checked)).toBe(false);

    // A fresh tick announces only that row, not the stale ones.
    await user.click(rowCheckboxes()[1]);
    expect(screen.getByTestId('count')).toHaveTextContent('1');
  });
});

describe('DataTable column classes and keyboard rows', () => {
  it('applies className to body cells and headerClassName to the header', () => {
    render(<DataTable data={data} columns={columns} searchable={false} />);
    expect(screen.getByText('Alpha').closest('td')).toHaveClass('cell-name');
    expect(screen.getByRole('columnheader', { name: /name/i })).toHaveClass('head-name');
  });

  it('opens a clickable row with Enter', async () => {
    const onRowClick = vi.fn();
    const user = userEvent.setup();
    render(<DataTable data={data} columns={columns} searchable={false} onRowClick={onRowClick} />);
    const row = screen.getByText('Beta').closest('tr')!;
    row.focus();
    await user.keyboard('{Enter}');
    expect(onRowClick).toHaveBeenCalledWith(data[1]);
  });

  it('marks the sorted column with aria-sort', async () => {
    const user = userEvent.setup();
    render(<DataTable data={data} columns={columns} searchable={false} />);
    const header = screen.getByRole('columnheader', { name: /name/i });
    expect(header).toHaveAttribute('aria-sort', 'none');
    await user.click(within(header).getByRole('button'));
    expect(header).toHaveAttribute('aria-sort', 'ascending');
  });
});

describe('DataTable sort controls', () => {
  interface Device {
    id: string;
    name: string;
    port_count: number;
  }
  const devices: Device[] = [
    { id: 'a', name: 'core-sw', port_count: 48 },
    { id: 'b', name: 'edge-sw', port_count: 8 },
  ];
  const deviceColumns: DataTableColumn<Device>[] = [
    { id: 'name', header: 'Name', accessorKey: 'name' },
    { id: 'ports', header: 'Ports', accessorFn: (d) => d.port_count },
    { id: 'summary', header: 'Summary', cell: (d) => `${d.name} (${d.port_count})` },
    { id: 'explicit', header: 'Explicit', sortable: true, cell: () => 'x' },
    { id: 'locked', header: 'Locked', accessorKey: 'name', sortable: false },
  ];

  function header(name: string) {
    return screen.getByRole('columnheader', { name: new RegExp(`^${name}$`, 'i') });
  }

  it('offers a sort button only on columns that have a value to sort by', () => {
    render(<DataTable data={devices} columns={deviceColumns} searchable={false} />);
    expect(within(header('Name')).getByRole('button')).toBeInTheDocument();
    expect(within(header('Ports')).getByRole('button')).toBeInTheDocument();
    // cell-only columns, even with sortable: true, and sortable: false
    for (const name of ['Summary', 'Explicit', 'Locked']) {
      expect(within(header(name)).queryByRole('button')).not.toBeInTheDocument();
      expect(header(name)).not.toHaveAttribute('aria-sort');
    }
  });

  it('sorts by an accessorFn column', async () => {
    const user = userEvent.setup();
    render(<DataTable data={devices} columns={deviceColumns} searchable={false} />);
    await user.click(within(header('Ports')).getByRole('button'));
    expect(header('Ports')).toHaveAttribute('aria-sort', 'ascending');
    const firstRow = screen.getAllByRole('row')[1];
    expect(within(firstRow).getByText('edge-sw (8)')).toBeInTheDocument();
  });
});

describe('DataTable column picker', () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it('is absent unless enabled', () => {
    render(<DataTable data={data} columns={columns} searchable={false} />);
    expect(screen.queryByRole('button', { name: COLUMNS_BUTTON })).not.toBeInTheDocument();
  });

  it('starts defaultHidden columns hidden and persists a choice', async () => {
    const user = userEvent.setup();
    const cols: DataTableColumn<Row>[] = [
      columns[0],
      { ...columns[1], defaultHidden: true },
    ];
    const { unmount } = render(
      <DataTable
        data={data}
        columns={cols}
        searchable={false}
        enableColumnVisibility
        columnVisibilityKey="test-table"
      />,
    );
    expect(screen.queryByText('online')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: COLUMNS_BUTTON }));
    await user.click(await screen.findByRole('menuitemcheckbox', { name: 'Status' }));
    expect(screen.getAllByText('online').length).toBeGreaterThan(0);
    unmount();

    render(
      <DataTable
        data={data}
        columns={cols}
        searchable={false}
        enableColumnVisibility
        columnVisibilityKey="test-table"
      />,
    );
    expect(screen.getAllByText('online').length).toBeGreaterThan(0);
  });
});
