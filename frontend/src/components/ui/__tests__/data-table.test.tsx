// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, vi } from 'vitest';
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
  { id: '3', name: 'Gamma', status: 'online' },
];

const columns: DataTableColumn<Row>[] = [
  { id: 'name', header: 'Name', accessorKey: 'name' },
  { id: 'status', header: 'Status', accessorKey: 'status' },
];

describe('DataTable', () => {
  it('renders headers and rows', () => {
    render(<DataTable data={data} columns={columns} />);
    expect(screen.getByText('Name')).toBeInTheDocument();
    expect(screen.getByText('Status')).toBeInTheDocument();
    expect(screen.getByText('Alpha')).toBeInTheDocument();
    expect(screen.getByText('Beta')).toBeInTheDocument();
    expect(screen.getByText('Gamma')).toBeInTheDocument();
  });

  it('shows the empty state when data is empty', () => {
    render(<DataTable data={[]} columns={columns} />);
    expect(screen.queryByText('Alpha')).not.toBeInTheDocument();
  });

  it('does NOT render selection checkboxes when selectable=false', () => {
    render(<DataTable data={data} columns={columns} />);
    expect(screen.queryAllByRole('checkbox').length).toBe(0);
  });

  it('renders selection checkboxes when selectable=true', () => {
    render(
      <DataTable
        data={data}
        columns={columns}
        selectable
        getRowId={(r) => r.id}
      />
    );
    // header checkbox + 1 per row
    expect(screen.getAllByRole('checkbox').length).toBe(data.length + 1);
  });

  it('fires onSelectionChange with the chosen rows', async () => {
    const onSelectionChange = vi.fn();
    const user = userEvent.setup();
    render(
      <DataTable
        data={data}
        columns={columns}
        selectable
        getRowId={(r) => r.id}
        onSelectionChange={onSelectionChange}
      />
    );
    const rowCheckboxes = screen.getAllByRole('checkbox').slice(1); // skip header
    await user.click(rowCheckboxes[0]);
    expect(onSelectionChange).toHaveBeenCalled();
    // Last call's first arg is selected rows array
    const calls = onSelectionChange.mock.calls;
    const [rows] = calls[calls.length - 1];
    expect(rows).toHaveLength(1);
    expect(rows[0].name).toBe('Alpha');
  });

  it('toggles all-page selection via header checkbox', async () => {
    const onSelectionChange = vi.fn();
    const user = userEvent.setup();
    render(
      <DataTable
        data={data}
        columns={columns}
        selectable
        getRowId={(r) => r.id}
        onSelectionChange={onSelectionChange}
      />
    );
    const headerCheckbox = screen.getAllByRole('checkbox')[0];
    await user.click(headerCheckbox);
    const calls = onSelectionChange.mock.calls;
    const [rows] = calls[calls.length - 1];
    expect(rows).toHaveLength(data.length);
  });

  it('renders custom cell function output', () => {
    const customColumns: DataTableColumn<Row>[] = [
      { id: 'name', header: 'Name', accessorKey: 'name' },
      {
        id: 'status',
        header: 'Status',
        cell: (row) => <span data-testid="custom-status">{row.status.toUpperCase()}</span>,
      },
    ];
    render(<DataTable data={data} columns={customColumns} />);
    const cells = screen.getAllByTestId('custom-status');
    expect(cells).toHaveLength(3);
    expect(cells[0]).toHaveTextContent('ONLINE');
  });

  it('shows skeleton when isLoading=true', () => {
    render(<DataTable data={[]} columns={columns} isLoading />);
    // Real row text should not appear
    expect(screen.queryByText('Alpha')).not.toBeInTheDocument();
  });

  it('fires onRowClick when a row is clicked', async () => {
    const onRowClick = vi.fn();
    const user = userEvent.setup();
    render(<DataTable data={data} columns={columns} onRowClick={onRowClick} />);
    // Click the row containing Alpha · find its ancestor <tr>
    const cell = screen.getByText('Alpha');
    const row = cell.closest('tr');
    expect(row).not.toBeNull();
    await user.click(within(row!).getByText('Alpha'));
    expect(onRowClick).toHaveBeenCalledOnce();
    expect(onRowClick.mock.calls[0][0].name).toBe('Alpha');
  });
});
