// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DataTable, type DataTableColumn } from '../data-table';

type Device = { id: string; name: string; count: number };
const devices: Device[] = [
  { id: 'b', name: 'Beta', count: 20 },
  { id: 'a', name: 'Alpha', count: 3 },
  { id: 'g', name: 'Gamma', count: 100 },
];
const columns: DataTableColumn<Device>[] = [
  { id: 'name', header: 'Name', accessorKey: 'name' },
  { id: 'count', header: 'Count', accessorKey: 'count' },
];
const names = () => screen.getAllByRole('row').slice(1).map(row => row.querySelector('td')?.textContent);

describe('DataTable sorting, filtering, and pagination', () => {
  it('sorts strings and numbers in both directions before pagination', async () => {
    const user = userEvent.setup();
    render(<DataTable data={devices} columns={columns} defaultPageSize={2} pageSizeOptions={[2, 3]} />);
    await user.click(screen.getByRole('button', { name: 'Name' }));
    expect(names()).toEqual(['Alpha', 'Beta']);
    await user.click(screen.getByRole('button', { name: 'Name' }));
    expect(names()).toEqual(['Gamma', 'Beta']);
    await user.click(screen.getByRole('button', { name: 'Count' }));
    expect(names()).toEqual(['Alpha', 'Beta']);
    await user.click(screen.getByRole('button', { name: 'Count' }));
    expect(names()).toEqual(['Gamma', 'Beta']);
  });

  it('navigates page boundaries and changes page size', async () => {
    const user = userEvent.setup();
    render(<DataTable data={devices} columns={columns} defaultPageSize={2} pageSizeOptions={[2, 3]} />);
    expect(screen.getByRole('button', { name: 'Previous page' })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Next page' }));
    expect(names()).toEqual(['Gamma']);
    expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled();
    await user.selectOptions(screen.getByRole('combobox', { name: 'Rows per page' }), '3');
    expect(names()).toEqual(['Beta', 'Alpha', 'Gamma']);
    expect(screen.getByText('Page 1 of 1')).toBeInTheDocument();
  });

  it('filters the full dataset and returns from a later page to the matching row', async () => {
    const user = userEvent.setup();
    render(<DataTable data={devices} columns={columns} defaultPageSize={2} pageSizeOptions={[2, 3]} />);
    await user.click(screen.getByRole('button', { name: 'Next page' }));
    await user.type(screen.getByPlaceholderText('Search...'), 'alpha');
    await waitFor(() => expect(names()).toEqual(['Alpha']));
    expect(screen.getByText('Page 1 of 1')).toBeInTheDocument();
    await user.clear(screen.getByPlaceholderText('Search...'));
    await waitFor(() => expect(names()).toEqual(['Beta', 'Alpha']));
  });

  it('selects only the current page and retains selection across page changes', async () => {
    const user = userEvent.setup();
    const onSelectionChange = vi.fn();
    render(<DataTable data={devices} columns={columns} selectable defaultPageSize={2}
      pageSizeOptions={[2, 3]} onSelectionChange={onSelectionChange} />);
    await user.click(screen.getByRole('checkbox', { name: 'Select all rows' }));
    expect(onSelectionChange.mock.lastCall?.[0].map((row: Device) => row.id)).toEqual(['b', 'a']);
    await user.click(screen.getByRole('button', { name: 'Next page' }));
    expect(screen.getByRole('checkbox', { name: 'Select row' })).not.toBeChecked();
    await user.click(screen.getByRole('checkbox', { name: 'Select row' }));
    expect(onSelectionChange.mock.lastCall?.[0]).toHaveLength(3);
    await user.click(screen.getByRole('button', { name: 'First page' }));
    expect(screen.getAllByRole('checkbox', { name: 'Select row' }).every(input => (input as HTMLInputElement).checked)).toBe(true);
  });

  it('renders every row when pagination is disabled, even above the page size', () => {
    render(<DataTable data={devices} columns={columns} paginated={false} defaultPageSize={1} />);
    expect(names()).toEqual(['Beta', 'Alpha', 'Gamma']);
    expect(screen.queryByRole('button', { name: 'Next page' })).not.toBeInTheDocument();
  });
});
