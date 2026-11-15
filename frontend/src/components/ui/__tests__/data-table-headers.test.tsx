// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Column headers read at one size. A sortable header is a small button
 * (text-xs); a header that cannot sort was a text-sm label, so on the switch
 * port table "Type" stood out larger than "Status" or "VLAN" beside it.
 * Compact rows also use the small text size and tighter cell padding.
 */
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';

interface Row { id: string; name: string; kind: string }
const data: Row[] = [{ id: 'a', name: 'Alpha', kind: 'access' }];
const columns: DataTableColumn<Row>[] = [
  { id: 'name', header: 'Name', accessorKey: 'name' },
  { id: 'kind', header: 'Type', accessorKey: 'kind', sortable: false },
];

describe('DataTable headers and compact rows', () => {
  it('draws sortable and unsortable headers at the same size', () => {
    render(<DataTable data={data} columns={columns} searchable={false} />);
    const sortable = screen.getByRole('button', { name: /Name/ });
    const plain = screen.getByText('Type');
    expect(sortable.className).toMatch(/\btext-xs\b/);
    expect(plain.className).toMatch(/\btext-xs\b/);
    expect(plain.className).not.toMatch(/\btext-sm\b/);
  });

  it('uses small text and tighter padding for compact rows', () => {
    render(<DataTable data={data} columns={columns} searchable={false} density="compact" />);
    const cell = screen.getByText('Alpha').closest('td') as HTMLElement;
    expect(cell.className).toMatch(/\btext-sm\b/);
    expect(cell.className).toMatch(/\bpx-3\b/);
    expect(cell.className).toMatch(/\bpy-2\b/);
  });
});
