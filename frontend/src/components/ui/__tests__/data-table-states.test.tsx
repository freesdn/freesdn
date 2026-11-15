// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Shared table quality: error states with the server's message, numeric
 * alignment, compact density, and the plain Table's density.
 */
import { describe, it, expect, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DataTable, type DataTableColumn } from '../data-table';
import { ErrorState } from '../empty-state';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../table';

interface Port {
  id: string;
  name: string;
  rx_mbps: number;
}

const ports: Port[] = [
  { id: 'p1', name: 'Gi1/0/1', rx_mbps: 940.5 },
  { id: 'p2', name: 'Gi1/0/2', rx_mbps: 12 },
];

const columns: DataTableColumn<Port>[] = [
  { id: 'name', header: 'Port', accessorKey: 'name' },
  { id: 'rx', header: 'RX (Mbps)', accessorKey: 'rx_mbps', align: 'right' },
];

const envelopeError = {
  response: {
    status: 502,
    data: {
      error: {
        code: 502,
        type: 'adapter_connection_error',
        message: 'Cannot connect to 10.20.0.2:443: connection refused',
        request_id: 'req-9',
      },
    },
  },
};

describe('DataTable error state', () => {
  it("replaces an empty table with the server's message and a retry", async () => {
    const onRetry = vi.fn();
    const user = userEvent.setup();
    render(<DataTable data={[]} columns={columns} error={envelopeError} onRetry={onRetry} />);
    const alert = screen.getByRole('alert');
    expect(within(alert).getByText('Cannot connect to 10.20.0.2:443: connection refused')).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    await user.click(within(alert).getByRole('button', { name: /try again/i }));
    expect(onRetry).toHaveBeenCalledOnce();
  });

  it('keeps stale rows visible under a banner when a refetch failed', () => {
    render(<DataTable data={ports} columns={columns} error={envelopeError} searchable={false} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Cannot connect to 10.20.0.2:443');
    expect(screen.getByRole('table')).toBeInTheDocument();
    expect(screen.getByText('Gi1/0/1')).toBeInTheDocument();
  });

  it('shows no error UI without an error', () => {
    render(<DataTable data={ports} columns={columns} searchable={false} />);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
});

describe('DataTable alignment and density', () => {
  it('right-aligns a numeric column, header and cells, with tabular figures', () => {
    render(<DataTable data={ports} columns={columns} searchable={false} />);
    const table = screen.getByRole('table');
    expect(table).toHaveClass('tabular-nums');
    const header = screen.getByRole('columnheader', { name: /rx/i });
    expect(header).toHaveClass('text-right');
    expect(header).not.toHaveClass('text-left');
    expect(screen.getByText('940.5').closest('td')).toHaveClass('text-right');
    expect(screen.getByText('Gi1/0/1').closest('td')).not.toHaveClass('text-right');
  });

  it('compact density tightens rows and the header', () => {
    render(<DataTable data={ports} columns={columns} searchable={false} density="compact" />);
    expect(screen.getByText('Gi1/0/1').closest('td')).toHaveClass('py-2');
    expect(screen.getByRole('columnheader', { name: /port/i })).toHaveClass('h-10');
  });

  it('defaults to comfortable density', () => {
    render(<DataTable data={ports} columns={columns} searchable={false} />);
    expect(screen.getByText('Gi1/0/1').closest('td')).toHaveClass('py-3');
  });
});

describe('ErrorState', () => {
  it("shows the server's message from a thrown error, as an alert", () => {
    render(<ErrorState error={envelopeError} />);
    expect(screen.getByRole('alert')).toHaveTextContent(
      'Cannot connect to 10.20.0.2:443: connection refused',
    );
  });

  it('retries with a refresh icon, not the "add" plus', () => {
    const { container } = render(<ErrorState message="Could not load ports" onRetry={() => {}} />);
    const button = screen.getByRole('button', { name: /try again/i });
    expect(button.querySelector('.lucide-refresh-cw')).not.toBeNull();
    expect(container.querySelector('.lucide-plus')).toBeNull();
  });
});

describe('Table (shared)', () => {
  it('matches DataTable density and renders figures at fixed width', () => {
    render(
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Port</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow>
            <TableCell>Gi1/0/1</TableCell>
          </TableRow>
        </TableBody>
      </Table>,
    );
    expect(screen.getByRole('table')).toHaveClass('tabular-nums');
    const cell = screen.getByRole('cell', { name: 'Gi1/0/1' });
    expect(cell).toHaveClass('px-4', 'py-3');
    expect(cell).not.toHaveClass('p-4');
    expect(screen.getByRole('columnheader', { name: 'Port' })).toHaveClass('whitespace-nowrap');
  });
});

describe('DataTable loading and selection labels', () => {
  it('announces loading, and an embedded table draws no second card', () => {
    const { container } = render(
      <div data-testid="outer">
        <DataTable data={[]} columns={columns} isLoading embedded itemName="ports" />
      </div>,
    );
    const status = screen.getByRole('status');
    expect(status).toHaveAttribute('aria-busy', 'true');
    expect(status).toHaveTextContent('Loading ports');
    expect(container.querySelector('.rounded-lg')).toBeNull();
  });

  it('a standalone loading table keeps its card', () => {
    const { container } = render(<DataTable data={[]} columns={columns} isLoading itemName="ports" />);
    expect(container.querySelector('.rounded-lg')).not.toBeNull();
  });

  it('names each row checkbox after its row when getRowLabel is given', () => {
    render(
      <DataTable
        data={ports}
        columns={columns}
        searchable={false}
        selectable
        getRowLabel={(p) => p.name}
      />,
    );
    expect(screen.getByRole('checkbox', { name: 'Select Gi1/0/1' })).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Select Gi1/0/2' })).toBeInTheDocument();
  });

  it('keeps the generic name without getRowLabel', () => {
    render(<DataTable data={ports} columns={columns} searchable={false} selectable />);
    expect(screen.getAllByRole('checkbox', { name: 'Select row' })).toHaveLength(2);
  });
});

