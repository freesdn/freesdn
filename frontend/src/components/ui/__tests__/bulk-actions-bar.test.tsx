// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Trash2, Download } from 'lucide-react';
import { BulkActionsBar } from '../bulk-actions-bar';

describe('BulkActionsBar', () => {
  it('renders nothing when selectedCount is 0', () => {
    const { container } = render(
      <BulkActionsBar selectedCount={0} onClear={() => {}} actions={[]} />
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('shows "1 item selected" with singular pluralization', () => {
    render(<BulkActionsBar selectedCount={1} onClear={() => {}} itemName="device" />);
    expect(screen.getByText('1 device selected')).toBeInTheDocument();
  });

  it('shows "N items selected" with plural pluralization', () => {
    render(<BulkActionsBar selectedCount={5} onClear={() => {}} itemName="device" />);
    expect(screen.getByText('5 devices selected')).toBeInTheDocument();
  });

  it('renders the declarative actions array', async () => {
    const onDelete = vi.fn();
    const onExport = vi.fn();
    const user = userEvent.setup();
    render(
      <BulkActionsBar
        selectedCount={3}
        onClear={() => {}}
        actions={[
          { label: 'Export', icon: Download, onClick: onExport },
          { label: 'Delete', icon: Trash2, variant: 'destructive', onClick: onDelete },
        ]}
      />
    );
    await user.click(screen.getByRole('button', { name: /export/i }));
    await user.click(screen.getByRole('button', { name: /delete/i }));
    expect(onExport).toHaveBeenCalledOnce();
    expect(onDelete).toHaveBeenCalledOnce();
  });

  it('fires onClear when the X button is clicked', async () => {
    const onClear = vi.fn();
    const user = userEvent.setup();
    render(<BulkActionsBar selectedCount={2} onClear={onClear} />);
    await user.click(screen.getByRole('button', { name: /clear selection/i }));
    expect(onClear).toHaveBeenCalledOnce();
  });

  it('renders children alongside declarative actions', () => {
    render(
      <BulkActionsBar
        selectedCount={1}
        onClear={() => {}}
        actions={[{ label: 'Delete', onClick: () => {} }]}
      >
        <button>Custom child</button>
      </BulkActionsBar>
    );
    expect(screen.getByRole('button', { name: 'Delete' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Custom child' })).toBeInTheDocument();
  });

  it('disables buttons when action.disabled is true', () => {
    render(
      <BulkActionsBar
        selectedCount={1}
        onClear={() => {}}
        actions={[{ label: 'Disabled action', onClick: () => {}, disabled: true }]}
      />
    );
    expect(screen.getByRole('button', { name: 'Disabled action' })).toBeDisabled();
  });

  it('never submits a surrounding form (every control is type="button")', async () => {
    const onSubmit = vi.fn((e: React.FormEvent) => e.preventDefault());
    const onDelete = vi.fn();
    const user = userEvent.setup();
    render(
      <form onSubmit={onSubmit}>
        <BulkActionsBar
          selectedCount={2}
          totalCount={10}
          isAllPageSelected
          onSelectAll={() => {}}
          onClear={() => {}}
          actions={[{ label: 'Delete', icon: Trash2, variant: 'destructive', onClick: onDelete }]}
        />
      </form>,
    );
    for (const button of screen.getAllByRole('button')) {
      expect(button).toHaveAttribute('type', 'button');
    }
    await user.click(screen.getByRole('button', { name: /delete/i }));
    await user.click(screen.getByRole('button', { name: /clear selection/i }));
    expect(onDelete).toHaveBeenCalledOnce();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('gives every control a keyboard focus ring that shows on the inverted pill', () => {
    render(
      <BulkActionsBar
        selectedCount={2}
        onClear={() => {}}
        actions={[{ label: 'Export', icon: Download, onClick: () => {} }]}
      />,
    );
    for (const button of screen.getAllByRole('button')) {
      expect(button).toHaveClass('focus-visible:ring-2', 'focus-visible:ring-background');
    }
  });
});
