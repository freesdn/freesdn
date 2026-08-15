// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { EmptyState } from '../empty-state';

describe('EmptyState', () => {
  it('renders title + optional description', () => {
    render(<EmptyState title="No devices" description="Add a device to get started" />);
    expect(screen.getByText('No devices')).toBeInTheDocument();
    expect(screen.getByText('Add a device to get started')).toBeInTheDocument();
  });

  it('fires the primary action onClick', async () => {
    const onClick = vi.fn();
    const user = userEvent.setup();
    render(
      <EmptyState
        title="No devices"
        action={{ label: 'Add device', onClick }}
      />
    );
    await user.click(screen.getByRole('button', { name: /add device/i }));
    expect(onClick).toHaveBeenCalledOnce();
  });

  it('fires both primary and secondary action handlers', async () => {
    const primary = vi.fn();
    const secondary = vi.fn();
    const user = userEvent.setup();
    render(
      <EmptyState
        title="Empty"
        action={{ label: 'Primary', onClick: primary }}
        secondaryAction={{ label: 'Secondary', onClick: secondary }}
      />
    );
    await user.click(screen.getByRole('button', { name: 'Primary' }));
    await user.click(screen.getByRole('button', { name: 'Secondary' }));
    expect(primary).toHaveBeenCalledOnce();
    expect(secondary).toHaveBeenCalledOnce();
  });

  it('renders compact variant without action when none provided', () => {
    render(<EmptyState title="Nothing here" variant="compact" />);
    expect(screen.getByText('Nothing here')).toBeInTheDocument();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });
});
