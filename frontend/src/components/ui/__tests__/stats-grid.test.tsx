// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { Activity, CheckCircle, AlertCircle, Server } from 'lucide-react';
import { StatsGrid } from '../stats-grid';

const sampleStats = [
  { title: 'Online', value: 42, icon: CheckCircle, variant: 'success' as const },
  { title: 'Issues', value: 3, icon: AlertCircle, variant: 'destructive' as const },
  { title: 'Recording', value: 12, icon: Activity, variant: 'info' as const, description: '12 active streams' },
];

describe('StatsGrid', () => {
  it('renders one card per stat with title + value', () => {
    render(<StatsGrid stats={sampleStats} columns={3} />);
    expect(screen.getByText('Online')).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
    expect(screen.getByText('Issues')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getByText('Recording')).toBeInTheDocument();
    expect(screen.getByText('12')).toBeInTheDocument();
  });

  it('renders the optional description', () => {
    render(<StatsGrid stats={sampleStats} columns={3} />);
    expect(screen.getByText('12 active streams')).toBeInTheDocument();
  });

  it('shows skeleton when isLoading=true (no stat values rendered)', () => {
    render(<StatsGrid stats={sampleStats} columns={3} isLoading />);
    expect(screen.queryByText('42')).not.toBeInTheDocument();
    expect(screen.queryByText('Online')).not.toBeInTheDocument();
  });

  it('renders empty without crashing on empty stats', () => {
    render(<StatsGrid stats={[]} columns={4} />);
    // No assertion needed · just shouldn't throw
  });

  it('renders a stat with linkTo as a router Link', () => {
    render(
      <MemoryRouter>
        <StatsGrid
          columns={2}
          stats={[
            { title: 'Active alerts', value: 7, icon: AlertCircle, variant: 'destructive', linkTo: '/alerts' },
            { title: 'Servers', value: 12, icon: Server, variant: 'primary' },
          ]}
        />
      </MemoryRouter>
    );
    // First stat is wrapped in <a href="/alerts">
    const link = screen.getByRole('link');
    expect(link).toHaveAttribute('href', '/alerts');
    expect(link).toHaveTextContent('7');
    expect(link).toHaveTextContent('Active alerts');
  });

  it('renders a stat with onClick as a button', async () => {
    const user = userEvent.setup();
    const handleClick = vi.fn();
    render(
      <StatsGrid
        columns={2}
        stats={[
          { title: 'Filter', value: 'All', icon: Server, variant: 'primary', onClick: handleClick },
        ]}
      />
    );
    const button = screen.getByRole('button');
    await user.click(button);
    expect(handleClick).toHaveBeenCalledOnce();
  });

  it('non-clickable stats render as plain divs (no link/button role)', () => {
    render(
      <StatsGrid
        columns={2}
        stats={[
          { title: 'Idle', value: 5, icon: Server, variant: 'primary' },
        ]}
      />
    );
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });
});
