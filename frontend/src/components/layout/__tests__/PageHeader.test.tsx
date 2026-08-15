// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Server, Plus, Download } from 'lucide-react';
import { PageHeader } from '../PageHeader';

describe('PageHeader', () => {
  it('renders title and description', () => {
    render(
      <PageHeader
        icon={Server}
        title="Controllers"
        description="Manage network controllers"
      />
    );
    expect(screen.getByText('Controllers')).toBeInTheDocument();
    expect(screen.getByText('Manage network controllers')).toBeInTheDocument();
  });

  it('prefers subtitle over description when both are passed', () => {
    render(
      <PageHeader
        title="Controllers"
        subtitle="From subtitle"
        description="From description"
      />
    );
    expect(screen.getByText('From subtitle')).toBeInTheDocument();
    expect(screen.queryByText('From description')).not.toBeInTheDocument();
  });

  it('fires onRefresh when refresh button is clicked', async () => {
    const onRefresh = vi.fn();
    const user = userEvent.setup();
    render(
      <PageHeader title="Controllers" onRefresh={onRefresh} />
    );
    // The refresh button has an icon · find it by its accessible role
    const buttons = screen.getAllByRole('button');
    // First (and likely only) button in this minimal config is Refresh
    await user.click(buttons[0]);
    expect(onRefresh).toHaveBeenCalledOnce();
  });

  it('renders primaryAction with label and fires onClick', async () => {
    const onClick = vi.fn();
    const user = userEvent.setup();
    render(
      <PageHeader
        title="Controllers"
        primaryAction={{ label: 'Add Controller', icon: Plus, onClick }}
      />
    );
    await user.click(screen.getByRole('button', { name: /add controller/i }));
    expect(onClick).toHaveBeenCalledOnce();
  });

  it('renders secondaryActions and fires their onClick handlers', async () => {
    const onExport = vi.fn();
    const user = userEvent.setup();
    render(
      <PageHeader
        title="Controllers"
        secondaryActions={[{ label: 'Export CSV', icon: Download, onClick: onExport }]}
      />
    );
    await user.click(screen.getByRole('button', { name: /export csv/i }));
    expect(onExport).toHaveBeenCalledOnce();
  });

  it('hides actions where hidden=true', () => {
    render(
      <PageHeader
        title="Controllers"
        secondaryActions={[
          { label: 'Visible', onClick: () => {} },
          { label: 'Hidden one', onClick: () => {}, hidden: true },
        ]}
      />
    );
    expect(screen.getByRole('button', { name: 'Visible' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Hidden one' })).not.toBeInTheDocument();
  });

  it('renders the actions slot (v2 style) verbatim', () => {
    render(
      <PageHeader
        title="Controllers"
        actions={<button data-testid="custom-actions">Custom</button>}
      />
    );
    expect(screen.getByTestId('custom-actions')).toBeInTheDocument();
  });
});
