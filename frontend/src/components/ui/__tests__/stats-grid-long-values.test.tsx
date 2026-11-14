// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * A long stat value (an address, a "288 / 520" ratio) steps down a size so
 * it fits a quarter-width card, and the full value, title and description are
 * on hover. The gateway overview's WAN IP read "203.0.113...." at 1440 px and
 * the switches page's port ratio "288 / ..." at 390 px, with no way to see
 * the rest. Titles and descriptions wrap to a second line before they are
 * cut ("Total Controll..." at 390 px).
 */
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Globe, Server } from 'lucide-react';
import { StatsGrid } from '../stats-grid';

describe('StatsGrid long values', () => {
  it('uses the smaller size and keeps the full value on hover', () => {
    render(
      <StatsGrid
        columns={4}
        stats={[
          { title: 'WAN IP', value: '203.0.113.10', icon: Globe, description: 'Latency: 9.4 ms, Loss: 0%' },
          { title: 'Switches', value: 31, icon: Server },
        ]}
      />,
    );
    const long = screen.getByText('203.0.113.10');
    expect(long.className).toMatch(/\btext-xl\b/);
    expect(long).toHaveAttribute('title', '203.0.113.10');
    expect(screen.getByText('Latency: 9.4 ms, Loss: 0%')).toHaveAttribute('title', 'Latency: 9.4 ms, Loss: 0%');
    expect(screen.getByText('WAN IP')).toHaveAttribute('title', 'WAN IP');
    // Title and description wrap to two lines before an ellipsis.
    expect(screen.getByText('WAN IP').className).toMatch(/\bline-clamp-2\b/);
    expect(screen.getByText('Latency: 9.4 ms, Loss: 0%').className).toMatch(/\bline-clamp-2\b/);
    // Below sm the icon sits above the value, so the value has the card's
    // full width on a phone; from sm up it is beside it.
    const body = screen.getAllByTestId('stat-card-body')[0];
    expect(body.className).toMatch(/(^|\s)flex-col(\s|$)/);
    expect(body.className).toMatch(/(^|\s)sm:flex-row(\s|$)/);
    const short = screen.getByText('31');
    expect(short.className).toMatch(/text-2xl/);
    expect(short.className).not.toMatch(/\btext-xl\b/);
  });
});
