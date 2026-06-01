// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { StatusBadge, StatusIndicator } from '../status-indicator';

describe('StatusBadge', () => {
  it('renders the default label for a known variant', () => {
    render(<StatusBadge variant="online" />);
    expect(screen.getByText('Online')).toBeInTheDocument();
  });

  it('prefers explicit children over the default label', () => {
    render(<StatusBadge variant="online">Connected</StatusBadge>);
    expect(screen.getByText('Connected')).toBeInTheDocument();
    expect(screen.queryByText('Online')).not.toBeInTheDocument();
  });

  it('falls back to back-compat `status` prop when `variant` is missing', () => {
    render(<StatusBadge status="offline" />);
    expect(screen.getByText('Offline')).toBeInTheDocument();
  });

  it('respects the `label` prop', () => {
    render(<StatusBadge variant="info" label="Custom label" />);
    expect(screen.getByText('Custom label')).toBeInTheDocument();
  });

  it('maps severity_critical to a destructive tone (red)', () => {
    const { container } = render(<StatusBadge variant="severity_critical" />);
    const badge = container.firstElementChild as HTMLElement;
    expect(badge.className).toMatch(/text-destructive/);
  });

  it('maps warning to a warning tone (amber)', () => {
    const { container } = render(<StatusBadge variant="warning" />);
    const badge = container.firstElementChild as HTMLElement;
    expect(badge.className).toMatch(/text-warning/);
  });

  it('hides the indicator dot when hideIcon=true', () => {
    const { container } = render(<StatusBadge variant="online" hideIcon />);
    // StatusIndicator renders a span with `relative inline-flex` wrapper
    expect(container.querySelectorAll('.relative.inline-flex').length).toBe(0);
  });
});

describe('StatusIndicator', () => {
  it('renders without crashing for an unknown variant (graceful fallback)', () => {
    // @ts-expect-error · intentionally testing fallback path
    render(<StatusIndicator status="this-does-not-exist" />);
    // Should not throw; renders a muted dot
  });
});
