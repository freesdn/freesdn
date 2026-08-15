// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AlertsWidget, type Alert } from '../AlertsWidget';

const baseAlert: Alert = {
  id: 'a1',
  severity: 'critical',
  title: 'Disk usage above 90% on switch-01',
  message: 'Available disk space is critically low.',
  timestamp: new Date().toISOString(),
};

describe('AlertsWidget · accessibility', () => {
  it('renders the empty state when no alerts are present', () => {
    render(<AlertsWidget alerts={[]} />);
    expect(screen.getByText(/all clear/i)).toBeInTheDocument();
  });

  it('icon-only acknowledge button has an accessible name including the alert title', () => {
    const onAcknowledge = vi.fn();
    render(<AlertsWidget alerts={[baseAlert]} onAcknowledge={onAcknowledge} />);

    // Match the full aria-label so we know the alert context is included
    // (not just a generic "acknowledge" · that would fail screen reader users
    // when multiple alerts are visible)
    const ackBtn = screen.getByRole('button', {
      name: /acknowledge alert: disk usage above 90% on switch-01/i,
    });
    expect(ackBtn).toBeInTheDocument();
    expect(ackBtn).toHaveAttribute('aria-label');
  });

  it('fires onAcknowledge with the alert id when the icon button is clicked', async () => {
    const onAcknowledge = vi.fn();
    const user = userEvent.setup();
    render(<AlertsWidget alerts={[baseAlert]} onAcknowledge={onAcknowledge} />);

    await user.click(
      screen.getByRole('button', {
        name: /acknowledge alert: disk usage above 90% on switch-01/i,
      }),
    );
    expect(onAcknowledge).toHaveBeenCalledWith('a1');
  });

  it('does NOT render the acknowledge button when onAcknowledge is omitted', () => {
    render(<AlertsWidget alerts={[baseAlert]} />);
    expect(
      screen.queryByRole('button', { name: /acknowledge alert/i }),
    ).not.toBeInTheDocument();
  });

  it('does NOT render the acknowledge button for already-acknowledged alerts', () => {
    render(
      <AlertsWidget
        alerts={[{ ...baseAlert, acknowledged: true }]}
        onAcknowledge={() => {}}
      />,
    );
    expect(
      screen.queryByRole('button', { name: /acknowledge alert/i }),
    ).not.toBeInTheDocument();
  });
});
