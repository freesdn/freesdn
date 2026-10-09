// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ComplianceGauge, complianceVariant, formatCompliance } from './SLACompliance';

describe('SLA measurement presentation', () => {
  it.each([null, NaN, Infinity, -1, 101])('shows unavailable for %s without a false zero gauge', value => {
    render(<ComplianceGauge value={value} unavailable="Not measured" />);
    expect(screen.getByText('Not measured')).toBeInTheDocument();
    expect(screen.queryByText('0.0%')).not.toBeInTheDocument();
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
    expect(complianceVariant(value)).toBe('default');
  });

  it('keeps measured zero visible and does not color it as success', () => {
    render(<ComplianceGauge value={0} unavailable="Not measured" />);
    expect(screen.getByText('0.0%')).toHaveClass('text-destructive');
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '0');
    expect(complianceVariant(0)).toBe('destructive');
    expect(formatCompliance(0, 'Not measured')).toBe('0.0%');
  });

  it.each([[80, 'warning'], [95, 'success'], [100, 'success']] as const)(
    'preserves the existing measured %s percent severity', (value, variant) => {
      render(<ComplianceGauge value={value} unavailable="Not measured" />);
      expect(screen.getByText(`${value.toFixed(1)}%`)).toHaveClass(`text-${variant}`);
      expect(complianceVariant(value)).toBe(variant);
    },
  );
});
