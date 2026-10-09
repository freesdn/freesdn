// SPDX-License-Identifier: AGPL-3.0-only
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { HealthGauge } from './HealthGauge';

describe('HealthGauge measured values', () => {
  it.each([null, undefined, Number.NaN, Infinity])('shows N/A for an unavailable value %s', (score) => {
    const { container } = render(<HealthGauge score={score} />);
    expect(screen.getByText('N/A')).toBeInTheDocument();
    expect(container.querySelector('.stroke-green-500')).toBeNull();
    expect(container.querySelector('.stroke-red-500')).toBeNull();
    expect(container.innerHTML).not.toContain('stroke-dashoffset="NaN"');
  });

  it('retains a real zero as a critical measurement', () => {
    const { container } = render(<HealthGauge score={0} />);
    expect(screen.getByText('0')).toBeInTheDocument();
    expect(screen.queryByText('N/A')).toBeNull();
    expect(container.querySelector('.stroke-red-500')).not.toBeNull();
  });
});
