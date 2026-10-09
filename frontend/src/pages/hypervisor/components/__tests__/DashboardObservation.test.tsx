// SPDX-License-Identifier: AGPL-3.0-only
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, screen } from '@testing-library/react';
import { renderWithProviders } from '@/test-utils';
import { DashboardObservation } from '../DashboardObservation';
import { observationFreshness } from '../dashboardObservationState';
import { dashboard } from './dashboardFixture';

afterEach(() => vi.useRealTimers());

describe('dashboard observation freshness', () => {
  it('retains server observation age even with a small client clock difference', () => {
    const data = dashboard({ observation_age_seconds: 8 });
    expect(observationFreshness(data, Date.parse(data.served_at!) - 1000)).toEqual({ state: 'current', age: 8 });
  });
  it.each([null, -1, NaN, Infinity])('refuses invalid observation age %s', age => {
    expect(observationFreshness(dashboard({ observation_age_seconds: age }), Date.now()).state).toBe('unavailable');
  });
  it.each(['collection_started_at', 'observed_at', 'served_at'] as const)('refuses missing or invalid %s', key => {
    expect(observationFreshness(dashboard({ [key]: 'not-a-date' }), Date.now()).state).toBe('unavailable');
  });
  it('refuses impossible timestamp ordering and substantial clock drift', () => {
    const future = new Date(Date.now() + 30000).toISOString();
    expect(observationFreshness(dashboard({ served_at: future }), Date.now()).state).toBe('unavailable');
    expect(observationFreshness(dashboard({ collection_started_at: future }), Date.now()).state).toBe('unavailable');
  });
  it('expires an observation at the freshness boundary without a new fetch', () => {
    vi.useFakeTimers();
    const data = dashboard();
    renderWithProviders(<DashboardObservation data={data} />);
    expect(screen.getByText(/Recent collection/)).toBeInTheDocument();
    act(() => vi.advanceTimersByTime(90000));
    expect(screen.getByText(/Observation is stale/)).toBeInTheDocument();
  });
  it('discloses visible scope, node filesystem semantics and registration aggregation', () => {
    renderWithProviders(<DashboardObservation data={dashboard()} fleet />);
    expect(screen.getByText(/only resources visible/)).toBeInTheDocument();
    expect(screen.getByText(/not datastore capacity/)).toBeInTheDocument();
    expect(screen.getByText(/Physical clusters are not deduplicated/)).toBeInTheDocument();
  });
});
