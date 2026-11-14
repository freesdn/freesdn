// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The "as of" indicator against real React Query state: a remembered answer,
 * a live answer, a device-busy 503 being waited out, and one that never cleared.
 */
import { describe, expect, it } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import { useQuery } from '@tanstack/react-query';
import { AxiosError, AxiosHeaders, type InternalAxiosRequestConfig } from 'axios';
import { AsOfIndicator, LiveReadStatus, formatAsOf } from '@/components/ui/live-read-status';
import { liveReadQueryOptions } from '@/lib/api/liveRead';
import { renderWithProviders } from '@/test-utils';

const DEVICE = 'gw-1';
const BUSY = 'Device busy: gateway full sync since 14:02:10 UTC (35s). Nothing was sent to it; try again in a few seconds.';

function busy503(retryAfter = '1'): AxiosError {
  const config = { headers: new AxiosHeaders() } as InternalAxiosRequestConfig;
  return new AxiosError('Request failed with status code 503', AxiosError.ERR_BAD_RESPONSE, config, {}, {
    data: { error: { code: 503, message: BUSY } },
    status: 503,
    statusText: '',
    headers: new AxiosHeaders({ 'retry-after': retryAfter }),
    config,
  });
}

function Panel({ name, fetch, enabled = true, retryLimit }: { name: string; fetch: () => Promise<unknown>; enabled?: boolean; retryLimit?: number }) {
  const options = liveReadQueryOptions();
  const { data, isPending } = useQuery({
    queryKey: ['gateways', DEVICE, name],
    queryFn: fetch,
    enabled,
    ...options,
    ...(retryLimit === undefined ? {} : { retry: (count: number, error: unknown) => count < retryLimit && options.retry(count, error) }),
  });
  return <p>{isPending ? `${name}: loading` : `${name}: ${JSON.stringify(data)}`}</p>;
}

describe('formatAsOf', () => {
  it('shows only the time for today and the date for another day', () => {
    const now = new Date(2026, 10, 13, 15, 0);
    const today = new Date(2026, 10, 13, 14, 2).toISOString();
    const earlier = new Date(2026, 10, 12, 9, 30).toISOString();
    expect(formatAsOf(today, now, 'en-GB')).toBe('14:02');
    expect(formatAsOf(earlier, now, 'en-GB')).toMatch(/12 Nov, 09:30/);
  });
});

describe('AsOfIndicator', () => {
  it('says the answer is from a busy device', () => {
    const asOf = new Date().toISOString();
    renderWithProviders(<AsOfIndicator asOf={asOf} reason="device_busy" />);
    const pill = screen.getByTestId('live-read-as-of');
    expect(pill).toHaveTextContent(/^As of .+, device busy$/);
    expect(pill.getAttribute('title')).toMatch(/nothing new was asked of it/);
  });
});

describe('LiveReadStatus', () => {
  it('shows the oldest remembered answer among the active reads', async () => {
    const older = '2026-11-13T09:00:00Z';
    const newer = '2026-11-13T09:30:00Z';
    renderWithProviders(
      <>
        <LiveReadStatus deviceId={DEVICE} />
        <Panel name="rules" fetch={async () => ({ data: { rules: [], as_of: newer, cached: true, cache_reason: 'device_busy' } })} />
        <Panel name="nat" fetch={async () => ({ data: { rules: [], as_of: older, cached: true, cache_reason: 'device_busy' } })} />
      </>,
    );
    const pill = await screen.findByTestId('live-read-as-of');
    expect(pill).toHaveTextContent(`As of ${formatAsOf(older)}, device busy`);
  });

  it('shows nothing while every read is live, and ignores reads that are not active', async () => {
    renderWithProviders(
      <>
        <LiveReadStatus deviceId={DEVICE} />
        <Panel name="live" fetch={async () => ({ data: { as_of: new Date().toISOString(), cached: false, cache_reason: null } })} />
        <Panel name="other-tab" enabled={false} fetch={async () => ({ data: { as_of: '2026-11-13T09:00:00Z', cached: true } })} />
      </>,
    );
    await screen.findByText(/live: \{/);
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });

  it('waits out a device-busy 503 calmly and then shows the read', async () => {
    let calls = 0;
    const fetch = async () => {
      calls += 1;
      if (calls === 1) throw busy503('1');
      return { data: { rules: ['ok'], as_of: new Date().toISOString(), cached: false, cache_reason: null } };
    };
    renderWithProviders(
      <>
        <LiveReadStatus deviceId={DEVICE} />
        <Panel name="rules" fetch={fetch} />
      </>,
    );
    const busy = await screen.findByTestId('live-read-busy');
    expect(busy).toHaveTextContent('Device busy, retrying');
    expect(busy.getAttribute('title')).toBe(BUSY);
    expect(screen.getByText('rules: loading')).toBeInTheDocument();
    await screen.findByText(/rules: .*"ok"/, undefined, { timeout: 3000 });
    expect(calls).toBe(2);
    await waitFor(() => expect(screen.queryByTestId('live-read-busy')).not.toBeInTheDocument());
  });

  it('offers a retry once the device stayed busy through every attempt', async () => {
    let busyLeft = 1;
    const fetch = async () => {
      if (busyLeft > 0) {
        busyLeft -= 1;
        throw busy503();
      }
      return { data: { ok: true } };
    };
    renderWithProviders(
      <>
        <LiveReadStatus deviceId={DEVICE} />
        <Panel name="rules" fetch={fetch} retryLimit={0} />
      </>,
    );
    const stuck = await screen.findByTestId('live-read-still-busy');
    expect(stuck).toHaveTextContent('Device still busy');
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    await screen.findByText('rules: {"data":{"ok":true}}');
    await waitFor(() => expect(screen.queryByTestId('live-read-still-busy')).not.toBeInTheDocument());
  });
});
