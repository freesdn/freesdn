import { describe, expect, it } from 'vitest';
import type { TFunction } from 'i18next';
import type { EnterpriseAnalytics } from '@/lib/api';
import { buildNetworkHealth, buildTrafficChartData, formatMebibytes } from './dashboardMetrics';

const t = ((key: string) => key) as TFunction;
const analytics = {
  hours: 1, health_score: 99,
  ports: { total_rx_bytes: 1048576, total_tx_bytes: 2097152, total_errors: 500 },
} as EnterpriseAnalytics;

describe('dashboard measurement semantics', () => {
  it('reports byte counters in MiB with no invented measurement window', () => {
    expect(buildTrafficChartData(analytics, t)).toEqual([{
      timestamp: 'DashboardPage.traffic.counterSnapshot', download: 1, upload: 2,
    }]);
  });
  it('never interprets counter totals or health score as measured network health', () => {
    const health = buildNetworkHealth(analytics, t);
    expect(health.latency.value).toBeNull();
    expect(health.packetLoss.value).toBeNull();
    expect(health.uptime.value).toBeNull();
    expect(health.throughput.download).toBeNull();
    expect(health.throughput.upload).toBeNull();
  });
  it('keeps missing data unavailable and accepts a reset without a negative rate', () => {
    expect(buildTrafficChartData(undefined, t)).toEqual([]);
    expect(buildNetworkHealth(undefined, t).uptime.value).toBeNull();
    const reset = { ...analytics, ports: { ...analytics.ports, total_rx_bytes: 0 } };
    expect(buildTrafficChartData(reset, t)[0].download).toBe(0);
    expect(buildNetworkHealth(reset, t).throughput.download).toBeNull();
  });
});

describe('formatMebibytes', () => {
  // The traffic widget shows the counter snapshot as two totals instead of a
  // one-point chart; the totals need a readable unit.
  it('scales MiB to the largest whole binary unit', () => {
    expect(formatMebibytes(812, 'en')).toBe('812 MiB');
    expect(formatMebibytes(3481.6, 'en')).toBe('3.4 GiB');
    expect(formatMebibytes(1.25 * 1024 * 1024, 'en')).toBe('1.3 TiB');
  });
  it('shows a dash for unusable input', () => {
    expect(formatMebibytes(Number.NaN)).toBe('-');
    expect(formatMebibytes(-1)).toBe('-');
  });
});
