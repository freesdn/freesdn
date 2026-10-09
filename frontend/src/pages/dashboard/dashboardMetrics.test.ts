import { describe, expect, it } from 'vitest';
import type { TFunction } from 'i18next';
import type { EnterpriseAnalytics } from '@/lib/api';
import { buildNetworkHealth, buildTrafficChartData } from './dashboardMetrics';

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
