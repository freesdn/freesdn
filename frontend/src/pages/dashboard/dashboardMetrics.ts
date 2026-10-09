import type { TFunction } from 'i18next';
import type { EnterpriseAnalytics } from '@/lib/api';

// ── Helper: build traffic chart data from enterprise analytics ──────

export function buildTrafficChartData(
  analytics: EnterpriseAnalytics | undefined,
  t: TFunction,
): { timestamp: string; download: number; upload: number }[] {
  if (!analytics) return [];

  // Current counters may reset at different times; they are a snapshot in
  // MiB, never a time-series or average Mbps over the event-query window.
  const totalTx = analytics.ports?.total_tx_bytes ?? 0;
  const totalRx = analytics.ports?.total_rx_bytes ?? 0;

  // If there is at least some data, show a single summary point so the
  // chart area is not entirely empty.
  if (totalTx === 0 && totalRx === 0) return [];

  // Show a single aggregated data point so the user sees real numbers.
  return [
    {
      timestamp: t('DashboardPage.traffic.counterSnapshot'),
      download: Math.round((totalRx / (1024 * 1024)) * 100) / 100,
      upload: Math.round((totalTx / (1024 * 1024)) * 100) / 100,
    },
  ];
}

// ── Helper: build network health from enterprise analytics ──────────

export function buildNetworkHealth(analytics: EnterpriseAnalytics | undefined, t: TFunction) {
  // Enterprise analytics sums current device counters. Its `hours` window
  // applies to events, not those counters. It cannot establish Mbps, packet
  // loss, latency, or availability; zero would falsely imply a measurement.
  void analytics;
  return {
    latency: { value: null, history: [] as number[] },
    throughput: { download: null, upload: null, history: [] as { download: number; upload: number }[] },
    packetLoss: { value: null, history: [] as number[] },
    uptime: { value: null, label: t('DashboardPage.networkHealth.notAvailable') },
  };
}

