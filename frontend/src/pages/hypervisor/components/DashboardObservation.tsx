// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useTranslation } from 'react-i18next';
import type { HypervisorDashboard } from '@/lib/api';
import { useObservationFreshness } from './dashboardObservationState';

export type Observation = Pick<HypervisorDashboard, 'collection_started_at' | 'observed_at' | 'served_at' | 'observation_age_seconds' | 'stale_after_seconds' | 'coverage' | 'metric_coverage'>;

export function DashboardObservation({ data, fleet = false }: { data: Observation; fleet?: boolean }) {
  const { t } = useTranslation('hypervisor');
  const freshness = useObservationFreshness(data);
  return <div className="rounded-lg border border-border bg-muted/30 p-4 space-y-2" role="status">
    <p className={freshness.state === 'current' && data.coverage === 'complete_visible' ? 'text-foreground' : 'text-warning'}>
      {t(`DashboardObservation.freshness.${freshness.state}`)} · {t(`DashboardObservation.coverage.${data.coverage}`)}
    </p>
    {freshness.age !== null && <p className="text-xs text-muted-foreground">{t('DashboardObservation.collected', { time: new Date(data.collection_started_at!).toLocaleString(), age: Math.floor(freshness.age) })}</p>}
    <p className="text-xs text-muted-foreground">{t('DashboardObservation.visibleScope')}</p>
    <p className="text-xs text-muted-foreground">{t('DashboardObservation.storageScope')}</p>
    {fleet && <p className="text-xs text-warning">{t('DashboardObservation.registrationScope')}</p>}
    <ul className="text-xs text-muted-foreground space-y-1">
      {(['cpu', 'memory', 'node_filesystem'] as const).map(key => {
        const coverage = data.metric_coverage?.[key];
        return <li key={key}>{t(`DashboardObservation.metrics.${key}`)}: {t(`DashboardObservation.metricStatus.${coverage?.status ?? 'unavailable'}`)}
          {coverage && <> · {t('DashboardObservation.contributors', { observed: coverage.observed_nodes, expected: coverage.expected_nodes })}
            {coverage.reasons?.length ? ` · ${coverage.reasons.map(reason => t(`DashboardObservation.reasons.${reason}`)).join(', ')}` : ''}</>}
        </li>;
      })}
    </ul>
  </div>;
}
