// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { enterpriseApi, type HealthDailySnapshotResponse } from '@/lib/api';


type RangeKey = '7d' | '30d' | '90d';

const RANGES: Array<{ label: RangeKey }> = [
  { label: '7d' },
  { label: '30d' },
  { label: '90d' },
];

export function HealthTrendChart({ siteId }: { siteId?: string }) {
  const { t } = useTranslation('enterprise');
  const [range, setRange] = useState<RangeKey>('7d');

  // Fetch daily snapshots from API
  const { data: dailySnapshots } = useQuery<HealthDailySnapshotResponse[]>({
    queryKey: ['health', 'history', range, siteId],
    queryFn: () =>
      enterpriseApi.getHealthHistory({ range, site_id: siteId }).then((r) => r.data),
    refetchInterval: 60000,
  });

  // Daily chart data from API snapshots
  const chartData = useMemo(() => {
    if (!dailySnapshots) return [];
    return dailySnapshots.map((snap) => ({
      time: new Date(snap.snapshot_date).toLocaleDateString([], { month: 'short', day: 'numeric' }),
      score: Math.round(snap.avg_health_score),
    }));
  }, [dailySnapshots]);

  const hasData = chartData.length > 0;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-base">{t('HealthTrendChart.title')}</CardTitle>
        <div className="flex gap-1">
          {RANGES.map((r) => (
            <Button
              key={r.label}
              variant={range === r.label ? 'default' : 'ghost'}
              size="sm"
              className="h-7 px-2 text-xs"
              onClick={() => setRange(r.label)}
            >
              {r.label}
            </Button>
          ))}
        </div>
      </CardHeader>
      <CardContent>
        {!hasData ? (
          <div className="flex items-center justify-center h-48 text-sm text-muted-foreground">
            {t('HealthTrendChart.empty')}
          </div>
        ) : (
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 5, right: 10, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="healthGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#22c55e" stopOpacity={0.4} />
                    <stop offset="50%" stopColor="#f59e0b" stopOpacity={0.2} />
                    <stop offset="100%" stopColor="#ef4444" stopOpacity={0.1} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis
                  dataKey="time"
                  tick={{ fontSize: 11 }}
                  className="text-muted-foreground"
                />
                <YAxis
                  domain={[0, 100]}
                  tick={{ fontSize: 11 }}
                  className="text-muted-foreground"
                  width={35}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'hsl(var(--card))',
                    border: '1px solid hsl(var(--border))',
                    borderRadius: '0.5rem',
                    fontSize: '0.75rem',
                  }}
                  formatter={(value) => [`${Number(value)}`, t('HealthTrendChart.healthScore')]}
                />
                <Area
                  type="monotone"
                  dataKey="score"
                  stroke="#3b82f6"
                  strokeWidth={2}
                  fill="url(#healthGradient)"
                  animationDuration={800}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
