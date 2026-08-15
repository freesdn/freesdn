// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Bell, ArrowRight } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { alertRulesApi } from '@/lib/api';

interface ActiveAlertsPanelProps {
  siteId?: string;
}

const severityStyles: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-500 border-red-500/20',
  warning: 'bg-amber-500/10 text-amber-500 border-amber-500/20',
  info: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
};

function timeAgo(dateStr: string, t: (key: string, options?: Record<string, unknown>) => string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const minutes = Math.floor(diff / 60_000);
  if (minutes < 1) return t('ActiveAlertsPanel.time.justNow');
  if (minutes < 60) return t('ActiveAlertsPanel.time.minutesAgo', { minutes });
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return t('ActiveAlertsPanel.time.hoursAgo', { hours });
  const days = Math.floor(hours / 24);
  return t('ActiveAlertsPanel.time.daysAgo', { days });
}

export function ActiveAlertsPanel({ siteId }: ActiveAlertsPanelProps) {
  const { t } = useTranslation('enterprise');
  const { data, isLoading, isError } = useQuery({
    queryKey: ['health', 'active-alerts', { siteId }],
    queryFn: () =>
      alertRulesApi
        .listAlerts({ status: 'firing', limit: 10, site_id: siteId })
        .then((r) => r.data),
    refetchInterval: 30_000,
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Bell className="h-4 w-4" />
          {t('ActiveAlertsPanel.title')}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-3">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-12" />
            ))}
          </div>
        ) : isError ? (
          <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
            {t('ActiveAlertsPanel.error')}
          </div>
        ) : !data?.alerts.length ? (
          <div className="flex flex-col items-center py-8 text-muted-foreground text-sm">
            <Bell className="h-8 w-8 mb-2 opacity-30" />
            {t('ActiveAlertsPanel.empty')}
          </div>
        ) : (
          <div className="space-y-2">
            {data.alerts.map((alert) => (
              <div
                key={alert.id}
                className="flex items-start gap-3 rounded-lg border p-3"
              >
                <Badge
                  variant="outline"
                  className={severityStyles[alert.severity] ?? severityStyles.info}
                >
                  {alert.severity}
                </Badge>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium truncate">
                    {alert.title ?? alert.message ?? t('ActiveAlertsPanel.fallbackTitle')}
                  </p>
                  {alert.device_id && (
                    <p className="text-xs text-muted-foreground mt-0.5">
                      {alert.device_id}
                    </p>
                  )}
                </div>
                <span className="text-xs text-muted-foreground whitespace-nowrap flex-shrink-0">
                  {alert.fired_at ? timeAgo(alert.fired_at, t) : ''}
                </span>
              </div>
            ))}

            <Link
              to="/alerts"
              className="flex items-center justify-center gap-1 pt-2 text-sm text-primary hover:underline"
            >
              {t('ActiveAlertsPanel.viewAll')}
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
