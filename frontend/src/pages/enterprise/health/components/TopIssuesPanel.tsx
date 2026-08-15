// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { AlertTriangle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import { enterpriseApi } from '@/lib/api';
import { HealthStatusBadge } from './HealthStatusBadge';

interface TopIssuesPanelProps {
  siteId?: string;
}

function scoreColor(score: number): string {
  if (score >= 90) return 'text-green-500';
  if (score >= 70) return 'text-amber-500';
  if (score >= 50) return 'text-orange-500';
  return 'text-red-500';
}

function componentBadgeColor(score: number): string {
  if (score >= 90) return 'bg-green-500/10 text-green-500 border-green-500/20';
  if (score >= 70) return 'bg-amber-500/10 text-amber-500 border-amber-500/20';
  if (score >= 50) return 'bg-orange-500/10 text-orange-500 border-orange-500/20';
  return 'bg-red-500/10 text-red-500 border-red-500/20';
}

export function TopIssuesPanel({ siteId }: TopIssuesPanelProps) {
  const { t } = useTranslation('enterprise');
  const { data, isLoading, isError } = useQuery({
    queryKey: ['health', 'top-issues', { siteId }],
    queryFn: () => enterpriseApi.getTopIssues({ site_id: siteId, limit: 10 }).then((r) => r.data),
    refetchInterval: 60_000,
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <AlertTriangle className="h-4 w-4" />
          {t('TopIssuesPanel.title')}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-3">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-12" />
            ))}
          </div>
        ) : isError ? (
          <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
            {t('TopIssuesPanel.error')}
          </div>
        ) : !data?.issues.length ? (
          <div className="flex flex-col items-center py-8 text-muted-foreground text-sm">
            <AlertTriangle className="h-8 w-8 mb-2 opacity-30" />
            {t('TopIssuesPanel.empty')}
          </div>
        ) : (
          <div className="space-y-2">
            {data.issues.map((issue) => (
              <div
                key={issue.device_id}
                className="flex items-center justify-between rounded-lg border p-3"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <Link
                      to={`/devices/${issue.device_id}`}
                      className="font-medium text-sm hover:underline truncate"
                    >
                      {issue.device_name}
                    </Link>
                    <HealthStatusBadge status={issue.health_status} />
                  </div>
                  {issue.site_name && (
                    <p className="text-xs text-muted-foreground mt-0.5">{issue.site_name}</p>
                  )}
                </div>
                <div className="flex items-center gap-3 flex-shrink-0 ml-3">
                  <Badge variant="outline" className={componentBadgeColor(issue.worst_component_score)}>
                    {issue.worst_component}: {issue.worst_component_score}
                  </Badge>
                  <span className={cn('text-lg font-bold tabular-nums', scoreColor(issue.health_score))}>
                    {issue.health_score}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
