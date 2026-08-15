// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { ShieldCheck, ArrowRight } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import { slaApi } from '@/lib/api';

interface SLAComplianceCardProps {
  siteId?: string;
}

export function SLAComplianceCard({ siteId }: SLAComplianceCardProps) {
  const { t } = useTranslation('enterprise');
  const { data, isLoading, isError } = useQuery({
    queryKey: ['health', 'sla-summary', { siteId }],
    queryFn: () => slaApi.getSummary({ site_id: siteId }).then((r) => r.data),
    refetchInterval: 60_000,
  });

  const compliance = data?.avg_compliance_percent ?? 0;
  const activePolicies = data?.active_policies ?? 0;
  // "0.0%" red is misleading when there are no SLA policies at all,
  // a fresh tenant sees a panic-coloured card on its first login because
  // the average of zero policies is mathematically 0. Treat 0 policies
  // as "N/A" with muted styling instead.
  const hasPolicies = activePolicies > 0;
  const complianceColor = !hasPolicies
    ? 'text-muted-foreground'
    : compliance >= 95 ? 'text-green-500'
    : compliance >= 80 ? 'text-amber-500'
    : 'text-red-500';

  const complianceBg = !hasPolicies
    ? 'bg-muted/30'
    : compliance >= 95 ? 'bg-green-500/10'
    : compliance >= 80 ? 'bg-amber-500/10'
    : 'bg-red-500/10';

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <ShieldCheck className="h-4 w-4" />
          {t('SLAComplianceCard.title')}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-3">
            <Skeleton className="h-20" />
            <Skeleton className="h-6 w-2/3" />
          </div>
        ) : isError ? (
          <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
            {t('SLAComplianceCard.error')}
          </div>
        ) : (
          <div className="space-y-4">
            <div className={cn('rounded-xl p-4 text-center', complianceBg)}>
              <span className={cn('text-4xl font-bold tabular-nums', complianceColor)}>
                {hasPolicies ? `${compliance.toFixed(1)}%` : t('SLAComplianceCard.notAvailable')}
              </span>
              <p className="text-xs text-muted-foreground mt-1">
                {hasPolicies ? t('SLAComplianceCard.overallCompliance') : t('SLAComplianceCard.noPolicies')}
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-lg border p-3 text-center">
                <div className="text-xl font-semibold">{data?.active_policies ?? 0}</div>
                <div className="text-xs text-muted-foreground">{t('SLAComplianceCard.activePolicies')}</div>
              </div>
              <div className="rounded-lg border p-3 text-center">
                <div className={cn('text-xl font-semibold', (data?.active_breaches ?? 0) > 0 ? 'text-red-500' : 'text-green-500')}>
                  {data?.active_breaches ?? 0}
                </div>
                <div className="text-xs text-muted-foreground">{t('SLAComplianceCard.activeBreaches')}</div>
              </div>
            </div>

            <Link
              to="/sla"
              className="flex items-center justify-center gap-1 text-sm text-primary hover:underline"
            >
              {t('SLAComplianceCard.viewDashboard')}
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
