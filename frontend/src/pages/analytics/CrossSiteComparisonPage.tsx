// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Cross-Site Comparison
 * =======================
 *
 * Compares every site in the operator's org side-by-side. Each metric
 * has a "worst" callout, the site with the lowest online-%, the site
 * with the most open alerts, etc., to help the operator triage
 * across a multi-site deployment without drilling into each site one
 * by one.
 *
 * Backed by GET /api/v1/analytics/sites/comparison (single batched
 * endpoint, total query cost is constant regardless of site count).
 */
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  AlertTriangle, MapPin, Activity, Phone, Server, Wifi, Camera,
  Shield, TrendingDown, ArrowRight,
} from 'lucide-react';
import { analyticsApi } from '@/lib/api/analytics';
import { PageHeader } from '@/components/layout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

type SiteRow = NonNullable<Awaited<ReturnType<typeof analyticsApi.getSitesComparison>>['data']>['sites'][number];

function StatCell({
  value,
  subtext,
  worstHere,
  emptyOk = false,
}: {
  value: number | string | null | undefined;
  subtext?: string;
  worstHere?: boolean;
  emptyOk?: boolean;  // Don't flag 0 as "worst" if 0 is good (e.g. alerts)
}) {
  const isEmpty = value == null || value === 0 || value === '';
  return (
    <td className={cn(
      'px-3 py-2 align-middle text-sm tabular-nums',
      worstHere && !emptyOk && 'bg-destructive/5',
    )}>
      <div className="flex flex-col">
        <span className={cn(
          'font-medium',
          isEmpty && 'text-muted-foreground',
          worstHere && !emptyOk && 'text-destructive',
        )}>
          {value ?? '-'}
        </span>
        {subtext && (
          <span className="text-[10px] text-muted-foreground">{subtext}</span>
        )}
      </div>
    </td>
  );
}

export function CrossSiteComparisonPage() {
  const navigate = useNavigate();
  const { t } = useTranslation('analytics');
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['analytics-sites-comparison'],
    queryFn: () => analyticsApi.getSitesComparison(),
    refetchInterval: 30_000,
    staleTime: 10_000,
  });

  const sites = data?.data?.sites ?? [];
  const summary = data?.data?.summary;

  // Identify the "worst" site per metric so the FE can highlight
  // outliers without forcing the operator to read every cell.
  const worstOnlinePct = sites.length > 0
    ? sites.reduce((acc, s) => {
        if (s.devices.online_pct == null) return acc;
        if (acc == null || s.devices.online_pct < acc.devices.online_pct!) return s;
        return acc;
      }, null as SiteRow | null)
    : null;
  const worstAlerts = sites.length > 0
    ? sites.reduce((acc, s) => {
        if (s.alerts.open === 0) return acc;
        if (acc == null || s.alerts.open > acc.alerts.open) return s;
        return acc;
      }, null as SiteRow | null)
    : null;
  const worstFwCompliance = sites.length > 0
    ? sites.reduce((acc, s) => {
        if (s.firmware.compliance_pct == null) return acc;
        if (acc == null || s.firmware.compliance_pct < acc.firmware.compliance_pct!) return s;
        return acc;
      }, null as SiteRow | null)
    : null;

  return (
    <div className="space-y-6">
      <PageHeader
        icon={MapPin}
        title={t('CrossSiteComparisonPage.header.title')}
        description={t('CrossSiteComparisonPage.header.description')}
        onRefresh={() => refetch()}
        refreshing={isLoading}
      />

      {isError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('CrossSiteComparisonPage.errors.loadFailed')}</span>
          </CardContent>
        </Card>
      )}

      {/* Org-level rollup, hidden when there are no sites so the empty
          state isn't accompanied by a row of zeroed summary cards. */}
      {summary && summary.total_sites > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <Card>
            <CardContent noOffset className="p-4 flex items-center gap-3">
              <MapPin className="h-8 w-8 text-primary" />
              <div>
                <div className="text-2xl font-semibold tabular-nums">{summary.total_sites}</div>
                <div className="text-xs text-muted-foreground">{t('CrossSiteComparisonPage.summary.sites')}</div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent noOffset className="p-4 flex items-center gap-3">
              <Server className="h-8 w-8 text-primary" />
              <div>
                <div className="text-2xl font-semibold tabular-nums">
                  {summary.total_online_devices}/{summary.total_devices}
                </div>
                <div className="text-xs text-muted-foreground">{t('CrossSiteComparisonPage.summary.devicesOnline')}</div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent noOffset className="p-4 flex items-center gap-3">
              <Phone className="h-8 w-8 text-primary" />
              <div>
                <div className="text-2xl font-semibold tabular-nums">{summary.total_phones}</div>
                <div className="text-xs text-muted-foreground">{t('CrossSiteComparisonPage.summary.phones')}</div>
              </div>
            </CardContent>
          </Card>
          <Card className={summary.total_critical_open > 0 ? 'border-destructive' : ''}>
            <CardContent noOffset className="p-4 flex items-center gap-3">
              <AlertTriangle className={cn(
                'h-8 w-8',
                summary.total_critical_open > 0 ? 'text-destructive' : 'text-muted-foreground',
              )} />
              <div>
                <div className="text-2xl font-semibold tabular-nums">{summary.total_alerts_open}</div>
                <div className="text-xs text-muted-foreground">
                  {t('CrossSiteComparisonPage.summary.openAlerts', { count: summary.total_critical_open })}
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Outlier callouts, one row per metric where one site is
          materially worse than the others. */}
      {(worstAlerts || (worstOnlinePct && (worstOnlinePct.devices.online_pct ?? 100) < 95) || worstFwCompliance) && (
        <Card className="border-amber-500/40 bg-amber-50/30 dark:bg-amber-950/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <TrendingDown className="h-4 w-4 text-amber-600" /> {t('CrossSiteComparisonPage.outliers.title')}
            </CardTitle>
          </CardHeader>
          <CardContent noOffset className="pt-0 pb-3 px-4 space-y-1 text-sm">
            {worstAlerts && worstAlerts.alerts.open > 0 && (
              <div className="flex items-center gap-2">
                <span className="text-muted-foreground">{t('CrossSiteComparisonPage.outliers.mostOpenAlerts')}</span>
                <Badge variant="destructive" className="font-mono">{worstAlerts.alerts.open}</Badge>
                <button
                  type="button"
                  onClick={() => navigate(`/sites/${worstAlerts.site_id}`)}
                  className="font-medium hover:underline">
                  {worstAlerts.name}
                </button>
                <span className="text-xs text-muted-foreground">
                  {t('CrossSiteComparisonPage.outliers.criticalCount', { count: worstAlerts.alerts.critical_open })}
                </span>
              </div>
            )}
            {worstOnlinePct && (worstOnlinePct.devices.online_pct ?? 100) < 95 && (
              <div className="flex items-center gap-2">
                <span className="text-muted-foreground">{t('CrossSiteComparisonPage.outliers.lowestOnlinePct')}</span>
                <Badge variant="warning" className="font-mono">{worstOnlinePct.devices.online_pct}%</Badge>
                <button
                  type="button"
                  onClick={() => navigate(`/sites/${worstOnlinePct.site_id}`)}
                  className="font-medium hover:underline">
                  {worstOnlinePct.name}
                </button>
                <span className="text-xs text-muted-foreground">
                  {t('CrossSiteComparisonPage.outliers.reachable', { online: worstOnlinePct.devices.online, total: worstOnlinePct.devices.total })}
                </span>
              </div>
            )}
            {worstFwCompliance && (worstFwCompliance.firmware.compliance_pct ?? 100) < 80 && (
              <div className="flex items-center gap-2">
                <span className="text-muted-foreground">{t('CrossSiteComparisonPage.outliers.firmwareCompliance')}</span>
                <Badge variant="warning" className="font-mono">{worstFwCompliance.firmware.compliance_pct}%</Badge>
                <button
                  type="button"
                  onClick={() => navigate(`/sites/${worstFwCompliance.site_id}`)}
                  className="font-medium hover:underline">
                  {worstFwCompliance.name}
                </button>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* The big side-by-side table. Each metric is a row, each site
          is a column header. This is the inverse of the usual
          "one row per site" listing, better for comparing the same
          metric across many sites at a glance. */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t('CrossSiteComparisonPage.table.title')}</CardTitle>
        </CardHeader>
        <CardContent noOffset className="pb-0 px-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/30">
                  <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground sticky left-0 bg-muted/30">
                    {t('CrossSiteComparisonPage.table.metric')}
                  </th>
                  {sites.map((s) => (
                    <th
                      key={s.site_id}
                      className="text-left px-3 py-2 text-xs font-medium"
                      style={{ minWidth: '180px' }}>
                      <button
                        type="button"
                        onClick={() => navigate(`/sites/${s.site_id}`)}
                        className="flex items-center gap-1 hover:underline">
                        <MapPin className="h-3.5 w-3.5 text-primary" />
                        {s.name}
                        <ArrowRight className="h-3 w-3 text-muted-foreground" />
                      </button>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y">
                {/* Devices section */}
                <tr className="bg-muted/10">
                  <td colSpan={sites.length + 1} className="px-4 py-1.5 text-[11px] uppercase font-semibold tracking-wide text-muted-foreground">
                    {t('CrossSiteComparisonPage.sections.devices')}
                  </td>
                </tr>
                <tr>
                  <td className="px-4 py-2 text-sm sticky left-0 bg-background flex items-center gap-2">
                    <Server className="h-3.5 w-3.5 text-muted-foreground" /> {t('CrossSiteComparisonPage.rows.total')}
                  </td>
                  {sites.map((s) => (
                    <StatCell key={s.site_id} value={s.devices.total} subtext={t('CrossSiteComparisonPage.subtext.online', { count: s.devices.online })} />
                  ))}
                </tr>
                <tr>
                  <td className="px-4 py-2 text-sm sticky left-0 bg-background flex items-center gap-2">
                    <Activity className="h-3.5 w-3.5 text-muted-foreground" /> {t('CrossSiteComparisonPage.rows.onlinePct')}
                  </td>
                  {sites.map((s) => (
                    <StatCell
                      key={s.site_id}
                      value={s.devices.online_pct != null ? `${s.devices.online_pct}%` : null}
                      worstHere={s.site_id === worstOnlinePct?.site_id && (s.devices.online_pct ?? 100) < 95}
                    />
                  ))}
                </tr>
                <tr>
                  <td className="px-4 py-2 text-sm sticky left-0 bg-background flex items-center gap-2">
                    <Server className="h-3.5 w-3.5 text-muted-foreground" /> {t('CrossSiteComparisonPage.rows.switches')}
                  </td>
                  {sites.map((s) => (
                    <StatCell key={s.site_id} value={s.devices.switches} />
                  ))}
                </tr>
                <tr>
                  <td className="px-4 py-2 text-sm sticky left-0 bg-background flex items-center gap-2">
                    <Wifi className="h-3.5 w-3.5 text-muted-foreground" /> {t('CrossSiteComparisonPage.rows.accessPoints')}
                  </td>
                  {sites.map((s) => (
                    <StatCell key={s.site_id} value={s.devices.access_points} />
                  ))}
                </tr>
                <tr>
                  <td className="px-4 py-2 text-sm sticky left-0 bg-background flex items-center gap-2">
                    <Camera className="h-3.5 w-3.5 text-muted-foreground" /> {t('CrossSiteComparisonPage.rows.cameras')}
                  </td>
                  {sites.map((s) => (
                    <StatCell key={s.site_id} value={s.devices.cameras} />
                  ))}
                </tr>

                {/* Phones section */}
                <tr className="bg-muted/10">
                  <td colSpan={sites.length + 1} className="px-4 py-1.5 text-[11px] uppercase font-semibold tracking-wide text-muted-foreground">
                    {t('CrossSiteComparisonPage.sections.phones')}
                  </td>
                </tr>
                <tr>
                  <td className="px-4 py-2 text-sm sticky left-0 bg-background flex items-center gap-2">
                    <Phone className="h-3.5 w-3.5 text-muted-foreground" /> {t('CrossSiteComparisonPage.rows.totalPhones')}
                  </td>
                  {sites.map((s) => (
                    <StatCell
                      key={s.site_id}
                      value={s.phones.total}
                      subtext={t('CrossSiteComparisonPage.subtext.registered', { count: s.phones.sip_registered })}
                    />
                  ))}
                </tr>
                <tr>
                  <td className="px-4 py-2 text-sm sticky left-0 bg-background flex items-center gap-2">
                    <Phone className="h-3.5 w-3.5 text-muted-foreground" /> {t('CrossSiteComparisonPage.rows.managed')}
                  </td>
                  {sites.map((s) => (
                    <StatCell key={s.site_id} value={s.phones.managed} />
                  ))}
                </tr>

                {/* Alerts section */}
                <tr className="bg-muted/10">
                  <td colSpan={sites.length + 1} className="px-4 py-1.5 text-[11px] uppercase font-semibold tracking-wide text-muted-foreground">
                    {t('CrossSiteComparisonPage.sections.alerts')}
                  </td>
                </tr>
                <tr>
                  <td className="px-4 py-2 text-sm sticky left-0 bg-background flex items-center gap-2">
                    <AlertTriangle className="h-3.5 w-3.5 text-muted-foreground" /> {t('CrossSiteComparisonPage.rows.open')}
                  </td>
                  {sites.map((s) => (
                    <StatCell
                      key={s.site_id}
                      value={s.alerts.open}
                      subtext={s.alerts.critical_open > 0 ? t('CrossSiteComparisonPage.subtext.critical', { count: s.alerts.critical_open }) : undefined}
                      worstHere={s.site_id === worstAlerts?.site_id && s.alerts.open > 0}
                      emptyOk
                    />
                  ))}
                </tr>
                <tr>
                  <td className="px-4 py-2 text-sm sticky left-0 bg-background flex items-center gap-2">
                    <AlertTriangle className="h-3.5 w-3.5 text-muted-foreground" /> {t('CrossSiteComparisonPage.rows.last24h')}
                  </td>
                  {sites.map((s) => (
                    <StatCell key={s.site_id} value={s.alerts.last_24h} emptyOk />
                  ))}
                </tr>
                <tr>
                  <td className="px-4 py-2 text-sm sticky left-0 bg-background flex items-center gap-2">
                    <AlertTriangle className="h-3.5 w-3.5 text-muted-foreground" /> {t('CrossSiteComparisonPage.rows.last7d')}
                  </td>
                  {sites.map((s) => (
                    <StatCell key={s.site_id} value={s.alerts.last_7d} emptyOk />
                  ))}
                </tr>

                {/* Controllers section */}
                <tr className="bg-muted/10">
                  <td colSpan={sites.length + 1} className="px-4 py-1.5 text-[11px] uppercase font-semibold tracking-wide text-muted-foreground">
                    {t('CrossSiteComparisonPage.sections.controllers')}
                  </td>
                </tr>
                <tr>
                  <td className="px-4 py-2 text-sm sticky left-0 bg-background flex items-center gap-2">
                    <Server className="h-3.5 w-3.5 text-muted-foreground" /> {t('CrossSiteComparisonPage.rows.total')}
                  </td>
                  {sites.map((s) => (
                    <StatCell
                      key={s.site_id}
                      value={s.controllers.total}
                      subtext={t('CrossSiteComparisonPage.subtext.connected', { count: s.controllers.connected })}
                    />
                  ))}
                </tr>

                {/* Firmware section */}
                <tr className="bg-muted/10">
                  <td colSpan={sites.length + 1} className="px-4 py-1.5 text-[11px] uppercase font-semibold tracking-wide text-muted-foreground">
                    {t('CrossSiteComparisonPage.sections.firmwareCompliance')}
                  </td>
                </tr>
                <tr>
                  <td className="px-4 py-2 text-sm sticky left-0 bg-background flex items-center gap-2">
                    <Shield className="h-3.5 w-3.5 text-muted-foreground" /> {t('CrossSiteComparisonPage.rows.compliant')}
                  </td>
                  {sites.map((s) => (
                    <StatCell
                      key={s.site_id}
                      value={s.firmware.compliance_pct != null ? `${s.firmware.compliance_pct}%` : null}
                      subtext={`${s.firmware.compliant}/${s.firmware.tracked}`}
                      worstHere={s.site_id === worstFwCompliance?.site_id && (s.firmware.compliance_pct ?? 100) < 80}
                    />
                  ))}
                </tr>
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {summary?.generated_at && (
        <div className="text-xs text-muted-foreground text-right">
          {t('CrossSiteComparisonPage.footer.generated', { timestamp: new Date(summary.generated_at).toLocaleString() })}
        </div>
      )}

      {!isLoading && sites.length === 0 && (
        <Card>
          <CardContent noOffset className="p-8 text-center text-sm text-muted-foreground">
            {t('CrossSiteComparisonPage.empty.before')} <Button variant="link" onClick={() => navigate('/sites')}>{t('CrossSiteComparisonPage.empty.createOne')}</Button> {t('CrossSiteComparisonPage.empty.after')}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export default CrossSiteComparisonPage;
