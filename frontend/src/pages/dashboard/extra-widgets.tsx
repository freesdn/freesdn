// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Extra dashboard widgets · richer data views built on top of the existing
 * EnterpriseAnalytics payload. Each component is intentionally small and
 * dense · they live INSIDE a DashboardWidgetCard, so no header/icon here.
 *
 * Every widget gets a ready-to-use React node from the analytics object.
 * If `analytics` is undefined, render a skeleton placeholder.
 */

import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ArrowRight, CheckCircle2, Cpu, MemoryStick } from 'lucide-react';
import { Skeleton } from '@/components/ui/skeleton';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import type { EnterpriseAnalytics, SiteHealthSummary } from '@/lib/api';

// ─── Helpers ─────────────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

function utilColor(pct: number): string {
  if (pct >= 85) return 'bg-destructive';
  if (pct >= 70) return 'bg-warning';
  return 'bg-success';
}

/** Compact horizontal bar with right-aligned numeric label. */
function MiniBar({
  label,
  pct,
  rightLabel,
  onClick,
}: {
  label: string;
  pct: number;
  rightLabel: string;
  onClick?: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={!onClick}
      className={cn(
        'group w-full text-left',
        onClick && 'cursor-pointer',
      )}
    >
      <div className="flex items-baseline justify-between text-xs mb-1">
        <span className="truncate font-medium text-foreground group-hover:text-primary transition-colors">
          {label}
        </span>
        <span className="tabular-nums text-muted-foreground shrink-0 ml-2">{rightLabel}</span>
      </div>
      <div className="h-1.5 rounded-full bg-muted overflow-hidden">
        <div
          className={cn('h-full transition-all', utilColor(pct))}
          style={{ width: `${Math.max(2, Math.min(100, pct))}%` }}
        />
      </div>
    </button>
  );
}

/** Centered numeric stat tile · used inside multi-stat widgets. */
function StatTile({
  label,
  value,
  tone,
}: {
  label: string;
  value: string | number;
  tone?: 'default' | 'success' | 'warning' | 'destructive' | 'info';
}) {
  const toneClass = {
    default: 'text-foreground',
    success: 'text-success',
    warning: 'text-warning',
    destructive: 'text-destructive',
    info: 'text-info',
  }[tone ?? 'default'];
  return (
    <div className="rounded-lg border bg-muted/30 px-3 py-2 text-center">
      <div className={cn('text-2xl font-bold tabular-nums leading-tight', toneClass)}>{value}</div>
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground mt-0.5">{label}</div>
    </div>
  );
}

// ─── Top CPU Consumers ───────────────────────────────────────────────

export function TopCpuWidget({ analytics }: { analytics?: EnterpriseAnalytics }) {
  const navigate = useNavigate();
  const { t } = useTranslation('dashboard');
  if (!analytics) return <Skeleton className="h-[200px] w-full rounded-lg" />;
  const items = analytics.top_devices_cpu?.slice(0, 5) ?? [];
  if (items.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-6 text-muted-foreground">
        <Cpu className="h-8 w-8 opacity-40 mb-2" />
        <p className="text-sm">{t('extraWidgets.cpu.empty')}</p>
      </div>
    );
  }
  return (
    <div className="space-y-2.5">
      {items.map((d) => (
        <MiniBar
          key={d.id}
          label={d.name}
          pct={d.cpu}
          rightLabel={`${d.cpu}%`}
          onClick={() => navigate(`/devices/${d.id}`)}
        />
      ))}
    </div>
  );
}

// ─── Top Memory Consumers ────────────────────────────────────────────

export function TopMemoryWidget({ analytics }: { analytics?: EnterpriseAnalytics }) {
  const navigate = useNavigate();
  const { t } = useTranslation('dashboard');
  if (!analytics) return <Skeleton className="h-[200px] w-full rounded-lg" />;
  const items = analytics.top_devices_memory?.slice(0, 5) ?? [];
  if (items.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-6 text-muted-foreground">
        <MemoryStick className="h-8 w-8 opacity-40 mb-2" />
        <p className="text-sm">{t('extraWidgets.memory.empty')}</p>
      </div>
    );
  }
  return (
    <div className="space-y-2.5">
      {items.map((d) => (
        <MiniBar
          key={d.id}
          label={d.name}
          pct={d.memory}
          rightLabel={`${d.memory}%`}
          onClick={() => navigate(`/devices/${d.id}`)}
        />
      ))}
    </div>
  );
}

// ─── Manufacturer Mix ────────────────────────────────────────────────

export function ManufacturerMixWidget({ analytics }: { analytics?: EnterpriseAnalytics }) {
  const { t } = useTranslation('dashboard');
  if (!analytics) return <Skeleton className="h-[200px] w-full rounded-lg" />;
  const items = analytics.fleet?.by_manufacturer?.slice(0, 6) ?? [];
  const total = items.reduce((sum, m) => sum + m.count, 0);
  if (total === 0) {
    return (
      <p className="text-sm text-muted-foreground text-center py-6">{t('extraWidgets.manufacturer.empty')}</p>
    );
  }
  return (
    <div className="space-y-2.5">
      {items.map((m) => {
        const pct = Math.round((m.count / total) * 100);
        return (
          <MiniBar
            key={m.name}
            label={m.name}
            pct={pct}
            rightLabel={`${m.count} (${pct}%)`}
          />
        );
      })}
    </div>
  );
}

// ─── Wi-Fi Band Mix ──────────────────────────────────────────────────

export function WifiBandsWidget({ analytics }: { analytics?: EnterpriseAnalytics }) {
  const { t } = useTranslation('dashboard');
  if (!analytics) return <Skeleton className="h-[160px] w-full rounded-lg" />;
  const c = analytics.clients;
  const wireless = (c?.band_2g ?? 0) + (c?.band_5g ?? 0) + (c?.band_6g ?? 0);
  if (wireless === 0) {
    return (
      <p className="text-sm text-muted-foreground text-center py-6">{t('extraWidgets.wifiBands.empty')}</p>
    );
  }
  const bands = [
    { label: '6 GHz', count: c?.band_6g ?? 0, color: 'bg-info' },
    { label: '5 GHz', count: c?.band_5g ?? 0, color: 'bg-primary' },
    { label: '2.4 GHz', count: c?.band_2g ?? 0, color: 'bg-warning' },
  ];
  return (
    <div className="space-y-3">
      <div className="flex h-2.5 rounded-full overflow-hidden bg-muted">
        {bands.map(
          (b) =>
            b.count > 0 && (
              <div
                key={b.label}
                className={b.color}
                style={{ width: `${(b.count / wireless) * 100}%` }}
                title={`${b.label}: ${b.count}`}
              />
            ),
        )}
      </div>
      <div className="space-y-1.5">
        {bands.map((b) => (
          <div key={b.label} className="flex items-center justify-between text-xs">
            <span className="flex items-center gap-2">
              <span className={cn('h-2.5 w-2.5 rounded-full', b.color)} />
              <span className="text-muted-foreground">{b.label}</span>
            </span>
            <span className="tabular-nums font-medium">
              {b.count}
              <span className="text-muted-foreground ml-1">
                ({wireless > 0 ? Math.round((b.count / wireless) * 100) : 0}%)
              </span>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Top SSIDs ───────────────────────────────────────────────────────

export function TopSsidsWidget({ analytics }: { analytics?: EnterpriseAnalytics }) {
  const { t } = useTranslation('dashboard');
  if (!analytics) return <Skeleton className="h-[200px] w-full rounded-lg" />;
  const ssids = analytics.clients?.top_ssids?.slice(0, 5) ?? [];
  if (ssids.length === 0) {
    return <p className="text-sm text-muted-foreground text-center py-6">{t('extraWidgets.ssids.empty')}</p>;
  }
  const max = Math.max(...ssids.map((s) => s.clients), 1);
  return (
    <div className="space-y-2.5">
      {ssids.map((s) => (
        <MiniBar
          key={s.ssid}
          label={s.ssid}
          pct={Math.round((s.clients / max) * 100)}
          rightLabel={
            s.clients === 1
              ? t('extraWidgets.ssids.clientCount', { count: s.clients })
              : t('extraWidgets.ssids.clientCountPlural', { count: s.clients })
          }
        />
      ))}
    </div>
  );
}

// ─── PoE Power Budget ────────────────────────────────────────────────

export function PoeBudgetWidget({ analytics }: { analytics?: EnterpriseAnalytics }) {
  const { t } = useTranslation('dashboard');
  if (!analytics) return <Skeleton className="h-[160px] w-full rounded-lg" />;
  const watts = analytics.ports?.total_poe_watts ?? 0;
  const ports = analytics.ports?.poe_ports ?? 0;
  return (
    <div className="space-y-3">
      <div className="text-center py-2">
        <div className="text-4xl font-bold tabular-nums">
          {watts}
          <span className="text-base text-muted-foreground ml-1">W</span>
        </div>
        <div className="text-xs text-muted-foreground mt-1">
          {ports === 1
            ? t('extraWidgets.poe.acrossPorts', { count: ports })
            : t('extraWidgets.poe.acrossPortsPlural', { count: ports })}
        </div>
      </div>
      <div className="grid grid-cols-2 gap-2">
        <StatTile label={t('extraWidgets.poe.avgPerPort')} value={ports > 0 ? `${(watts / ports).toFixed(1)} W` : '-'} />
        <StatTile label={t('extraWidgets.poe.active')} value={ports} tone="info" />
      </div>
    </div>
  );
}

// ─── Security Posture ────────────────────────────────────────────────

export function SecurityPostureWidget({ analytics }: { analytics?: EnterpriseAnalytics }) {
  const { t } = useTranslation('dashboard');
  if (!analytics) return <Skeleton className="h-[200px] w-full rounded-lg" />;
  const s = analytics.security;
  const failedLogins = s?.failed_logins_window ?? 0;
  const ipBlocks = s?.active_ip_blocks ?? 0;
  const anomalies = s?.unresolved_anomalies ?? 0;
  const secEvents = s?.total_security_events ?? 0;
  const hours = analytics.hours ?? 24;
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-2">
        <StatTile
          label={t('extraWidgets.security.failedLogins')}
          value={failedLogins}
          tone={failedLogins > 10 ? 'destructive' : 'success'}
        />
        <StatTile
          label={t('extraWidgets.security.ipBlocks')}
          value={ipBlocks}
          tone={ipBlocks > 0 ? 'warning' : 'success'}
        />
        <StatTile
          label={t('extraWidgets.security.anomalies')}
          value={anomalies}
          tone={anomalies > 0 ? 'destructive' : 'success'}
        />
        <StatTile label={t('extraWidgets.security.secEvents')} value={secEvents} tone="info" />
      </div>
      <p className="text-[10px] text-muted-foreground text-center uppercase tracking-wide">
        {t('extraWidgets.security.lastHours', { hours })}
      </p>
    </div>
  );
}

// ─── Audit Activity ──────────────────────────────────────────────────

export function AuditActivityWidget({ analytics }: { analytics?: EnterpriseAnalytics }) {
  const { t } = useTranslation('dashboard');
  if (!analytics) return <Skeleton className="h-[200px] w-full rounded-lg" />;
  const audit = analytics.audit;
  const total = audit?.total_events ?? 0;
  const byLevel = audit?.by_level ?? {};
  if (total === 0) {
    return <p className="text-sm text-muted-foreground text-center py-6">{t('extraWidgets.audit.empty')}</p>;
  }
  const levels = Object.entries(byLevel)
    .map(([level, count]) => ({ level, count }))
    .sort((a, b) => b.count - a.count);
  const max = Math.max(...levels.map((l) => l.count), 1);
  const toneFor = (level: string): string => {
    if (/critical|error|fatal/i.test(level)) return 'bg-destructive';
    if (/warn/i.test(level)) return 'bg-warning';
    if (/info/i.test(level)) return 'bg-info';
    return 'bg-muted-foreground';
  };
  return (
    <div className="space-y-2.5">
      <div className="flex items-baseline justify-between">
        <span className="text-2xl font-bold tabular-nums">{total}</span>
        <span className="text-xs text-muted-foreground">{t('extraWidgets.audit.totalEvents')}</span>
      </div>
      <div className="space-y-1.5">
        {levels.map((l) => (
          <div key={l.level}>
            <div className="flex items-baseline justify-between text-xs mb-0.5">
              <span className="capitalize text-foreground font-medium">{l.level}</span>
              <span className="tabular-nums text-muted-foreground">{l.count}</span>
            </div>
            <div className="h-1.5 rounded-full bg-muted overflow-hidden">
              <div
                className={cn('h-full', toneFor(l.level))}
                style={{ width: `${(l.count / max) * 100}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Incident Overview ───────────────────────────────────────────────

export function IncidentOverviewWidget({ analytics }: { analytics?: EnterpriseAnalytics }) {
  const navigate = useNavigate();
  const { t } = useTranslation('dashboard');
  if (!analytics) return <Skeleton className="h-[200px] w-full rounded-lg" />;
  const i = analytics.incidents;
  if (!i || i.total === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-6">
        <CheckCircle2 className="h-10 w-10 text-success/60 mb-2" />
        <p className="text-sm font-medium">{t('extraWidgets.incidents.allClear')}</p>
        <p className="text-xs text-muted-foreground">{t('extraWidgets.incidents.noneInWindow')}</p>
      </div>
    );
  }
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-3 gap-2">
        <StatTile label={t('extraWidgets.incidents.open')} value={i.open} tone={i.open > 0 ? 'destructive' : 'success'} />
        <StatTile
          label={t('extraWidgets.incidents.investigating')}
          value={i.investigating}
          tone={i.investigating > 0 ? 'warning' : 'default'}
        />
        <StatTile label={t('extraWidgets.incidents.resolved')} value={i.resolved} tone="success" />
      </div>
      <Button
        variant="outline"
        size="sm"
        className="w-full"
        onClick={() => navigate('/incidents')}
      >
        {t('extraWidgets.incidents.viewAll')}
        <ArrowRight className="h-3.5 w-3.5 ml-1.5" />
      </Button>
    </div>
  );
}

// ─── Port Status ─────────────────────────────────────────────────────

export function PortStatusWidget({ analytics }: { analytics?: EnterpriseAnalytics }) {
  const { t } = useTranslation('dashboard');
  if (!analytics) return <Skeleton className="h-[160px] w-full rounded-lg" />;
  const p = analytics.ports;
  if (!p || p.total === 0) {
    return <p className="text-sm text-muted-foreground text-center py-6">{t('extraWidgets.ports.empty')}</p>;
  }
  const upPct = Math.round((p.up / p.total) * 100);
  return (
    <div className="space-y-3">
      <div className="text-center">
        <div className="text-3xl font-bold tabular-nums">
          {p.up}
          <span className="text-base text-muted-foreground">/{p.total}</span>
        </div>
        <div className="text-xs text-muted-foreground mt-0.5">{t('extraWidgets.ports.portsUp', { pct: upPct })}</div>
      </div>
      <div className="grid grid-cols-3 gap-2">
        <StatTile label={t('extraWidgets.ports.up')} value={p.up} tone="success" />
        <StatTile label={t('extraWidgets.ports.down')} value={p.down} tone={p.down > 0 ? 'destructive' : 'default'} />
        <StatTile label={t('extraWidgets.ports.errors')} value={p.total_errors} tone={p.total_errors > 0 ? 'warning' : 'default'} />
      </div>
      <div className="text-center text-[10px] text-muted-foreground">
        {t('extraWidgets.ports.aggregateTraffic', { value: formatBytes(p.total_tx_bytes + p.total_rx_bytes) })}
      </div>
    </div>
  );
}

// ─── Site Health Map ─────────────────────────────────────────────────

export function SiteHealthWidget({ sites }: { sites?: SiteHealthSummary[] }) {
  const navigate = useNavigate();
  const { t } = useTranslation('dashboard');
  if (!sites) return <Skeleton className="h-[200px] w-full rounded-lg" />;
  if (sites.length === 0) {
    return <p className="text-sm text-muted-foreground text-center py-6">{t('extraWidgets.siteHealth.empty')}</p>;
  }
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
      {sites.slice(0, 6).map((site) => {
        const tone =
          site.avg_health_score >= 90
            ? 'border-success/40 bg-success/5'
            : site.avg_health_score >= 70
              ? 'border-warning/40 bg-warning/5'
              : 'border-destructive/40 bg-destructive/5';
        return (
          <button
            key={site.site_id}
            onClick={() => navigate(`/sites/${site.site_id}`)}
            className={cn(
              'rounded-lg border px-3 py-2 text-left transition-all hover:border-primary/40 hover:bg-muted/50',
              tone,
            )}
          >
            <div className="text-xs font-medium truncate">{site.site_name}</div>
            <div className="flex items-baseline justify-between mt-1">
              <span className="text-lg font-bold tabular-nums">
                {Math.round(site.avg_health_score)}
                <span className="text-xs text-muted-foreground">%</span>
              </span>
              <Badge variant="outline" className="text-[9px] px-1 py-0 h-4">
                {t('extraWidgets.siteHealth.deviceCount', { count: site.device_count })}
              </Badge>
            </div>
          </button>
        );
      })}
    </div>
  );
}
