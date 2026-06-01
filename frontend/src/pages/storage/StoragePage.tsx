// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Storage Page
 *
 * Single-pane read-only dashboard for storage appliances (TrueNAS).
 * Surfaces live ZFS pool health + capacity + redundancy + scrub, active
 * alerts, per-disk SMART temperature/status/errors, sharing services, and
 * data-protection coverage, proxied via GET /controllers/{id}/storage.
 * No writes.
 */

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  HardDrive,
  Plus,
  Database,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Server,
  Cpu,
  Clock,
  MemoryStick,
  Lock,
  Thermometer,
  ShieldCheck,
  ShieldAlert,
  Activity,
  Share2,
  Layers,
  type LucideIcon,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import { StatsGrid } from '@/components/ui/stats-grid';
import { HealthRing } from '@/components/ui/health-ring';
import { MetricBar } from '@/components/ui/metric-bar';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { PageHeader } from '@/components/layout';
import { useSiteStore } from '@/stores/siteStore';
import { controllersApi } from '@/lib/api';
import type { StorageInventory, StoragePool, StorageDisk } from '@/lib/api';
import { cn } from '@/lib/utils';
import { AddTrueNASDialog } from './AddTrueNASDialog';

// ─── helpers ─────────────────────────────────────────────────────────────
function formatBytes(n: number, decimals = 1): string {
  if (!n || n <= 0) return '0 B';
  const k = 1024;
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(k)), units.length - 1);
  return `${(n / Math.pow(k, i)).toFixed(decimals)} ${units[i]}`;
}

function formatUptime(seconds: number): string {
  if (!seconds || seconds <= 0) return '-';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  if (d > 0) return `${d}d ${h}h`;
  const m = Math.floor((seconds % 3600) / 60);
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
}

function timeAgo(ms: number | null): string {
  if (!ms) return '';
  const diff = Date.now() - ms;
  if (diff < 0) return 'just now';
  const days = Math.floor(diff / 86_400_000);
  if (days > 0) return `${days}d ago`;
  const hrs = Math.floor(diff / 3_600_000);
  if (hrs > 0) return `${hrs}h ago`;
  const min = Math.floor(diff / 60_000);
  return min > 0 ? `${min}m ago` : 'just now';
}

function tempColor(t: number | null): string {
  if (t == null) return 'text-muted-foreground';
  if (t >= 55) return 'text-destructive font-semibold';
  if (t >= 45) return 'text-warning';
  return 'text-success';
}

/** HealthRing/MetricBar tone for a "fill %" where MORE used is WORSE. */
type Tone = 'success' | 'warning' | 'destructive' | 'info' | 'primary' | 'muted';
function fillTone(pct: number): Tone {
  if (pct >= 90) return 'destructive';
  if (pct >= 75) return 'warning';
  return 'success';
}

const HEALTH_META: Record<string, { label: string; cls: string; Icon: LucideIcon }> = {
  ok: { label: 'Healthy', cls: 'text-success', Icon: CheckCircle2 },
  warning: { label: 'Degraded', cls: 'text-warning', Icon: AlertTriangle },
  error: { label: 'Fault', cls: 'text-destructive', Icon: XCircle },
};

const ALERT_META: Record<string, { cls: string; Icon: LucideIcon }> = {
  CRITICAL: { cls: 'border-destructive/40 bg-destructive/10 text-destructive', Icon: XCircle },
  ALERT: { cls: 'border-destructive/40 bg-destructive/10 text-destructive', Icon: XCircle },
  ERROR: { cls: 'border-destructive/40 bg-destructive/10 text-destructive', Icon: XCircle },
  WARNING: { cls: 'border-warning/40 bg-warning/10 text-warning', Icon: AlertTriangle },
  NOTICE: { cls: 'border-info/30 bg-info/10 text-info', Icon: AlertTriangle },
  INFO: { cls: 'border-border bg-muted/40 text-muted-foreground', Icon: AlertTriangle },
};

const SERVICE_LABELS: Record<string, string> = {
  cifs: 'SMB', nfs: 'NFS', iscsitarget: 'iSCSI', ssh: 'SSH', snmp: 'SNMP', ftp: 'FTP', webdav: 'WebDAV',
};
const SERVICE_ORDER = ['cifs', 'nfs', 'iscsitarget', 'ssh', 'snmp'];

interface ControllerListItem {
  id: string;
  name: string;
  host: string;
  status?: string;
}

export default function StoragePage() {
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const [addOpen, setAddOpen] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const {
    data: devicesResp,
    isLoading: devicesLoading,
    isError: devicesError,
    refetch: refetchDevices,
  } = useQuery({
    queryKey: ['storage-devices', selectedSiteId],
    queryFn: async () =>
      (await controllersApi.getAll(selectedSiteId ?? undefined, 100, 'truenas')).data,
  });

  const devices: ControllerListItem[] = useMemo(() => devicesResp?.items ?? [], [devicesResp]);
  const activeId = selectedId && devices.some((d) => d.id === selectedId) ? selectedId : devices[0]?.id ?? null;

  const {
    data: inv,
    isLoading: invLoading,
    isFetching: invFetching,
    isError: invIsError,
    error: invError,
    refetch: refetchInv,
  } = useQuery({
    queryKey: ['storage-inventory', activeId],
    queryFn: async () => (await controllersApi.getStorage(activeId!)).data,
    enabled: !!activeId,
    retry: false,
    refetchInterval: 30_000,
  });

  const invErrorDetail =
    (invError as import('axios').AxiosError<{ detail?: string }>)?.response?.data?.detail ||
    (invError as { message?: string })?.message ||
    'Could not reach the appliance.';

  return (
    <div className="space-y-6">
      <PageHeader
        icon={HardDrive}
        title="Storage"
        subtitle="ZFS pool health, capacity, redundancy, disk temps and alerts across your storage appliances, read-only."
        actions={
          <Button onClick={() => setAddOpen(true)}>
            <Plus className="h-4 w-4 mr-2" /> Add TrueNAS Storage
          </Button>
        }
        onRefresh={() => {
          refetchDevices();
          if (activeId) refetchInv();
        }}
        refreshing={invFetching}
      />

      {devicesLoading ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-28 rounded-xl" />)}
        </div>
      ) : devicesError ? (
        <ErrorState message="Failed to load storage appliances." onRetry={() => refetchDevices()} />
      ) : devices.length === 0 ? (
        <EmptyState
          icon={HardDrive}
          title="No storage appliances yet"
          description="Connect a TrueNAS appliance to surface pool health, capacity, disks, and alerts in one pane."
          action={{ label: 'Add TrueNAS Storage', onClick: () => setAddOpen(true) }}
        />
      ) : (
        <>
          {devices.length > 1 && (
            <div className="flex flex-wrap gap-2">
              {devices.map((d) => (
                <button
                  key={d.id}
                  type="button"
                  onClick={() => setSelectedId(d.id)}
                  className={cn(
                    'flex items-center gap-2 rounded-lg border px-3.5 py-2 text-sm transition-colors',
                    d.id === activeId
                      ? 'border-primary bg-primary/10 text-primary font-medium shadow-sm'
                      : 'border-border hover:bg-accent',
                  )}
                >
                  <HardDrive className="h-4 w-4" />
                  <span>{d.name}</span>
                </button>
              ))}
            </div>
          )}

          {invLoading ? (
            <div className="space-y-6">
              <Skeleton className="h-36 rounded-xl" />
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                {[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-24 rounded-xl" />)}
              </div>
              <Skeleton className="h-48 rounded-xl" />
            </div>
          ) : invIsError ? (
            <ErrorState message={invErrorDetail} onRetry={() => refetchInv()} />
          ) : inv ? (
            <StorageDashboard inv={inv} />
          ) : null}
        </>
      )}

      <AddTrueNASDialog open={addOpen} onOpenChange={setAddOpen} />
    </div>
  );
}

// ─── dashboard ─────────────────────────────────────────────────────────────
function StorageDashboard({ inv }: { inv: StorageInventory }) {
  const health = HEALTH_META[inv.health.status] ?? HEALTH_META.ok;

  const totalSize = inv.pools.reduce((a, p) => a + p.size, 0);
  const totalUsed = inv.pools.reduce((a, p) => a + p.allocated, 0);
  const usedPct = totalSize ? (totalUsed / totalSize) * 100 : 0;
  const healthyPools = inv.pools.filter((p) => p.healthy).length;
  const hottest = inv.disks.reduce<number | null>(
    (m, d) => (d.temperature_c != null && (m == null || d.temperature_c > m) ? d.temperature_c : m),
    null,
  );
  const rawTotal = inv.disks.reduce((a, d) => a + d.size, 0);
  const dp = inv.data_protection;
  const dpTotal = dp.snapshot_tasks + dp.replication + dp.cloudsync;
  const crit = inv.health.critical_alert_count;

  // ── uniform KPI row ───────────────────────────────────────────────────
  const stats = [
    {
      title: 'Pools',
      value: inv.pools.length,
      icon: Database,
      variant: healthyPools === inv.pools.length ? ('success' as const) : ('destructive' as const),
      description: `${healthyPools}/${inv.pools.length} healthy`,
    },
    {
      title: 'Disks',
      value: inv.disks.length,
      icon: hottest != null && hottest >= 55 ? Thermometer : HardDrive,
      variant:
        hottest != null && hottest >= 55 ? ('destructive' as const)
        : hottest != null && hottest >= 45 ? ('warning' as const)
        : ('success' as const),
      description: hottest != null ? `hottest ${hottest.toFixed(0)}°C · ${formatBytes(rawTotal)} raw` : `${formatBytes(rawTotal)} raw`,
    },
    {
      title: 'Data protection',
      value: dpTotal,
      icon: dpTotal > 0 ? ShieldCheck : ShieldAlert,
      variant: dpTotal > 0 ? ('success' as const) : ('warning' as const),
      description: dpTotal > 0 ? `${dp.snapshot_tasks} snap · ${dp.replication} repl · ${dp.cloudsync} cloud` : 'no snapshot/replication tasks',
    },
    {
      title: 'Alerts',
      value: inv.health.alert_count,
      icon: crit > 0 ? XCircle : inv.health.alert_count > 0 ? AlertTriangle : CheckCircle2,
      variant: crit > 0 ? ('destructive' as const) : inv.health.alert_count > 0 ? ('warning' as const) : ('success' as const),
      description: crit > 0 ? `${crit} critical` : inv.health.alert_count > 0 ? 'active' : 'all clear',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Hero: capacity ring + appliance identity + system facts */}
      <Card className="overflow-hidden">
        <CardContent className="p-5 sm:p-6">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex items-center gap-5">
              <HealthRing value={usedPct} tone={fillTone(usedPct)} size="lg" label="used" />
              <div className="min-w-0 space-y-1.5">
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="text-xl font-semibold tracking-tight truncate">
                    {inv.system.hostname || inv.name}
                  </h2>
                  {inv.system.version && (
                    <Badge variant="outline" className="text-xs font-normal">{inv.system.version}</Badge>
                  )}
                </div>
                <div className="text-sm text-muted-foreground truncate">
                  {inv.host}
                  {inv.system.product ? ` · ${inv.system.product}` : ''}
                </div>
                <div className={cn('inline-flex items-center gap-1.5 text-sm font-medium', health.cls)}>
                  <health.Icon className="h-4 w-4" />
                  {health.label}
                  <span className="text-muted-foreground font-normal">
                    · {formatBytes(totalUsed)} of {formatBytes(totalSize)} used · {formatBytes(totalSize - totalUsed)} free
                  </span>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-x-8 gap-y-4 sm:grid-cols-4 lg:grid-cols-2 xl:grid-cols-4 lg:shrink-0">
              <Fact Icon={Cpu} label="Model" value={inv.system.product || '-'} />
              <Fact Icon={MemoryStick} label="Memory" value={formatBytes(inv.system.physmem)} />
              <Fact Icon={Clock} label="Uptime" value={formatUptime(inv.system.uptime_seconds)} />
              <Fact Icon={Server} label="Timezone" value={inv.system.timezone || '-'} />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Active alerts banner, the headline (e.g. a hot disk) */}
      {inv.alerts.length > 0 && (
        <div className="space-y-2">
          {inv.alerts.map((a, i) => {
            const meta = ALERT_META[a.level?.toUpperCase()] ?? ALERT_META.INFO;
            return (
              <div key={i} className={cn('flex items-start gap-3 rounded-lg border p-3 text-sm', meta.cls)}>
                <meta.Icon className="h-4 w-4 mt-0.5 shrink-0" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold uppercase text-xs tracking-wide">{a.level}</span>
                    {a.klass && <span className="text-xs opacity-70">{a.klass}</span>}
                    {a.at_ms && <span className="text-xs opacity-60">· {timeAgo(a.at_ms)}</span>}
                  </div>
                  <div className="break-words">{a.message}</div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Uniform KPI row */}
      <StatsGrid stats={stats} columns={4} />

      {/* Pools */}
      <Section icon={Database} title="Pools" badge={`${inv.pools.length}`}>
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 xl:grid-cols-3">
          {inv.pools.map((p) => <PoolCard key={p.name} pool={p} />)}
        </div>
      </Section>

      {/* Services */}
      <Section icon={Share2} title="Sharing & Services">
        <div className="flex flex-wrap gap-2">
          {SERVICE_ORDER.map((svc) => {
            const found = inv.services.find((s) => s.service === svc);
            const running = found?.state === 'RUNNING';
            return (
              <div
                key={svc}
                className={cn(
                  'flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm',
                  running ? 'border-success/40 bg-success/10' : 'border-border bg-muted/30 text-muted-foreground',
                )}
              >
                <span className={cn('h-2 w-2 rounded-full', running ? 'bg-success' : 'bg-muted-foreground/40')} />
                <span className="font-medium">{SERVICE_LABELS[svc] ?? svc}</span>
                <span className="text-xs opacity-60">{running ? 'running' : 'stopped'}</span>
              </div>
            );
          })}
        </div>
      </Section>

      {/* Disks */}
      <Section
        icon={Thermometer}
        title="Disks"
        badge={`${inv.disks.length} · ${formatBytes(rawTotal)} raw`}
      >
        <DataTable
          data={inv.disks}
          columns={diskColumns}
          getRowId={(d) => d.name}
          searchable
          paginated={inv.disks.length > 50}
          defaultPageSize={50}
        />
      </Section>

      {/* Datasets */}
      <Section
        icon={Layers}
        title="Datasets"
        badge={`${inv.datasets.length} · ${inv.snapshot_count} snapshot${inv.snapshot_count === 1 ? '' : 's'}`}
      >
        <DataTable
          data={inv.datasets}
          columns={datasetColumns}
          getRowId={(d) => d.id}
          searchable
          paginated={inv.datasets.length > 25}
          emptyState={<div className="py-10 text-center text-sm text-muted-foreground">No datasets.</div>}
        />
      </Section>
    </div>
  );
}

// ─── columns ─────────────────────────────────────────────────────────────
const diskColumns: DataTableColumn<StorageDisk>[] = [
  {
    id: 'name',
    header: 'Device',
    accessorFn: (d) => d.name,
    cell: (d) => <span className="font-mono text-xs">{d.name}</span>,
  },
  {
    id: 'type',
    header: 'Type',
    cell: (d) => <Badge variant="outline" className="text-xs font-normal">{d.type || '-'}</Badge>,
  },
  {
    id: 'model',
    header: 'Model',
    accessorFn: (d) => d.model,
    cell: (d) => <span className="block max-w-[220px] truncate" title={d.model}>{d.model || '-'}</span>,
  },
  {
    id: 'size',
    header: 'Size',
    accessorFn: (d) => d.size,
    className: 'text-right tabular-nums',
    headerClassName: 'text-right',
    cell: (d) => formatBytes(d.size),
  },
  {
    id: 'temp',
    header: 'Temp',
    accessorFn: (d) => d.temperature_c ?? -1,
    className: 'text-right tabular-nums',
    headerClassName: 'text-right',
    cell: (d) => (
      <span className={tempColor(d.temperature_c)}>
        {d.temperature_c != null ? `${d.temperature_c.toFixed(0)}°C` : '-'}
      </span>
    ),
  },
  {
    id: 'status',
    header: 'Status',
    accessorFn: (d) => d.zfs_status ?? '',
    cell: (d) => {
      if (!d.zfs_status) return <span className="text-xs text-muted-foreground">unassigned</span>;
      const ok = d.zfs_status === 'ONLINE';
      return <span className={cn('text-xs font-medium', ok ? 'text-success' : 'text-destructive')}>{d.zfs_status}</span>;
    },
  },
  {
    id: 'pool',
    header: 'Pool / vdev',
    accessorFn: (d) => d.pool ?? '',
    cell: (d) => (
      <span className="text-xs text-muted-foreground">
        {d.pool ? `${d.pool}${d.vdev_type ? ` · ${d.vdev_type}` : ''}` : '-'}
      </span>
    ),
  },
  {
    id: 'errors',
    header: 'Errors',
    accessorFn: (d) => (d.read_errors ?? 0) + (d.write_errors ?? 0) + (d.checksum_errors ?? 0),
    className: 'text-right tabular-nums',
    headerClassName: 'text-right',
    cell: (d) => {
      const errs = (d.read_errors ?? 0) + (d.write_errors ?? 0) + (d.checksum_errors ?? 0);
      if (!d.pool) return <span className="text-muted-foreground">-</span>;
      return <span className={cn(errs > 0 ? 'text-destructive font-semibold' : 'text-muted-foreground')}>{errs}</span>;
    },
  },
];

type StorageDataset = StorageInventory['datasets'][number];

const datasetColumns: DataTableColumn<StorageDataset>[] = [
  {
    id: 'id',
    header: 'Dataset',
    accessorFn: (d) => d.id,
    cell: (d) => <span className="font-mono text-xs">{d.id}</span>,
  },
  {
    id: 'type',
    header: 'Type',
    cell: (d) => <Badge variant="outline" className="text-xs font-normal">{d.type}</Badge>,
  },
  {
    id: 'used',
    header: 'Used',
    accessorFn: (d) => d.used_bytes,
    className: 'text-right tabular-nums',
    headerClassName: 'text-right',
    cell: (d) => formatBytes(d.used_bytes),
  },
  {
    id: 'usage',
    header: 'Usage',
    sortable: false,
    className: 'w-[160px]',
    cell: (d) => {
      const total = d.used_bytes + d.available_bytes;
      const pct = total > 0 ? (d.used_bytes / total) * 100 : 0;
      return <MetricBar value={pct} thresholds={[75, 90]} variant="thin" showValue />;
    },
  },
  {
    id: 'available',
    header: 'Available',
    accessorFn: (d) => d.available_bytes,
    className: 'text-right tabular-nums',
    headerClassName: 'text-right',
    cell: (d) => formatBytes(d.available_bytes),
  },
  {
    id: 'flags',
    header: 'Flags',
    sortable: false,
    cell: (d) => (
      <div className="flex gap-1">
        {d.encrypted && <Badge variant="outline" className="text-xs font-normal">Encrypted</Badge>}
        {d.locked && <Badge variant="destructive" className="text-xs">Locked</Badge>}
        {!d.encrypted && !d.locked && <span className="text-xs text-muted-foreground">-</span>}
      </div>
    ),
  },
];

// ─── small building blocks ───────────────────────────────────────────────
function Fact({ Icon, label, value }: { Icon: LucideIcon; label: string; value: string }) {
  return (
    <div className="flex items-start gap-2.5">
      <Icon className="h-4 w-4 text-muted-foreground shrink-0 mt-0.5" />
      <div className="min-w-0">
        <div className="text-xs text-muted-foreground">{label}</div>
        <div className="text-sm font-medium truncate" title={value}>{value}</div>
      </div>
    </div>
  );
}

function Section({ icon: Icon, title, badge, children }: { icon: LucideIcon; title: string; badge?: string; children: React.ReactNode }) {
  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold flex items-center gap-2">
        <Icon className="h-4 w-4 text-muted-foreground" />
        {title}
        {badge && (
          <span className="rounded-full bg-muted px-2 py-0.5 text-xs font-normal text-muted-foreground">{badge}</span>
        )}
      </h3>
      {children}
    </div>
  );
}

function PoolCard({ pool: p }: { pool: StoragePool }) {
  const scrub = p.scrub;
  const scrubClean = scrub && (scrub.errors ?? 0) === 0 && scrub.state === 'FINISHED';
  return (
    <Card className="h-full transition-shadow hover:shadow-md">
      <CardContent className="p-4 flex h-full flex-col gap-3">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <Database className="h-4 w-4 text-muted-foreground shrink-0" />
            <span className="font-semibold truncate">{p.name}</span>
            {!p.is_decrypted && <Lock className="h-3.5 w-3.5 text-warning shrink-0" />}
          </div>
          <Badge variant={p.healthy ? 'success' : 'destructive'}>{p.status}</Badge>
        </div>

        <div className="flex items-center gap-4">
          <HealthRing value={p.usage_percent} tone={fillTone(p.usage_percent)} size="md" label="used" />
          <div className="min-w-0 flex-1 space-y-2">
            <div className="text-xs text-muted-foreground">
              <span className="text-foreground font-medium">{formatBytes(p.allocated)}</span> used ·{' '}
              {formatBytes(p.free)} free
              <div className="opacity-70">of {formatBytes(p.size)} total</div>
            </div>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
              <span className="inline-flex items-center gap-1">
                <ShieldCheck className="h-3.5 w-3.5" />
                {p.redundancy.type}{p.redundancy.width > 1 ? ` · ${p.redundancy.width}-wide` : ''}
              </span>
              {p.fragmentation && <span>frag {p.fragmentation}</span>}
            </div>
          </div>
        </div>

        <div className="mt-auto flex items-center gap-1.5 border-t pt-2.5 text-xs">
          <Activity className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
          {scrub && scrub.state ? (
            <span className={scrubClean ? 'text-success' : 'text-warning'}>
              Scrub {scrub.state.toLowerCase()}
              {scrub.finished_at_ms ? ` ${timeAgo(scrub.finished_at_ms)}` : ''}
              {scrub.errors != null ? ` · ${scrub.errors} error${scrub.errors === 1 ? '' : 's'}` : ''}
            </span>
          ) : (
            <span className="text-muted-foreground">No scrub history</span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
