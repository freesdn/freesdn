// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Enterprise Device Inventory
 * ==========================================
 *
 * Full-featured device management console. Built strictly on canonical
 * design-system primitives · no bespoke status/type/icon/progress maps.
 */

import { useState, useMemo, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, useLocation } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import {
  HardDrive,
  MoreHorizontal,
  Power,
  Download,
  Eye,
  X,
  Filter,
  CheckCircle2,
  XCircle,
  Clock3,
  Cpu,
  MemoryStick,
  Trash2,
  RefreshCw,
  Loader2,
} from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { useToast } from '@/hooks/use-toast';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { PageHeader, PageToolbar } from '@/components/layout';
import { StatsGrid } from '@/components/ui/stats-grid';
import { StatusBadge, type StatusVariant } from '@/components/ui/status-indicator';
import {
  DeviceTypeIcon,
  getDeviceTypeLabel,
  getAllDeviceTypes,
} from '@/components/ui/device-type-icon';
import { HealthRing } from '@/components/ui/health-ring';
import { MetricBar, MetricBreakdown } from '@/components/ui/metric-bar';
import { LastUpdated } from '@/components/ui/last-updated';
import { ErrorState } from '@/components/ui/empty-state';
import { SearchBar } from '@/components/ui/search-bar';
import { TypeBadge } from '@/components/ui/type-badge';
import { devicesApi, deviceControlApi, getApiErrorMessage } from '@/lib/api';


/* ============================================================
   Types
   ============================================================ */

interface Device {
  id: string;
  name: string;
  device_type: string;
  model: string | null;
  manufacturer: string | null;
  mac_address: string;
  ip_address: string | null;
  firmware_version: string | null;
  serial_number: string | null;
  status: string;
  is_active: boolean;
  is_managed: boolean;
  uptime_seconds: number | null;
  cpu_usage_percent: number | null;
  memory_usage_percent: number | null;
  controller_id: string | null;
  site_id: string;
  location: string | null;
  floor: string | null;
  room: string | null;
  notes: string | null;
  connection_type: string | null;
  vlan_id: number | null;
  port_count: number;
  active_port_count: number;
  client_count: number;
  last_seen: string | null;
  created_at: string;
  updated_at: string;
  external_id: string | null;
  metadata: Record<string, unknown>;
  capabilities: Record<string, unknown>;
}


/* ============================================================
   Status mapping · device.status → canonical StatusVariant
   ============================================================ */

function toStatusVariant(status: string): StatusVariant {
  switch (status) {
    case 'online':
      return 'online';
    case 'offline':
      return 'offline';
    case 'degraded':
      return 'warning';
    case 'adopting':
    case 'provisioning':
      return 'syncing';
    case 'adoption_failed':
      return 'error';
    default:
      return 'unknown';
  }
}

function deviceTypeIconStatus(
  status: string,
): 'online' | 'offline' | 'degraded' | 'pending' | 'unknown' | 'neutral' {
  switch (status) {
    case 'online':
      return 'online';
    case 'offline':
    case 'adoption_failed':
      return 'offline';
    case 'degraded':
      return 'degraded';
    case 'adopting':
    case 'provisioning':
      return 'pending';
    case 'unknown':
      return 'unknown';
    default:
      return 'neutral';
  }
}

/** Shape returned by GET /devices/stats/summary (DeviceStats). Counts are
 *  aggregated server-side over the full org/site scope (not the 500-row cap). */
interface DeviceAggStats {
  total_devices: number;
  online_devices: number;
  offline_devices: number;
  by_type: Record<string, number>;
  by_status: Record<string, number>;
}

const STATUS_OPTIONS: Array<{ value: string; labelKey: string }> = [
  { value: 'online', labelKey: 'online' },
  { value: 'offline', labelKey: 'offline' },
  { value: 'degraded', labelKey: 'degraded' },
  { value: 'adopting', labelKey: 'adopting' },
  { value: 'provisioning', labelKey: 'provisioning' },
  { value: 'adoption_failed', labelKey: 'adoptionFailed' },
  { value: 'unknown', labelKey: 'unknown' },
];


/* ============================================================
   Utility Functions
   ============================================================ */

function formatUptime(seconds: number | null): string {
  if (!seconds) return '-';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function formatLastSeen(ts: string | null, t: (key: string, opts?: Record<string, unknown>) => string): string {
  if (!ts) return t('DevicesPage.lastSeen.never');
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return t('DevicesPage.lastSeen.justNow');
  if (mins < 60) return t('DevicesPage.lastSeen.minutesAgo', { n: mins });
  const hrs = Math.floor(diff / 3_600_000);
  if (hrs < 24) return t('DevicesPage.lastSeen.hoursAgo', { n: hrs });
  const days = Math.floor(diff / 86_400_000);
  if (days < 30) return t('DevicesPage.lastSeen.daysAgo', { n: days });
  return new Date(ts).toLocaleDateString();
}


/* ============================================================
   Filters
   ============================================================ */

interface Filters {
  search: string;
  type: string;
  status: string;
  manufacturer: string;
  managed: string;
}

const DEFAULT_FILTERS: Filters = {
  search: '',
  type: 'all',
  status: 'all',
  manufacturer: 'all',
  managed: 'all',
};


/* ============================================================
   Main Page
   ============================================================ */

export default function DevicesPage() {
  const { t } = useTranslation('devices');
  const navigate = useNavigate();
  const location = useLocation();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [selectedDevices, setSelectedDevices] = useState<Device[]>([]);
  // Reboot is destructive and was firing straight from the menu with no
  // confirmation at all. The backend's confirm=true gate was the only thing
  // between a mis-click and a rebooted device -- and because the client never
  // sent it, the button simply 400'd, which hid the missing dialog. Fixing the
  // payload without adding this would turn a broken button into a dangerous one.
  const [rebootTargets, setRebootTargets] = useState<string[]>([]);
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false);
  const [isBulkDeleting, setIsBulkDeleting] = useState(false);
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // ── URL-driven tab state ──
  // /devices         → 'dashboard' (default)
  // /devices/list    → 'list'
  const activeTab = location.pathname === '/devices/list' ? 'list' : 'dashboard';
  const setActiveTab = (v: string) => {
    navigate(v === 'dashboard' ? '/devices' : `/devices/${v}`, { replace: true });
  };

  // ---- Data ----
  const { data: devices = [], isLoading, isError, refetch, dataUpdatedAt } = useQuery<Device[]>({
    queryKey: ['devices', { siteId: selectedSiteId }],
    queryFn: async () => {
      const r = await devicesApi.getAll({
        per_page: 500,
        ...(selectedSiteId ? { site_id: selectedSiteId } : {}),
      });
      return r.data.items ?? [];
    },
    // No poll: the global WebSocket invalidates ['devices'] on every
    // device_discovered/updated/status_change, discovery_complete,
    // port_link_*/status and nvr.* event (useWebSocket.ts).
  });

  // Aggregate, org/site-wide device stats. The `devices` list above is capped
  // at 500 rows, so the headline counts and the by-type breakdown are sourced
  // from this server-side aggregate to stay correct even past the cap. (The
  // aggregate has no vendor / managed / CPU-mem data, those stay list-derived.)
  const { data: aggStats } = useQuery<DeviceAggStats>({
    queryKey: ['device-stats', { siteId: selectedSiteId }],
    queryFn: async () => {
      const r = await devicesApi.getStats(selectedSiteId ?? undefined);
      return r.data;
    },
    // No poll: the same device_* and discovery_complete WS events
    // invalidate ['device-stats'] (useWebSocket.ts).
  });

  const rebootMutation = useMutation({
    mutationFn: (id: string) => deviceControlApi.reboot(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['devices'] }),
    onError: (err: unknown) => {
      toast({
        title: t('common:error'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  // ── Bulk action handlers ──
  const handleBulkReboot = useCallback(() => {
    const onlineSelected = selectedDevices.filter((d) => d.status === 'online');
    if (onlineSelected.length === 0) {
      toast({
        title: t('DevicesPage.toasts.noRebootEligible.title'),
        description: t('DevicesPage.toasts.noRebootEligible.description'),
        variant: 'destructive',
      });
      return;
    }
    // Confirm first -- see the rebootTargets comment above.
    setRebootTargets(onlineSelected.map((d) => d.id));
  }, [selectedDevices, toast, t]);

  const confirmReboot = useCallback(() => {
    const ids = rebootTargets;
    setRebootTargets([]);
    if (ids.length === 0) return;
    // Per-device dispatch; each mutation surfaces its own failure toast via
    // the mutation's onError. We only announce dispatch, not success.
    ids.forEach((id) => rebootMutation.mutate(id));
    toast({
      title: t('DevicesPage.toasts.rebootInitiated.title'),
      description: t('DevicesPage.toasts.rebootInitiated.description', { n: ids.length }),
    });
    setSelectedDevices([]);
  }, [rebootTargets, rebootMutation, toast, t]);

  const handleBulkDelete = useCallback(async () => {
    if (selectedDevices.length === 0) return;
    setIsBulkDeleting(true);
    const results = await Promise.allSettled(
      selectedDevices.map((d) => devicesApi.delete(d.id)),
    );
    const ok = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.length - ok;
    setIsBulkDeleting(false);
    setBulkDeleteOpen(false);
    queryClient.invalidateQueries({ queryKey: ['devices'] });
    toast({
      title: t('common:delete'),
      description: t('DevicesPage.filters.countFiltered', { shown: ok, total: results.length }),
      variant: failed > 0 ? 'destructive' : undefined,
    });
    setSelectedDevices([]);
  }, [selectedDevices, queryClient, toast, t]);

  // ---- Derived ----
  const manufacturers = useMemo(() => {
    const set = new Set<string>();
    devices.forEach((d) => { if (d.manufacturer) set.add(d.manufacturer); });
    return [...set].sort();
  }, [devices]);

  const typesPresent = useMemo(() => {
    const set = new Set<string>();
    devices.forEach((d) => set.add(d.device_type));
    return getAllDeviceTypes().filter((t) => set.has(t.key));
  }, [devices]);

  const stats = useMemo(() => {
    // managed/unmanaged + avg CPU/mem have no server-side aggregate, so they
    // are derived from the (capped) device list.
    let managed = 0;
    let totalCpu = 0, cpuCount = 0, totalMem = 0, memCount = 0;
    for (const d of devices) {
      if (d.is_managed) managed++;
      if (d.cpu_usage_percent != null) { totalCpu += d.cpu_usage_percent; cpuCount++; }
      if (d.memory_usage_percent != null) { totalMem += d.memory_usage_percent; memCount++; }
    }

    // Headline counts come from the org/site-wide aggregate when available so
    // they stay correct past the 500-row list cap; fall back to the list.
    if (aggStats) {
      const byStatus = aggStats.by_status ?? {};
      return {
        total: aggStats.total_devices,
        online: aggStats.online_devices,
        offline: aggStats.offline_devices,
        degraded: byStatus.degraded ?? 0,
        pending: (byStatus.adopting ?? 0) + (byStatus.provisioning ?? 0),
        managed,
        unmanaged: devices.length - managed,
        avgCpu: cpuCount > 0 ? Math.round(totalCpu / cpuCount) : null,
        avgMem: memCount > 0 ? Math.round(totalMem / memCount) : null,
      };
    }

    let online = 0, offline = 0, degraded = 0, pending = 0;
    for (const d of devices) {
      if (d.status === 'online') online++;
      else if (d.status === 'offline') offline++;
      else if (d.status === 'degraded') degraded++;
      else if (d.status === 'adopting' || d.status === 'provisioning') pending++;
    }
    return {
      total: devices.length,
      online,
      offline,
      degraded,
      pending,
      managed,
      unmanaged: devices.length - managed,
      avgCpu: cpuCount > 0 ? Math.round(totalCpu / cpuCount) : null,
      avgMem: memCount > 0 ? Math.round(totalMem / memCount) : null,
    };
  }, [devices, aggStats]);

  const breakdowns = useMemo(() => {
    const vendorCounts: Record<string, number> = {};
    const unknownVendor = t('DevicesPage.unknownVendor');
    // by-type prefers the org/site-wide aggregate (correct past the 500 cap);
    // by-vendor has no aggregate, so it stays derived from the device list.
    const typeCounts: Record<string, number> = { ...(aggStats?.by_type ?? {}) };
    const typeTotal = aggStats?.total_devices ?? devices.length;
    for (const d of devices) {
      if (!aggStats) typeCounts[d.device_type] = (typeCounts[d.device_type] || 0) + 1;
      const m = d.manufacturer || unknownVendor;
      vendorCounts[m] = (vendorCounts[m] || 0) + 1;
    }
    const types = Object.entries(typeCounts)
      .sort(([, a], [, b]) => b - a)
      .map(([type, value]) => ({
        label: getDeviceTypeLabel(type),
        value,
        total: typeTotal,
      }));
    const vendors = Object.entries(vendorCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 8)
      .map(([label, value]) => ({ label, value, total: devices.length }));
    return { types, vendors };
  }, [devices, aggStats, t]);

  const filteredDevices = useMemo(
    () =>
      devices.filter((d) => {
        if (filters.search) {
          const q = filters.search.toLowerCase();
          const haystack = [
            d.name,
            d.mac_address,
            d.ip_address ?? '',
            d.model ?? '',
            d.manufacturer ?? '',
          ]
            .join(' ')
            .toLowerCase();
          if (!haystack.includes(q)) return false;
        }
        if (filters.type !== 'all' && d.device_type !== filters.type) return false;
        if (filters.status !== 'all' && d.status !== filters.status) return false;
        if (filters.manufacturer !== 'all' && d.manufacturer !== filters.manufacturer) return false;
        if (filters.managed === 'managed' && !d.is_managed) return false;
        if (filters.managed === 'unmanaged' && d.is_managed) return false;
        return true;
      }),
    [devices, filters],
  );

  const hasActiveFilters =
    filters.search !== '' ||
    filters.type !== 'all' ||
    filters.status !== 'all' ||
    filters.manufacturer !== 'all' ||
    filters.managed !== 'all';

  const handleRowClick = useCallback((d: Device) => navigate(`/devices/${d.id}`), [navigate]);

  // ── CSV export (client-side, from already-loaded rows) ──
  const exportCsv = useCallback((rows: Device[]) => {
    if (rows.length === 0) return;
    const cols: Array<[string, (d: Device) => string | number | null]> = [
      ['name', (d) => d.name],
      ['device_type', (d) => d.device_type],
      ['manufacturer', (d) => d.manufacturer],
      ['model', (d) => d.model],
      ['ip_address', (d) => d.ip_address],
      ['mac_address', (d) => d.mac_address],
      ['firmware_version', (d) => d.firmware_version],
      ['serial_number', (d) => d.serial_number],
      ['status', (d) => d.status],
      ['is_managed', (d) => String(d.is_managed)],
      ['location', (d) => d.location],
      ['floor', (d) => d.floor],
      ['room', (d) => d.room],
      ['vlan_id', (d) => d.vlan_id],
      ['port_count', (d) => d.port_count],
      ['active_port_count', (d) => d.active_port_count],
      ['client_count', (d) => d.client_count],
      ['last_seen', (d) => d.last_seen],
    ];
    const escape = (v: string | number | null): string => {
      const s = v == null ? '' : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const header = cols.map(([h]) => h).join(',');
    const body = rows.map((d) => cols.map(([, fn]) => escape(fn(d))).join(',')).join('\n');
    const blob = new Blob([`${header}\n${body}`], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `devices-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, []);

  const handleBulkExport = useCallback(() => {
    exportCsv(selectedDevices);
    toast({
      title: t('DevicesPage.toasts.exportQueued.title'),
      description: t('DevicesPage.toasts.exportQueued.description', { n: selectedDevices.length }),
    });
    setSelectedDevices([]);
  }, [exportCsv, selectedDevices, toast, t]);

  // ---- Table Columns ----
  const columns: DataTableColumn<Device>[] = useMemo(() => [
    {
      id: 'status_dot',
      header: '',
      sortable: false,
      className: 'w-[44px]',
      cell: (d) => (
        <TooltipProvider delayDuration={200}>
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="inline-flex">
                <StatusBadge variant={toStatusVariant(d.status)} size="sm" />
              </span>
            </TooltipTrigger>
            <TooltipContent side="right">
              <p className="text-xs capitalize">{d.status.replace(/_/g, ' ')}</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      ),
    },
    {
      id: 'name',
      header: t('DevicesPage.columns.device'),
      accessorFn: (d) =>
        `${d.name} ${d.mac_address} ${d.ip_address ?? ''} ${d.model ?? ''} ${d.manufacturer ?? ''}`,
      cell: (d) => (
        <div className="flex items-center gap-3 min-w-[220px]">
          <DeviceTypeIcon
            type={d.device_type}
            status={deviceTypeIconStatus(d.status)}
            size="md"
          />
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-medium truncate">{d.name}</span>
              {!d.is_managed && (
                <StatusBadge variant="warning" size="sm" hideIcon>
                  {t('DevicesPage.badges.unmanaged')}
                </StatusBadge>
              )}
            </div>
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              {d.ip_address && <span className="font-mono">{d.ip_address}</span>}
              {d.ip_address && d.mac_address && (
                <span className="text-muted-foreground/60">·</span>
              )}
              <span className="font-mono uppercase">{d.mac_address}</span>
            </div>
          </div>
        </div>
      ),
    },
    {
      id: 'type',
      header: t('DevicesPage.columns.type'),
      accessorFn: (d) => getDeviceTypeLabel(d.device_type),
      cell: (d) => (
        <span className="inline-flex items-center gap-2">
          <DeviceTypeIcon type={d.device_type} size="sm" bare />
          <span className="text-sm">{getDeviceTypeLabel(d.device_type)}</span>
        </span>
      ),
    },
    {
      id: 'manufacturer',
      header: t('DevicesPage.columns.vendor'),
      accessorFn: (d) => d.manufacturer ?? '',
      cell: (d) =>
        d.manufacturer ? (
          <TypeBadge type={d.manufacturer.toLowerCase()} label={d.manufacturer} size="sm" />
        ) : (
          <span className="text-sm text-muted-foreground">-</span>
        ),
    },
    {
      id: 'model',
      header: t('DevicesPage.columns.modelFirmware'),
      accessorFn: (d) => `${d.model ?? ''} ${d.firmware_version ?? ''}`,
      cell: (d) => (
        <div className="max-w-[200px]">
          <span className="text-sm truncate block">
            {d.model || <span className="text-muted-foreground">-</span>}
          </span>
          {d.firmware_version && (
            <span className="text-[11px] font-mono text-muted-foreground truncate block">
              v{d.firmware_version}
            </span>
          )}
        </div>
      ),
    },
    {
      id: 'uptime',
      header: t('DevicesPage.columns.uptime'),
      accessorFn: (d) => d.uptime_seconds ?? -1,
      cell: (d) =>
        d.uptime_seconds ? (
          <span className="text-sm font-mono tabular-nums">{formatUptime(d.uptime_seconds)}</span>
        ) : (
          <span className="text-xs text-muted-foreground">-</span>
        ),
    },
    {
      id: 'cpu',
      header: t('DevicesPage.columns.cpu'),
      accessorFn: (d) => d.cpu_usage_percent ?? -1,
      cell: (d) => <MetricBar value={d.cpu_usage_percent} />,
    },
    {
      id: 'memory',
      header: t('DevicesPage.columns.memory'),
      accessorFn: (d) => d.memory_usage_percent ?? -1,
      cell: (d) => <MetricBar value={d.memory_usage_percent} />,
    },
    {
      id: 'ports',
      header: t('DevicesPage.columns.ports'),
      accessorFn: (d) => d.port_count,
      cell: (d) => {
        if (!d.port_count) return <span className="text-xs text-muted-foreground">-</span>;
        return (
          <span className="text-sm tabular-nums">
            <span className="font-medium text-foreground">{d.active_port_count}</span>
            <span className="text-muted-foreground"> / {d.port_count}</span>
          </span>
        );
      },
    },
    {
      id: 'last_seen',
      header: t('DevicesPage.columns.lastSeen'),
      accessorFn: (d) => d.last_seen ?? '',
      cell: (d) => (
        <TooltipProvider delayDuration={200}>
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="text-xs text-muted-foreground whitespace-nowrap cursor-default">
                {formatLastSeen(d.last_seen, t)}
              </span>
            </TooltipTrigger>
            {d.last_seen && (
              <TooltipContent>
                <p className="text-xs font-mono">{new Date(d.last_seen).toLocaleString()}</p>
              </TooltipContent>
            )}
          </Tooltip>
        </TooltipProvider>
      ),
    },
    {
      id: 'actions',
      header: '',
      sortable: false,
      cell: (d) => (
        <div className="flex items-center justify-end" onClick={(e) => e.stopPropagation()}>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8"
                aria-label={t('DevicesPage.actions.actionsFor', { name: d.name })}
              >
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              <DropdownMenuItem onClick={() => navigate(`/devices/${d.id}`)}>
                <Eye className="mr-2 h-4 w-4" /> {t('DevicesPage.actions.viewDetails')}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={() => setRebootTargets([d.id])}
                disabled={d.status !== 'online' || rebootMutation.isPending}
              >
                <Power className="mr-2 h-4 w-4" /> {t('DevicesPage.actions.reboot')}
              </DropdownMenuItem>
              <DropdownMenuItem disabled>
                <Download className="mr-2 h-4 w-4" /> {t('DevicesPage.actions.exportConfig')}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      ),
    },
  ], [navigate, rebootMutation, t]);


  // ---- Error ----
  if (isError) {
    return (
      <div className="space-y-6">
        <PageHeader
          icon={HardDrive}
          title={t('DevicesPage.title')}
          description={t('DevicesPage.descriptionShort')}
        />
        <ErrorState
          message={t('DevicesPage.error.message')}
          onRetry={() => refetch()}
        />
      </div>
    );
  }

  // ---- Render ----
  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        icon={HardDrive}
        title={t('DevicesPage.title')}
        description={t('DevicesPage.description', { n: devices.length })}
        onRefresh={() => refetch()}
        refreshing={isLoading}
        actions={
          <div className="flex items-center gap-2">
            <LastUpdated timestamp={dataUpdatedAt} hideOnMobile />
            <Button
              variant="outline"
              size="sm"
              onClick={() => exportCsv(filteredDevices)}
              disabled={filteredDevices.length === 0}
            >
              <Download className="mr-2 h-4 w-4" /> {t('DevicesPage.actions.exportCsv')}
            </Button>
          </div>
        }
      />

      {/* Tabs: Dashboard (analytics) vs Devices (list) */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <TabsList>
          <TabsTrigger value="dashboard">{t('DevicesPage.tabs.dashboard')}</TabsTrigger>
          <TabsTrigger value="list">
            {t('DevicesPage.tabs.devices')}
            <span className="ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px] font-medium leading-none text-muted-foreground">
              {devices.length}
            </span>
          </TabsTrigger>
        </TabsList>

        {/* ──────────────── DASHBOARD TAB ──────────────── */}
        <TabsContent value="dashboard" className="space-y-6 mt-0">
      <StatsGrid
        columns={4}
        isLoading={isLoading}
        stats={[
          {
            title: t('DevicesPage.stats.total.title'),
            value: stats.total,
            icon: HardDrive,
            variant: 'primary',
            description: t('DevicesPage.stats.managedUnmanaged', {
              managed: stats.managed,
              unmanaged: stats.unmanaged,
            }),
          },
          {
            title: t('DevicesPage.stats.online.title'),
            value: stats.online,
            icon: CheckCircle2,
            variant: 'success',
            description:
              stats.total > 0
                ? t('DevicesPage.stats.online.availability', {
                    percent: Math.round((stats.online / stats.total) * 100),
                  })
                : t('DevicesPage.stats.online.noDevices'),
          },
          {
            title: t('DevicesPage.stats.offline.title'),
            value: stats.offline,
            icon: XCircle,
            variant: stats.offline > 0 ? 'destructive' : 'default',
            description:
              stats.degraded > 0
                ? t('DevicesPage.stats.offline.degraded', { n: stats.degraded })
                : t('DevicesPage.stats.offline.needsAttention'),
          },
          {
            title: t('DevicesPage.stats.pending.title'),
            value: stats.pending,
            icon: Clock3,
            variant: stats.pending > 0 ? 'info' : 'default',
            description: t('DevicesPage.stats.pending.awaitingAdoption'),
          },
        ]}
      />

      {/* Detail breakdown · health ring + by-type + by-vendor */}
      {stats.total > 0 && (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {/* Health overview with HealthRing + status breakdown + avg CPU/Mem */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base font-medium">{t('DevicesPage.cards.healthOverview')}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-4">
                <HealthRing
                  value={stats.online}
                  max={stats.total}
                  size="lg"
                  label={t('DevicesPage.metrics.online')}
                />
                <div className="space-y-1">
                  <p className="text-2xl font-bold tabular-nums">
                    {stats.online}
                    <span className="text-sm text-muted-foreground font-normal">
                      {' '}/ {stats.total}
                    </span>
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {t('DevicesPage.stats.managedUnmanaged', {
                      managed: stats.managed,
                      unmanaged: stats.unmanaged,
                    })}
                  </p>
                </div>
              </div>
              <MetricBreakdown
                items={[
                  { label: t('DevicesPage.metrics.online'), value: stats.online, total: stats.total, tone: 'success' },
                  { label: t('DevicesPage.metrics.offline'), value: stats.offline, total: stats.total, tone: 'destructive' },
                  { label: t('DevicesPage.metrics.degraded'), value: stats.degraded, total: stats.total, tone: 'warning' },
                  { label: t('DevicesPage.metrics.pending'), value: stats.pending, total: stats.total, tone: 'info' },
                ]}
              />
              {(stats.avgCpu != null || stats.avgMem != null) && (
                <div className="space-y-3 pt-2 border-t border-border">
                  {stats.avgCpu != null && (
                    <div className="space-y-1">
                      <div className="flex items-center justify-between text-sm">
                        <span className="flex items-center gap-2 text-muted-foreground">
                          <Cpu className="h-3.5 w-3.5" /> {t('DevicesPage.metrics.avgCpu')}
                        </span>
                        <span className="font-medium tabular-nums">{stats.avgCpu}%</span>
                      </div>
                      <MetricBar value={stats.avgCpu} hideValue variant="thin" />
                    </div>
                  )}
                  {stats.avgMem != null && (
                    <div className="space-y-1">
                      <div className="flex items-center justify-between text-sm">
                        <span className="flex items-center gap-2 text-muted-foreground">
                          <MemoryStick className="h-3.5 w-3.5" /> {t('DevicesPage.metrics.avgMemory')}
                        </span>
                        <span className="font-medium tabular-nums">{stats.avgMem}%</span>
                      </div>
                      <MetricBar value={stats.avgMem} hideValue variant="thin" />
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          {/* By Type */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base font-medium">{t('DevicesPage.cards.byType')}</CardTitle>
            </CardHeader>
            <CardContent>
              {breakdowns.types.length > 0 ? (
                <MetricBreakdown items={breakdowns.types} defaultTone="info" />
              ) : (
                <p className="text-sm text-muted-foreground">{t('DevicesPage.noData')}</p>
              )}
            </CardContent>
          </Card>

          {/* By Vendor */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base font-medium">{t('DevicesPage.cards.byVendor')}</CardTitle>
            </CardHeader>
            <CardContent>
              {breakdowns.vendors.length > 0 ? (
                <MetricBreakdown items={breakdowns.vendors} defaultTone="primary" />
              ) : (
                <p className="text-sm text-muted-foreground">{t('DevicesPage.noData')}</p>
              )}
            </CardContent>
          </Card>
        </div>
      )}
        </TabsContent>

        {/* ──────────────── DEVICES LIST TAB ──────────────── */}
        <TabsContent value="list" className="space-y-6 mt-0">
      {/* Toolbar · search + filters */}
      <PageToolbar>
        <SearchBar
          value={filters.search}
          onChange={(v) => setFilters({ ...filters, search: v })}
          placeholder={t('DevicesPage.filters.searchPlaceholder')}
        />
        <Select
          value={filters.type}
          onValueChange={(v) => setFilters({ ...filters, type: v })}
        >
          <SelectTrigger className="w-full sm:w-[160px]" aria-label={t('DevicesPage.filters.byTypeAria')}>
            <SelectValue placeholder={t('DevicesPage.filters.allTypes')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('DevicesPage.filters.allTypes')}</SelectItem>
            {(typesPresent.length > 0 ? typesPresent : getAllDeviceTypes()).map((t) => (
              <SelectItem key={t.key} value={t.key}>
                {t.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={filters.status}
          onValueChange={(v) => setFilters({ ...filters, status: v })}
        >
          <SelectTrigger className="w-full sm:w-[160px]" aria-label={t('DevicesPage.filters.byStatusAria')}>
            <SelectValue placeholder={t('DevicesPage.filters.allStatuses')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('DevicesPage.filters.allStatuses')}</SelectItem>
            {STATUS_OPTIONS.map((s) => (
              <SelectItem key={s.value} value={s.value}>
                {t(`DevicesPage.statusOptions.${s.labelKey}`)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {manufacturers.length > 1 && (
          <Select
            value={filters.manufacturer}
            onValueChange={(v) => setFilters({ ...filters, manufacturer: v })}
          >
            <SelectTrigger className="w-full sm:w-[160px]" aria-label={t('DevicesPage.filters.byVendorAria')}>
              <SelectValue placeholder={t('DevicesPage.filters.allVendors')} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t('DevicesPage.filters.allVendors')}</SelectItem>
              {manufacturers.map((m) => (
                <SelectItem key={m} value={m}>
                  {m}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        <Select
          value={filters.managed}
          onValueChange={(v) => setFilters({ ...filters, managed: v })}
        >
          <SelectTrigger className="w-full sm:w-[140px]" aria-label={t('DevicesPage.filters.byManagementAria')}>
            <SelectValue placeholder={t('DevicesPage.filters.all')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('DevicesPage.filters.all')}</SelectItem>
            <SelectItem value="managed">{t('DevicesPage.filters.managed')}</SelectItem>
            <SelectItem value="unmanaged">{t('DevicesPage.filters.unmanaged')}</SelectItem>
          </SelectContent>
        </Select>
        {hasActiveFilters && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setFilters(DEFAULT_FILTERS)}
            className="gap-1.5 text-muted-foreground hover:text-foreground"
          >
            <X className="h-3.5 w-3.5" />
            {t('DevicesPage.filters.clear')}
          </Button>
        )}
        <span className="ml-auto inline-flex items-center gap-1.5 text-xs text-muted-foreground tabular-nums">
          <Filter className="h-3.5 w-3.5" />
          {filteredDevices.length === devices.length
            ? t('DevicesPage.filters.countAll', { n: devices.length })
            : t('DevicesPage.filters.countFiltered', {
                shown: filteredDevices.length,
                total: devices.length,
              })}
        </span>
      </PageToolbar>

      {/* Data table · DataTable self-wraps in Card per design language */}
      <DataTable
        data={filteredDevices}
        columns={columns}
        isLoading={isLoading}
        selectable
        onSelectionChange={setSelectedDevices}
        searchable={false}
        onRowClick={handleRowClick}
        itemName={t('DevicesPage.itemNamePlural')}
        paginated
        defaultPageSize={25}
        pageSizeOptions={[25, 50, 100]}
        getRowId={(d) => d.id}
      />
        </TabsContent>
      </Tabs>

      {/* Bulk Actions · floating dark pill, conditional on selection */}
      <BulkActionsBar
        selectedCount={selectedDevices.length}
        itemName={t('DevicesPage.itemName')}
        onClear={() => setSelectedDevices([])}
        actions={[
          { label: t('DevicesPage.bulkActions.reboot'), icon: RefreshCw, onClick: handleBulkReboot },
          { label: t('DevicesPage.bulkActions.export'), icon: Download, onClick: handleBulkExport },
          { label: t('DevicesPage.bulkActions.delete'), icon: Trash2, variant: 'destructive', onClick: () => setBulkDeleteOpen(true) },
        ]}
      />

      {/* Bulk delete confirmation */}
      <AlertDialog
        open={rebootTargets.length > 0}
        onOpenChange={(open) => !open && setRebootTargets([])}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('DevicesPage.actions.reboot')}</AlertDialogTitle>
            <AlertDialogDescription>
              {rebootTargets.length > 1
                ? t('DevicesPage.toasts.rebootInitiated.description', { n: rebootTargets.length })
                : t('actions.rebootConfirm')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common:cancel')}</AlertDialogCancel>
            <AlertDialogAction onClick={confirmReboot}>{t('common:confirm')}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={bulkDeleteOpen} onOpenChange={setBulkDeleteOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('DevicesPage.toasts.bulkDelete.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('actions.forgetConfirm')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isBulkDeleting}>
              {t('common:cancel')}
            </AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive hover:bg-destructive/90 text-destructive-foreground"
              disabled={isBulkDeleting}
              onClick={(e) => {
                e.preventDefault();
                void handleBulkDelete();
              }}
            >
              {isBulkDeleting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {t('common:delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
