// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Enterprise Site Detail Page
 * ==========================================
 *
 * Single pane of glass for a remote site:
 * Overview, Network (subnets), VPN, Agent, Devices, Settings
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState, useMemo, useCallback, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams, useNavigate, Navigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { sitesApi, devicesApi, vpnApi, agentsApi, controllersApi, getApiErrorMessage } from '@/lib/api';
import type { SiteVPNConfig, SiteVPNConfigList, AgentSummary, BrainVPNDiscovery, BrainVPNServer, VPNPreflightResult, VPNDeviceReachability } from '@/lib/api/types';
import {
  AlertTriangle,
  ArrowLeft,
  RefreshCw,
  Edit,
  Trash2,
  Building2,
  MapPin,
  Server,
  Wifi,
  Activity,
  CheckCircle,
  XCircle,
  AlertCircle,
  Copy,
  Settings,
  MoreHorizontal,
  Shield,
  Eye,
  ExternalLink,
  Loader2,
  Globe,
  Network,
  Bot,
  Plus,
  Signal,
  Star,
  Search,
  Download,
  Unplug,
  Upload,
  Zap,
  Router,
  WifiOff,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';
import { PageHeader } from '@/components/layout';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { StatsGrid } from '@/components/ui/stats-grid';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Skeleton } from '@/components/ui/skeleton';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { AgentSchedulesPanel } from '@/components/agent/AgentSchedulesPanel';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
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
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { FormDialog } from '@/components/ui/form-dialog';
import { FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { z } from 'zod';
import { DataTable, DataTableColumn } from '@/components/ui/data-table';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';


/* ============================================================
   Types
   ============================================================ */

interface Site {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  address: string | null;
  city: string | null;
  country: string | null;
  timezone: string;
  time_format: string;
  date_format: string;
  is_active: boolean;
  organization_id: string;
  settings: Record<string, unknown>;
  subnets: SubnetEntry[];
  gateway_ip: string | null;
  controller_count: number;
  device_count: number;
  online_device_count: number;
  created_at: string;
  updated_at: string;
}

interface SubnetEntry {
  cidr: string;
  name: string;
  vlan_id?: number | null;
  description?: string;
}

interface Device {
  id: string;
  name: string;
  device_type: string;
  status: string;
  ip_address: string | null;
  mac_address: string | null;
  model: string | null;
  manufacturer: string | null;
  firmware_version: string | null;
  is_active: boolean;
  last_seen: string | null;
  updated_at: string;
}


/* ============================================================
   Sub-Components
   ============================================================ */

function DetailRow({ label, value, mono, copyable }: {
  label: string; value: string | number | null | undefined; mono?: boolean; copyable?: boolean;
}) {
  const { t } = useTranslation('sites');
  const display = value != null && value !== '' ? String(value) : '-';
  const isEmpty = display === '-';

  return (
    <div className="flex items-center justify-between py-2.5 border-b border-border last:border-0">
      <dt className="text-sm text-muted-foreground shrink-0">{label}</dt>
      <dd className={cn(
        'text-sm text-right truncate max-w-[60%]',
        mono && !isEmpty && 'font-mono',
        isEmpty && 'text-muted-foreground',
      )}>
        {copyable && !isEmpty ? (
          <TooltipProvider delayDuration={200}>
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  className="inline-flex items-center gap-1.5 hover:text-primary transition-colors"
                  onClick={() => navigator.clipboard.writeText(display).catch(() => {})}
                >
                  {display}
                  <Copy className="h-3 w-3 opacity-40" />
                </button>
              </TooltipTrigger>
              <TooltipContent><p className="text-xs">{t('SiteDetailPage.common.clickToCopy')}</p></TooltipContent>
            </Tooltip>
          </TooltipProvider>
        ) : display}
      </dd>
    </div>
  );
}

function StatusBadge({ active }: { active: boolean }) {
  const { t } = useTranslation('sites');
  return (
    <Badge
      variant="outline"
      className={cn(
        'gap-1 text-xs font-medium',
        active
          ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600'
          : 'border-muted-foreground/30 bg-muted-foreground/10 text-muted-foreground',
      )}
    >
      {active ? <CheckCircle className="h-3 w-3" /> : <XCircle className="h-3 w-3" />}
      {active ? t('SiteDetailPage.common.active') : t('SiteDetailPage.common.inactive')}
    </Badge>
  );
}

function DeviceStatusDot({ status }: { status: string }) {
  const color = status === 'online' ? 'bg-emerald-500' : status === 'offline' ? 'bg-red-500' : 'bg-amber-500';
  return <span className={cn('inline-block h-2 w-2 rounded-full', color)} />;
}

function formatDate(ts: string | null): string {
  if (!ts) return '-';
  return new Date(ts).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

type TFn = (key: string, opts?: Record<string, unknown>) => string;

function formatRelative(ts: string | null | undefined, t: TFn): string {
  if (!ts) return t('SiteDetailPage.relative.never');
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return t('SiteDetailPage.relative.justNow');
  if (mins < 60) return t('SiteDetailPage.relative.minutesAgo', { n: mins });
  const hrs = Math.floor(diff / 3_600_000);
  if (hrs < 24) return t('SiteDetailPage.relative.hoursAgo', { n: hrs });
  const days = Math.floor(diff / 86_400_000);
  if (days < 30) return t('SiteDetailPage.relative.daysAgo', { n: days });
  return new Date(ts).toLocaleDateString();
}

const DEVICE_TYPE_LABELS: Record<string, string> = {
  switch: 'Switch', access_point: 'Access Point', router: 'Router', gateway: 'Gateway',
  firewall: 'Firewall', camera: 'Camera', nvr: 'NVR', voip_phone: 'VoIP Phone',
  pbx: 'PBX', server: 'Server', hypervisor: 'Hypervisor', other: 'Other',
};

const STATUS_LABELS: Record<string, string> = {
  online: 'Online', offline: 'Offline', degraded: 'Degraded',
  adopting: 'Adopting', provisioning: 'Provisioning', unknown: 'Unknown',
};

const VPN_STATUS_COLORS: Record<string, string> = {
  connected: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600',
  disconnected: 'border-muted-foreground/30 bg-muted-foreground/10 text-muted-foreground',
  connecting: 'border-amber-500/30 bg-amber-500/10 text-amber-600',
  error: 'border-red-500/30 bg-red-500/10 text-red-600',
  not_configured: 'border-muted-foreground/30 bg-muted-foreground/10 text-muted-foreground',
};

const AGENT_STATUS_COLORS: Record<string, string> = {
  online: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600',
  offline: 'border-muted-foreground/30 bg-muted-foreground/10 text-muted-foreground',
  connecting: 'border-amber-500/30 bg-amber-500/10 text-amber-600',
  error: 'border-red-500/30 bg-red-500/10 text-red-600',
  maintenance: 'border-blue-500/30 bg-blue-500/10 text-blue-600',
};


/* ============================================================
   Main Component
   ============================================================ */

const VALID_TABS = new Set(['overview', 'network', 'vpn', 'agent', 'devices', 'settings']);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export default function SiteDetailPage() {
  const { siteId, tab } = useParams<{ siteId: string; tab?: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { t } = useTranslation('sites');

  const validSiteId = !!(siteId && UUID_RE.test(siteId));
  const activeTab = tab && VALID_TABS.has(tab) ? tab : 'overview';
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [editMode, setEditMode] = useState(false);

  const setActiveTab = useCallback((value: string) => {
    navigate(
      value === 'overview' ? `/sites/${siteId}` : `/sites/${siteId}/${value}`,
      { replace: true },
    );
  }, [siteId, navigate]);

  // ── Fetch site ────────────────────────────────────────────
  const { data: site, isLoading, isError, error, refetch, isFetching } = useQuery<Site>({
    queryKey: ['site', siteId],
    queryFn: async () => {
      const r = await sitesApi.getById(siteId!);
      return r.data;
    },
    enabled: validSiteId,
    refetchInterval: 30_000,
  });

  // ── Fetch devices for this site ───────────────────────────
  const { data: devices = [], isLoading: devicesLoading } = useQuery<Device[]>({
    queryKey: ['site-devices', siteId],
    queryFn: async () => {
      const r = await devicesApi.getAll({ site_id: siteId, per_page: 100 });
      return r.data.items ?? r.data ?? [];
    },
    enabled: !!siteId,
    refetchInterval: 30_000,
  });

  // ── Fetch VPN config for this site ────────────────────────
  const { data: vpnConfig, isLoading: vpnLoading, isError: vpnError } = useQuery<SiteVPNConfig | null>({
    queryKey: ['site-vpn', siteId],
    queryFn: async () => {
      try {
        const r = await vpnApi.getSiteConfig(siteId!);
        return r.data;
      } catch (err: unknown) {
        // 404 means no VPN config · that's expected, return null
        if (err && typeof err === 'object' && 'response' in err) {
          const axiosErr = err as { response?: { status?: number } };
          if (axiosErr.response?.status === 404) return null;
        }
        throw err; // Re-throw non-404 errors so React Query surfaces them
      }
    },
    enabled: !!siteId,
    refetchInterval: 30_000,
  });

  // ── Fetch agents for this site ────────────────────────────
  const { data: agents = [], isLoading: agentsLoading } = useQuery<AgentSummary[]>({
    queryKey: ['site-agents', siteId],
    queryFn: async () => {
      const r = await agentsApi.getForSite(siteId!);
      return r.data ?? [];
    },
    enabled: !!siteId,
    refetchInterval: 15_000,
  });

  // ── Update mutation ───────────────────────────────────────
  const updateMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) => sitesApi.update(siteId!, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['site', siteId] });
      queryClient.invalidateQueries({ queryKey: ['sites'] });
      setEditMode(false);
      toast({ title: t('SiteDetailPage.toasts.siteUpdated') });
    },
    onError: (err: any) => {
      toast({ title: t('SiteDetailPage.common.error'), description: err?.response?.data?.detail || t('SiteDetailPage.toasts.updateFailed'), variant: 'destructive' });
    },
  });

  // ── Delete mutation ───────────────────────────────────────
  const deleteMutation = useMutation({
    mutationFn: () => sitesApi.delete(siteId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sites'] });
      navigate('/sites');
    },
    onError: (err: any) => {
      toast({ title: t('SiteDetailPage.common.error'), description: err?.response?.data?.detail || t('SiteDetailPage.toasts.deleteFailed'), variant: 'destructive' });
    },
  });

  // ── Device table columns ──────────────────────────────────
  const deviceColumns: DataTableColumn<Device>[] = useMemo(() => [
    {
      id: 'name', header: t('SiteDetailPage.deviceTable.device'), accessorFn: (d: Device) => d.name,
      cell: (d: Device) => (
        <button className="flex items-center gap-3 text-left hover:underline" onClick={() => navigate(`/devices/${d.id}`)}>
          <div className="min-w-0">
            <div className="flex items-center gap-2 font-medium">
              <DeviceStatusDot status={d.status} />
              {d.name}
            </div>
            <div className="text-xs text-muted-foreground">
              {t(`SiteDetailPage.deviceTypes.${d.device_type}`, { defaultValue: DEVICE_TYPE_LABELS[d.device_type] ?? d.device_type })}
              {d.manufacturer && ` \u00b7 ${d.manufacturer}`}
            </div>
          </div>
        </button>
      ),
    },
    {
      id: 'status', header: t('SiteDetailPage.deviceTable.status'), accessorKey: 'status' as keyof Device,
      cell: (d: Device) => (
        <Badge variant="outline" className={cn('text-xs',
          d.status === 'online' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600' :
          d.status === 'offline' ? 'border-red-500/30 bg-red-500/10 text-red-600' :
          'border-amber-500/30 bg-amber-500/10 text-amber-600',
        )}>
          {t(`SiteDetailPage.statuses.${d.status}`, { defaultValue: STATUS_LABELS[d.status] ?? d.status })}
        </Badge>
      ),
    },
    {
      id: 'ip', header: t('SiteDetailPage.deviceTable.ipAddress'), accessorKey: 'ip_address' as keyof Device,
      cell: (d: Device) => <span className="font-mono text-sm">{d.ip_address ?? '-'}</span>,
    },
    {
      id: 'model', header: t('SiteDetailPage.deviceTable.model'), accessorKey: 'model' as keyof Device,
      cell: (d: Device) => <span className="text-sm text-muted-foreground">{d.model ?? '-'}</span>,
    },
    {
      id: 'lastSeen', header: t('SiteDetailPage.deviceTable.lastSeen'),
      accessorFn: (d: Device) => d.last_seen ?? d.updated_at,
      cell: (d: Device) => <span className="text-xs text-muted-foreground">{formatRelative(d.last_seen ?? d.updated_at, t)}</span>,
    },
  ], [navigate, t]);


  // Guard: reject malformed siteId (path traversal, injection)
  if (!validSiteId) {
    return <Navigate to="/sites" replace />;
  }

  // ── Loading state ─────────────────────────────────────────
  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <Skeleton className="h-10 w-10 rounded-lg" />
          <div className="space-y-2"><Skeleton className="h-6 w-64" /><Skeleton className="h-4 w-40" /></div>
        </div>
        <div className="grid gap-4 md:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-28" />)}
        </div>
        <Skeleton className="h-96" />
      </div>
    );
  }

  // ── Error state ───────────────────────────────────────────
  if (isError || !site) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <div className="flex h-16 w-16 items-center justify-center rounded-full bg-red-100 dark:bg-red-900/30 mb-4">
          <AlertCircle className="h-8 w-8 text-red-500" />
        </div>
        <h2 className="text-xl font-semibold">{t('SiteDetailPage.errors.loadFailedTitle')}</h2>
        <p className="text-muted-foreground mt-1 max-w-sm">
          {(error as Error)?.message || t('SiteDetailPage.errors.loadFailedDesc')}
        </p>
        <div className="flex gap-2 mt-6">
          <Button variant="outline" onClick={() => navigate('/sites')}>
            <ArrowLeft className="mr-2 h-4 w-4" /> {t('SiteDetailPage.actions.backToSites')}
          </Button>
          <Button onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> {t('SiteDetailPage.actions.retry')}
          </Button>
        </div>
      </div>
    );
  }

  const offlineCount = site.device_count - site.online_device_count;
  const healthPct = site.device_count > 0 ? Math.round((site.online_device_count / site.device_count) * 100) : 0;
  const location = [site.address, site.city, site.country].filter(Boolean).join(', ');
  const onlineAgent = agents.find(a => a.status === 'online');
  const vpnConnected = vpnConfig?.status === 'connected';

  return (
    <TooltipProvider delayDuration={300}>
      <div className="space-y-6">

        {/* ---- Header ---- */}
        <PageHeader
          icon={Building2}
          title={site.name}
          description={[
            location || site.slug,
            site.timezone,
            site.subnets.length > 0 ? t('SiteDetailPage.header.subnetCount', { count: site.subnets.length }) : null,
          ].filter(Boolean).join(' \u00b7 ')}
          breadcrumbs={
            <button
              onClick={() => navigate('/sites')}
              className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
            >
              <ArrowLeft className="h-3.5 w-3.5" /> {t('SiteDetailPage.actions.backToSites')}
            </button>
          }
          actions={
            <>
              <StatusBadge active={site.is_active} />
              {vpnConnected && (
                <Badge variant="outline" className="gap-1 text-xs border-emerald-500/30 bg-emerald-500/10 text-emerald-600">
                  <Globe className="h-3 w-3" /> VPN
                </Badge>
              )}
              {onlineAgent && (
                <Badge variant="outline" className="gap-1 text-xs border-blue-500/30 bg-blue-500/10 text-blue-600">
                  <Bot className="h-3 w-3" /> Agent
                </Badge>
              )}
              <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
                <RefreshCw className={cn('mr-2 h-4 w-4', isFetching && 'animate-spin')} />
                {t('SiteDetailPage.actions.sync')}
              </Button>
              <Button variant="outline" size="sm" onClick={() => { setActiveTab('settings'); setEditMode(true); }}>
                <Edit className="mr-2 h-4 w-4" /> {t('SiteDetailPage.actions.edit')}
              </Button>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="icon" className="h-9 w-9"><MoreHorizontal className="h-4 w-4" /></Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-52">
                  <DropdownMenuItem onClick={() => navigate(`/devices?site=${siteId}`)}>
                    <Eye className="mr-2 h-4 w-4" /> {t('SiteDetailPage.actions.viewAllDevices')}
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem className="text-red-500 focus:text-red-500" onClick={() => setDeleteOpen(true)}>
                    <Trash2 className="mr-2 h-4 w-4" /> {t('SiteDetailPage.actions.deleteSite')}
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </>
          }
        />


        {/* ---- Quick Stats ---- */}
        <StatsGrid
          columns={4}
          stats={[
            { title: t('SiteDetailPage.stats.controllers'), value: site.controller_count, icon: Server, variant: 'primary' },
            { title: t('SiteDetailPage.stats.devices'), value: site.device_count, icon: Wifi, variant: 'info' },
            { title: t('SiteDetailPage.stats.online'), value: site.online_device_count, icon: Activity, variant: 'success' },
            {
              title: t('SiteDetailPage.stats.health'),
              value: site.device_count > 0 ? `${healthPct}%` : '-',
              icon: Shield,
              variant: healthPct >= 90 ? 'success' : healthPct >= 70 ? 'warning' : 'destructive',
              description: site.device_count > 0 && offlineCount > 0
                ? t('SiteDetailPage.stats.devicesOffline', { count: offlineCount })
                : undefined,
            },
          ]}
        />


        {/* ---- Tabs ---- */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList>
            <TabsTrigger value="overview" className="gap-1.5">
              <Building2 className="h-4 w-4" /> {t('SiteDetailPage.tabs.overview')}
            </TabsTrigger>
            <TabsTrigger value="network" className="gap-1.5">
              <Network className="h-4 w-4" /> {t('SiteDetailPage.tabs.network')}
              {site.subnets.length > 0 && (
                <Badge variant="secondary" className="ml-1 px-1.5 py-0 text-xs tabular-nums">{site.subnets.length}</Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="vpn" className="gap-1.5">
              <Globe className="h-4 w-4" /> {t('SiteDetailPage.tabs.vpn')}
              {vpnConnected && <span className="ml-1 h-2 w-2 rounded-full bg-emerald-500" />}
            </TabsTrigger>
            <TabsTrigger value="agent" className="gap-1.5">
              <Bot className="h-4 w-4" /> {t('SiteDetailPage.tabs.agent')}
              {onlineAgent && <span className="ml-1 h-2 w-2 rounded-full bg-emerald-500" />}
            </TabsTrigger>
            <TabsTrigger value="devices" className="gap-1.5">
              <Wifi className="h-4 w-4" /> {t('SiteDetailPage.tabs.devices')}
              {site.device_count > 0 && (
                <Badge variant="secondary" className="ml-1 px-1.5 py-0 text-xs tabular-nums">{site.device_count}</Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="settings" className="gap-1.5">
              <Settings className="h-4 w-4" /> {t('SiteDetailPage.tabs.settings')}
            </TabsTrigger>
          </TabsList>


          {/* --- Overview Tab --- */}
          <TabsContent value="overview" className="space-y-6">
            <div className="grid gap-6 lg:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <Building2 className="h-4 w-4 text-primary" /> {t('SiteDetailPage.overview.siteInformation')}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <dl className="divide-y-0">
                    <DetailRow label={t('SiteDetailPage.fields.name')} value={site.name} />
                    <DetailRow label={t('SiteDetailPage.fields.slug')} value={site.slug} mono copyable />
                    <DetailRow label={t('SiteDetailPage.fields.id')} value={site.id} mono copyable />
                    <DetailRow label={t('SiteDetailPage.fields.gatewayIp')} value={site.gateway_ip} mono copyable />
                    <DetailRow label={t('SiteDetailPage.fields.status')} value={site.is_active ? t('SiteDetailPage.common.active') : t('SiteDetailPage.common.inactive')} />
                    <DetailRow label={t('SiteDetailPage.fields.subnets')} value={site.subnets.length > 0 ? site.subnets.map(s => s.cidr).join(', ') : null} mono />
                    <DetailRow label={t('SiteDetailPage.fields.description')} value={site.description} />
                  </dl>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <MapPin className="h-4 w-4 text-primary" /> {t('SiteDetailPage.overview.locationAndTime')}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <dl className="divide-y-0">
                    <DetailRow label={t('SiteDetailPage.fields.address')} value={site.address} />
                    <DetailRow label={t('SiteDetailPage.fields.city')} value={site.city} />
                    <DetailRow label={t('SiteDetailPage.fields.country')} value={site.country} />
                    <DetailRow label={t('SiteDetailPage.fields.timezone')} value={site.timezone} />
                    <DetailRow label={t('SiteDetailPage.fields.timeFormat')} value={site.time_format} />
                    <DetailRow label={t('SiteDetailPage.fields.dateFormat')} value={site.date_format} />
                    <DetailRow label={t('SiteDetailPage.fields.created')} value={formatDate(site.created_at)} />
                    <DetailRow label={t('SiteDetailPage.fields.updated')} value={formatDate(site.updated_at)} />
                  </dl>
                </CardContent>
              </Card>
            </div>

            {/* Connectivity Status Summary */}
            <div className="grid gap-6 lg:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <Globe className="h-4 w-4 text-primary" /> {t('SiteDetailPage.overview.vpnStatus')}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {vpnLoading ? <Skeleton className="h-16" /> : vpnConfig ? (
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">{t('SiteDetailPage.vpn.provider')}</span>
                        <span className="text-sm font-medium capitalize">{vpnConfig.vpn_type}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">{t('SiteDetailPage.fields.status')}</span>
                        <Badge variant="outline" className={cn('text-xs', VPN_STATUS_COLORS[vpnConfig.status] ?? '')}>
                          {vpnConfig.status.replace(/_/g, ' ')}
                        </Badge>
                      </div>
                      {vpnConfig.last_health_check && (
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-muted-foreground">{t('SiteDetailPage.vpn.lastCheck')}</span>
                          <span className="text-xs text-muted-foreground">{formatRelative(vpnConfig.last_health_check, t)}</span>
                        </div>
                      )}
                      <Button variant="outline" size="sm" className="w-full mt-2" onClick={() => setActiveTab('vpn')}>
                        {t('SiteDetailPage.actions.configureVpn')}
                      </Button>
                    </div>
                  ) : (
                    <div className="text-center py-4">
                      <Unplug className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
                      <p className="text-sm text-muted-foreground">{t('SiteDetailPage.overview.noVpnConfigured')}</p>
                      <Button variant="outline" size="sm" className="mt-3" onClick={() => setActiveTab('vpn')}>
                        {t('SiteDetailPage.actions.setupVpn')}
                      </Button>
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <Bot className="h-4 w-4 text-primary" /> {t('SiteDetailPage.overview.agentStatus')}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {agentsLoading ? <Skeleton className="h-16" /> : agents.length > 0 ? (
                    <div className="space-y-3">
                      {agents.slice(0, 2).map(agent => (
                        <div key={agent.id} className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className={cn('h-2 w-2 rounded-full',
                              agent.status === 'online' ? 'bg-emerald-500' : agent.status === 'error' ? 'bg-red-500' : 'bg-muted-foreground'
                            )} />
                            <span className="text-sm font-medium">{agent.name}</span>
                          </div>
                          <Badge variant="outline" className={cn('text-xs', AGENT_STATUS_COLORS[agent.status] ?? '')}>
                            {agent.status}
                          </Badge>
                        </div>
                      ))}
                      <Button variant="outline" size="sm" className="w-full mt-2" onClick={() => setActiveTab('agent')}>
                        {t('SiteDetailPage.actions.manageAgents')}
                      </Button>
                    </div>
                  ) : (
                    <div className="text-center py-4">
                      <Bot className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
                      <p className="text-sm text-muted-foreground">{t('SiteDetailPage.overview.noAgentsDeployed')}</p>
                      <Button variant="outline" size="sm" className="mt-3" onClick={() => setActiveTab('agent')}>
                        {t('SiteDetailPage.actions.deployAgent')}
                      </Button>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* Device Health Summary */}
            {site.device_count > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <Activity className="h-4 w-4 text-primary" /> {t('SiteDetailPage.overview.deviceHealthSummary')}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center gap-6">
                    <div className="flex-1">
                      <div className="flex justify-between text-sm mb-2">
                        <span className="text-muted-foreground">{t('SiteDetailPage.overview.devicesOnlineRatio', { online: site.online_device_count, total: site.device_count })}</span>
                        <span className={cn('font-medium',
                          healthPct >= 90 ? 'text-emerald-600' : healthPct >= 70 ? 'text-amber-500' : 'text-red-500',
                        )}>{healthPct}%</span>
                      </div>
                      <div className="h-2.5 w-full overflow-hidden rounded-full bg-muted">
                        <div className={cn('h-full rounded-full transition-all duration-500',
                          healthPct >= 90 ? 'bg-emerald-500' : healthPct >= 70 ? 'bg-amber-500' : 'bg-red-500',
                        )} style={{ width: `${healthPct}%` }} />
                      </div>
                    </div>
                    <div className="flex gap-6 text-sm">
                      <div className="text-center">
                        <div className="text-lg font-bold text-emerald-600 tabular-nums">{site.online_device_count}</div>
                        <div className="text-xs text-muted-foreground">{t('SiteDetailPage.stats.online')}</div>
                      </div>
                      <div className="text-center">
                        <div className="text-lg font-bold text-red-500 tabular-nums">{offlineCount}</div>
                        <div className="text-xs text-muted-foreground">{t('SiteDetailPage.stats.offline')}</div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>


          {/* --- Network Tab --- */}
          <TabsContent value="network" className="space-y-6">
            <SiteNetworkTab
              site={site}
              siteId={siteId!}
              onUpdate={(data) => updateMutation.mutate(data)}
              isPending={updateMutation.isPending}
              agents={agents}
              toast={toast}
            />
          </TabsContent>


          {/* --- VPN Tab --- */}
          <TabsContent value="vpn" className="space-y-6">
            <SiteVPNTab
              siteId={siteId!}
              vpnConfig={vpnConfig}
              vpnLoading={vpnLoading}
              vpnError={vpnError}
              toast={toast}
            />
          </TabsContent>


          {/* --- Agent Tab --- */}
          <TabsContent value="agent" className="space-y-6">
            <SiteAgentTab
              siteId={siteId!}
              siteName={site.name}
              agents={agents}
              agentsLoading={agentsLoading}
              toast={toast}
            />
            <AgentSchedulesPanel siteId={siteId} />
          </TabsContent>


          {/* --- Devices Tab --- */}
          <TabsContent value="devices" className="space-y-4">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base">
                    {t('SiteDetailPage.devices.titleAt', { name: site.name })}
                    <Badge variant="secondary" className="ml-2 tabular-nums">{site.device_count}</Badge>
                  </CardTitle>
                  <Button variant="outline" size="sm" onClick={() => navigate(`/devices?site=${siteId}`)}>
                    <ExternalLink className="mr-2 h-3.5 w-3.5" /> {t('SiteDetailPage.actions.fullInventory')}
                  </Button>
                </div>
              </CardHeader>
              <CardContent className="pt-0">
                {devicesLoading ? (
                  <div className="space-y-3 py-4">
                    {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}
                  </div>
                ) : (
                  <DataTable embedded columns={deviceColumns} data={devices} getRowId={(d) => d.id}
                    itemName={t('SiteDetailPage.devices.itemName')} onRowClick={(d) => navigate(`/devices/${d.id}`)} />
                )}
              </CardContent>
            </Card>
          </TabsContent>


          {/* --- Settings Tab --- */}
          <TabsContent value="settings" className="space-y-6">
            <SiteSettingsForm site={site} editMode={editMode} setEditMode={setEditMode}
              onSave={(data) => updateMutation.mutate(data)} isPending={updateMutation.isPending} />
          </TabsContent>
        </Tabs>


        {/* ---- Delete Confirmation ---- */}
        <AlertDialog open={deleteOpen} onOpenChange={setDeleteOpen}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>{t('SiteDetailPage.deleteDialog.title', { name: site.name })}</AlertDialogTitle>
              <AlertDialogDescription>
                {t('SiteDetailPage.deleteDialog.description')}
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>{t('SiteDetailPage.common.cancel')}</AlertDialogCancel>
              <AlertDialogAction className="bg-destructive text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50" onClick={() => deleteMutation.mutate()} disabled={deleteMutation.isPending}>
                {deleteMutation.isPending ? t('SiteDetailPage.deleteDialog.deleting') : t('SiteDetailPage.actions.deleteSite')}
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>

      </div>
    </TooltipProvider>
  );
}


/* ============================================================
   Network Tab · Subnet management + reachability
   ============================================================ */

function SiteNetworkTab({ site, siteId, onUpdate, isPending, agents, toast }: {
  site: Site; siteId: string;
  onUpdate: (data: Record<string, unknown>) => void;
  isPending: boolean;
  agents: AgentSummary[];
  toast: ReturnType<typeof useToast>['toast'];
}) {
  const { t } = useTranslation('sites');
  const [showAddSubnet, setShowAddSubnet] = useState(false);
  const [editGateway, setEditGateway] = useState(false);
  const [gatewayIp, setGatewayIp] = useState(site.gateway_ip ?? '');
  const queryClient = useQueryClient();

  const CIDR_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/;
  const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

  // Subnet form schema. CIDR validated via regex; vlan_id optional 1-4094.
  const subnetSchema = z
    .object({
      cidr: z.string().min(1, t('SiteDetailPage.network.validation.cidrRequired')),
      name: z.string(),
      vlan_id: z.string(),
      description: z.string(),
    })
    .superRefine((data, ctx) => {
      if (!CIDR_RE.test(data.cidr.trim())) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['cidr'],
          message: t('SiteDetailPage.network.validation.cidrInvalid'),
        });
      }
      if (data.vlan_id) {
        const n = parseInt(data.vlan_id, 10);
        if (!Number.isInteger(n) || n < 1 || n > 4094) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['vlan_id'],
            message: t('SiteDetailPage.network.validation.vlanRange'),
          });
        }
      }
    });
  type SubnetFormValues = z.infer<typeof subnetSchema>;
  const subnetDefaults: SubnetFormValues = { cidr: '', name: '', vlan_id: '', description: '' };

  const handleRemoveSubnet = (idx: number) => {
    onUpdate({ subnets: site.subnets.filter((_, i) => i !== idx) });
  };

  const handleSaveGateway = () => {
    const ip = gatewayIp.trim();
    if (ip && !IP_RE.test(ip)) {
      toast({ title: t('SiteDetailPage.network.invalidIpTitle'), description: t('SiteDetailPage.network.invalidIpDesc'), variant: 'destructive' });
      return;
    }
    onUpdate({ gateway_ip: ip || null });
    setEditGateway(false);
  };

  // Scan trigger via agent
  const scanMutation = useMutation({
    mutationFn: async () => {
      const onlineAgent = agents.find(a => a.status === 'online');
      if (!onlineAgent) throw new Error(t('SiteDetailPage.network.errors.noOnlineAgent'));
      const targets = site.subnets.map(s => s.cidr);
      if (targets.length === 0) throw new Error(t('SiteDetailPage.network.errors.noSubnetsToScan'));
      return agentsApi.createTask(onlineAgent.id, {
        task_type: 'scan_network',
        task_data: { targets, methods: ['tcp_connect', 'mdns', 'ssdp'] },
        priority: 3,
      });
    },
    onSuccess: () => {
      toast({ title: t('SiteDetailPage.network.scanStartedTitle'), description: t('SiteDetailPage.network.scanStartedDesc') });
      queryClient.invalidateQueries({ queryKey: ['site-agents', siteId] });
    },
    onError: (err: any) => {
      toast({ title: t('SiteDetailPage.network.scanFailedTitle'), description: err?.message || t('SiteDetailPage.network.scanFailedDesc'), variant: 'destructive' });
    },
  });

  const onlineAgent = agents.find(a => a.status === 'online');

  return (
    <>
      {/* Gateway IP */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-base flex items-center gap-2">
              <Signal className="h-4 w-4 text-primary" /> {t('SiteDetailPage.network.siteGateway')}
            </CardTitle>
            {!editGateway && (
              <Button variant="outline" size="sm" onClick={() => setEditGateway(true)}>
                <Edit className="mr-2 h-4 w-4" /> {t('SiteDetailPage.actions.edit')}
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {editGateway ? (
            <div className="flex items-end gap-3">
              <div className="flex-1">
                <Label>{t('SiteDetailPage.fields.gatewayIp')}</Label>
                <Input value={gatewayIp} onChange={(e) => setGatewayIp(e.target.value)}
                  placeholder={t('SiteDetailPage.network.gatewayIpPlaceholder')} className="font-mono" />
              </div>
              <Button onClick={handleSaveGateway} disabled={isPending}>{t('SiteDetailPage.common.save')}</Button>
              <Button variant="outline" onClick={() => { setEditGateway(false); setGatewayIp(site.gateway_ip ?? ''); }}>{t('SiteDetailPage.common.cancel')}</Button>
            </div>
          ) : (
            <div className="flex items-center gap-3">
              <span className="font-mono text-sm">{site.gateway_ip || t('SiteDetailPage.network.notConfigured')}</span>
              {site.gateway_ip && (
                <Badge variant="outline" className="text-xs border-border">
                  {site.subnets.length > 0 ? t('SiteDetailPage.network.routeToSubnets') : t('SiteDetailPage.network.noSubnets')}
                </Badge>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Subnets */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-base flex items-center gap-2">
              <Network className="h-4 w-4 text-primary" /> {t('SiteDetailPage.network.subnets')}
              <Badge variant="secondary" className="tabular-nums">{site.subnets.length}</Badge>
            </CardTitle>
            <div className="flex gap-2">
              {onlineAgent && site.subnets.length > 0 && (
                <Button variant="outline" size="sm" onClick={() => scanMutation.mutate()} disabled={scanMutation.isPending}>
                  <Search className={cn('mr-2 h-4 w-4', scanMutation.isPending && 'animate-spin')} />
                  {t('SiteDetailPage.network.scanAllSubnets')}
                </Button>
              )}
              <Button size="sm" onClick={() => setShowAddSubnet(true)}>
                <Plus className="mr-2 h-4 w-4" /> {t('SiteDetailPage.network.addSubnet')}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {site.subnets.length === 0 ? (
            <div className="text-center py-8">
              <Network className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
              <p className="text-sm font-medium">{t('SiteDetailPage.network.emptyTitle')}</p>
              <p className="text-xs text-muted-foreground mt-1">{t('SiteDetailPage.network.emptyDesc')}</p>
              <Button variant="outline" size="sm" className="mt-4" onClick={() => setShowAddSubnet(true)}>
                <Plus className="mr-2 h-4 w-4" /> {t('SiteDetailPage.network.addFirstSubnet')}
              </Button>
            </div>
          ) : (
            <div className="space-y-2">
              {site.subnets.map((subnet, idx) => (
                <div key={subnet.cidr} className="flex items-center justify-between p-3 rounded-lg border border-border hover:bg-accent">
                  <div className="flex items-center gap-4">
                    <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-100 dark:bg-blue-900/30">
                      <Network className="h-4 w-4 text-blue-500" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm font-medium">{subnet.cidr}</span>
                        {subnet.name && <Badge variant="secondary" className="text-xs">{subnet.name}</Badge>}
                        {subnet.vlan_id && <Badge variant="outline" className="text-xs">VLAN {subnet.vlan_id}</Badge>}
                      </div>
                      {subnet.description && <p className="text-xs text-muted-foreground mt-0.5">{subnet.description}</p>}
                    </div>
                  </div>
                  <Button variant="ghost" size="icon" className="h-8 w-8 text-red-400 hover:text-red-600"
                    onClick={() => { if (confirm(t('SiteDetailPage.network.confirmRemoveSubnet'))) handleRemoveSubnet(idx); }}>
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Add Subnet Dialog */}
      <FormDialog<SubnetFormValues>
        open={showAddSubnet}
        onOpenChange={setShowAddSubnet}
        title={t('SiteDetailPage.network.addSubnet')}
        description={t('SiteDetailPage.network.addSubnetDesc')}
        schema={subnetSchema}
        defaultValues={subnetDefaults}
        submitLabel={t('SiteDetailPage.network.addSubnet')}
        onSubmit={async (values) => {
          const entry: SubnetEntry = {
            cidr: values.cidr.trim(),
            name: values.name.trim(),
            vlan_id: values.vlan_id ? parseInt(values.vlan_id, 10) : null,
            description: values.description.trim(),
          };
          // onUpdate is sync (parent owns the mutation); close on success.
          onUpdate({ subnets: [...site.subnets, entry] });
          setShowAddSubnet(false);
        }}
      >
        {(form) => (
          <>
            <FormField
              control={form.control}
              name="cidr"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('SiteDetailPage.network.form.cidr')}</FormLabel>
                  <FormControl>
                    <Input placeholder="192.168.1.0/24" className="font-mono" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <div className="grid grid-cols-2 gap-3">
              <FormField
                control={form.control}
                name="name"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('SiteDetailPage.fields.name')}</FormLabel>
                    <FormControl>
                      <Input placeholder={t('SiteDetailPage.network.form.namePlaceholder')} {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="vlan_id"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('SiteDetailPage.network.form.vlanId')}</FormLabel>
                    <FormControl>
                      <Input type="number" placeholder="1" min={1} max={4094} {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>
            <FormField
              control={form.control}
              name="description"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('SiteDetailPage.fields.description')}</FormLabel>
                  <FormControl>
                    <Input placeholder={t('SiteDetailPage.network.form.descriptionPlaceholder')} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </>
        )}
      </FormDialog>
    </>
  );
}


/* ============================================================
   VPN Tab · Site VPN configuration (Freedom of choice)
   Supports: Brain VPN (firewall built-in), Tailscale, WireGuard,
   OpenVPN, Netbird, ZeroTier, IPsec · any combination
   ============================================================ */

const BRAIN_TYPES = new Set(['opnsense', 'pfsense', 'mikrotik', 'openwrt']);

function SiteVPNTab({ siteId, vpnConfig, vpnLoading, vpnError, toast }: {
  siteId: string;
  vpnConfig: SiteVPNConfig | null | undefined;
  vpnLoading: boolean;
  vpnError?: boolean;
  toast: ReturnType<typeof useToast>['toast'];
}) {
  const { t } = useTranslation('sites');
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [showOvpnImport, setShowOvpnImport] = useState(false);
  const [brainDiscovery, setBrainDiscovery] = useState<BrainVPNDiscovery | null>(null);
  const [discoveringBrain, setDiscoveringBrain] = useState<string | null>(null);
  const [importingServer, setImportingServer] = useState<string | null>(null);
  const [syncingController, setSyncingController] = useState<string | null>(null);

  const [form, setForm] = useState({
    vpn_type: vpnConfig?.vpn_type ?? 'tailscale',
    enabled: vpnConfig?.enabled ?? true,
    tailscale_node: vpnConfig?.tailscale_node ?? '',
    tailscale_hostname: vpnConfig?.tailscale_hostname ?? '',
    wireguard_interface: vpnConfig?.wireguard_interface ?? '',
    vpn_endpoint: vpnConfig?.vpn_endpoint ?? '',
    health_check_ip: vpnConfig?.health_check_ip ?? '',
    remote_subnets: (vpnConfig?.remote_subnets ?? []).join(', '),
    local_subnets: (vpnConfig?.local_subnets ?? []).join(', '),
    openvpn_config_path: vpnConfig?.openvpn_config_path ?? '',
    netbird_peer_id: vpnConfig?.netbird_peer_id ?? '',
    netbird_group: vpnConfig?.netbird_group ?? '',
    zerotier_network_id: vpnConfig?.zerotier_network_id ?? '',
  });

  useEffect(() => {
    if (vpnConfig && !editing) {
      setForm({
        vpn_type: vpnConfig.vpn_type ?? 'tailscale',
        enabled: vpnConfig.enabled ?? true,
        tailscale_node: vpnConfig.tailscale_node ?? '',
        tailscale_hostname: vpnConfig.tailscale_hostname ?? '',
        wireguard_interface: vpnConfig.wireguard_interface ?? '',
        vpn_endpoint: vpnConfig.vpn_endpoint ?? '',
        health_check_ip: vpnConfig.health_check_ip ?? '',
        remote_subnets: (vpnConfig.remote_subnets ?? []).join(', '),
        local_subnets: (vpnConfig.local_subnets ?? []).join(', '),
        openvpn_config_path: vpnConfig.openvpn_config_path ?? '',
        netbird_peer_id: vpnConfig.netbird_peer_id ?? '',
        netbird_group: vpnConfig.netbird_group ?? '',
        zerotier_network_id: vpnConfig.zerotier_network_id ?? '',
      });
    }
  }, [vpnConfig, editing]);

  // Fetch brain-capable controllers at this site
  const { data: controllersRes } = useQuery({
    queryKey: ['site-controllers', siteId],
    queryFn: () => controllersApi.getAll(siteId),
  });
  const brainControllers = useMemo(() => {
    type CtrlItem = { id: string; controller_type: string; name?: string; [k: string]: unknown };
    const raw = controllersRes?.data;
    const all: CtrlItem[] = (raw && typeof raw === 'object' && 'items' in raw ? (raw as { items: CtrlItem[] }).items : raw) ?? [];
    return (Array.isArray(all) ? all : []).filter((c) => BRAIN_TYPES.has(c.controller_type));
  }, [controllersRes]);

  const saveMutation = useMutation({
    mutationFn: async () => {
      const payload: Partial<SiteVPNConfig> = {
        vpn_type: form.vpn_type,
        enabled: form.enabled,
        health_check_ip: form.health_check_ip || undefined,
        remote_subnets: form.remote_subnets ? form.remote_subnets.split(',').map(s => s.trim()).filter(Boolean) : [],
        local_subnets: form.local_subnets ? form.local_subnets.split(',').map(s => s.trim()).filter(Boolean) : [],
      };
      if (form.vpn_type === 'tailscale') {
        payload.tailscale_node = form.tailscale_node || undefined;
        payload.tailscale_hostname = form.tailscale_hostname || undefined;
      } else if (form.vpn_type === 'wireguard') {
        payload.wireguard_interface = form.wireguard_interface || undefined;
        payload.vpn_endpoint = form.vpn_endpoint || undefined;
      } else if (form.vpn_type === 'openvpn') {
        payload.openvpn_config_path = form.openvpn_config_path || undefined;
      } else if (form.vpn_type === 'netbird') {
        payload.netbird_peer_id = form.netbird_peer_id || undefined;
        payload.netbird_group = form.netbird_group || undefined;
      } else if (form.vpn_type === 'zerotier') {
        payload.zerotier_network_id = form.zerotier_network_id || undefined;
      }
      return vpnApi.updateSiteConfig(siteId, payload);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['site-vpn', siteId] });
      toast({ title: t('SiteDetailPage.vpn.toasts.saved') });
      setEditing(false);
    },
    onError: (err: any) => {
      toast({ title: t('SiteDetailPage.common.error'), description: err?.response?.data?.detail || t('SiteDetailPage.vpn.toasts.saveFailed'), variant: 'destructive' });
    },
  });

  const testMutation = useMutation({
    mutationFn: () => vpnApi.testSiteVPN(siteId),
    onSuccess: (res) => {
      // Backend POST /vpn/sites/{id}/test returns `vpn_connected` (not `reachable`).
      const data = res.data as { vpn_connected?: boolean; latency_ms?: number; error?: string };
      if (data?.vpn_connected) {
        toast({ title: t('SiteDetailPage.vpn.toasts.testPassed'), description: t('SiteDetailPage.vpn.toasts.latency', { ms: data.latency_ms ?? '?' }) });
      } else {
        toast({ title: t('SiteDetailPage.vpn.toasts.testFailed'), description: data?.error || t('SiteDetailPage.vpn.toasts.siteNotReachable'), variant: 'destructive' });
      }
      queryClient.invalidateQueries({ queryKey: ['site-vpn', siteId] });
    },
    onError: (err: any) => {
      toast({ title: t('SiteDetailPage.vpn.toasts.testError'), description: err?.response?.data?.detail || t('SiteDetailPage.vpn.toasts.connectivityFailed'), variant: 'destructive' });
    },
  });

  // Brain VPN discovery
  const handleDiscoverBrain = async (controllerId: string) => {
    setDiscoveringBrain(controllerId);
    try {
      const res = await vpnApi.brain.discoverServers(controllerId);
      setBrainDiscovery(res.data);
    } catch (err: unknown) {
      toast({ title: t('SiteDetailPage.vpn.toasts.discoveryFailed'), description: getApiErrorMessage(err, t('SiteDetailPage.vpn.toasts.couldNotReachBrain')), variant: 'destructive' });
    } finally {
      setDiscoveringBrain(null);
    }
  };

  // Brain VPN import
  const handleImportBrainVPN = async (controllerId: string, vpnType: string, server: BrainVPNServer) => {
    if (importingServer) return; // prevent double-click
    setImportingServer(server.id);
    try {
      const res = await vpnApi.brain.importConfig(controllerId, {
        vpn_type: vpnType,
        vpn_server_id: server.id,
        site_id: siteId,
      });
      toast({ title: t('SiteDetailPage.vpn.toasts.imported'), description: res.data.message });
      queryClient.invalidateQueries({ queryKey: ['site-vpn', siteId] });
      setBrainDiscovery(null);
    } catch (err: unknown) {
      toast({ title: t('SiteDetailPage.vpn.toasts.importFailed'), description: getApiErrorMessage(err, t('SiteDetailPage.vpn.toasts.importConfigFailed')).slice(0, 200), variant: 'destructive' });
    } finally {
      setImportingServer(null);
    }
  };

  // Brain subnet sync
  const handleSyncBrainSubnets = async (controllerId: string) => {
    if (syncingController) return; // prevent double-click
    setSyncingController(controllerId);
    try {
      const res = await vpnApi.brain.syncSubnets(controllerId);
      toast({ title: t('SiteDetailPage.vpn.toasts.subnetsSynced'), description: res.data.message });
      queryClient.invalidateQueries({ queryKey: ['site', siteId] });
    } catch (err: unknown) {
      toast({ title: t('SiteDetailPage.vpn.toasts.syncFailed'), description: getApiErrorMessage(err, t('SiteDetailPage.vpn.toasts.syncSubnetsFailed')).slice(0, 200), variant: 'destructive' });
    } finally {
      setSyncingController(null);
    }
  };

  // OpenVPN config import. Errors propagate to FormDialog's banner.
  const ovpnImportMutation = useMutation({
    mutationFn: (configContent: string) =>
      vpnApi.importOpenVPNConfig({ site_id: siteId, config_content: configContent }),
    onSuccess: (res) => {
      toast({ title: t('SiteDetailPage.vpn.toasts.ovpnImported'), description: t('SiteDetailPage.vpn.toasts.ovpnEndpoint', { endpoint: res.data.vpn_endpoint, port: res.data.port }) });
      queryClient.invalidateQueries({ queryKey: ['site-vpn', siteId] });
      setShowOvpnImport(false);
    },
  });

  const ovpnSchema = z.object({
    config_content: z.string().min(1, t('SiteDetailPage.vpn.validation.pasteConfig')).max(102400, t('SiteDetailPage.vpn.validation.configTooLarge')),
  });
  type OvpnFormValues = z.infer<typeof ovpnSchema>;

  // ── Multi-VPN Per Site ──────────────────────────────
  const [showAddConfig, setShowAddConfig] = useState(false);
  const [addConfigForm, setAddConfigForm] = useState({ vpn_type: 'tailscale', enabled: true, auto_connect: false });

  const { data: multiConfigs } = useQuery<SiteVPNConfigList>({
    queryKey: ['siteVpnConfigs', siteId],
    queryFn: async () => {
      const r = await vpnApi.siteConfigs.list(siteId);
      return r.data;
    },
    enabled: !!siteId,
  });

  const createSiteConfig = useMutation({
    mutationFn: (data: Partial<SiteVPNConfig>) => vpnApi.siteConfigs.create(siteId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['siteVpnConfigs', siteId] });
      queryClient.invalidateQueries({ queryKey: ['site-vpn', siteId] });
      toast({ title: t('SiteDetailPage.vpn.toasts.configAdded') });
      setShowAddConfig(false);
      setAddConfigForm({ vpn_type: 'tailscale', enabled: true, auto_connect: false });
    },
    onError: (err: any) => {
      toast({ title: t('SiteDetailPage.common.error'), description: err?.response?.data?.detail || t('SiteDetailPage.vpn.toasts.createConfigFailed'), variant: 'destructive' });
    },
  });

  const deleteSiteConfig = useMutation({
    mutationFn: (configId: string) => vpnApi.siteConfigs.remove(siteId, configId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['siteVpnConfigs', siteId] });
      queryClient.invalidateQueries({ queryKey: ['site-vpn', siteId] });
      toast({ title: t('SiteDetailPage.vpn.toasts.configRemoved') });
    },
    onError: (err: any) => {
      toast({ title: t('SiteDetailPage.common.error'), description: err?.response?.data?.detail || t('SiteDetailPage.vpn.toasts.removeConfigFailed'), variant: 'destructive' });
    },
  });

  const setPrimaryConfig = useMutation({
    mutationFn: (configId: string) => vpnApi.siteConfigs.setPrimary(siteId, configId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['siteVpnConfigs', siteId] });
      queryClient.invalidateQueries({ queryKey: ['site-vpn', siteId] });
      toast({ title: t('SiteDetailPage.vpn.toasts.primaryUpdated') });
    },
    onError: (err: any) => {
      toast({ title: t('SiteDetailPage.common.error'), description: err?.response?.data?.detail || t('SiteDetailPage.vpn.toasts.setPrimaryFailed'), variant: 'destructive' });
    },
  });

  // ── VPN Preflight · auto-polls every 60s ──────────────────
  const { data: preflightData, isLoading: preflightLoading } = useQuery<VPNPreflightResult>({
    queryKey: ['vpnPreflight', siteId],
    queryFn: async () => {
      const r = await vpnApi.preflight.site(siteId);
      return r.data;
    },
    enabled: !!siteId,
    refetchInterval: 60000,
  });

  // ── Device Reachability · manual fetch only ──────────────
  const [reachabilityOpen, setReachabilityOpen] = useState(false);
  const {
    data: reachabilityData,
    isLoading: reachabilityLoading,
    isFetching: reachabilityFetching,
    refetch: refetchReachability,
  } = useQuery<{ site_id: string; devices: VPNDeviceReachability[] }>({
    queryKey: ['vpnReachability', siteId],
    queryFn: async () => {
      const r = await vpnApi.getSiteReachability(siteId);
      return r.data;
    },
    enabled: false,
  });

  if (vpnLoading) return <Skeleton className="h-64" />;

  if (vpnError) return (
    <Card className="border-destructive">
      <CardContent noOffset className="flex items-center gap-3 p-6">
        <AlertTriangle className="h-5 w-5 text-destructive shrink-0" />
        <div>
          <p className="text-sm font-medium">{t('SiteDetailPage.vpn.loadFailedTitle')}</p>
          <p className="text-xs text-muted-foreground mt-1">{t('SiteDetailPage.vpn.loadFailedDesc')}</p>
        </div>
      </CardContent>
    </Card>
  );

  const configured = vpnConfig && vpnConfig.status !== 'not_configured';

  return (
    <>
      {/* ── VPN Preflight Indicator ─────────────────────────── */}
      <div className="mb-2">
        {preflightLoading ? (
          <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg border border-border bg-muted">
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
            <span className="text-sm text-muted-foreground">{t('SiteDetailPage.vpn.preflight.checking')}</span>
          </div>
        ) : preflightData?.skipped ? (
          <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg border border-border bg-muted">
            <Globe className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm text-muted-foreground">{t('SiteDetailPage.vpn.preflight.directAccess')}</span>
            <Badge variant="outline" className="ml-auto text-xs border-border bg-muted text-muted-foreground">{t('SiteDetailPage.vpn.preflight.skipped')}</Badge>
          </div>
        ) : preflightData?.reachable ? (
          <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg border border-emerald-500/30 bg-emerald-500/5 dark:bg-emerald-900/10">
            <Wifi className="h-4 w-4 text-emerald-600" />
            <span className="text-sm font-medium text-emerald-700 dark:text-emerald-400">
              {preflightData.latency_ms != null
                ? t('SiteDetailPage.vpn.preflight.connectedWithLatency', { ms: preflightData.latency_ms })
                : t('SiteDetailPage.vpn.preflight.connected')}
            </span>
            <Badge variant="outline" className="ml-auto text-xs border-emerald-500/30 bg-emerald-500/10 text-emerald-600">
              {preflightData.vpn_type ?? t('SiteDetailPage.vpn.preflight.active')}
            </Badge>
          </div>
        ) : preflightData ? (
          <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg border border-red-500/30 bg-red-500/5 dark:bg-red-900/10">
            <WifiOff className="h-4 w-4 text-red-500" />
            <span className="text-sm font-medium text-red-600 dark:text-red-400">
              {t('SiteDetailPage.vpn.preflight.unreachable')}
            </span>
            {preflightData.error && (
              <TooltipProvider delayDuration={200}>
                <Tooltip>
                  <TooltipTrigger>
                    <AlertCircle className="h-3.5 w-3.5 text-red-400" />
                  </TooltipTrigger>
                  <TooltipContent side="bottom"><p className="text-xs max-w-xs">{preflightData.error}</p></TooltipContent>
                </Tooltip>
              </TooltipProvider>
            )}
            <Badge variant="outline" className="ml-auto text-xs border-red-500/30 bg-red-500/10 text-red-600">{t('SiteDetailPage.vpn.preflight.unreachableBadge')}</Badge>
          </div>
        ) : null}
      </div>

      {/* ── Multi-VPN Configurations ──────────────────── */}
      {multiConfigs?.total && multiConfigs.total >= 1 && (
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-base flex items-center gap-2">
                <Globe className="h-4 w-4 text-primary" /> {t('SiteDetailPage.vpn.configurations')}
                <Badge variant="secondary" className="text-xs tabular-nums">{multiConfigs.total}</Badge>
              </CardTitle>
              <Button variant="outline" size="sm" onClick={() => setShowAddConfig(true)}>
                <Plus className="mr-1.5 h-3.5 w-3.5" /> {t('SiteDetailPage.vpn.addVpnConfig')}
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {multiConfigs.configs.map((cfg) => (
                <div
                  key={cfg.id}
                  className={cn(
                    'flex items-center justify-between p-3 rounded-lg border',
                    cfg.is_primary
                      ? 'border-primary/30 bg-primary/5 dark:bg-primary/10'
                      : 'bg-muted',
                  )}
                >
                  <div className="flex items-center gap-3">
                    {cfg.is_primary && (
                      <Star className="h-4 w-4 text-amber-500 fill-amber-500 shrink-0" />
                    )}
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium capitalize">{cfg.vpn_type}</span>
                        <Badge variant="outline" className={cn('text-xs', VPN_STATUS_COLORS[cfg.status] ?? '')}>
                          {cfg.status.replace(/_/g, ' ')}
                        </Badge>
                        {cfg.is_primary && (
                          <Badge variant="secondary" className="text-xs">{t('SiteDetailPage.vpn.primary')}</Badge>
                        )}
                        {!cfg.enabled && (
                          <Badge variant="outline" className="text-xs border-border text-muted-foreground">{t('SiteDetailPage.vpn.disabled')}</Badge>
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground mt-0.5">
                        {cfg.vpn_endpoint || cfg.tailscale_hostname || cfg.netbird_peer_id || cfg.zerotier_network_id || t('SiteDetailPage.vpn.noEndpointConfigured')}
                        {cfg.vpn_source === 'brain_import' && ` \u00b7 ${t('SiteDetailPage.vpn.viaBrain')}`}
                      </p>
                    </div>
                  </div>
                  {!cfg.is_primary && (
                    <div className="flex items-center gap-1.5 shrink-0">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => cfg.id && setPrimaryConfig.mutate(cfg.id)}
                        disabled={setPrimaryConfig.isPending}
                      >
                        <Star className="mr-1 h-3.5 w-3.5" /> {t('SiteDetailPage.vpn.setPrimary')}
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-red-600 hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-900/20"
                        onClick={() => {
                          if (cfg.id && confirm(t('SiteDetailPage.vpn.confirmRemoveConfig'))) {
                            deleteSiteConfig.mutate(cfg.id);
                          }
                        }}
                        disabled={deleteSiteConfig.isPending}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── Add VPN Config Dialog ──────────────────────── */}
      {showAddConfig && (
        <Card className="border-dashed border-primary/40">
          <CardHeader className="pb-3">
            <CardTitle className="text-base">{t('SiteDetailPage.vpn.addConfigTitle')}</CardTitle>
            <CardDescription>{t('SiteDetailPage.vpn.addConfigDesc')}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="grid gap-2">
                <Label>{t('SiteDetailPage.vpn.provider')}</Label>
                <Select value={addConfigForm.vpn_type} onValueChange={(v) => setAddConfigForm({ ...addConfigForm, vpn_type: v })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="tailscale">Tailscale</SelectItem>
                    <SelectItem value="wireguard">WireGuard</SelectItem>
                    <SelectItem value="openvpn">OpenVPN</SelectItem>
                    <SelectItem value="netbird">Netbird</SelectItem>
                    <SelectItem value="zerotier">ZeroTier</SelectItem>
                    <SelectItem value="ipsec">IPsec</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="flex items-center gap-4">
                <Label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={addConfigForm.enabled}
                    onChange={(e) => setAddConfigForm({ ...addConfigForm, enabled: e.target.checked })}
                    className="rounded border-border"
                  />
                  {t('SiteDetailPage.vpn.enabled')}
                </Label>
                <Label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={addConfigForm.auto_connect}
                    onChange={(e) => setAddConfigForm({ ...addConfigForm, auto_connect: e.target.checked })}
                    className="rounded border-border"
                  />
                  {t('SiteDetailPage.vpn.autoConnect')}
                </Label>
              </div>
              <div className="flex justify-end gap-2 pt-1">
                <Button variant="outline" size="sm" onClick={() => setShowAddConfig(false)}>{t('SiteDetailPage.common.cancel')}</Button>
                <Button
                  size="sm"
                  onClick={() => createSiteConfig.mutate({
                    vpn_type: addConfigForm.vpn_type,
                    enabled: addConfigForm.enabled,
                    auto_connect: addConfigForm.auto_connect,
                  })}
                  disabled={createSiteConfig.isPending}
                >
                  {createSiteConfig.isPending && <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />}
                  {t('SiteDetailPage.vpn.createConfig')}
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── Brain VPN Gateway ────────────────────────────────── */}
      {brainControllers.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Router className="h-4 w-4 text-primary" /> {t('SiteDetailPage.vpn.brain.title')}
            </CardTitle>
            <CardDescription>
              {t('SiteDetailPage.vpn.brain.description')}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {brainControllers.map((ctrl: any) => (
                <div key={ctrl.id} className="flex items-center justify-between p-3 rounded-lg border bg-muted">
                  <div className="flex items-center gap-3">
                    <div className="h-9 w-9 rounded-lg bg-orange-100 dark:bg-orange-900/30 flex items-center justify-center">
                      <Shield className="h-4 w-4 text-orange-600" />
                    </div>
                    <div>
                      <p className="text-sm font-medium">{ctrl.name}</p>
                      <p className="text-xs text-muted-foreground capitalize">{ctrl.controller_type} &middot; {ctrl.host}</p>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" onClick={() => handleSyncBrainSubnets(ctrl.id)}
                      disabled={syncingController === ctrl.id}>
                      {syncingController === ctrl.id
                        ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                        : <Network className="mr-1.5 h-3.5 w-3.5" />}
                      {t('SiteDetailPage.vpn.brain.syncSubnets')}
                    </Button>
                    <Button size="sm" onClick={() => handleDiscoverBrain(ctrl.id)}
                      disabled={discoveringBrain === ctrl.id}>
                      {discoveringBrain === ctrl.id
                        ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                        : <Search className="mr-1.5 h-3.5 w-3.5" />}
                      {t('SiteDetailPage.vpn.brain.discoverVpn')}
                    </Button>
                  </div>
                </div>
              ))}

              {/* Brain discovery results */}
              {brainDiscovery && (
                <div className="mt-3 space-y-3 p-3 rounded-lg border border-orange-200 dark:border-orange-800 bg-orange-50/50 dark:bg-orange-900/10">
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-medium">{t('SiteDetailPage.vpn.brain.serversOn', { name: brainDiscovery.controller_name })}</p>
                    <Button variant="ghost" size="sm" onClick={() => setBrainDiscovery(null)}>
                      <XCircle className="h-4 w-4" />
                    </Button>
                  </div>
                  {brainDiscovery.openvpn.length === 0 && brainDiscovery.wireguard.length === 0 && brainDiscovery.ipsec.length === 0 && (
                    <p className="text-xs text-muted-foreground">{t('SiteDetailPage.vpn.brain.noServersFound')}</p>
                  )}
                  {brainDiscovery.openvpn.map((srv) => (
                    <div key={srv.id} className="flex items-center justify-between p-2 rounded border bg-card">
                      <div>
                        <p className="text-xs font-medium">{t('SiteDetailPage.vpn.brain.openvpnLabel', { description: srv.description })}</p>
                        <p className="text-xs text-muted-foreground">{t('SiteDetailPage.vpn.brain.protocolPort', { protocol: srv.protocol?.toUpperCase(), port: srv.port })}</p>
                      </div>
                      <Button size="sm" variant="outline" disabled={importingServer === srv.id}
                        onClick={() => handleImportBrainVPN(brainDiscovery.controller_id, 'openvpn', srv)}>
                        {importingServer === srv.id ? <Loader2 className="mr-1.5 h-3 w-3 animate-spin" /> : <Download className="mr-1.5 h-3 w-3" />} {t('SiteDetailPage.vpn.brain.import')}
                      </Button>
                    </div>
                  ))}
                  {brainDiscovery.wireguard.map((srv) => (
                    <div key={srv.id} className="flex items-center justify-between p-2 rounded border bg-card">
                      <div>
                        <p className="text-xs font-medium">{t('SiteDetailPage.vpn.brain.wireguardLabel', { name: srv.name })}</p>
                        <p className="text-xs text-muted-foreground">{t('SiteDetailPage.vpn.brain.port', { port: srv.listen_port })}</p>
                      </div>
                      <Button size="sm" variant="outline" disabled={importingServer === srv.id}
                        onClick={() => handleImportBrainVPN(brainDiscovery.controller_id, 'wireguard', srv)}>
                        {importingServer === srv.id ? <Loader2 className="mr-1.5 h-3 w-3 animate-spin" /> : <Download className="mr-1.5 h-3 w-3" />} {t('SiteDetailPage.vpn.brain.import')}
                      </Button>
                    </div>
                  ))}
                  {brainDiscovery.ipsec.map((srv) => (
                    <div key={srv.id} className="flex items-center justify-between p-2 rounded border bg-card">
                      <div>
                        <p className="text-xs font-medium">{t('SiteDetailPage.vpn.brain.ipsecLabel', { description: srv.description })}</p>
                        <p className="text-xs text-muted-foreground">{srv.remote_gateway}</p>
                      </div>
                      <Button size="sm" variant="outline" disabled={importingServer === srv.id}
                        onClick={() => handleImportBrainVPN(brainDiscovery.controller_id, 'ipsec', srv)}>
                        {importingServer === srv.id ? <Loader2 className="mr-1.5 h-3 w-3 animate-spin" /> : <Download className="mr-1.5 h-3 w-3" />} {t('SiteDetailPage.vpn.brain.import')}
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── VPN Status / Config Card ─────────────────────────── */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-base flex items-center gap-2">
                <Globe className="h-4 w-4 text-primary" /> {t('SiteDetailPage.vpn.connection')}
                {vpnConfig?.vpn_source === 'brain_import' && (
                  <Badge variant="outline" className="text-xs ml-1">{t('SiteDetailPage.vpn.viaBrain')}</Badge>
                )}
              </CardTitle>
              <CardDescription>{t('SiteDetailPage.vpn.connectionDesc')}</CardDescription>
            </div>
            <div className="flex gap-2">
              {configured && (
                <Button variant="outline" size="sm" onClick={() => testMutation.mutate()} disabled={testMutation.isPending}>
                  <Zap className={cn('mr-2 h-4 w-4', testMutation.isPending && 'animate-spin')} />
                  {t('SiteDetailPage.vpn.test')}
                </Button>
              )}
              <Button variant="outline" size="sm" onClick={() => setShowOvpnImport(true)}>
                <Upload className="mr-2 h-4 w-4" /> {t('SiteDetailPage.vpn.importOvpn')}
              </Button>
              {configured && (
                <Button variant="outline" size="sm" onClick={() => setShowAddConfig(true)}>
                  <Plus className="mr-2 h-4 w-4" /> {t('SiteDetailPage.vpn.addVpn')}
                </Button>
              )}
              {!editing && (
                <Button variant="outline" size="sm" onClick={() => setEditing(true)}>
                  <Edit className="mr-2 h-4 w-4" /> {configured ? t('SiteDetailPage.actions.edit') : t('SiteDetailPage.vpn.setup')}
                </Button>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {!editing && configured ? (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-xs text-muted-foreground">{t('SiteDetailPage.vpn.provider')}</span>
                  <p className="text-sm font-medium capitalize">{vpnConfig!.vpn_type}</p>
                </div>
                <div>
                  <span className="text-xs text-muted-foreground">{t('SiteDetailPage.fields.status')}</span>
                  <div className="mt-0.5">
                    <Badge variant="outline" className={cn('text-xs', VPN_STATUS_COLORS[vpnConfig!.status] ?? '')}>
                      {vpnConfig!.status.replace(/_/g, ' ')}
                    </Badge>
                  </div>
                </div>
                {vpnConfig!.tailscale_hostname && (
                  <div>
                    <span className="text-xs text-muted-foreground">{t('SiteDetailPage.vpn.tailscaleHostname')}</span>
                    <p className="text-sm font-mono">{vpnConfig!.tailscale_hostname}</p>
                  </div>
                )}
                {vpnConfig!.vpn_endpoint && (
                  <div>
                    <span className="text-xs text-muted-foreground">{t('SiteDetailPage.vpn.endpoint')}</span>
                    <p className="text-sm font-mono">{vpnConfig!.vpn_endpoint}{vpnConfig!.vpn_port ? `:${vpnConfig!.vpn_port}` : ''}</p>
                  </div>
                )}
                {vpnConfig!.health_check_ip && (
                  <div>
                    <span className="text-xs text-muted-foreground">{t('SiteDetailPage.vpn.healthCheckIp')}</span>
                    <p className="text-sm font-mono">{vpnConfig!.health_check_ip}</p>
                  </div>
                )}
                {vpnConfig!.last_health_check && (
                  <div>
                    <span className="text-xs text-muted-foreground">{t('SiteDetailPage.vpn.lastHealthCheck')}</span>
                    <p className="text-sm">{formatRelative(vpnConfig!.last_health_check, t)}</p>
                  </div>
                )}
              </div>
              {(vpnConfig!.remote_subnets?.length ?? 0) > 0 && (
                <div>
                  <span className="text-xs text-muted-foreground">{t('SiteDetailPage.vpn.advertisedSubnets')}</span>
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {vpnConfig!.remote_subnets!.map((s) => (
                      <Badge key={s} variant="outline" className="font-mono text-xs">{s}</Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : !editing && !configured ? (
            <div className="text-center py-8">
              <Globe className="h-12 w-12 text-muted-foreground mx-auto mb-3" />
              <h3 className="text-lg font-semibold">{t('SiteDetailPage.vpn.noVpnTitle')}</h3>
              <p className="text-sm text-muted-foreground mt-1 max-w-md mx-auto">
                {t('SiteDetailPage.vpn.noVpnDesc')}
              </p>
              <div className="flex justify-center gap-2 mt-4">
                {brainControllers.length > 0 && (
                  <Button variant="outline" onClick={() => handleDiscoverBrain(brainControllers[0].id)}>
                    <Router className="mr-2 h-4 w-4" /> {t('SiteDetailPage.vpn.connectViaBrain')}
                  </Button>
                )}
                <Button onClick={() => setEditing(true)}>
                  <Globe className="mr-2 h-4 w-4" /> {t('SiteDetailPage.vpn.manualSetup')}
                </Button>
                <Button variant="outline" onClick={() => setShowOvpnImport(true)}>
                  <Upload className="mr-2 h-4 w-4" /> {t('SiteDetailPage.vpn.importOvpn')}
                </Button>
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="grid gap-4">
                <div className="grid gap-2">
                  <Label>{t('SiteDetailPage.vpn.provider')}</Label>
                  <Select value={form.vpn_type} onValueChange={(v) => setForm({ ...form, vpn_type: v })}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="tailscale">Tailscale</SelectItem>
                      <SelectItem value="wireguard">WireGuard</SelectItem>
                      <SelectItem value="openvpn">OpenVPN</SelectItem>
                      <SelectItem value="netbird">Netbird</SelectItem>
                      <SelectItem value="zerotier">ZeroTier</SelectItem>
                      <SelectItem value="ipsec">IPsec</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {form.vpn_type === 'tailscale' && (
                  <div className="grid grid-cols-2 gap-3">
                    <div className="grid gap-2">
                      <Label>{t('SiteDetailPage.vpn.form.tailscaleNode')}</Label>
                      <Input value={form.tailscale_node} onChange={(e) => setForm({ ...form, tailscale_node: e.target.value })}
                        placeholder="site-router" />
                    </div>
                    <div className="grid gap-2">
                      <Label>{t('SiteDetailPage.vpn.form.tailscaleHostname')}</Label>
                      <Input value={form.tailscale_hostname} onChange={(e) => setForm({ ...form, tailscale_hostname: e.target.value })}
                        placeholder="100.64.0.5" className="font-mono" />
                    </div>
                  </div>
                )}

                {form.vpn_type === 'wireguard' && (
                  <div className="grid grid-cols-2 gap-3">
                    <div className="grid gap-2">
                      <Label>{t('SiteDetailPage.vpn.form.interface')}</Label>
                      <Input value={form.wireguard_interface} onChange={(e) => setForm({ ...form, wireguard_interface: e.target.value })}
                        placeholder="wg0" className="font-mono" />
                    </div>
                    <div className="grid gap-2">
                      <Label>{t('SiteDetailPage.vpn.endpoint')}</Label>
                      <Input value={form.vpn_endpoint} onChange={(e) => setForm({ ...form, vpn_endpoint: e.target.value })}
                        placeholder="vpn.example.com:51820" className="font-mono" />
                    </div>
                  </div>
                )}

                {form.vpn_type === 'openvpn' && (
                  <div className="grid gap-3">
                    <div className="grid gap-2">
                      <Label>{t('SiteDetailPage.vpn.form.configPath')}</Label>
                      <Input value={form.openvpn_config_path} onChange={(e) => setForm({ ...form, openvpn_config_path: e.target.value })}
                        placeholder="/etc/openvpn/site-a.conf" className="font-mono" />
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {t('SiteDetailPage.vpn.form.openvpnHint')}
                    </p>
                  </div>
                )}

                {form.vpn_type === 'netbird' && (
                  <div className="grid grid-cols-2 gap-3">
                    <div className="grid gap-2">
                      <Label>{t('SiteDetailPage.vpn.form.peerId')}</Label>
                      <Input value={form.netbird_peer_id} onChange={(e) => setForm({ ...form, netbird_peer_id: e.target.value })}
                        placeholder="peer-xyz" className="font-mono" />
                    </div>
                    <div className="grid gap-2">
                      <Label>{t('SiteDetailPage.vpn.form.group')}</Label>
                      <Input value={form.netbird_group} onChange={(e) => setForm({ ...form, netbird_group: e.target.value })}
                        placeholder="site-a-group" />
                    </div>
                  </div>
                )}

                {form.vpn_type === 'zerotier' && (
                  <div className="grid gap-2">
                    <Label>{t('SiteDetailPage.vpn.form.zerotierNetworkId')}</Label>
                    <Input value={form.zerotier_network_id} onChange={(e) => setForm({ ...form, zerotier_network_id: e.target.value })}
                      placeholder="8056c2e21c000001" className="font-mono" maxLength={16} />
                    <p className="text-xs text-muted-foreground">{t('SiteDetailPage.vpn.form.zerotierHint')}</p>
                  </div>
                )}

                <div className="grid gap-2">
                  <Label>{t('SiteDetailPage.vpn.healthCheckIp')}</Label>
                  <Input value={form.health_check_ip} onChange={(e) => setForm({ ...form, health_check_ip: e.target.value })}
                    placeholder={t('SiteDetailPage.vpn.form.healthCheckIpPlaceholder')} className="font-mono" />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="grid gap-2">
                    <Label>{t('SiteDetailPage.vpn.form.remoteSubnets')}</Label>
                    <Input value={form.remote_subnets} onChange={(e) => setForm({ ...form, remote_subnets: e.target.value })}
                      placeholder="192.168.1.0/24, 192.168.2.0/24" className="font-mono text-xs" />
                  </div>
                  <div className="grid gap-2">
                    <Label>{t('SiteDetailPage.vpn.form.localSubnets')}</Label>
                    <Input value={form.local_subnets} onChange={(e) => setForm({ ...form, local_subnets: e.target.value })}
                      placeholder="10.0.0.0/8" className="font-mono text-xs" />
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <Label className="flex items-center gap-2 cursor-pointer">
                    <input type="checkbox" checked={form.enabled}
                      onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                      className="rounded border-border" />
                    {t('SiteDetailPage.vpn.vpnEnabled')}
                  </Label>
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <Button variant="outline" onClick={() => setEditing(false)}>{t('SiteDetailPage.common.cancel')}</Button>
                <Button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}>
                  {saveMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                  {t('SiteDetailPage.vpn.saveVpnConfig')}
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── OpenVPN Import Dialog ────────────────────────────── */}
      <FormDialog<OvpnFormValues>
        open={showOvpnImport}
        onOpenChange={setShowOvpnImport}
        title={t('SiteDetailPage.vpn.ovpnDialog.title')}
        description={t('SiteDetailPage.vpn.ovpnDialog.description')}
        schema={ovpnSchema}
        defaultValues={{ config_content: '' }}
        submitLabel={t('SiteDetailPage.vpn.ovpnDialog.submit')}
        contentClassName="sm:max-w-xl"
        onSubmit={async (values) => {
          await ovpnImportMutation.mutateAsync(values.config_content);
        }}
      >
        {(form) => (
          <FormField
            control={form.control}
            name="config_content"
            render={({ field }) => (
              <FormItem>
                <FormControl>
                  <textarea
                    maxLength={102400}
                    placeholder="client&#10;dev tun&#10;proto udp&#10;remote vpn.example.com 1194&#10;..."
                    className="w-full h-64 font-mono text-xs p-3 rounded-lg border bg-muted resize-none"
                    {...field}
                  />
                </FormControl>
                <p className="text-xs text-muted-foreground">
                  {t('SiteDetailPage.vpn.ovpnDialog.hint')}
                </p>
                <FormMessage />
              </FormItem>
            )}
          />
        )}
      </FormDialog>

      {/* ── Setup Guide (when not configured) ────────────────── */}
      {!configured && !editing && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t('SiteDetailPage.vpn.methods.title')}</CardTitle>
            <CardDescription>{t('SiteDetailPage.vpn.methods.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid sm:grid-cols-2 gap-4">
              <div className="p-3 rounded-lg border space-y-2">
                <div className="flex items-center gap-2">
                  <Router className="h-4 w-4 text-orange-500" />
                  <span className="text-sm font-medium">{t('SiteDetailPage.vpn.methods.brainTitle')}</span>
                  <Badge variant="outline" className="text-xs">{t('SiteDetailPage.vpn.methods.recommended')}</Badge>
                </div>
                <p className="text-xs text-muted-foreground">
                  {t('SiteDetailPage.vpn.methods.brainDesc')}
                </p>
              </div>
              <div className="p-3 rounded-lg border space-y-2">
                <div className="flex items-center gap-2">
                  <Globe className="h-4 w-4 text-blue-500" />
                  <span className="text-sm font-medium">Tailscale</span>
                </div>
                <p className="text-xs text-muted-foreground">
                  {t('SiteDetailPage.vpn.methods.tailscaleDesc')}
                </p>
              </div>
              <div className="p-3 rounded-lg border space-y-2">
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-green-500" />
                  <span className="text-sm font-medium">WireGuard</span>
                </div>
                <p className="text-xs text-muted-foreground">
                  {t('SiteDetailPage.vpn.methods.wireguardDesc')}
                </p>
              </div>
              <div className="p-3 rounded-lg border space-y-2">
                <div className="flex items-center gap-2">
                  <Network className="h-4 w-4 text-purple-500" />
                  <span className="text-sm font-medium">OpenVPN</span>
                </div>
                <p className="text-xs text-muted-foreground">
                  {t('SiteDetailPage.vpn.methods.openvpnDesc')}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── Device Reachability ─────────────────────────────── */}
      <Card>
        <CardHeader className="pb-3">
          <button
            className="flex items-center justify-between w-full text-left"
            onClick={() => setReachabilityOpen(!reachabilityOpen)}
          >
            <div className="flex items-center gap-2">
              <CardTitle className="text-base flex items-center gap-2">
                <Signal className="h-4 w-4 text-primary" /> {t('SiteDetailPage.reachability.title')}
              </CardTitle>
              {reachabilityData?.devices && (
                <Badge variant="secondary" className="tabular-nums text-xs">
                  {t('SiteDetailPage.reachability.reachableCount', { reachable: reachabilityData.devices.filter(d => d.reachable).length, total: reachabilityData.devices.length })}
                </Badge>
              )}
            </div>
            {reachabilityOpen
              ? <ChevronDown className="h-4 w-4 text-muted-foreground" />
              : <ChevronRight className="h-4 w-4 text-muted-foreground" />}
          </button>
        </CardHeader>
        {reachabilityOpen && (
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <p className="text-xs text-muted-foreground">
                  {t('SiteDetailPage.reachability.description')}
                </p>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => refetchReachability()}
                  disabled={reachabilityLoading || reachabilityFetching}
                >
                  {reachabilityFetching
                    ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                    : <RefreshCw className="mr-1.5 h-3.5 w-3.5" />}
                  {t('SiteDetailPage.reachability.check')}
                </Button>
              </div>

              {reachabilityFetching && !reachabilityData && (
                <Skeleton className="h-32" />
              )}

              {reachabilityData?.devices && reachabilityData.devices.length > 0 ? (
                <div className="rounded-lg border overflow-hidden">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b bg-muted">
                        <th className="text-left px-3 py-2 font-medium text-xs text-muted-foreground">{t('SiteDetailPage.reachability.deviceName')}</th>
                        <th className="text-left px-3 py-2 font-medium text-xs text-muted-foreground">{t('SiteDetailPage.reachability.type')}</th>
                        <th className="text-left px-3 py-2 font-medium text-xs text-muted-foreground">{t('SiteDetailPage.reachability.ip')}</th>
                        <th className="text-center px-3 py-2 font-medium text-xs text-muted-foreground">{t('SiteDetailPage.fields.status')}</th>
                        <th className="text-right px-3 py-2 font-medium text-xs text-muted-foreground">{t('SiteDetailPage.reachability.latency')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {reachabilityData.devices.map((dev) => (
                        <tr key={dev.device_id} className="border-b last:border-0 hover:bg-accent">
                          <td className="px-3 py-2 font-medium">{dev.device_name}</td>
                          <td className="px-3 py-2 text-muted-foreground capitalize">
                            {t(`SiteDetailPage.deviceTypes.${dev.device_type}`, { defaultValue: DEVICE_TYPE_LABELS[dev.device_type] ?? dev.device_type })}
                          </td>
                          <td className="px-3 py-2 font-mono text-xs">{dev.ip ?? '-'}</td>
                          <td className="px-3 py-2 text-center">
                            {dev.reachable ? (
                              <CheckCircle className="h-4 w-4 text-emerald-500 inline-block" />
                            ) : (
                              <TooltipProvider delayDuration={200}>
                                <Tooltip>
                                  <TooltipTrigger>
                                    <XCircle className="h-4 w-4 text-red-500 inline-block" />
                                  </TooltipTrigger>
                                  {dev.error && (
                                    <TooltipContent side="left"><p className="text-xs max-w-xs">{dev.error}</p></TooltipContent>
                                  )}
                                </Tooltip>
                              </TooltipProvider>
                            )}
                          </td>
                          <td className="px-3 py-2 text-right font-mono text-xs text-muted-foreground">
                            {dev.latency_ms != null ? `${dev.latency_ms}ms` : '-'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : reachabilityData?.devices && reachabilityData.devices.length === 0 ? (
                <div className="text-center py-6 text-sm text-muted-foreground">
                  {t('SiteDetailPage.reachability.noDevices')}
                </div>
              ) : !reachabilityFetching ? (
                <div className="text-center py-6 text-sm text-muted-foreground">
                  {t('SiteDetailPage.reachability.instruction')}
                </div>
              ) : null}
            </div>
          </CardContent>
        )}
      </Card>
    </>
  );
}


/* ============================================================
   Agent Tab · Agent management for this site
   ============================================================ */

function SiteAgentTab({ siteId, siteName, agents, agentsLoading, toast }: {
  siteId: string; siteName: string;
  agents: AgentSummary[];
  agentsLoading: boolean;
  toast: ReturnType<typeof useToast>['toast'];
}) {
  const { t } = useTranslation('sites');
  const queryClient = useQueryClient();
  const [showRegister, setShowRegister] = useState(false);
  const [agentName, setAgentName] = useState('');
  const [withWireGuard, setWithWireGuard] = useState(false);
  const [wgForm, setWgForm] = useState({ server_public_key: '', server_endpoint: '', agent_address: '' });
  const [regResult, setRegResult] = useState<{
    agent_id: string; agent_key: string; websocket_url: string;
    wg_config?: string; wg_server_peer?: string;
  } | null>(null);

  const registerMutation = useMutation({
    mutationFn: async () => {
      const r = await agentsApi.register({ site_id: siteId, name: agentName.trim() || `${siteName}-agent` } as any);
      const data = r.data as any;
      let wgData: { agent_config?: string; server_peer_block?: string } = {};

      if (withWireGuard && wgForm.server_public_key && wgForm.server_endpoint && wgForm.agent_address) {
        try {
          const wgRes = await vpnApi.provisionAgentWireGuard({
            site_id: siteId,
            server_public_key: wgForm.server_public_key,
            server_endpoint: wgForm.server_endpoint,
            agent_address: wgForm.agent_address,
          });
          wgData = wgRes.data;
        } catch {
          // WG provisioning is optional, don't fail registration
        }
      }
      return { ...data, wg_config: wgData.agent_config, wg_server_peer: wgData.server_peer_block };
    },
    onSuccess: (data: any) => {
      setRegResult({
        agent_id: data.agent_id, agent_key: data.agent_key, websocket_url: data.websocket_url,
        wg_config: data.wg_config, wg_server_peer: data.wg_server_peer,
      });
      queryClient.invalidateQueries({ queryKey: ['site-agents', siteId] });
      toast({ title: t('SiteDetailPage.agent.toasts.registered') });
    },
    onError: (err: any) => {
      toast({ title: t('SiteDetailPage.common.error'), description: err?.response?.data?.detail || t('SiteDetailPage.agent.toasts.registerFailed'), variant: 'destructive' });
    },
  });

  const approveMutation = useMutation({
    mutationFn: (agentId: string) => agentsApi.approve(agentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['site-agents', siteId] });
      toast({ title: t('SiteDetailPage.agent.toasts.approved') });
    },
    onError: (err: any) => {
      toast({ title: t('SiteDetailPage.common.error'), description: err?.response?.data?.detail || t('SiteDetailPage.agent.toasts.approveFailed'), variant: 'destructive' });
    },
  });

  if (agentsLoading) return <Skeleton className="h-64" />;

  return (
    <>
      {/* Agent List */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-base flex items-center gap-2">
                <Bot className="h-4 w-4 text-primary" /> {t('SiteDetailPage.agent.siteAgents')}
                <Badge variant="secondary" className="tabular-nums">{agents.length}</Badge>
              </CardTitle>
              <CardDescription>{t('SiteDetailPage.agent.siteAgentsDesc')}</CardDescription>
            </div>
            <Button size="sm" onClick={() => { setShowRegister(true); setRegResult(null); setAgentName(''); }}>
              <Plus className="mr-2 h-4 w-4" /> {t('SiteDetailPage.agent.registerAgent')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {agents.length === 0 ? (
            <div className="text-center py-8">
              <Bot className="h-12 w-12 text-muted-foreground mx-auto mb-3" />
              <h3 className="text-lg font-semibold">{t('SiteDetailPage.agent.emptyTitle')}</h3>
              <p className="text-sm text-muted-foreground mt-1 max-w-md mx-auto">
                {t('SiteDetailPage.agent.emptyDesc')}
              </p>
              <Button className="mt-4" onClick={() => { setShowRegister(true); setRegResult(null); setAgentName(''); }}>
                <Download className="mr-2 h-4 w-4" /> {t('SiteDetailPage.agent.deployFirstAgent')}
              </Button>
            </div>
          ) : (
            <div className="space-y-3">
              {agents.map(agent => (
                <div key={agent.id} className="flex items-center justify-between p-4 rounded-lg border border-border">
                  <div className="flex items-center gap-4">
                    <div className={cn('flex h-10 w-10 items-center justify-center rounded-lg',
                      agent.status === 'online' ? 'bg-emerald-100 dark:bg-emerald-900/30' :
                      agent.status === 'error' ? 'bg-red-100 dark:bg-red-900/30' :
                      'bg-muted',
                    )}>
                      <Bot className={cn('h-5 w-5',
                        agent.status === 'online' ? 'text-emerald-600' :
                        agent.status === 'error' ? 'text-red-500' : 'text-muted-foreground'
                      )} />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-sm">{agent.name}</span>
                        <Badge variant="outline" className={cn('text-xs', AGENT_STATUS_COLORS[agent.status] ?? '')}>
                          {agent.status}
                        </Badge>
                        {!agent.is_approved && (
                          <Badge variant="outline" className="text-xs border-amber-500/30 bg-amber-500/10 text-amber-600">
                            {t('SiteDetailPage.agent.pendingApproval')}
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-3 text-xs text-muted-foreground mt-0.5">
                        <span>{agent.agent_type}</span>
                        {agent.last_ip && <span className="font-mono">{agent.last_ip}</span>}
                        {agent.last_heartbeat && <span>{t('SiteDetailPage.agent.lastSeen', { time: formatRelative(agent.last_heartbeat, t) })}</span>}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {!agent.is_approved && (
                      <Button size="sm" variant="outline" onClick={() => approveMutation.mutate(agent.id)}>
                        <CheckCircle className="mr-2 h-4 w-4" /> {t('SiteDetailPage.agent.approve')}
                      </Button>
                    )}
                    <Button size="sm" variant="ghost" onClick={() => window.open(`/agents?id=${agent.id}`, '_self')}>
                      <ExternalLink className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Register Agent Dialog */}
      <Dialog open={showRegister} onOpenChange={(v) => { setShowRegister(v); if (!v) { setAgentName(''); setRegResult(null); setWithWireGuard(false); setWgForm({ server_public_key: '', server_endpoint: '', agent_address: '' }); } }}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{t('SiteDetailPage.agent.registerDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('SiteDetailPage.agent.registerDialog.description', { name: siteName })}
            </DialogDescription>
          </DialogHeader>
          {!regResult ? (
            <>
              <div className="grid gap-4 py-4">
                <div className="grid gap-2">
                  <Label>{t('SiteDetailPage.agent.agentName')}</Label>
                  <Input value={agentName} onChange={(e) => setAgentName(e.target.value)}
                    placeholder={`${siteName.toLowerCase().replace(/\s+/g, '-')}-agent`} />
                </div>

                {/* WireGuard auto-provisioning toggle */}
                <div className="flex items-center gap-2 pt-1">
                  <Label className="flex items-center gap-2 cursor-pointer">
                    <input type="checkbox" checked={withWireGuard}
                      onChange={(e) => setWithWireGuard(e.target.checked)}
                      className="rounded border-border" />
                    {t('SiteDetailPage.agent.registerDialog.generateWireguard')}
                  </Label>
                </div>

                {withWireGuard && (
                  <div className="space-y-3 p-3 rounded-lg border border-blue-200 dark:border-blue-800 bg-blue-50/50 dark:bg-blue-900/10">
                    <p className="text-xs text-muted-foreground">
                      {t('SiteDetailPage.agent.registerDialog.wireguardHint')}
                    </p>
                    <div className="grid gap-2">
                      <Label className="text-xs">{t('SiteDetailPage.agent.registerDialog.serverPublicKey')}</Label>
                      <Input value={wgForm.server_public_key}
                        onChange={(e) => setWgForm({ ...wgForm, server_public_key: e.target.value })}
                        placeholder={t('SiteDetailPage.agent.registerDialog.serverPublicKeyPlaceholder')} className="font-mono text-xs" />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="grid gap-2">
                        <Label className="text-xs">{t('SiteDetailPage.agent.registerDialog.serverEndpoint')}</Label>
                        <Input value={wgForm.server_endpoint}
                          onChange={(e) => setWgForm({ ...wgForm, server_endpoint: e.target.value })}
                          placeholder="vpn.freesdn.com:51820" className="font-mono text-xs" />
                      </div>
                      <div className="grid gap-2">
                        <Label className="text-xs">{t('SiteDetailPage.agent.registerDialog.agentVpnAddress')}</Label>
                        <Input value={wgForm.agent_address}
                          onChange={(e) => setWgForm({ ...wgForm, agent_address: e.target.value })}
                          placeholder="10.100.0.5/32" className="font-mono text-xs" />
                      </div>
                    </div>
                  </div>
                )}
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setShowRegister(false)}>{t('SiteDetailPage.common.cancel')}</Button>
                <Button onClick={() => registerMutation.mutate()} disabled={registerMutation.isPending}>
                  {registerMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Plus className="mr-2 h-4 w-4" />}
                  {t('SiteDetailPage.agent.register')}
                </Button>
              </DialogFooter>
            </>
          ) : (
            <div className="space-y-4 py-4 max-h-[70vh] overflow-y-auto">
              <div className="rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 p-4">
                <p className="text-sm font-medium text-amber-800 dark:text-amber-200">
                  {t('SiteDetailPage.agent.result.saveCredentials')}
                </p>
              </div>
              <div className="space-y-3">
                <div>
                  <Label className="text-xs text-muted-foreground">{t('SiteDetailPage.agent.result.agentId')}</Label>
                  <div className="flex items-center gap-2 mt-1">
                    <code className="flex-1 text-xs bg-muted p-2 rounded font-mono break-all">{regResult.agent_id}</code>
                    <Button size="icon" variant="ghost" className="h-8 w-8 shrink-0"
                      onClick={() => { navigator.clipboard.writeText(regResult.agent_id); toast({ title: t('SiteDetailPage.common.copied') }); }}>
                      <Copy className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground">{t('SiteDetailPage.agent.result.apiKey')}</Label>
                  <div className="flex items-center gap-2 mt-1">
                    <code className="flex-1 text-xs bg-muted p-2 rounded font-mono break-all">{regResult.agent_key}</code>
                    <Button size="icon" variant="ghost" className="h-8 w-8 shrink-0"
                      onClick={() => { navigator.clipboard.writeText(regResult.agent_key); toast({ title: t('SiteDetailPage.common.copied') }); }}>
                      <Copy className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground">{t('SiteDetailPage.agent.result.websocketUrl')}</Label>
                  <div className="flex items-center gap-2 mt-1">
                    <code className="flex-1 text-xs bg-muted p-2 rounded font-mono break-all">{regResult.websocket_url}</code>
                    <Button size="icon" variant="ghost" className="h-8 w-8 shrink-0"
                      onClick={() => { navigator.clipboard.writeText(regResult.websocket_url); toast({ title: t('SiteDetailPage.common.copied') }); }}>
                      <Copy className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>

                {/* WireGuard config output */}
                {regResult.wg_config && (
                  <div className="pt-2 border-t border-border">
                    <div className="rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-3 mb-2">
                      <p className="text-xs font-medium text-red-800 dark:text-red-200">
                        {t('SiteDetailPage.agent.result.wgPrivateKeyWarning')}
                      </p>
                    </div>
                    <div className="flex items-center justify-between mb-2">
                      <Label className="text-xs text-muted-foreground">{t('SiteDetailPage.agent.result.wgAgentConfig')}</Label>
                      <Button size="sm" variant="outline" className="h-7 text-xs"
                        onClick={() => { navigator.clipboard.writeText(regResult.wg_config!); toast({ title: t('SiteDetailPage.agent.result.configCopied') }); }}>
                        <Copy className="mr-1.5 h-3 w-3" /> {t('SiteDetailPage.actions.copy')}
                      </Button>
                    </div>
                    <pre className="text-xs bg-muted p-3 rounded font-mono whitespace-pre-wrap break-all">{regResult.wg_config}</pre>
                  </div>
                )}
                {regResult.wg_server_peer && (
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <Label className="text-xs text-muted-foreground">{t('SiteDetailPage.agent.result.addToServerConf')}</Label>
                      <Button size="sm" variant="outline" className="h-7 text-xs"
                        onClick={() => { navigator.clipboard.writeText(regResult.wg_server_peer!); toast({ title: t('SiteDetailPage.agent.result.peerBlockCopied') }); }}>
                        <Copy className="mr-1.5 h-3 w-3" /> {t('SiteDetailPage.actions.copy')}
                      </Button>
                    </div>
                    <pre className="text-xs bg-muted p-3 rounded font-mono whitespace-pre-wrap break-all">{regResult.wg_server_peer}</pre>
                  </div>
                )}
              </div>
              <DialogFooter>
                <Button onClick={() => setShowRegister(false)}>{t('SiteDetailPage.common.done')}</Button>
              </DialogFooter>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Agent Setup Instructions */}
      {agents.length === 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t('SiteDetailPage.agent.guide.title')}</CardTitle>
          </CardHeader>
          <CardContent>
            <ol className="space-y-3 text-sm">
              <li className="flex gap-3">
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary text-xs font-bold">1</span>
                <span>{t('SiteDetailPage.agent.guide.step1')}</span>
              </li>
              <li className="flex gap-3">
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary text-xs font-bold">2</span>
                <span>{t('SiteDetailPage.agent.guide.step2Before')} <button className="text-primary underline" onClick={() => window.open('/agents', '_self')}>{t('SiteDetailPage.agent.guide.step2Link')}</button></span>
              </li>
              <li className="flex gap-3">
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary text-xs font-bold">3</span>
                <span>{t('SiteDetailPage.agent.guide.step3')}</span>
              </li>
              <li className="flex gap-3">
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary text-xs font-bold">4</span>
                <span>{t('SiteDetailPage.agent.guide.step4')} <code className="text-xs bg-muted px-1.5 py-0.5 rounded">freesdn-agent --server URL --agent-id ID --agent-key KEY</code></span>
              </li>
              <li className="flex gap-3">
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary text-xs font-bold">5</span>
                <span>{t('SiteDetailPage.agent.guide.step5')}</span>
              </li>
            </ol>
          </CardContent>
        </Card>
      )}
    </>
  );
}


/* ============================================================
   Settings Form
   ============================================================ */

function SiteSettingsForm({
  site, editMode, setEditMode, onSave, isPending,
}: {
  site: Site; editMode: boolean; setEditMode: (v: boolean) => void;
  onSave: (data: Record<string, unknown>) => void; isPending: boolean;
}) {
  const { t } = useTranslation('sites');
  // auto_adopt_known_vendors lives in site.settings, backend reads
  // it on every upsert_batch to decide whether to promote high-
  // confidence discoveries directly to managed devices.
  const siteSettings = (site.settings || {}) as Record<string, unknown>;
  const [form, setForm] = useState({
    name: site.name,
    description: site.description ?? '',
    address: site.address ?? '',
    city: site.city ?? '',
    country: site.country ?? '',
    timezone: site.timezone,
    time_format: site.time_format,
    date_format: site.date_format,
    is_active: site.is_active,
    gateway_ip: site.gateway_ip ?? '',
    auto_adopt_known_vendors: Boolean(siteSettings.auto_adopt_known_vendors),
    auto_adopt_min_confidence: Number(siteSettings.auto_adopt_min_confidence ?? 0.7),
  });

  const handleCancel = () => {
    const s = (site.settings || {}) as Record<string, unknown>;
    setForm({
      name: site.name,
      description: site.description ?? '',
      address: site.address ?? '',
      city: site.city ?? '',
      country: site.country ?? '',
      timezone: site.timezone,
      time_format: site.time_format,
      date_format: site.date_format,
      is_active: site.is_active,
      gateway_ip: site.gateway_ip ?? '',
      auto_adopt_known_vendors: Boolean(s.auto_adopt_known_vendors),
      auto_adopt_min_confidence: Number(s.auto_adopt_min_confidence ?? 0.7),
    });
    setEditMode(false);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Merge auto-adopt fields back into settings JSONB rather than
    // sending them as top-level columns, keeps the column count
    // stable as we accumulate more per-site behavior toggles.
    const nextSettings = {
      ...(site.settings || {}),
      auto_adopt_known_vendors: form.auto_adopt_known_vendors,
      auto_adopt_min_confidence: form.auto_adopt_min_confidence,
    };
    const { auto_adopt_known_vendors, auto_adopt_min_confidence, ...rest } = form;
    onSave({
      ...rest,
      gateway_ip: form.gateway_ip.trim() || null,
      settings: nextSettings,
    });
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            <Settings className="h-4 w-4 text-primary" /> {t('SiteDetailPage.settings.title')}
          </CardTitle>
          {!editMode && (
            <Button variant="outline" size="sm" onClick={() => setEditMode(true)}>
              <Edit className="mr-2 h-4 w-4" /> {t('SiteDetailPage.actions.edit')}
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit}>
          <div className="grid gap-4">
            <div className="grid gap-2">
              <Label>{t('SiteDetailPage.fields.name')}</Label>
              <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} disabled={!editMode} />
            </div>
            <div className="grid gap-2">
              <Label>{t('SiteDetailPage.fields.description')}</Label>
              <Textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} disabled={!editMode} rows={2} />
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
              <div className="grid gap-2">
                <Label>{t('SiteDetailPage.fields.city')}</Label>
                <Input value={form.city} onChange={(e) => setForm({ ...form, city: e.target.value })} disabled={!editMode} />
              </div>
              <div className="grid gap-2">
                <Label>{t('SiteDetailPage.fields.country')}</Label>
                <Input value={form.country} onChange={(e) => setForm({ ...form, country: e.target.value })} disabled={!editMode} />
              </div>
              <div className="grid gap-2">
                <Label>{t('SiteDetailPage.fields.timezone')}</Label>
                <Input value={form.timezone} onChange={(e) => setForm({ ...form, timezone: e.target.value })} disabled={!editMode} />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="grid gap-2">
                <Label>{t('SiteDetailPage.fields.address')}</Label>
                <Input value={form.address} onChange={(e) => setForm({ ...form, address: e.target.value })} disabled={!editMode} />
              </div>
              <div className="grid gap-2">
                <Label>{t('SiteDetailPage.fields.gatewayIp')}</Label>
                <Input value={form.gateway_ip} onChange={(e) => setForm({ ...form, gateway_ip: e.target.value })}
                  disabled={!editMode} placeholder="192.168.1.1" className="font-mono" />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="grid gap-2">
                <Label>{t('SiteDetailPage.fields.timeFormat')}</Label>
                <Input value={form.time_format} onChange={(e) => setForm({ ...form, time_format: e.target.value })} disabled={!editMode} />
              </div>
              <div className="grid gap-2">
                <Label>{t('SiteDetailPage.fields.dateFormat')}</Label>
                <Input value={form.date_format} onChange={(e) => setForm({ ...form, date_format: e.target.value })} disabled={!editMode} />
              </div>
            </div>
            {editMode && (
              <div className="flex items-center gap-2 pt-2">
                <Label className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" checked={form.is_active}
                    onChange={(e) => setForm({ ...form, is_active: e.target.checked })}
                    className="rounded border-border" />
                  {t('SiteDetailPage.settings.siteIsActive')}
                </Label>
              </div>
            )}

            {/* Discovery auto-adopt, opt-in per site. When on, every
                discovered host with a recognized vendor + driver match
                above the confidence threshold is promoted directly to
                the managed inventory, skipping the Adopt step. */}
            <div className="rounded border p-4 space-y-3 mt-2">
              <div className="font-medium text-sm">{t('SiteDetailPage.settings.autoAdopt.heading')}</div>
              <Label className="flex items-start gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={form.auto_adopt_known_vendors}
                  onChange={(e) => setForm({
                    ...form,
                    auto_adopt_known_vendors: e.target.checked,
                  })}
                  disabled={!editMode}
                  className="mt-0.5 rounded border-border"
                />
                <span className="flex-1">
                  <div>{t('SiteDetailPage.settings.autoAdopt.toggleLabel')}</div>
                  <div className="text-xs text-muted-foreground font-normal">
                    {t('SiteDetailPage.settings.autoAdopt.toggleDesc')}
                  </div>
                </span>
              </Label>
              {form.auto_adopt_known_vendors && (
                <div className="grid gap-2 pl-6">
                  <Label className="text-xs">
                    {t('SiteDetailPage.settings.autoAdopt.minConfidence')}
                  </Label>
                  <Input
                    type="number"
                    min={0}
                    max={1}
                    step={0.05}
                    value={form.auto_adopt_min_confidence}
                    onChange={(e) => setForm({
                      ...form,
                      auto_adopt_min_confidence: parseFloat(e.target.value) || 0.7,
                    })}
                    disabled={!editMode}
                    className="font-mono w-32"
                  />
                  <div className="text-xs text-muted-foreground">
                    {t('SiteDetailPage.settings.autoAdopt.minConfidenceHint')}
                  </div>
                </div>
              )}
            </div>
          </div>
          {editMode && (
            <div className="flex justify-end gap-2 pt-6">
              <Button type="button" variant="outline" onClick={handleCancel}>{t('SiteDetailPage.common.cancel')}</Button>
              <Button type="submit" disabled={isPending || !form.name.trim()}>
                {isPending ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />{t('SiteDetailPage.common.saving')}</> : t('SiteDetailPage.settings.saveChanges')}
              </Button>
            </div>
          )}
        </form>
      </CardContent>
    </Card>
  );
}

export { SiteDetailPage };
