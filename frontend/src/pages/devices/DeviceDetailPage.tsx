// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Enterprise Device Detail Page
 * =============================================
 *
 * Comprehensive single-device view with identity, health gauges,
 * port status, network info, and management actions · all API-driven.
 */

import { useParams, useNavigate } from 'react-router-dom';
import { useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { devicesApi, deviceControlApi, credentialsApi, getApiErrorMessage } from '@/lib/api';
import {
  ArrowLeft,
  RefreshCw,
  Power,
  Settings,
  Activity,
  Wifi,
  HardDrive,
  Router,
  Camera,
  Server,
  MoreHorizontal,
  CheckCircle,
  XCircle,
  AlertCircle,
  AlertTriangle,
  Clock,
  Zap,
  Cpu,
  Network,
  Cable,
  Edit,
  Trash2,
  Download,
  Upload,
  Globe,
  Shield,
  Phone,
  Radio,
  DoorOpen,
  Video,
  Copy,
  Info,
  Loader2,
  ExternalLink,
  KeyRound,
} from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
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
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks/use-toast';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Skeleton } from '@/components/ui/skeleton';
import { Separator } from '@/components/ui/separator';
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
import { cn } from '@/lib/utils';


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
  credential_id: string | null;
  driver_id: string | null;
  discovery_method: string | null;
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
   Constants
   ============================================================ */

// `labelKey` is a suffix under DeviceDetailPage.deviceTypes.*, translated at the use site.
const TYPE_META: Record<string, { icon: typeof Server; labelKey: string; color: string }> = {
  switch:         { icon: HardDrive,  labelKey: 'switch',         color: 'text-blue-500' },
  access_point:   { icon: Wifi,       labelKey: 'access_point',   color: 'text-indigo-500' },
  router:         { icon: Router,     labelKey: 'router',         color: 'text-teal-500' },
  gateway:        { icon: Globe,      labelKey: 'gateway',        color: 'text-cyan-500' },
  firewall:       { icon: Shield,     labelKey: 'firewall',       color: 'text-rose-500' },
  camera:         { icon: Camera,     labelKey: 'camera',         color: 'text-violet-500' },
  nvr:            { icon: Video,      labelKey: 'nvr',            color: 'text-purple-500' },
  dvr:            { icon: Video,      labelKey: 'dvr',            color: 'text-purple-400' },
  access_control: { icon: DoorOpen,   labelKey: 'access_control', color: 'text-amber-500' },
  intercom:       { icon: Radio,      labelKey: 'intercom',       color: 'text-orange-500' },
  voip_phone:     { icon: Phone,      labelKey: 'voip_phone',     color: 'text-green-500' },
  pbx:            { icon: Phone,      labelKey: 'pbx',            color: 'text-emerald-500' },
  server:         { icon: Cpu,        labelKey: 'server',         color: 'text-muted-foreground' },
  iot:            { icon: Zap,        labelKey: 'iot',            color: 'text-yellow-500' },
  sensor:         { icon: Activity,   labelKey: 'sensor',         color: 'text-lime-500' },
  other:          { icon: Server,     labelKey: 'other',          color: 'text-muted-foreground' },
};

// `labelKey` is a suffix under DeviceDetailPage.statuses.*, translated at the use site.
const STATUS_META: Record<string, { icon: typeof CheckCircle; labelKey: string; dot: string; bg: string; text: string; border: string }> = {
  online:          { icon: CheckCircle,   labelKey: 'online',          dot: 'bg-emerald-500', bg: 'bg-emerald-500/10', text: 'text-emerald-600 dark:text-emerald-400', border: 'border-emerald-500/20' },
  offline:         { icon: XCircle,       labelKey: 'offline',         dot: 'bg-red-500',     bg: 'bg-red-500/10',     text: 'text-red-600 dark:text-red-400',         border: 'border-red-500/20' },
  degraded:        { icon: AlertTriangle, labelKey: 'degraded',        dot: 'bg-amber-500',   bg: 'bg-amber-500/10',   text: 'text-amber-600 dark:text-amber-400',     border: 'border-amber-500/20' },
  adopting:        { icon: RefreshCw,     labelKey: 'adopting',        dot: 'bg-blue-500',    bg: 'bg-blue-500/10',    text: 'text-blue-600 dark:text-blue-400',       border: 'border-blue-500/20' },
  provisioning:    { icon: RefreshCw,     labelKey: 'provisioning',    dot: 'bg-blue-500',    bg: 'bg-blue-500/10',    text: 'text-blue-600 dark:text-blue-400',       border: 'border-blue-500/20' },
  adoption_failed: { icon: XCircle,       labelKey: 'adoption_failed', dot: 'bg-red-500',     bg: 'bg-red-500/10',     text: 'text-red-600 dark:text-red-400',         border: 'border-red-500/20' },
  unknown:         { icon: AlertCircle,   labelKey: 'unknown',         dot: 'bg-muted-foreground',   bg: 'bg-muted-foreground/10',   text: 'text-muted-foreground',     border: 'border-muted-foreground/20' },
};


/* ============================================================
   Sub-Components
   ============================================================ */

function DeviceIcon({ type, className }: { type: string; className?: string }) {
  const meta = TYPE_META[type] || TYPE_META.other;
  const Icon = meta.icon;
  return <Icon className={cn('h-6 w-6', meta.color, className)} />;
}

function StatusBadge({ status }: { status: string }) {
  const { t } = useTranslation('devices');
  const meta = STATUS_META[status] || STATUS_META.unknown;
  const Icon = meta.icon;
  const pulse = status === 'adopting' || status === 'provisioning';
  return (
    <span className={cn(
      'inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold',
      meta.bg, meta.text, meta.border,
      pulse && 'animate-pulse',
    )}>
      <Icon className="h-3.5 w-3.5" />
      {t(`DeviceDetailPage.statuses.${meta.labelKey}`)}
    </span>
  );
}


/* ============================================================
   Gauge Ring · used for CPU / Memory
   ============================================================ */

function GaugeRing({ value, label, size = 80 }: { value: number | null; label: string; size?: number }) {
  const pct = value != null ? Math.min(Math.round(value), 100) : 0;
  const r = (size - 10) / 2;
  const c = 2 * Math.PI * r;
  const offset = c - (pct / 100) * c;
  const color = value == null ? '#94a3b8' : pct > 90 ? '#ef4444' : pct > 70 ? '#f59e0b' : '#10b981';

  return (
    <div className="flex flex-col items-center gap-1.5">
      <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="currentColor" strokeWidth={5}
            className="text-slate-200 dark:text-slate-700" />
          {value != null && (
            <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={5}
              strokeDasharray={c} strokeDashoffset={offset} strokeLinecap="round"
              className="transition-all duration-700" />
          )}
        </svg>
        <span className="absolute text-lg font-bold tabular-nums">
          {value != null ? `${pct}%` : '-'}
        </span>
      </div>
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
    </div>
  );
}


/* ============================================================
   Detail Row · key/value pair
   ============================================================ */

function DetailRow({ label, value, mono, copyable }: {
  label: string; value: string | number | null | undefined; mono?: boolean; copyable?: boolean;
}) {
  const { t } = useTranslation('devices');
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
                  onClick={() => navigator.clipboard.writeText(display)}
                >
                  {display}
                  <Copy className="h-3 w-3 opacity-40" />
                </button>
              </TooltipTrigger>
              <TooltipContent><p className="text-xs">{t('DeviceDetailPage.detailRow.clickToCopy')}</p></TooltipContent>
            </Tooltip>
          </TooltipProvider>
        ) : display}
      </dd>
    </div>
  );
}


/* ============================================================
   Utility Functions
   ============================================================ */

function formatUptime(seconds: number | null, t: TFunction): string {
  if (!seconds) return '-';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return t('DeviceDetailPage.uptime.dhm', { d, h, m });
  if (h > 0) return t('DeviceDetailPage.uptime.hm', { h, m });
  return t('DeviceDetailPage.uptime.m', { m });
}

function formatDate(ts: string | null): string {
  if (!ts) return '-';
  return new Date(ts).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function formatRelative(ts: string | null, t: TFunction): string {
  if (!ts) return t('DeviceDetailPage.relative.never');
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return t('DeviceDetailPage.relative.justNow');
  if (mins < 60) return t('DeviceDetailPage.relative.minutesAgo', { n: mins });
  const hrs = Math.floor(diff / 3_600_000);
  if (hrs < 24) return t('DeviceDetailPage.relative.hoursAgo', { n: hrs });
  const days = Math.floor(diff / 86_400_000);
  return t('DeviceDetailPage.relative.daysAgo', { n: days });
}


/* ============================================================
   Management URL Helper
   ============================================================ */

function getManagementUrl(device: Device): string | null {
  const { device_type, id, external_id } = device;

  // Parse external_id pattern  "type:uuid"
  const extUuid = external_id?.split(':')[1] ?? null;

  switch (device_type) {
    case 'nvr':
      return extUuid ? `/cameras/nvrs/${extUuid}` : null;
    case 'camera':
      return extUuid ? `/cameras/${extUuid}` : null;
    case 'switch':
      return `/switches/${id}`;
    case 'access_point':
      return `/access-points/${id}`;
    case 'voip_phone':
      return extUuid ? `/voip/phones/${extUuid}` : '/voip/phones';
    case 'pbx':
      return extUuid ? `/voip/pbx/${extUuid}` : '/voip/pbx';
    case 'firewall':
    case 'gateway':
      return '/firewall';
    default:
      return null;
  }
}

function getManagementLabel(deviceType: string, t: TFunction): string {
  switch (deviceType) {
    case 'nvr':           return t('DeviceDetailPage.manage.nvr');
    case 'camera':        return t('DeviceDetailPage.manage.camera');
    case 'switch':        return t('DeviceDetailPage.manage.switch');
    case 'access_point':  return t('DeviceDetailPage.manage.accessPoint');
    case 'voip_phone':    return t('DeviceDetailPage.manage.phone');
    case 'pbx':           return t('DeviceDetailPage.manage.pbx');
    case 'firewall':      return t('DeviceDetailPage.manage.firewall');
    case 'gateway':       return t('DeviceDetailPage.manage.gateway');
    default:              return t('DeviceDetailPage.manage.default');
  }
}


/* ============================================================
   Main Component
   ============================================================ */

const VALID_DEVICE_TABS = new Set(['overview', 'network', 'ports', 'system']);

export default function DeviceDetailPage() {
  const { t } = useTranslation('devices');
  const { deviceId, tab } = useParams<{ deviceId: string; tab?: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const activeTab = tab && VALID_DEVICE_TABS.has(tab) ? tab : 'overview';

  const setActiveTab = useCallback((value: string) => {
    navigate(
      value === 'overview' ? `/devices/${deviceId}` : `/devices/${deviceId}/${value}`,
      { replace: true },
    );
  }, [deviceId, navigate]);

  // ---- Fetch device ----
  const { data: device, isLoading, isError, error, refetch, isFetching } = useQuery<Device>({
    queryKey: ['device', deviceId],
    queryFn: async () => {
      const r = await devicesApi.getById(deviceId!);
      return r.data;
    },
    enabled: !!deviceId,
    refetchInterval: 15_000,
  });

  const { toast } = useToast();
  const [credDialogOpen, setCredDialogOpen] = useState(false);
  const [selectedCredId, setSelectedCredId] = useState<string>('');
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [removeDialogOpen, setRemoveDialogOpen] = useState(false);
  const [editForm, setEditForm] = useState({
    name: '',
    location: '',
    floor: '',
    room: '',
    notes: '',
  });

  // ---- Reboot mutation ----
  const rebootMutation = useMutation({
    mutationFn: () => deviceControlApi.reboot(deviceId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['device', deviceId] });
      queryClient.invalidateQueries({ queryKey: ['devices'] });
    },
    onError: (err: unknown) => {
      toast({
        title: t('common:error'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  // ---- Credentials (for the assign-credential dialog) ----
  const { data: credentials = [] } = useQuery({
    queryKey: ['credentials-for-assign'],
    queryFn: async () => {
      const r = await credentialsApi.list();
      return r.data ?? [];  // backend returns a bare array
    },
    enabled: credDialogOpen,
  });

  const assignCredMutation = useMutation({
    mutationFn: async () => {
      return devicesApi.update(deviceId!, {
        credential_id: selectedCredId || null,
      });
    },
    onSuccess: () => {
      toast({ title: t('DeviceDetailPage.toast.credentialUpdated') });
      setCredDialogOpen(false);
      queryClient.invalidateQueries({ queryKey: ['device', deviceId] });
    },
    onError: (err: unknown) => {
      toast({
        title: t('DeviceDetailPage.toast.updateFailed'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  // ---- Edit device mutation ----
  const editMutation = useMutation({
    mutationFn: async () => {
      return devicesApi.update(deviceId!, {
        name: editForm.name.trim(),
        location: editForm.location.trim() || null,
        floor: editForm.floor.trim() || null,
        room: editForm.room.trim() || null,
        notes: editForm.notes.trim() || null,
      });
    },
    onSuccess: () => {
      toast({ title: t('common:success') });
      setEditDialogOpen(false);
      queryClient.invalidateQueries({ queryKey: ['device', deviceId] });
      queryClient.invalidateQueries({ queryKey: ['devices'] });
    },
    onError: (err: unknown) => {
      toast({
        title: t('DeviceDetailPage.toast.updateFailed'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  // ---- Remove device mutation ----
  const removeMutation = useMutation({
    mutationFn: () => devicesApi.delete(deviceId!),
    onSuccess: () => {
      toast({ title: t('common:success') });
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      setRemoveDialogOpen(false);
      navigate('/devices');
    },
    onError: (err: unknown) => {
      toast({
        title: t('common:error'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  const openEditDialog = useCallback(() => {
    if (!device) return;
    setEditForm({
      name: device.name ?? '',
      location: device.location ?? '',
      floor: device.floor ?? '',
      room: device.room ?? '',
      notes: device.notes ?? '',
    });
    setEditDialogOpen(true);
  }, [device]);


  // ---- Loading state ----
  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <Skeleton className="h-10 w-10 rounded-lg" />
          <div className="space-y-2">
            <Skeleton className="h-6 w-64" />
            <Skeleton className="h-4 w-40" />
          </div>
        </div>
        <div className="grid gap-4 md:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-28" />)}
        </div>
        <Skeleton className="h-96" />
      </div>
    );
  }

  // ---- Error state ----
  if (isError || !device) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <div className="flex h-16 w-16 items-center justify-center rounded-full bg-red-100 dark:bg-red-900/30 mb-4">
          <AlertCircle className="h-8 w-8 text-red-500" />
        </div>
        <h2 className="text-xl font-semibold">{t('DeviceDetailPage.error.title')}</h2>
        <p className="text-muted-foreground mt-1 max-w-sm">{(error as Error)?.message || t('DeviceDetailPage.error.notFound')}</p>
        <div className="flex gap-2 mt-6">
          <Button variant="outline" onClick={() => navigate('/devices')}>
            <ArrowLeft className="mr-2 h-4 w-4" /> {t('DeviceDetailPage.error.backToInventory')}
          </Button>
          <Button onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> {t('DeviceDetailPage.error.retry')}
          </Button>
        </div>
      </div>
    );
  }

  const typeMeta = TYPE_META[device.device_type] || TYPE_META.other;
  const portUsagePct = device.port_count > 0 ? Math.round((device.active_port_count / device.port_count) * 100) : null;

  return (
    <TooltipProvider delayDuration={300}>
      <div className="space-y-6">

        {/* ──── Header ──── */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Button variant="ghost" size="icon" onClick={() => navigate('/devices')}>
              <ArrowLeft className="h-5 w-5" />
            </Button>
            <div className={cn(
              'flex h-12 w-12 shrink-0 items-center justify-center rounded-xl',
              device.status === 'online' ? 'bg-emerald-100 dark:bg-emerald-900/30' : device.status === 'offline' ? 'bg-red-100 dark:bg-red-900/30' : 'bg-muted',
            )}>
              <DeviceIcon type={device.device_type} className="h-6 w-6" />
            </div>
            <div>
              <h2 className="text-xl font-semibold flex items-center gap-2">
                {device.name}
                <StatusBadge status={device.status} />
                {!device.is_managed && (
                  <Badge variant="outline" className="bg-warning/10 text-warning border-warning/20">
                    {t('DeviceDetailPage.badge.unmanaged')}
                  </Badge>
                )}
              </h2>
              <p className="text-sm text-muted-foreground">
                {t(`DeviceDetailPage.deviceTypes.${typeMeta.labelKey}`)}
                {device.manufacturer && ` · ${device.manufacturer}`}
                {device.model && ` · ${device.model}`}
                {device.ip_address && ` · ${device.ip_address}`}
              </p>
            </div>
          </div>

          {/* Actions · refresh/utility left, primary rightmost */}
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
              <RefreshCw className={cn('mr-2 h-4 w-4', isFetching && 'animate-spin')} />
              {t('DeviceDetailPage.actions.sync')}
            </Button>
            <Button
              variant="outline" size="sm"
              onClick={() => rebootMutation.mutate()}
              disabled={device.status !== 'online' || rebootMutation.isPending}
            >
              {rebootMutation.isPending
                ? <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                : <Power className="mr-2 h-4 w-4" />
              }
              {t('DeviceDetailPage.actions.reboot')}
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="icon" className="h-9 w-9">
                  <MoreHorizontal className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-56">
                <DropdownMenuItem onClick={openEditDialog}>
                  <Edit className="mr-2 h-4 w-4" /> {t('DeviceDetailPage.menu.editDevice')}
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={() => {
                    setSelectedCredId(device.credential_id || '');
                    setCredDialogOpen(true);
                  }}
                >
                  <KeyRound className="mr-2 h-4 w-4" />
                  {device.credential_id ? t('DeviceDetailPage.menu.changeCredential') : t('DeviceDetailPage.menu.assignCredential')}
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => refetch()}>
                  <RefreshCw className="mr-2 h-4 w-4" /> {t('DeviceDetailPage.menu.reprobe')}
                </DropdownMenuItem>
                <DropdownMenuItem disabled>
                  <Download className="mr-2 h-4 w-4" /> {t('DeviceDetailPage.menu.backupConfig')}
                </DropdownMenuItem>
                <DropdownMenuItem disabled>
                  <Upload className="mr-2 h-4 w-4" /> {t('DeviceDetailPage.menu.upgradeFirmware')}
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  className="text-destructive focus:text-destructive"
                  onClick={() => setRemoveDialogOpen(true)}
                >
                  <Trash2 className="mr-2 h-4 w-4" /> {t('DeviceDetailPage.menu.removeDevice')}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
            {(() => {
              const mgmtUrl = getManagementUrl(device);
              return mgmtUrl ? (
                <Button variant="default" size="sm" onClick={() => navigate(mgmtUrl)} className="gap-1.5">
                  <ExternalLink className="h-4 w-4" />
                  {getManagementLabel(device.device_type, t)}
                </Button>
              ) : null;
            })()}
          </div>
        </div>

        {/* ──── Lifecycle / provenance banner ──── */}
        {device.status === 'adopting' && (
          <div className="flex items-start gap-3 rounded-lg border border-blue-500/20 bg-blue-500/10 p-3 text-sm">
            <RefreshCw className="mt-0.5 h-4 w-4 shrink-0 animate-spin text-blue-500" />
            <div>
              <div className="font-medium text-blue-700 dark:text-blue-300">
                {t('DeviceDetailPage.banner.adoptionInProgress.title')}
              </div>
              <div className="text-xs text-muted-foreground">
                {device.controller_id
                  ? t('DeviceDetailPage.banner.adoptionInProgress.withController')
                  : t('DeviceDetailPage.banner.adoptionInProgress.noController')}
              </div>
            </div>
          </div>
        )}
        {!device.controller_id
          && device.discovery_method
          && ['auto_adopt', 'agent', 'bulk_adopt'].includes(device.discovery_method)
          && device.status === 'online' && (
          <div className="flex items-start gap-3 rounded-lg border border-emerald-500/20 bg-emerald-500/10 p-3 text-sm">
            <Info className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" />
            <div>
              <div className="font-medium text-emerald-700 dark:text-emerald-300">
                {t('DeviceDetailPage.banner.agentDiscovery.title')}
              </div>
              <div className="text-xs text-muted-foreground">
                {t('DeviceDetailPage.banner.agentDiscovery.description')}
              </div>
            </div>
          </div>
        )}


        {/* ──── Quick Stats ──── */}
        <div className="grid gap-4 grid-cols-2 lg:grid-cols-4">
          <Card>
            <CardContent noOffset className="pb-4">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-medium text-muted-foreground">{t('DeviceDetailPage.stats.uptime')}</span>
                <Clock className="h-4 w-4 text-muted-foreground" />
              </div>
              <p className="text-lg font-semibold tabular-nums">{formatUptime(device.uptime_seconds, t)}</p>
              <p className="text-xs text-muted-foreground">{t('DeviceDetailPage.stats.sinceLastReboot')}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent noOffset className="pb-4">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-medium text-muted-foreground">{t('DeviceDetailPage.stats.activePorts')}</span>
                <Network className="h-4 w-4 text-muted-foreground" />
              </div>
              <p className="text-lg font-semibold tabular-nums">
                {device.port_count > 0 ? `${device.active_port_count} / ${device.port_count}` : '-'}
              </p>
              {device.port_count > 0 && <Progress value={portUsagePct ?? 0} className="mt-1.5 h-1" />}
            </CardContent>
          </Card>
          <Card>
            <CardContent noOffset className="pb-4">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-medium text-muted-foreground">CPU</span>
                <Cpu className="h-4 w-4 text-muted-foreground" />
              </div>
              <p className="text-lg font-semibold tabular-nums">
                {device.cpu_usage_percent != null ? `${Math.round(device.cpu_usage_percent)}%` : '-'}
              </p>
              {device.cpu_usage_percent != null && <Progress value={device.cpu_usage_percent} className="mt-1.5 h-1" />}
            </CardContent>
          </Card>
          <Card>
            <CardContent noOffset className="pb-4">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-medium text-muted-foreground">{t('DeviceDetailPage.stats.connectedClients')}</span>
                <Activity className="h-4 w-4 text-muted-foreground" />
              </div>
              <p className="text-lg font-semibold tabular-nums">{device.client_count}</p>
              <p className="text-xs text-muted-foreground">{t('DeviceDetailPage.stats.activeConnections')}</p>
            </CardContent>
          </Card>
        </div>


        {/* ──── Tabbed Content ──── */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
          <TabsList>
            <TabsTrigger value="overview" className="gap-2">
              <Info className="h-4 w-4" />
              {t('DeviceDetailPage.tabs.overview')}
            </TabsTrigger>
            <TabsTrigger value="network" className="gap-2">
              <Globe className="h-4 w-4" />
              {t('DeviceDetailPage.tabs.network')}
            </TabsTrigger>
            {device.port_count > 0 && (
              <TabsTrigger value="ports" className="gap-2">
                <Cable className="h-4 w-4" />
                {t('DeviceDetailPage.tabs.ports', { count: device.port_count })}
              </TabsTrigger>
            )}
            <TabsTrigger value="system" className="gap-2">
              <Settings className="h-4 w-4" />
              {t('DeviceDetailPage.tabs.system')}
            </TabsTrigger>
          </TabsList>


          {/* ── Overview Tab ── */}
          <TabsContent value="overview">
            <div className="grid gap-6 lg:grid-cols-2">
              {/* Identity */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">{t('DeviceDetailPage.identity.title')}</CardTitle>
                </CardHeader>
                <CardContent>
                  <dl>
                    <DetailRow label={t('DeviceDetailPage.identity.name')} value={device.name} />
                    <DetailRow label={t('DeviceDetailPage.identity.type')} value={t(`DeviceDetailPage.deviceTypes.${typeMeta.labelKey}`)} />
                    <DetailRow label={t('DeviceDetailPage.identity.manufacturer')} value={device.manufacturer} />
                    <DetailRow label={t('DeviceDetailPage.identity.model')} value={device.model} />
                    <DetailRow label={t('DeviceDetailPage.identity.serialNumber')} value={device.serial_number} mono copyable />
                    <DetailRow label={t('DeviceDetailPage.identity.macAddress')} value={device.mac_address} mono copyable />
                    <DetailRow label={t('DeviceDetailPage.identity.firmware')} value={device.firmware_version} mono />
                  </dl>
                </CardContent>
              </Card>

              {/* Location & Management */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">{t('DeviceDetailPage.location.title')}</CardTitle>
                </CardHeader>
                <CardContent>
                  <dl>
                    <DetailRow label={t('DeviceDetailPage.location.status')} value={t(`DeviceDetailPage.statuses.${(STATUS_META[device.status] || STATUS_META.unknown).labelKey}`)} />
                    <DetailRow label={t('DeviceDetailPage.location.managed')} value={device.is_managed ? t('DeviceDetailPage.common.yes') : t('DeviceDetailPage.common.no')} />
                    <DetailRow label={t('DeviceDetailPage.location.active')} value={device.is_active ? t('DeviceDetailPage.common.yes') : t('DeviceDetailPage.common.no')} />
                    <DetailRow label={t('DeviceDetailPage.location.location')} value={device.location} />
                    <DetailRow label={t('DeviceDetailPage.location.floor')} value={device.floor} />
                    <DetailRow label={t('DeviceDetailPage.location.room')} value={device.room} />
                    <DetailRow label={t('DeviceDetailPage.location.lastSeen')} value={device.last_seen ? `${formatRelative(device.last_seen, t)} · ${formatDate(device.last_seen)}` : null} />
                    <DetailRow label={t('DeviceDetailPage.location.notes')} value={device.notes} />
                  </dl>
                </CardContent>
              </Card>
            </div>
          </TabsContent>


          {/* ── Network Tab ── */}
          <TabsContent value="network">
            <div className="grid gap-6 lg:grid-cols-2">
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">{t('DeviceDetailPage.networkConfig.title')}</CardTitle>
                </CardHeader>
                <CardContent>
                  <dl>
                    <DetailRow label={t('DeviceDetailPage.networkConfig.ipAddress')} value={device.ip_address} mono copyable />
                    <DetailRow label={t('DeviceDetailPage.networkConfig.macAddress')} value={device.mac_address} mono copyable />
                    <DetailRow label={t('DeviceDetailPage.networkConfig.connectionType')} value={device.connection_type?.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())} />
                    <DetailRow label={t('DeviceDetailPage.networkConfig.vlanId')} value={device.vlan_id} mono />
                    <DetailRow label={t('DeviceDetailPage.networkConfig.controllerId')} value={device.controller_id} mono copyable />
                    <DetailRow label={t('DeviceDetailPage.networkConfig.siteId')} value={device.site_id} mono copyable />
                    <DetailRow label={t('DeviceDetailPage.networkConfig.externalId')} value={device.external_id} mono copyable />
                  </dl>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">{t('DeviceDetailPage.portSummary.title')}</CardTitle>
                </CardHeader>
                <CardContent>
                  {device.port_count > 0 ? (
                    <div className="space-y-4">
                      <div className="flex items-center gap-4">
                        <div className="flex-1">
                          <div className="flex justify-between text-sm mb-1">
                            <span className="text-muted-foreground">{t('DeviceDetailPage.portSummary.utilization')}</span>
                            <span className="font-mono tabular-nums font-medium">{portUsagePct}%</span>
                          </div>
                          <Progress value={portUsagePct ?? 0} className="h-2" />
                        </div>
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4 text-center">
                        <div>
                          <p className="text-2xl font-bold tabular-nums">{device.port_count}</p>
                          <p className="text-xs text-muted-foreground">{t('DeviceDetailPage.portSummary.total')}</p>
                        </div>
                        <div>
                          <p className="text-2xl font-bold tabular-nums text-emerald-600 dark:text-emerald-400">{device.active_port_count}</p>
                          <p className="text-xs text-muted-foreground">{t('DeviceDetailPage.portSummary.active')}</p>
                        </div>
                        <div>
                          <p className="text-2xl font-bold tabular-nums text-muted-foreground">{device.port_count - device.active_port_count}</p>
                          <p className="text-xs text-muted-foreground">{t('DeviceDetailPage.portSummary.unused')}</p>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="text-center py-8 text-muted-foreground">
                      <Cable className="h-8 w-8 mx-auto mb-2 opacity-30" />
                      <p className="text-sm">{t('DeviceDetailPage.portSummary.noData')}</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>


          {/* ── Ports Tab (only when port_count > 0) ── */}
          {device.port_count > 0 && (
            <TabsContent value="ports">
              <Card>
                <CardHeader>
                  <CardTitle>{t('DeviceDetailPage.portManagement.title')}</CardTitle>
                  <CardDescription>
                    {t('DeviceDetailPage.portManagement.description', {
                      active: device.active_port_count,
                      total: device.port_count,
                      pct: portUsagePct,
                    })}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {/* Visual port grid */}
                  <div className="p-4 rounded-lg bg-muted/50 mb-4">
                    <div className="flex flex-wrap gap-1.5">
                      {Array.from({ length: device.port_count }, (_, i) => {
                        const isActive = i < device.active_port_count;
                        return (
                          <Tooltip key={i}>
                            <TooltipTrigger asChild>
                              <div className={cn(
                                'flex h-8 w-8 items-center justify-center rounded text-xs font-medium transition-colors',
                                isActive ? 'bg-emerald-500 text-white' : 'bg-muted text-muted-foreground',
                              )}>
                                {i + 1}
                              </div>
                            </TooltipTrigger>
                            <TooltipContent>
                              <p className="text-xs">{t('DeviceDetailPage.portManagement.portTooltip', {
                                n: i + 1,
                                state: isActive ? t('DeviceDetailPage.portManagement.active') : t('DeviceDetailPage.portManagement.inactive'),
                              })}</p>
                            </TooltipContent>
                          </Tooltip>
                        );
                      })}
                    </div>
                    <div className="flex items-center gap-4 mt-3 text-xs text-muted-foreground">
                      <span className="flex items-center gap-1.5">
                        <div className="h-3 w-3 rounded bg-emerald-500" /> {t('DeviceDetailPage.portManagement.active')}
                      </span>
                      <span className="flex items-center gap-1.5">
                        <div className="h-3 w-3 rounded bg-muted" /> {t('DeviceDetailPage.portManagement.inactive')}
                      </span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          )}


          {/* ── System Tab ── */}
          <TabsContent value="system">
            <div className="grid gap-6 lg:grid-cols-2">
              {/* Health Gauges */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">{t('DeviceDetailPage.systemHealth.title')}</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center justify-around py-4">
                    <GaugeRing value={device.cpu_usage_percent} label={t('DeviceDetailPage.systemHealth.cpu')} size={96} />
                    <GaugeRing value={device.memory_usage_percent} label={t('DeviceDetailPage.systemHealth.memory')} size={96} />
                  </div>
                  <Separator className="my-4" />
                  <div className="grid grid-cols-2 gap-4 text-center">
                    <div>
                      <p className="text-lg font-bold tabular-nums">{formatUptime(device.uptime_seconds, t)}</p>
                      <p className="text-xs text-muted-foreground">{t('DeviceDetailPage.systemHealth.uptime')}</p>
                    </div>
                    <div>
                      <p className="text-lg font-bold tabular-nums">{device.client_count}</p>
                      <p className="text-xs text-muted-foreground">{t('DeviceDetailPage.systemHealth.connectedClients')}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Timestamps & Metadata */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">{t('DeviceDetailPage.metadata.title')}</CardTitle>
                </CardHeader>
                <CardContent>
                  <dl>
                    <DetailRow label={t('DeviceDetailPage.metadata.deviceId')} value={device.id} mono copyable />
                    <DetailRow label={t('DeviceDetailPage.metadata.created')} value={formatDate(device.created_at)} />
                    <DetailRow label={t('DeviceDetailPage.metadata.lastUpdated')} value={formatDate(device.updated_at)} />
                    <DetailRow label={t('DeviceDetailPage.metadata.lastSeen')} value={formatDate(device.last_seen)} />
                    <DetailRow label={t('DeviceDetailPage.metadata.connectionType')} value={device.connection_type} />
                    <DetailRow label={t('DeviceDetailPage.metadata.vlan')} value={device.vlan_id} mono />
                  </dl>
                  {Object.keys(device.capabilities ?? {}).length > 0 && (
                    <>
                      <Separator className="my-4" />
                      <h4 className="text-sm font-medium mb-2">{t('DeviceDetailPage.metadata.capabilities')}</h4>
                      <div className="flex flex-wrap gap-1.5">
                        {Object.keys(device.capabilities ?? {}).map(cap => (
                          <Badge key={cap} variant="secondary" className="text-xs">
                            {cap.replace(/_/g, ' ')}
                          </Badge>
                        ))}
                      </div>
                    </>
                  )}
                  {Object.keys(device.metadata ?? {}).length > 0 && (
                    <>
                      <Separator className="my-4" />
                      <h4 className="text-sm font-medium mb-2">{t('DeviceDetailPage.metadata.metadataHeading')}</h4>
                      <pre className="text-xs bg-muted p-3 rounded-md overflow-auto max-h-48 font-mono">
                        {JSON.stringify(device.metadata, null, 2)}
                      </pre>
                    </>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </div>

      {/* ──── Assign / change credential dialog ──── */}
      <Dialog open={credDialogOpen} onOpenChange={setCredDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {device.credential_id ? t('DeviceDetailPage.credDialog.titleChange') : t('DeviceDetailPage.credDialog.titleAssign')}
            </DialogTitle>
            <DialogDescription>
              {t('DeviceDetailPage.credDialog.description', { name: device.name })}
            </DialogDescription>
          </DialogHeader>
          <div className="py-2">
            <Select value={selectedCredId} onValueChange={setSelectedCredId}>
              <SelectTrigger>
                <SelectValue placeholder={t('DeviceDetailPage.credDialog.selectPlaceholder')} />
              </SelectTrigger>
              <SelectContent>
                {credentials.map((c: any) => (
                  <SelectItem key={c.id} value={c.id}>
                    {c.name}
                    {c.username ? ` (${c.username})` : ''}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {credentials.length === 0 && (
              <p className="mt-2 text-xs text-muted-foreground">
                {t('DeviceDetailPage.credDialog.noCredentials')}
              </p>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCredDialogOpen(false)}>
              {t('DeviceDetailPage.credDialog.cancel')}
            </Button>
            <Button
              onClick={() => assignCredMutation.mutate()}
              disabled={assignCredMutation.isPending || !selectedCredId}
            >
              {assignCredMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <KeyRound className="mr-2 h-4 w-4" />
              )}
              {t('DeviceDetailPage.credDialog.save')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ──── Edit device dialog ──── */}
      <Dialog open={editDialogOpen} onOpenChange={setEditDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('DeviceDetailPage.menu.editDevice')}</DialogTitle>
            <DialogDescription>{device.name}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <Label htmlFor="edit-device-name">{t('DeviceDetailPage.identity.name')}</Label>
              <Input
                id="edit-device-name"
                value={editForm.name}
                onChange={(e) => setEditForm((f) => ({ ...f, name: e.target.value }))}
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="edit-device-floor">{t('DeviceDetailPage.location.floor')}</Label>
                <Input
                  id="edit-device-floor"
                  value={editForm.floor}
                  onChange={(e) => setEditForm((f) => ({ ...f, floor: e.target.value }))}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="edit-device-room">{t('DeviceDetailPage.location.room')}</Label>
                <Input
                  id="edit-device-room"
                  value={editForm.room}
                  onChange={(e) => setEditForm((f) => ({ ...f, room: e.target.value }))}
                />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="edit-device-location">{t('DeviceDetailPage.location.location')}</Label>
              <Input
                id="edit-device-location"
                value={editForm.location}
                onChange={(e) => setEditForm((f) => ({ ...f, location: e.target.value }))}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="edit-device-notes">{t('DeviceDetailPage.location.notes')}</Label>
              <Textarea
                id="edit-device-notes"
                rows={3}
                value={editForm.notes}
                onChange={(e) => setEditForm((f) => ({ ...f, notes: e.target.value }))}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditDialogOpen(false)}>
              {t('common:cancel')}
            </Button>
            <Button
              onClick={() => editMutation.mutate()}
              disabled={editMutation.isPending || !editForm.name.trim()}
            >
              {editMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Edit className="mr-2 h-4 w-4" />
              )}
              {t('common:save')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ──── Remove device confirmation ──── */}
      <AlertDialog open={removeDialogOpen} onOpenChange={setRemoveDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('DeviceDetailPage.menu.removeDevice')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('actions.forgetConfirm')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={removeMutation.isPending}>
              {t('common:cancel')}
            </AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive hover:bg-destructive/90 text-destructive-foreground"
              disabled={removeMutation.isPending}
              onClick={(e) => {
                e.preventDefault();
                removeMutation.mutate();
              }}
            >
              {removeMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {t('common:delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </TooltipProvider>
  );
}
