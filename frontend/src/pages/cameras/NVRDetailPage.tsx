// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * NVR Detail / Status Page  ·  Deep NVR Integration
 *
 * Tabs:
 *  1. Overview   · device info, CPU/memory, firmware, timestamps
 *  2. Channels   · thumbnail grid + table with live status & capabilities
 *  3. Storage    · real-time HDD utilisation with per-disk breakdown
 *  4. Network    · NIC configuration, DNS, NTP/time settings
 *  5. Playback   · recording search + timeline by channel & date range
 *  6. Settings   · edit name / port / credentials, reboot, delete
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState, useMemo, useRef, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeft,
  Camera,
  Clock,
  Cpu,
  Database,
  Globe,
  HardDrive,
  Hash,
  Info,
  Key,
  Layers,
  Loader2,
  MoreHorizontal,
  Network,
  Play,
  Power,
  RefreshCw,
  Search,
  Server,
  Settings,
  Shield,
  Trash2,
  Video,
  VideoOff,
  Wifi,
  WifiOff,
  Zap,
  AlertTriangle,
  Activity,
  Calendar,
  Eye,
  EyeOff,
  FileVideo,
  MonitorSmartphone,
  Thermometer,
  CheckCircle2,
  XCircle,
  Timer,
  CalendarDays,
  Save,
  Download,
  Plus,
  X,
  Link2,
  ExternalLink,
  Pause,
  SkipBack,
  SkipForward,
  Rewind,
  FastForward,
  ChevronDown,
} from 'lucide-react';
import { PageHeader } from '@/components/layout';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { EmptyState, ErrorState, InlineErrorBanner } from '@/components/ui/empty-state';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import { StatsGrid } from '@/components/ui/stats-grid';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
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
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { camerasApi, nvrApi, getApiErrorMessage } from '@/lib/api';
import type { HolidayEntry } from '@/lib/api/types';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { RecordedHlsPlayer } from '@/components/cameras/RecordedHlsPlayer';
import { RecordingTimeline } from '@/components/cameras/RecordingTimeline';
import { RecordingCalendar } from '@/components/cameras/RecordingCalendar';
import { VendorCapabilityNote } from '@/components/cameras/VendorCapabilityNote';
import { toCsv, downloadCsv } from '@/lib/csv';

const VALID_NVR_TABS = new Set(['overview', 'channels', 'storage', 'network', 'playback', 'ch-status', 'holidays']);

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

interface NVRData {
  id: string;
  name: string;
  description?: string;
  ip_address: string;
  port: number;
  mac_address?: string;
  vendor?: string;
  model?: string;
  firmware_version?: string;
  serial_number?: string;
  device_type: string;
  channel_count: number;
  storage_total_gb?: number;
  storage_used_gb?: number;
  status: string;
  last_seen?: string;
  last_synced_at?: string;
  external_device_id?: string;
  created_at?: string;
  updated_at?: string;
  // Backend returns a boolean 'configured' flag here, never the key string.
  stream_encryption_key?: boolean;
  settings?: Record<string, any>;
}

interface ChannelData {
  id: string;
  name: string;
  channel_id?: number;
  ip_address: string;
  status: string;
  camera_type?: string;
  has_ptz?: boolean;
  has_audio?: boolean;
  model?: string;
  vendor?: string;
  is_recording?: boolean;
}

interface StorageData {
  total_gb: number;
  used_gb: number;
  free_gb: number;
  percent_used: number;
  disk_count: number;
  healthy_count: number;
  unhealthy_count: number;
  disks: DiskData[];
}

interface SMARTAttribute {
  id: number;
  name: string;
  current: number;
  worst: number;
  threshold: number;
  raw_value: string;
  status: string;
}

interface DiskData {
  id?: number;
  name?: string;
  capacity_mb?: number;
  free_mb?: number;
  status?: string;
  hdd_type?: string;
  property?: string;
  // Extended info
  model?: string;
  serial_number?: string;
  firmware?: string;
  capacity_bytes?: number;
  // SMART health
  smart_status?: string;
  temperature_c?: number;
  power_on_hours?: number;
  smart_self_test_percent?: number;
  smart_attributes?: SMARTAttribute[];
}

interface SystemInfo {
  device: Record<string, string>;
  system_status: Record<string, any>;
  time: Record<string, any>;
  network_interfaces: NetworkInterface[];
  storage: StorageData;
  recording_tracks: RecordingTrack[];
}

interface NetworkInterface {
  id?: string;
  ip_address?: string;
  subnet_mask?: string;
  gateway?: string;
  primary_dns?: string;
  secondary_dns?: string;
  mac_address?: string;
  mtu?: number;
  speed?: string;
  duplex?: string;
  addressing_type?: string;
  auto_negotiate?: boolean;
  ipv6_address?: string;
}

interface RecordingTrack {
  id?: string;
  channel?: number;
  track_type?: string;
  enabled?: boolean;
  description?: string;
  codec?: string;
  loop_enable?: boolean;
  src_url?: string;
}

interface RecordingSegment {
  source_id?: string;
  track_id?: string;
  start_time?: string;
  end_time?: string;
  playback_uri?: string;
  content_type?: string;
  codec?: string;
  recording_type?: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

function fmtStorage(gb: number): string {
  if (gb >= 1024) return `${(gb / 1024).toFixed(1)} TB`;
  if (gb >= 1) return `${Math.round(gb)} GB`;
  return `${Math.round(gb * 1024)} MB`;
}

function fmtStorageMB(mb: number): string {
  if (mb >= 1024 * 1024) return `${(mb / (1024 * 1024)).toFixed(1)} TB`;
  if (mb >= 1024) return `${(mb / 1024).toFixed(1)} GB`;
  return `${Math.round(mb)} MB`;
}

function fmtPowerOnHours(hours: number): string {
  if (hours >= 8760) {
    const years = (hours / 8760).toFixed(1);
    return `${years}y (${hours.toLocaleString()}h)`;
  }
  if (hours >= 720) {
    const months = Math.round(hours / 720);
    return `~${months}mo (${hours.toLocaleString()}h)`;
  }
  if (hours >= 24) {
    const days = Math.round(hours / 24);
    return `${days}d (${hours.toLocaleString()}h)`;
  }
  return `${hours}h`;
}

function smartStatusBadge(status?: string | null): { variant: 'outline'; className: string; kind: 'unknown' | 'healthy' | 'warning' | 'critical' } {
  if (!status) return { variant: 'outline', className: 'bg-muted/50 text-muted-foreground border-muted', kind: 'unknown' };
  const s = status.toLowerCase();
  if (['ok', 'good', 'normal', 'passed'].includes(s))
    return { variant: 'outline', className: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20', kind: 'healthy' };
  if (['warning', 'marginal'].includes(s))
    return { variant: 'outline', className: 'bg-amber-500/10 text-amber-500 border-amber-500/20', kind: 'warning' };
  return { variant: 'outline', className: 'bg-red-500/10 text-red-500 border-red-500/20', kind: 'critical' };
}

function tempColor(c: number | null | undefined): string {
  if (c == null) return 'text-muted-foreground';
  if (c <= 40) return 'text-emerald-500';
  if (c <= 50) return 'text-amber-500';
  return 'text-red-500';
}

function fmtDate(iso?: string): string {
  if (!iso) return '-';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

// Slug for CSV filenames: lowercase, ASCII-ish, dashed.
function slugify(s: string): string {
  return (s || 'nvr')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'nvr';
}

function fmtTimeAgo(iso: string | undefined, t: (key: string, opts?: Record<string, unknown>) => string): string {
  if (!iso) return t('NVRDetailPage.timeAgo.never');
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return t('NVRDetailPage.timeAgo.justNow');
  if (mins < 60) return t('NVRDetailPage.timeAgo.minutes', { n: mins });
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return t('NVRDetailPage.timeAgo.hours', { n: hrs });
  return t('NVRDetailPage.timeAgo.days', { n: Math.floor(hrs / 24) });
}

function StatusBadge({ status }: { status: string }) {
  const { t } = useTranslation('cameras');
  const map: Record<string, { label: string; cls: string }> = {
    online: { label: t('NVRDetailPage.status.online'), cls: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' },
    offline: { label: t('NVRDetailPage.status.offline'), cls: 'bg-red-500/10 text-red-500 border-red-500/20' },
    recording: { label: t('NVRDetailPage.status.recording'), cls: 'bg-blue-500/10 text-blue-500 border-blue-500/20' },
    rebooting: { label: t('NVRDetailPage.status.rebooting'), cls: 'bg-amber-500/10 text-amber-500 border-amber-500/20' },
    error: { label: t('NVRDetailPage.status.error'), cls: 'bg-red-500/10 text-red-500 border-red-500/20' },
    unknown: { label: t('NVRDetailPage.status.unknown'), cls: 'bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20' },
  };
  const c = map[status] ?? map.unknown;
  return <Badge variant="outline" className={cn('text-[11px]', c.cls)}>{c.label}</Badge>;
}

function InfoRow({ icon: Icon, label, value, mono }: {
  icon: typeof Info; label: string; value: React.ReactNode; mono?: boolean;
}) {
  return (
    <div className="flex items-center gap-3 py-2">
      <Icon className="h-4 w-4 text-muted-foreground shrink-0" />
      <span className="text-sm text-muted-foreground w-36 shrink-0">{label}</span>
      <span className={cn('text-sm font-medium truncate', mono && 'font-mono text-xs')}>
        {value || '-'}
      </span>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Channel Thumbnail (lazy-loaded snapshot)
// ═══════════════════════════════════════════════════════════════════════════════

function ChannelThumb({ cameraId, name, status }: { cameraId: string; name: string; status: string }) {
  const imgRef = useRef<HTMLImageElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [loaded, setLoaded] = useState(false);
  const isOnline = status === 'online' || status === 'recording';

  // Helper: fetch a short-lived snapshot URL and assign it to the <img>
  const loadSnapshot = useCallback(async () => {
    if (!imgRef.current) return;
    try {
      const url = `${await camerasApi.getSnapshotUrlAsync(cameraId)}&_t=${Date.now()}`;
      if (imgRef.current) imgRef.current.src = url;
    } catch {
      // Stream token fetch failed · clear image (error state)
      if (imgRef.current) imgRef.current.src = '';
    }
  }, [cameraId]);

  useEffect(() => {
    if (!isOnline || !containerRef.current) return;
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting) loadSnapshot();
    }, { threshold: 0.1 });
    observer.observe(containerRef.current);

    const iv = setInterval(() => {
      if (imgRef.current && containerRef.current) {
        const r = containerRef.current.getBoundingClientRect();
        if (r.top < window.innerHeight && r.bottom > 0) loadSnapshot();
      }
    }, 20_000);
    return () => { observer.disconnect(); clearInterval(iv); };
  }, [cameraId, isOnline, loadSnapshot]);

  if (!isOnline) {
    return (
      <div ref={containerRef} className="aspect-video bg-muted/50 rounded flex items-center justify-center">
        <VideoOff className="h-6 w-6 text-muted-foreground/30" />
      </div>
    );
  }
  return (
    <div ref={containerRef} className="aspect-video bg-black rounded overflow-hidden relative">
      <img ref={imgRef} alt={name} className="w-full h-full object-contain" onLoad={() => setLoaded(true)} onError={() => setLoaded(false)} />
      {!loaded && (
        <div className="absolute inset-0 flex items-center justify-center bg-muted/50">
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main Page Component
// ═══════════════════════════════════════════════════════════════════════════════

export default function NVRDetailPage() {
  const { t } = useTranslation('cameras');
  const { id, tab } = useParams<{ id: string; tab?: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { toast } = useToast();

  // ── Path-based tab state ──
  const activeTab = tab && VALID_NVR_TABS.has(tab) ? tab : 'overview';
  const setActiveTab = useCallback((value: string) => {
    navigate(value === 'overview' ? `/cameras/nvrs/${id}` : `/cameras/nvrs/${id}/${value}`, { replace: true });
  }, [id, navigate]);

  const [showSettings, setShowSettings] = useState(false);
  const [confirmReboot, setConfirmReboot] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [showAllTracks, setShowAllTracks] = useState(false);
  // Channel preselected from the Channels tab's "Open playback" action.
  const [playbackChannelId, setPlaybackChannelId] = useState<string | null>(null);
  // Selected channel rows (for bulk CSV export).
  const [selectedChannelIds, setSelectedChannelIds] = useState<Set<string>>(new Set());

  // Switch to the Playback tab with a given channel preselected.
  const openPlaybackForChannel = useCallback((cameraId: string) => {
    setPlaybackChannelId(cameraId);
    setActiveTab('playback');
  }, [setActiveTab]);

  const toggleChannelSelection = useCallback((chId: string) => {
    setSelectedChannelIds(prev => {
      const next = new Set(prev);
      if (next.has(chId)) next.delete(chId); else next.add(chId);
      return next;
    });
  }, []);

  // Copy a short-lived snapshot URL for a channel to the clipboard.
  const copySnapshotUrl = useCallback(async (cameraId: string) => {
    try {
      const url = await camerasApi.getSnapshotUrlAsync(cameraId);
      await navigator.clipboard.writeText(url);
      toast({ title: t('NVRDetailPage.channels.snapshotUrlCopied') });
    } catch (err: unknown) {
      toast({ title: getApiErrorMessage(err, t('NVRDetailPage.channels.snapshotUrlFailed')), variant: 'destructive' as any });
    }
  }, [t, toast]);

  // ── Core Data ──

  const { data: nvrRes, isLoading, isError } = useQuery({
    queryKey: ['nvr-detail', id],
    queryFn: () => nvrApi.getById(id!),
    enabled: !!id,
    refetchInterval: 30_000,
  });

  const nvr: NVRData | null = nvrRes?.data ?? null;
  const isOnline = nvr?.status === 'online';

  const {
    data: channelsRes,
    isLoading: channelsLoading,
    isError: channelsError,
    refetch: refetchChannels,
  } = useQuery({
    queryKey: ['nvr-channels', id],
    queryFn: () => nvrApi.getChannels(id!),
    enabled: !!id,
    refetchInterval: 30_000,
  });
  const channels: ChannelData[] = useMemo(() => channelsRes?.data?.items ?? [], [channelsRes?.data?.items]);
  // A finished fetch with zero items is a genuine empty state; an error must not
  // be masked as "No channels".
  const channelsFetched = !!channelsRes && !channelsError;

  const { data: storageRes, refetch: refetchStorage, isLoading: storageLoading, isError: storageError } = useQuery({
    queryKey: ['nvr-storage', id],
    queryFn: () => nvrApi.getStorage(id!),
    enabled: !!id && isOnline,
    staleTime: 60_000,
  });
  const storage: StorageData | null = storageRes?.data ?? null;

  const { data: sysInfoRes, isLoading: _sysInfoLoading, isError: sysInfoError, refetch: refetchSysInfo } = useQuery({
    queryKey: ['nvr-sysinfo', id],
    queryFn: () => nvrApi.getSystemInfo(id!),
    enabled: !!id && isOnline,
    staleTime: 120_000,
  });
  const sysInfo: SystemInfo | null = sysInfoRes?.data?.data ?? null;

  const { data: networkRes, isLoading: networkLoading, isError: networkError, refetch: refetchNetwork } = useQuery({
    queryKey: ['nvr-network', id],
    queryFn: () => nvrApi.getNetwork(id!),
    enabled: !!id && isOnline && activeTab === 'network',
    staleTime: 120_000,
  });
  const netData = networkRes?.data?.data ?? null;

  const { data: recStatusRes } = useQuery({
    queryKey: ['nvr-rec-status', id],
    queryFn: () => nvrApi.getRecordingStatus(id!),
    enabled: !!id && isOnline && activeTab === 'overview',
    staleTime: 60_000,
  });
  const recTracks: RecordingTrack[] = recStatusRes?.data?.data ?? [];

  // ── Live Channel Status (ISAPI) ──
  const { data: chStatusRes } = useQuery({
    queryKey: ['nvr', id, 'channel-status'],
    queryFn: () => nvrApi.getChannelStatus(id!).then(r => r.data),
    enabled: !!id && isOnline,
    refetchInterval: 15_000,
  });
  // Merge live status into DB channels. The live `ip_address` is the NVR-side
  // channel descriptor, not the camera's own IP, so it never matches a DB
  // channel, match purely on channel_id.
  const enrichedChannels = useMemo(() => {
    const liveChStatus: { id: number; name: string; online: boolean; ip_address?: string }[] = chStatusRes?.channels ?? [];
    if (liveChStatus.length === 0) return channels;
    const statusByCh = new Map(liveChStatus.map(c => [c.id, c.online]));
    return channels.map(ch => {
      const liveOnline = ch.channel_id != null ? statusByCh.get(ch.channel_id) : undefined;
      if (liveOnline === undefined) return ch;
      return { ...ch, status: liveOnline ? 'online' : 'offline' };
    });
  }, [channels, chStatusRes?.channels]);

  // ── Mutations ──

  const syncMut = useMutation({
    mutationFn: () => nvrApi.sync(id!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['nvr-detail', id] });
      qc.invalidateQueries({ queryKey: ['nvr-channels', id] });
      toast({ title: t('NVRDetailPage.toasts.syncSuccess') });
    },
    onError: () => { toast({ title: t('NVRDetailPage.toasts.syncFailed'), variant: 'destructive' as any }); },
  });

  const deleteMut = useMutation({
    mutationFn: () => nvrApi.delete(id!),
    onSuccess: () => navigate('/cameras/nvrs'),
    onError: () => { toast({ title: t('NVRDetailPage.toasts.deleteFailed'), variant: 'destructive' as any }); },
  });

  const rebootMut = useMutation({
    mutationFn: () => nvrApi.reboot(id!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['nvr-detail', id] });
      toast({ title: t('NVRDetailPage.toasts.rebootSent') });
    },
    onError: () => { toast({ title: t('NVRDetailPage.toasts.rebootFailed'), variant: 'destructive' as any }); },
  });

  // ── Stream Encryption Key ──
  // stream_encryption_key on the NVR is a boolean 'configured' flag, never the key
  // string. The editable input is always independent and starts blank.
  const [encryptionKey, setEncryptionKey] = useState('');
  const [showEncKey, setShowEncKey] = useState(false);

  const encKeyMut = useMutation({
    mutationFn: (key: string) => nvrApi.update(id!, { stream_encryption_key: key } as any),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['nvr-detail', id] });
      toast({ title: t('NVRDetailPage.toasts.encKeySaved') });
    },
    onError: () => { toast({ title: t('NVRDetailPage.toasts.encKeySaveFailed'), variant: 'destructive' as any }); },
  });

  const encKeyChanged = encryptionKey !== '';
  const encKeyConfigured = !!nvr?.stream_encryption_key;

  // ── Stats ──

  const chStats = useMemo(() => ({
    total: enrichedChannels.length,
    online: enrichedChannels.filter(c => c.status === 'online').length,
    offline: enrichedChannels.filter(c => c.status === 'offline').length,
    recording: enrichedChannels.filter(c => c.is_recording).length,
  }), [enrichedChannels]);

  const storagePct = nvr?.storage_total_gb && nvr.storage_total_gb > 0
    ? Math.round(((nvr.storage_used_gb ?? 0) / nvr.storage_total_gb) * 100)
    : null;

  // ── CSV export (channels) ──
  const exportChannelsCsv = useCallback((rows: ChannelData[]) => {
    if (rows.length === 0) return;
    downloadCsv(
      `${slugify(nvr?.name ?? 'nvr')}-channels`,
      toCsv(rows, [
        { key: 'name', header: t('NVRDetailPage.csv.name'), value: (r) => r.name },
        { key: 'channel_id', header: t('NVRDetailPage.csv.channelId'), value: (r) => r.channel_id ?? '' },
        { key: 'status', header: t('NVRDetailPage.csv.status'), value: (r) => r.status },
        { key: 'ip_address', header: t('NVRDetailPage.csv.ipAddress'), value: (r) => r.ip_address ?? '' },
        { key: 'model', header: t('NVRDetailPage.csv.model'), value: (r) => r.model ?? r.camera_type ?? '' },
        { key: 'vendor', header: t('NVRDetailPage.csv.vendor'), value: (r) => r.vendor ?? '' },
      ]),
    );
  }, [nvr?.name, t]);

  // ── CSV export (per-disk SMART attributes) ──
  const exportSmartCsv = useCallback((disk: DiskData, idx: number) => {
    const attrs = disk.smart_attributes ?? [];
    if (attrs.length === 0) return;
    const diskLabel = disk.name || disk.model || `disk-${(disk.id ?? idx) + 1}`;
    downloadCsv(
      `${slugify(nvr?.name ?? 'nvr')}-smart-${slugify(diskLabel)}`,
      toCsv(attrs, [
        { key: 'id', header: t('NVRDetailPage.csv.smartId'), value: (r) => r.id ?? '' },
        { key: 'name', header: t('NVRDetailPage.csv.smartName'), value: (r) => r.name ?? '' },
        { key: 'current', header: t('NVRDetailPage.csv.smartCurrent'), value: (r) => r.current ?? '' },
        { key: 'worst', header: t('NVRDetailPage.csv.smartWorst'), value: (r) => r.worst ?? '' },
        { key: 'threshold', header: t('NVRDetailPage.csv.smartThreshold'), value: (r) => r.threshold ?? '' },
        { key: 'raw_value', header: t('NVRDetailPage.csv.smartRaw'), value: (r) => r.raw_value ?? '' },
        { key: 'status', header: t('NVRDetailPage.csv.smartStatus'), value: (r) => r.status ?? '' },
      ]),
    );
  }, [nvr?.name, t]);

  // ── Loading / Error ──

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <Skeleton className="h-9 w-9" />
          <div className="space-y-2"><Skeleton className="h-6 w-48" /><Skeleton className="h-4 w-32" /></div>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">{[...Array(5)].map((_, i) => <Skeleton key={i} className="h-20" />)}</div>
        <Skeleton className="h-[500px]" />
      </div>
    );
  }

  if (isError || !nvr) {
    return (
      <Card className="border-destructive">
        <EmptyState
          icon={AlertTriangle}
          title={t('NVRDetailPage.notFound.title')}
          description={t('NVRDetailPage.notFound.description')}
          action={{
            label: t('NVRDetailPage.notFound.back'),
            icon: ArrowLeft,
            onClick: () => navigate('/cameras/nvrs'),
          }}
        />
      </Card>
    );
  }

  const cpuUsage = sysInfo?.system_status?.cpu_usage;
  const memUsage = sysInfo?.system_status?.memory_usage;

  return (
    <div className="space-y-6">
      {/* ── HEADER ── */}
      <PageHeader
        icon={Server}
        title={nvr.name}
        description={`${nvr.vendor ?? ''} ${nvr.model ?? ''} · ${nvr.ip_address}:${nvr.port}${nvr.firmware_version ? ` · fw ${nvr.firmware_version}` : ''}`}
        breadcrumbs={
          <Link to="/cameras/nvrs" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-3.5 w-3.5" />{t('NVRDetailPage.aria.back')}
          </Link>
        }
        actions={
          <>
            <StatusBadge status={nvr.status} />
            <Button variant="outline" size="sm" onClick={() => syncMut.mutate()} disabled={syncMut.isPending}>
              <RefreshCw className={cn('h-4 w-4 mr-2', syncMut.isPending && 'animate-spin')} />
              {syncMut.isPending ? t('NVRDetailPage.actions.syncing') : t('NVRDetailPage.actions.sync')}
            </Button>
            <Button variant="outline" size="sm" onClick={() => setShowSettings(true)}>
              <Settings className="h-4 w-4 mr-2" /> {t('NVRDetailPage.actions.settings')}
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" aria-label={t('NVRDetailPage.aria.moreActions')}><MoreHorizontal className="h-4 w-4" /></Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => refetchStorage()}>
                  <Database className="h-4 w-4 mr-2" /> {t('NVRDetailPage.menu.refreshStorage')}
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => refetchSysInfo()}>
                  <Cpu className="h-4 w-4 mr-2" /> {t('NVRDetailPage.menu.refreshSystemInfo')}
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  className="text-amber-500"
                  onClick={() => setConfirmReboot(true)}
                >
                  <Power className="h-4 w-4 mr-2" /> {t('NVRDetailPage.menu.rebootNvr')}
                </DropdownMenuItem>
                <DropdownMenuItem
                  className="text-destructive"
                  onClick={() => setConfirmDelete(true)}
                >
                  <Trash2 className="h-4 w-4 mr-2" /> {t('NVRDetailPage.menu.deleteNvr')}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </>
        }
      />

      {/* ── QUICK STATS ── */}
      <StatsGrid
        columns={4}
        stats={[
          { title: t('NVRDetailPage.stats.channels'), value: chStats.total, icon: Camera, variant: 'primary' },
          { title: t('NVRDetailPage.stats.online'), value: chStats.online, icon: Wifi, variant: 'success' },
          { title: t('NVRDetailPage.stats.offline'), value: chStats.offline, icon: WifiOff, variant: 'destructive' },
          { title: t('NVRDetailPage.stats.recording'), value: chStats.recording, icon: Video, variant: 'info' },
          { title: t('NVRDetailPage.stats.cpu'), value: cpuUsage != null ? `${cpuUsage}%` : '-', icon: Cpu, variant: 'primary' },
          { title: t('NVRDetailPage.stats.storage'), value: storagePct != null ? `${storagePct}%` : '-', icon: Database, variant: 'warning' },
        ]}
      />

      {/* ── TABS ── */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview">{t('NVRDetailPage.tabs.overview')}</TabsTrigger>
          <TabsTrigger value="channels">{t('NVRDetailPage.tabs.channels', { n: chStats.total })}</TabsTrigger>
          <TabsTrigger value="storage">{t('NVRDetailPage.tabs.storage')}</TabsTrigger>
          <TabsTrigger value="network">{t('NVRDetailPage.tabs.network')}</TabsTrigger>
          <TabsTrigger value="playback">{t('NVRDetailPage.tabs.playback')}</TabsTrigger>
          <TabsTrigger value="ch-status">{t('NVRDetailPage.tabs.channelStatus')}</TabsTrigger>
          <TabsTrigger value="holidays">{t('NVRDetailPage.tabs.holidays')}</TabsTrigger>
        </TabsList>

        {/* ════════════ OVERVIEW TAB ════════════ */}
        <TabsContent value="overview" className="space-y-6 mt-4">
          {/* Live system-info fetch failed, explains the missing CPU/Mem/clock cards */}
          {isOnline && sysInfoError && (
            <InlineErrorBanner onRetry={() => refetchSysInfo()}>
              {t('NVRDetailPage.overview.sysInfoError')}
            </InlineErrorBanner>
          )}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Device Information */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-base flex items-center gap-2"><Info className="h-4 w-4" /> {t('NVRDetailPage.deviceInfo.title')}</CardTitle>
              </CardHeader>
              <CardContent className="divide-y">
                <InfoRow icon={Server} label={t('NVRDetailPage.deviceInfo.name')} value={nvr.name} />
                <InfoRow icon={Globe} label={t('NVRDetailPage.deviceInfo.ipAddress')} value={`${nvr.ip_address}:${nvr.port}`} mono />
                <InfoRow icon={Cpu} label={t('NVRDetailPage.deviceInfo.model')} value={nvr.model} />
                <InfoRow icon={Shield} label={t('NVRDetailPage.deviceInfo.vendor')} value={nvr.vendor} />
                <InfoRow icon={Zap} label={t('NVRDetailPage.deviceInfo.firmware')} value={nvr.firmware_version} />
                <InfoRow icon={Hash} label={t('NVRDetailPage.deviceInfo.serialNumber')} value={nvr.serial_number} mono />
                <InfoRow icon={Layers} label={t('NVRDetailPage.deviceInfo.macAddress')} value={nvr.mac_address} mono />
                <InfoRow icon={Camera} label={t('NVRDetailPage.deviceInfo.channelCapacity')} value={nvr.channel_count} />
                <InfoRow icon={Activity} label={t('NVRDetailPage.deviceInfo.deviceType')} value={nvr.device_type} />
                {nvr.external_device_id && <InfoRow icon={Key} label={t('NVRDetailPage.deviceInfo.deviceId')} value={nvr.external_device_id} mono />}
              </CardContent>
            </Card>

            {/* Status & System Health */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-base flex items-center gap-2"><Activity className="h-4 w-4" /> {t('NVRDetailPage.health.title')}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="divide-y">
                  <InfoRow icon={Wifi} label={t('NVRDetailPage.health.status')} value={<StatusBadge status={nvr.status} />} />
                  <InfoRow icon={Clock} label={t('NVRDetailPage.health.lastSeen')} value={
                    <span>{fmtDate(nvr.last_seen)} <span className="text-muted-foreground text-xs">({fmtTimeAgo(nvr.last_seen, t)})</span></span>
                  } />
                  <InfoRow icon={RefreshCw} label={t('NVRDetailPage.health.lastSynced')} value={fmtDate(nvr.last_synced_at)} />
                  <InfoRow icon={Clock} label={t('NVRDetailPage.health.created')} value={fmtDate(nvr.created_at)} />
                </div>

                {/* CPU & Memory gauges */}
                {(cpuUsage != null || memUsage != null) && (
                  <>
                    <Separator />
                    <div className="grid grid-cols-2 gap-4">
                      {cpuUsage != null && (
                        <div className="space-y-1.5">
                          <div className="flex items-center justify-between text-sm">
                            <span className="text-muted-foreground">{t('NVRDetailPage.health.cpu')}</span>
                            <span className="font-medium">{cpuUsage}%</span>
                          </div>
                          <Progress value={cpuUsage} className={cn('h-2',
                            cpuUsage > 90 ? '[&>div]:bg-red-500' : cpuUsage > 70 ? '[&>div]:bg-amber-500' : '[&>div]:bg-emerald-500')} />
                        </div>
                      )}
                      {memUsage != null && (
                        <div className="space-y-1.5">
                          <div className="flex items-center justify-between text-sm">
                            <span className="text-muted-foreground">{t('NVRDetailPage.health.memory')}</span>
                            <span className="font-medium">{memUsage}%</span>
                          </div>
                          <Progress value={memUsage} className={cn('h-2',
                            memUsage > 90 ? '[&>div]:bg-red-500' : memUsage > 70 ? '[&>div]:bg-amber-500' : '[&>div]:bg-emerald-500')} />
                        </div>
                      )}
                    </div>
                  </>
                )}

                {/* Storage summary */}
                <Separator />
                <div className="space-y-2">
                  <p className="text-sm font-medium">{t('NVRDetailPage.health.storage')}</p>
                  {storagePct != null ? (
                    <div className="space-y-2">
                      <div className="flex justify-between text-xs">
                        <span>{t('NVRDetailPage.storage.usedValue', { value: fmtStorage(nvr.storage_used_gb ?? 0) })}</span>
                        <span className="text-muted-foreground">{t('NVRDetailPage.storage.freeValue', { value: fmtStorage((nvr.storage_total_gb ?? 0) - (nvr.storage_used_gb ?? 0)) })}</span>
                      </div>
                      <Progress value={storagePct} className={cn('h-2.5',
                        storagePct > 90 ? '[&>div]:bg-red-500' : storagePct > 75 ? '[&>div]:bg-amber-500' : '[&>div]:bg-emerald-500')} />
                      <p className="text-[11px] text-muted-foreground text-center">
                        {t('NVRDetailPage.storage.pctOfTotal', { pct: storagePct, total: fmtStorage(nvr.storage_total_gb ?? 0) })}
                      </p>
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground">{t('NVRDetailPage.storage.notAvailable')}</p>
                  )}
                </div>

                {/* NVR Time */}
                {sysInfo?.time?.device_time && (
                  <>
                    <Separator />
                    <div className="space-y-1">
                      <InfoRow icon={Clock} label={t('NVRDetailPage.time.nvrClock')} value={fmtDate(sysInfo.time.device_time)} />
                      <InfoRow icon={Timer} label={t('NVRDetailPage.time.timeMode')} value={sysInfo.time.time_mode || t('NVRDetailPage.time.manual')} />
                      {sysInfo.time.ntp_server && <InfoRow icon={Globe} label={t('NVRDetailPage.time.ntpServer')} value={sysInfo.time.ntp_server} mono />}
                    </div>
                  </>
                )}

                {/* Extended device info from ISAPI */}
                {sysInfo?.device && (
                  <>
                    <Separator />
                    <div className="space-y-1">
                      {sysInfo.device.hardwareVersion && <InfoRow icon={Cpu} label={t('NVRDetailPage.deviceInfo.hardwareVer')} value={sysInfo.device.hardwareVersion} />}
                      {sysInfo.device.encoderVersion && <InfoRow icon={MonitorSmartphone} label={t('NVRDetailPage.deviceInfo.encoderVer')} value={sysInfo.device.encoderVersion} />}
                      {sysInfo.device.firmwareDate && <InfoRow icon={Calendar} label={t('NVRDetailPage.deviceInfo.firmwareDate')} value={sysInfo.device.firmwareDate} />}
                    </div>
                  </>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Recording Tracks Summary */}
          {recTracks.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-base flex items-center gap-2">
                  <FileVideo className="h-4 w-4" /> {t('NVRDetailPage.tracks.title', { n: recTracks.length })}
                </CardTitle>
              </CardHeader>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('NVRDetailPage.tracks.trackId')}</TableHead>
                    <TableHead>{t('NVRDetailPage.tracks.channel')}</TableHead>
                    <TableHead>{t('NVRDetailPage.tracks.type')}</TableHead>
                    <TableHead>{t('NVRDetailPage.tracks.enabled')}</TableHead>
                    <TableHead>{t('NVRDetailPage.tracks.loop')}</TableHead>
                    <TableHead>{t('NVRDetailPage.tracks.description')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(showAllTracks ? recTracks : recTracks.slice(0, 20)).map((tr, i) => (
                    <TableRow key={tr.id ?? i}>
                      <TableCell className="font-mono text-xs">{tr.id ?? '-'}</TableCell>
                      <TableCell>{tr.channel ?? '-'}</TableCell>
                      <TableCell className="text-muted-foreground text-xs">{tr.track_type ?? '-'}</TableCell>
                      <TableCell>
                        {tr.enabled ? (
                          <Badge variant="outline" className="text-[10px] bg-emerald-500/10 text-emerald-500 border-emerald-500/20">{t('NVRDetailPage.common.yes')}</Badge>
                        ) : (
                          <Badge variant="outline" className="text-[10px] bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20">{t('NVRDetailPage.common.no')}</Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-xs">{tr.loop_enable ? t('NVRDetailPage.common.yes') : t('NVRDetailPage.common.no')}</TableCell>
                      <TableCell className="text-xs text-muted-foreground truncate max-w-[200px]">{tr.description ?? '-'}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {recTracks.length > 20 && (
                <div className="flex items-center justify-between px-4 py-3 border-t">
                  <p className="text-xs text-muted-foreground">
                    {t('NVRDetailPage.tracks.showingCount', { shown: showAllTracks ? recTracks.length : 20, total: recTracks.length })}
                  </p>
                  <Button variant="ghost" size="sm" onClick={() => setShowAllTracks(v => !v)}>
                    {showAllTracks ? t('NVRDetailPage.tracks.showLess') : t('NVRDetailPage.tracks.showAll')}
                  </Button>
                </div>
              )}
            </Card>
          )}

          {/* Stream Encryption Key (Hikvision NVRs) */}
          {nvr.device_type?.toLowerCase().includes('hikvision') || nvr.vendor?.toLowerCase().includes('hikvision') ? (
            <Card>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Shield className="h-4 w-4" /> {t('NVRDetailPage.encryption.title')}
                    {encKeyConfigured && (
                      <Badge variant="outline" className="text-[10px] bg-emerald-500/10 text-emerald-500 border-emerald-500/20 ml-2">{t('NVRDetailPage.encryption.configured')}</Badge>
                    )}
                  </CardTitle>
                </div>
                <CardDescription>
                  {t('NVRDetailPage.encryption.description')}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <form onSubmit={e => e.preventDefault()}>
                  <div className="flex gap-2">
                    <div className="relative flex-1">
                      <Input
                        type={showEncKey ? 'text' : 'password'}
                        value={encryptionKey}
                        onChange={e => setEncryptionKey(e.target.value)}
                        placeholder={t('NVRDetailPage.encryption.placeholder')}
                        className="pr-10 font-mono text-sm"
                        maxLength={64}
                        autoComplete="off"
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        aria-label={showEncKey ? t('NVRDetailPage.aria.hideKey') : t('NVRDetailPage.aria.showKey')}
                        className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7 p-0"
                        onClick={() => setShowEncKey(!showEncKey)}
                      >
                        {showEncKey ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                      </Button>
                    </div>
                    <Button
                      type="button"
                      size="sm"
                      disabled={!encKeyChanged || encKeyMut.isPending}
                      onClick={() => encKeyMut.mutate(encryptionKey)}
                    >
                      {encKeyMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : t('NVRDetailPage.encryption.saveKey')}
                    </Button>
                    {encKeyConfigured && (
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        disabled={encKeyMut.isPending}
                        onClick={() => { setEncryptionKey(''); encKeyMut.mutate(''); }}
                      >
                        {t('NVRDetailPage.encryption.remove')}
                      </Button>
                    )}
                  </div>
                </form>
                {encKeyMut.isError && !encKeyMut.isPending && (
                  <p className="text-xs text-destructive">{t('NVRDetailPage.encryption.saveError')}</p>
                )}
              </CardContent>
            </Card>
          ) : null}
        </TabsContent>
        <TabsContent value="channels" className="space-y-4 mt-4">
          {channelsLoading ? (
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
              {Array.from({ length: 8 }).map((_, i) => (
                <Card key={i}>
                  <Skeleton className="aspect-video rounded-none" />
                  <CardContent noOffset className="p-2.5 space-y-2">
                    <Skeleton className="h-4 w-3/4" />
                    <Skeleton className="h-3 w-1/2" />
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : channelsError ? (
            <Card>
              <ErrorState message={t('NVRDetailPage.channels.loadError')} onRetry={() => refetchChannels()} />
            </Card>
          ) : enrichedChannels.length === 0 ? (
            <Card>
              <EmptyState
                variant="card"
                icon={Camera}
                title={t('NVRDetailPage.channels.emptyTitle')}
                description={t('NVRDetailPage.channels.empty')}
                action={channelsFetched ? {
                  label: t('NVRDetailPage.channels.syncNow'),
                  icon: RefreshCw,
                  onClick: () => syncMut.mutate(),
                } : undefined}
              />
            </Card>
          ) : (
            <>
              {/* Toolbar: bulk-selection bar + CSV export */}
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="min-h-[2rem] flex items-center">
                  {selectedChannelIds.size > 0 ? (
                    <div className="flex items-center gap-2 rounded-md border bg-muted/40 px-3 py-1.5">
                      <span className="text-sm font-medium">
                        {t('NVRDetailPage.channels.selectedCount', { n: selectedChannelIds.size })}
                      </span>
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-7"
                        onClick={() => exportChannelsCsv(enrichedChannels.filter(c => selectedChannelIds.has(c.id)))}
                      >
                        <Download className="h-3.5 w-3.5 mr-1.5" /> {t('NVRDetailPage.channels.exportSelected')}
                      </Button>
                      <Button variant="ghost" size="sm" className="h-7" onClick={() => setSelectedChannelIds(new Set())}>
                        <X className="h-3.5 w-3.5 mr-1.5" /> {t('NVRDetailPage.channels.clearSelection')}
                      </Button>
                    </div>
                  ) : (
                    <span className="text-xs text-muted-foreground">{t('NVRDetailPage.channels.selectHint')}</span>
                  )}
                </div>
                <Button variant="outline" size="sm" onClick={() => exportChannelsCsv(enrichedChannels)}>
                  <Download className="h-4 w-4 mr-2" /> {t('NVRDetailPage.channels.exportCsv')}
                </Button>
              </div>

              {/* Thumbnail Grid */}
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                {enrichedChannels.map(ch => (
                  <Card key={ch.id} className="cursor-pointer hover:border-primary/40 transition-colors overflow-hidden focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    role="button"
                    tabIndex={0}
                    aria-label={t('NVRDetailPage.aria.openChannel', { name: ch.name })}
                    onClick={() => navigate(`/cameras/${ch.id}`)}
                    onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); navigate(`/cameras/${ch.id}`); } }}>
                    <ChannelThumb cameraId={ch.id} name={ch.name} status={ch.status} />
                    <CardContent noOffset className="p-2.5">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium truncate">{ch.name}</span>
                        <StatusBadge status={ch.status} />
                      </div>
                      <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
                        {ch.channel_id != null && <span>{t('NVRDetailPage.channels.chShort', { n: ch.channel_id })}</span>}
                        {ch.ip_address && <span className="font-mono">{ch.ip_address}</span>}
                        {ch.has_ptz && <Badge variant="secondary" className="text-[9px] px-1 py-0">PTZ</Badge>}
                        {ch.has_audio && <Badge variant="secondary" className="text-[9px] px-1 py-0">{t('NVRDetailPage.channels.audio')}</Badge>}
                        {ch.is_recording && (
                          <Badge variant="outline" className="text-[9px] px-1 py-0 bg-red-500/10 text-red-500 border-red-500/20 gap-0.5">
                            <span className="h-1.5 w-1.5 rounded-full bg-red-500 animate-pulse" /> {t('NVRDetailPage.channels.rec')}
                          </Badge>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>

              {/* Detailed Table */}
              <Card>
                <CardHeader className="pb-2 flex-row items-center justify-between space-y-0">
                  <CardTitle className="text-base">{t('NVRDetailPage.channels.detailsTitle')}</CardTitle>
                  <Button variant="outline" size="sm" onClick={() => exportChannelsCsv(enrichedChannels)}>
                    <Download className="h-4 w-4 mr-2" /> {t('NVRDetailPage.channels.exportCsv')}
                  </Button>
                </CardHeader>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-10">
                        <input
                          type="checkbox"
                          className="h-4 w-4 rounded border-input accent-primary align-middle"
                          aria-label={t('NVRDetailPage.channels.selectAllAria')}
                          checked={enrichedChannels.length > 0 && selectedChannelIds.size === enrichedChannels.length}
                          ref={el => { if (el) el.indeterminate = selectedChannelIds.size > 0 && selectedChannelIds.size < enrichedChannels.length; }}
                          onChange={e => {
                            e.stopPropagation();
                            setSelectedChannelIds(e.target.checked ? new Set(enrichedChannels.map(c => c.id)) : new Set());
                          }}
                        />
                      </TableHead>
                      <TableHead className="w-16">{t('NVRDetailPage.channels.chHeader')}</TableHead>
                      <TableHead>{t('NVRDetailPage.channels.name')}</TableHead>
                      <TableHead>{t('NVRDetailPage.channels.status')}</TableHead>
                      <TableHead>{t('NVRDetailPage.channels.ipAddress')}</TableHead>
                      <TableHead>{t('NVRDetailPage.channels.model')}</TableHead>
                      <TableHead>{t('NVRDetailPage.channels.capabilities')}</TableHead>
                      <TableHead>{t('NVRDetailPage.channels.recording')}</TableHead>
                      <TableHead className="w-10 text-right">{t('NVRDetailPage.channels.actions')}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {enrichedChannels.map(ch => (
                      <TableRow key={ch.id} className="cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset"
                        role="button"
                        tabIndex={0}
                        aria-label={t('NVRDetailPage.aria.openChannel', { name: ch.name })}
                        onClick={() => navigate(`/cameras/${ch.id}`)}
                        onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); navigate(`/cameras/${ch.id}`); } }}>
                        <TableCell onClick={e => e.stopPropagation()}>
                          <input
                            type="checkbox"
                            className="h-4 w-4 rounded border-input accent-primary align-middle"
                            aria-label={t('NVRDetailPage.channels.selectRowAria', { name: ch.name })}
                            checked={selectedChannelIds.has(ch.id)}
                            onChange={() => toggleChannelSelection(ch.id)}
                          />
                        </TableCell>
                        <TableCell className="font-mono text-sm">{ch.channel_id ?? '-'}</TableCell>
                        <TableCell className="font-medium">{ch.name}</TableCell>
                        <TableCell><StatusBadge status={ch.status} /></TableCell>
                        <TableCell className="font-mono text-xs">{ch.ip_address}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">{ch.model || ch.camera_type || '-'}</TableCell>
                        <TableCell>
                          <div className="flex gap-1">
                            {ch.has_ptz && <Badge variant="secondary" className="text-[10px] px-1 py-0">PTZ</Badge>}
                            {ch.has_audio && <Badge variant="secondary" className="text-[10px] px-1 py-0">{t('NVRDetailPage.channels.audio')}</Badge>}
                            {!ch.has_ptz && !ch.has_audio && <span className="text-xs text-muted-foreground">-</span>}
                          </div>
                        </TableCell>
                        <TableCell>
                          {ch.is_recording ? (
                            <Badge variant="outline" className="text-[10px] bg-red-500/10 text-red-500 border-red-500/20 gap-1">
                              <span className="h-1.5 w-1.5 rounded-full bg-red-500 animate-pulse" /> {t('NVRDetailPage.channels.rec')}
                            </Badge>
                          ) : <span className="text-xs text-muted-foreground">-</span>}
                        </TableCell>
                        <TableCell className="text-right" onClick={e => e.stopPropagation()}>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-7 w-7"
                                aria-label={t('NVRDetailPage.channels.rowActionsAria', { name: ch.name })}
                                onClick={e => e.stopPropagation()}
                              >
                                <MoreHorizontal className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => navigate(`/cameras/${ch.id}/stream`)}>
                                <Video className="h-4 w-4 mr-2" /> {t('NVRDetailPage.channels.actionViewLive')}
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => openPlaybackForChannel(ch.id)}>
                                <Play className="h-4 w-4 mr-2" /> {t('NVRDetailPage.channels.actionOpenPlayback')}
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => copySnapshotUrl(ch.id)}>
                                <Link2 className="h-4 w-4 mr-2" /> {t('NVRDetailPage.channels.actionCopySnapshot')}
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem onClick={() => navigate(`/cameras/${ch.id}`)}>
                                <ExternalLink className="h-4 w-4 mr-2" /> {t('NVRDetailPage.channels.actionOpenDetail')}
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </Card>
            </>
          )}
        </TabsContent>

        {/* ════════════ STORAGE TAB ════════════ */}
        <TabsContent value="storage" className="space-y-4 mt-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-semibold">{t('NVRDetailPage.storage.realtimeTitle')}</h3>
              {storage && (
                <p className="text-xs text-muted-foreground mt-0.5">
                  {t('NVRDetailPage.storage.disksDetected', { n: storage.disk_count || storage.disks?.length || 0 })}
                  {storage.unhealthy_count > 0 && (
                    <span className="text-red-500 font-medium ml-2">
                      {t('NVRDetailPage.storage.disksNeedAttention', { n: storage.unhealthy_count })}
                    </span>
                  )}
                </p>
              )}
            </div>
            <Button variant="outline" size="sm" onClick={() => refetchStorage()} disabled={storageLoading}>
              <RefreshCw className={cn('h-4 w-4 mr-2', storageLoading && 'animate-spin')} /> {t('NVRDetailPage.storage.refresh')}
            </Button>
          </div>

          {/* Live storage fetch failed, explain why the cached numbers below may be stale */}
          {isOnline && storageError && (
            <InlineErrorBanner onRetry={() => refetchStorage()}>
              {t('NVRDetailPage.storage.liveError')}
            </InlineErrorBanner>
          )}

          {/* Overall utilisation + health summary cards */}
          {storage ? (
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
              {/* Total capacity */}
              <Card>
                <CardContent noOffset className="p-4">
                  <div className="flex items-center gap-2 text-muted-foreground mb-1">
                    <Database className="h-4 w-4" />
                    <span className="text-xs font-medium uppercase tracking-wide">{t('NVRDetailPage.storage.totalCapacity')}</span>
                  </div>
                  <p className="text-2xl font-bold">{fmtStorage(storage.total_gb)}</p>
                </CardContent>
              </Card>
              {/* Used */}
              <Card>
                <CardContent noOffset className="p-4">
                  <div className="flex items-center gap-2 text-muted-foreground mb-1">
                    <HardDrive className="h-4 w-4" />
                    <span className="text-xs font-medium uppercase tracking-wide">{t('NVRDetailPage.storage.used')}</span>
                  </div>
                  <p className="text-2xl font-bold">{fmtStorage(storage.used_gb)}</p>
                  <p className="text-xs text-muted-foreground">{t('NVRDetailPage.storage.pctUtilised', { pct: storage.percent_used })}</p>
                </CardContent>
              </Card>
              {/* Free */}
              <Card>
                <CardContent noOffset className="p-4">
                  <div className="flex items-center gap-2 text-muted-foreground mb-1">
                    <Database className="h-4 w-4" />
                    <span className="text-xs font-medium uppercase tracking-wide">{t('NVRDetailPage.storage.free')}</span>
                  </div>
                  <p className="text-2xl font-bold">{fmtStorage(storage.free_gb)}</p>
                  <p className="text-xs text-muted-foreground">{t('NVRDetailPage.storage.pctAvailable', { pct: (100 - storage.percent_used).toFixed(1) })}</p>
                </CardContent>
              </Card>
              {/* Health */}
              <Card>
                <CardContent noOffset className="p-4">
                  <div className="flex items-center gap-2 text-muted-foreground mb-1">
                    <Shield className="h-4 w-4" />
                    <span className="text-xs font-medium uppercase tracking-wide">{t('NVRDetailPage.storage.diskHealth')}</span>
                  </div>
                  {storage.unhealthy_count > 0 ? (
                    <>
                      <p className="text-2xl font-bold text-red-500">{t('NVRDetailPage.storage.issues', { n: storage.unhealthy_count })}</p>
                      <p className="text-xs text-red-400">{t('NVRDetailPage.storage.attentionRequired')}</p>
                    </>
                  ) : (
                    <>
                      <p className="text-2xl font-bold text-emerald-500">{t('NVRDetailPage.storage.allGood')}</p>
                      <p className="text-xs text-muted-foreground">{t('NVRDetailPage.storage.disksHealthy', { n: storage.healthy_count || storage.disks?.length || 0 })}</p>
                    </>
                  )}
                </CardContent>
              </Card>
            </div>
          ) : null}

          {/* Overall progress bar */}
          <Card>
            <CardContent noOffset className="p-6">
              {storage ? (
                <div className="space-y-4">
                  <div className="flex justify-between text-sm">
                    <span className="font-medium">{t('NVRDetailPage.storage.usedValue', { value: fmtStorage(storage.used_gb) })}</span>
                    <span className="text-muted-foreground">{t('NVRDetailPage.storage.freeOfTotal', { free: fmtStorage(storage.free_gb), total: fmtStorage(storage.total_gb) })}</span>
                  </div>
                  <Progress value={storage.percent_used} className={cn('h-4',
                    storage.percent_used > 90 ? '[&>div]:bg-red-500' : storage.percent_used > 75 ? '[&>div]:bg-amber-500' : '[&>div]:bg-emerald-500')} />
                  <p className="text-sm text-muted-foreground text-center">
                    {t('NVRDetailPage.storage.utilisationRemaining', { pct: storage.percent_used, remaining: fmtStorage(storage.free_gb) })}
                  </p>
                </div>
              ) : storagePct != null ? (
                <div className="space-y-3">
                  <div className="flex justify-between text-sm">
                    <span>{t('NVRDetailPage.storage.usedCached', { value: fmtStorage(nvr.storage_used_gb ?? 0) })}</span>
                    <span className="text-muted-foreground">{t('NVRDetailPage.storage.totalValue', { value: fmtStorage(nvr.storage_total_gb ?? 0) })}</span>
                  </div>
                  <Progress value={storagePct} className="h-4" />
                  <p className="text-xs text-muted-foreground text-center">{t('NVRDetailPage.storage.cachedNote')}</p>
                </div>
              ) : (
                <div className="text-center py-6">
                  <Database className="h-10 w-10 text-muted-foreground/30 mx-auto mb-3" />
                  <p className="text-sm text-muted-foreground">{t('NVRDetailPage.storage.unavailableOffline')}</p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Storage Forecast (estimate) */}
          {storage && storage.total_gb > 0 && (
            <Card>
              <CardContent noOffset className="p-6">
                <div className="flex items-center gap-2 mb-1">
                  <Activity className="h-4 w-4 text-muted-foreground" />
                  <h4 className="text-sm font-semibold">{t('NVRDetailPage.forecast.title')}</h4>
                  <Badge variant="outline" className="text-[10px] bg-muted/50 text-muted-foreground border-muted ml-1">
                    {t('NVRDetailPage.forecast.estimateBadge')}
                  </Badge>
                </div>
                <p className="text-[11px] text-muted-foreground mb-3">{t('NVRDetailPage.forecast.estimateDisclaimer')}</p>
                {(() => {
                  const freeGb = storage.free_gb;
                  const usedGb = storage.used_gb;
                  const totalGb = storage.total_gb;
                  // Use utilization-based estimate: if storage is X% full, estimate
                  // daily rate from used percentage vs total capacity.
                  // Falls back to capacity/30 when usage is very low (<5%).
                  const usePct = totalGb > 0 ? usedGb / totalGb : 0;
                  const dailyRateGb = usePct > 0.05
                    ? usedGb / Math.max(1, Math.round(usePct * 30))
                    : totalGb > 0 ? totalGb / 30 : 0;
                  const daysRemaining = dailyRateGb > 0 ? Math.floor(freeGb / dailyRateGb) : Infinity;
                  // This figure is a single-snapshot extrapolation, not a measured
                  // trend, so one noisy reading must NOT trip a hard red CRITICAL on
                  // its own. Only escalate to critical styling when the volume is
                  // ALSO genuinely near-full (corroborating signal), otherwise a low
                  // estimate is shown as a soft amber "watch" note.
                  const lowEstimate = daysRemaining < 7;
                  const nearFull = storage.percent_used >= 90;
                  const isCritical = lowEstimate && nearFull;
                  const isWatch = (lowEstimate && !nearFull) || (daysRemaining >= 7 && daysRemaining <= 30);

                  return (
                    <div className="space-y-3">
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <p className="text-xs text-muted-foreground">{t('NVRDetailPage.forecast.dailyRateLabel')}</p>
                          <p className="text-lg font-bold">{t('NVRDetailPage.forecast.dailyRateValue', { value: dailyRateGb.toFixed(1) })}</p>
                        </div>
                        <div>
                          <p className="text-xs text-muted-foreground">{t('NVRDetailPage.forecast.daysRemainingLabel')}</p>
                          <p className={cn(
                            'text-lg font-bold',
                            isCritical && 'text-red-500',
                            !isCritical && isWatch && 'text-amber-500',
                            !isCritical && !isWatch && 'text-emerald-500',
                          )}>
                            {daysRemaining === Infinity ? '-' : t('NVRDetailPage.forecast.daysRemainingValueEstimate', { n: daysRemaining })}
                          </p>
                        </div>
                      </div>
                      {isCritical && (
                        <div className="flex items-start gap-2 rounded-md bg-red-500/10 border border-red-500/20 px-3 py-2">
                          <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5 flex-shrink-0" />
                          <div className="text-xs">
                            <p className="font-medium text-red-500">{t('NVRDetailPage.forecast.criticalTitle')}</p>
                            <p className="text-muted-foreground">{t('NVRDetailPage.forecast.criticalBody', { pct: storage.percent_used })}</p>
                          </div>
                        </div>
                      )}
                      {!isCritical && isWatch && (
                        <div className="flex items-start gap-2 rounded-md bg-amber-500/10 border border-amber-500/20 px-3 py-2">
                          <AlertTriangle className="h-4 w-4 text-amber-500 mt-0.5 flex-shrink-0" />
                          <p className="text-xs text-amber-500">{t('NVRDetailPage.forecast.watchBody')}</p>
                        </div>
                      )}
                    </div>
                  );
                })()}
              </CardContent>
            </Card>
          )}

          {/* Per-disk detail cards */}
          {storage && storage.disks?.length > 0 && (
            <div className="space-y-4">
              <h4 className="text-sm font-semibold flex items-center gap-2">
                <HardDrive className="h-4 w-4" /> {t('NVRDetailPage.disks.title', { n: storage.disks.length })}
              </h4>

              {storage.disks.map((disk, i) => {
                const totalMB = disk.capacity_mb ?? 0;
                const freeMB = disk.free_mb ?? 0;
                const usedMB = totalMB - freeMB;
                const pct = totalMB > 0 ? Math.round((usedMB / totalMB) * 100) : null;
                const smartBadge = smartStatusBadge(disk.smart_status);
                const hasExtended = disk.model || disk.serial_number || disk.firmware;
                const hasSmart = disk.smart_status || disk.temperature_c != null || disk.power_on_hours != null;

                return (
                  <Card key={disk.id ?? i} className="overflow-hidden">
                    {/* Disk header */}
                    <CardHeader className="pb-3">
                      <div className="flex items-start justify-between">
                        <div className="flex items-center gap-3">
                          <div className={cn('p-2 rounded-lg',
                            disk.status === 'ok' || disk.status === 'normal'
                              ? 'bg-emerald-500/10' : 'bg-amber-500/10')}>
                            <HardDrive className={cn('h-5 w-5',
                              disk.status === 'ok' || disk.status === 'normal'
                                ? 'text-emerald-500' : 'text-amber-500')} />
                          </div>
                          <div>
                            <CardTitle className="text-base">
                              {disk.name || t('NVRDetailPage.disks.diskN', { n: (disk.id ?? i) + 1 })}
                              {disk.model && <span className="text-sm font-normal text-muted-foreground ml-2">({disk.model})</span>}
                            </CardTitle>
                            <CardDescription className="text-xs mt-0.5">
                              {[
                                disk.hdd_type && t('NVRDetailPage.disks.typePrefix', { value: disk.hdd_type }),
                                disk.property && t('NVRDetailPage.disks.propertyPrefix', { value: disk.property }),
                                disk.serial_number && t('NVRDetailPage.disks.snPrefix', { value: disk.serial_number }),
                              ].filter(Boolean).join(' · ') || t('NVRDetailPage.disks.hddN', { n: (disk.id ?? i) + 1 })}
                            </CardDescription>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          {/* HDD status badge */}
                          <Badge variant="outline" className={cn('text-[10px]',
                            disk.status === 'ok' || disk.status === 'normal'
                              ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'
                              : 'bg-amber-500/10 text-amber-500 border-amber-500/20'
                          )}>{disk.status ?? t('NVRDetailPage.disks.statusUnknown')}</Badge>
                          {/* SMART badge */}
                          {hasSmart && (
                            <Badge variant={smartBadge.variant} className={cn('text-[10px] gap-1', smartBadge.className)}>
                              {smartBadge.kind === 'healthy'
                                ? <CheckCircle2 className="h-3 w-3" />
                                : smartBadge.kind === 'critical'
                                  ? <XCircle className="h-3 w-3" />
                                  : <AlertTriangle className="h-3 w-3" />}
                              {t('NVRDetailPage.disks.smartLabel', { status: t(`NVRDetailPage.smart.${smartBadge.kind}`) })}
                            </Badge>
                          )}
                        </div>
                      </div>
                    </CardHeader>

                    <CardContent className="pb-4 space-y-4">
                      {/* Capacity bar */}
                      {pct != null && (
                        <div className="space-y-2">
                          <div className="flex justify-between text-sm">
                            <span>{t('NVRDetailPage.storage.usedValue', { value: fmtStorageMB(usedMB) })}</span>
                            <span className="text-muted-foreground">{t('NVRDetailPage.storage.freeOfTotal', { free: fmtStorageMB(freeMB), total: fmtStorageMB(totalMB) })}</span>
                          </div>
                          <Progress value={pct} className={cn('h-3',
                            pct > 90 ? '[&>div]:bg-red-500' : pct > 75 ? '[&>div]:bg-amber-500' : '[&>div]:bg-emerald-500')} />
                          <p className="text-xs text-muted-foreground text-center">{t('NVRDetailPage.storage.pctUtilised', { pct })}</p>
                        </div>
                      )}

                      {/* Info grid · Extended + SMART metrics */}
                      {(hasExtended || hasSmart) && (
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-2">
                          {/* Temperature */}
                          {disk.temperature_c != null && (
                            <div className="flex items-center gap-2 rounded-md border p-2.5">
                              <Thermometer className={cn('h-4 w-4', tempColor(disk.temperature_c))} />
                              <div>
                                <p className="text-[10px] uppercase tracking-wide text-muted-foreground">{t('NVRDetailPage.disks.temperature')}</p>
                                <p className={cn('text-sm font-semibold', tempColor(disk.temperature_c))}>
                                  {disk.temperature_c}°C
                                </p>
                              </div>
                            </div>
                          )}

                          {/* Power-on hours */}
                          {disk.power_on_hours != null && (
                            <div className="flex items-center gap-2 rounded-md border p-2.5">
                              <Clock className="h-4 w-4 text-muted-foreground" />
                              <div>
                                <p className="text-[10px] uppercase tracking-wide text-muted-foreground">{t('NVRDetailPage.disks.powerOnTime')}</p>
                                <p className="text-sm font-semibold">{fmtPowerOnHours(disk.power_on_hours)}</p>
                              </div>
                            </div>
                          )}

                          {/* Model */}
                          {disk.model && (
                            <div className="flex items-center gap-2 rounded-md border p-2.5">
                              <HardDrive className="h-4 w-4 text-muted-foreground" />
                              <div>
                                <p className="text-[10px] uppercase tracking-wide text-muted-foreground">{t('NVRDetailPage.disks.model')}</p>
                                <p className="text-sm font-medium truncate max-w-[160px]" title={disk.model}>{disk.model}</p>
                              </div>
                            </div>
                          )}

                          {/* Serial */}
                          {disk.serial_number && (
                            <div className="flex items-center gap-2 rounded-md border p-2.5">
                              <Hash className="h-4 w-4 text-muted-foreground" />
                              <div>
                                <p className="text-[10px] uppercase tracking-wide text-muted-foreground">{t('NVRDetailPage.disks.serialNumber')}</p>
                                <p className="text-sm font-mono truncate max-w-[160px]" title={disk.serial_number}>{disk.serial_number}</p>
                              </div>
                            </div>
                          )}

                          {/* Firmware */}
                          {disk.firmware && (
                            <div className="flex items-center gap-2 rounded-md border p-2.5">
                              <Zap className="h-4 w-4 text-muted-foreground" />
                              <div>
                                <p className="text-[10px] uppercase tracking-wide text-muted-foreground">{t('NVRDetailPage.disks.firmware')}</p>
                                <p className="text-sm font-mono">{disk.firmware}</p>
                              </div>
                            </div>
                          )}

                          {/* HDD Type */}
                          {disk.hdd_type && (
                            <div className="flex items-center gap-2 rounded-md border p-2.5">
                              <Layers className="h-4 w-4 text-muted-foreground" />
                              <div>
                                <p className="text-[10px] uppercase tracking-wide text-muted-foreground">{t('NVRDetailPage.disks.diskType')}</p>
                                <p className="text-sm font-medium">{disk.hdd_type}</p>
                              </div>
                            </div>
                          )}

                          {/* Property (R/W, Redundant, etc.) */}
                          {disk.property && (
                            <div className="flex items-center gap-2 rounded-md border p-2.5">
                              <Settings className="h-4 w-4 text-muted-foreground" />
                              <div>
                                <p className="text-[10px] uppercase tracking-wide text-muted-foreground">{t('NVRDetailPage.disks.property')}</p>
                                <p className="text-sm font-medium">{disk.property}</p>
                              </div>
                            </div>
                          )}

                          {/* SMART self-test progress */}
                          {disk.smart_self_test_percent != null && disk.smart_self_test_percent > 0 && disk.smart_self_test_percent < 100 && (
                            <div className="flex items-center gap-2 rounded-md border p-2.5">
                              <Activity className="h-4 w-4 text-blue-500" />
                              <div>
                                <p className="text-[10px] uppercase tracking-wide text-muted-foreground">{t('NVRDetailPage.disks.smartTest')}</p>
                                <p className="text-sm font-semibold text-blue-500">{t('NVRDetailPage.disks.smartTestProgress', { pct: disk.smart_self_test_percent })}</p>
                              </div>
                            </div>
                          )}
                        </div>
                      )}

                      {/* S.M.A.R.T. Attributes table */}
                      {disk.smart_attributes && disk.smart_attributes.length > 0 && (
                        <div className="pt-2">
                          <div className="flex items-center justify-between mb-2">
                            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
                              {t('NVRDetailPage.smartTable.title', { n: disk.smart_attributes.length })}
                            </p>
                            <Button variant="outline" size="sm" className="h-7 text-xs" onClick={() => exportSmartCsv(disk, i)}>
                              <Download className="h-3.5 w-3.5 mr-1.5" /> {t('NVRDetailPage.smartTable.exportCsv')}
                            </Button>
                          </div>
                          <div className="rounded-md border overflow-hidden">
                            <Table>
                              <TableHeader>
                                <TableRow className="bg-muted/50">
                                  <TableHead className="text-[10px] py-1.5">{t('NVRDetailPage.smartTable.id')}</TableHead>
                                  <TableHead className="text-[10px] py-1.5">{t('NVRDetailPage.smartTable.attribute')}</TableHead>
                                  <TableHead className="text-[10px] py-1.5 text-right">{t('NVRDetailPage.smartTable.current')}</TableHead>
                                  <TableHead className="text-[10px] py-1.5 text-right">{t('NVRDetailPage.smartTable.worst')}</TableHead>
                                  <TableHead className="text-[10px] py-1.5 text-right">{t('NVRDetailPage.smartTable.threshold')}</TableHead>
                                  <TableHead className="text-[10px] py-1.5 text-right">{t('NVRDetailPage.smartTable.raw')}</TableHead>
                                  <TableHead className="text-[10px] py-1.5">{t('NVRDetailPage.smartTable.status')}</TableHead>
                                </TableRow>
                              </TableHeader>
                              <TableBody>
                                {disk.smart_attributes.map((attr, ai) => {
                                  const failing = attr.threshold > 0 && attr.current > 0 && attr.current <= attr.threshold;
                                  return (
                                    <TableRow key={attr.id || ai} className={cn(failing && 'bg-red-500/5')}>
                                      <TableCell className="font-mono text-[10px] py-1">{attr.id || '-'}</TableCell>
                                      <TableCell className="text-[11px] py-1 font-medium">{attr.name || '-'}</TableCell>
                                      <TableCell className={cn('font-mono text-[10px] py-1 text-right', failing && 'text-red-500 font-bold')}>
                                        {attr.current || '-'}
                                      </TableCell>
                                      <TableCell className="font-mono text-[10px] py-1 text-right">{attr.worst || '-'}</TableCell>
                                      <TableCell className="font-mono text-[10px] py-1 text-right">{attr.threshold || '-'}</TableCell>
                                      <TableCell className="font-mono text-[10px] py-1 text-right">{attr.raw_value || '-'}</TableCell>
                                      <TableCell className="py-1">
                                        {attr.status ? (
                                          // Color strictly by the computed failing flag (current <= threshold).
                                          // 'pre-fail' / 'old-age' are SMART attribute TYPES, not failures, so
                                          // they render neutral unless the value actually breaches threshold.
                                          <Badge variant="outline" className={cn('text-[9px] px-1 py-0',
                                            failing
                                              ? 'bg-red-500/10 text-red-500 border-red-500/20'
                                              : 'bg-muted text-muted-foreground border-muted'
                                          )}>{attr.status}</Badge>
                                        ) : '-'}
                                      </TableCell>
                                    </TableRow>
                                  );
                                })}
                              </TableBody>
                            </Table>
                          </div>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>

        {/* ════════════ NETWORK TAB ════════════ */}
        <TabsContent value="network" className="space-y-4 mt-4">
          {!isOnline ? (
            <Card>
              <CardContent noOffset className="p-8 text-center">
                <Network className="h-10 w-10 text-muted-foreground/30 mx-auto mb-3" />
                <p className="text-sm text-muted-foreground">{t('NVRDetailPage.network.offline')}</p>
              </CardContent>
            </Card>
          ) : networkLoading ? (
            <Card>
              <CardContent noOffset className="p-8 text-center">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground mx-auto mb-3" />
                <p className="text-sm text-muted-foreground">{t('NVRDetailPage.network.loading')}</p>
              </CardContent>
            </Card>
          ) : networkError ? (
            <Card>
              <ErrorState message={t('NVRDetailPage.network.loadError')} onRetry={() => refetchNetwork()} />
            </Card>
          ) : !netData ? (
            <Card>
              <CardContent noOffset className="p-8 text-center">
                <Network className="h-10 w-10 text-muted-foreground/30 mx-auto mb-3" />
                <p className="text-sm text-muted-foreground">{t('NVRDetailPage.network.empty')}</p>
              </CardContent>
            </Card>
          ) : (
            <>
              {/* Time / NTP */}
              {netData.time && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base flex items-center gap-2"><Clock className="h-4 w-4" /> {t('NVRDetailPage.network.timeNtpTitle')}</CardTitle>
                  </CardHeader>
                  <CardContent className="divide-y">
                    <InfoRow icon={Clock} label={t('NVRDetailPage.network.deviceTime')} value={fmtDate(netData.time.device_time)} />
                    <InfoRow icon={Timer} label={t('NVRDetailPage.network.timeMode')} value={netData.time.time_mode || t('NVRDetailPage.time.manual')} />
                    <InfoRow icon={Globe} label={t('NVRDetailPage.network.timeZone')} value={netData.time.time_zone} />
                    {netData.time.ntp_server && <InfoRow icon={Globe} label={t('NVRDetailPage.network.ntpServer')} value={netData.time.ntp_server} mono />}
                    {netData.time.ntp_port && <InfoRow icon={Hash} label={t('NVRDetailPage.network.ntpPort')} value={netData.time.ntp_port} />}
                  </CardContent>
                </Card>
              )}

              {/* Network Interfaces */}
              {netData.interfaces?.length > 0 && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base flex items-center gap-2">
                      <Network className="h-4 w-4" /> {t('NVRDetailPage.network.interfacesTitle', { n: netData.interfaces.length })}
                    </CardTitle>
                  </CardHeader>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>{t('NVRDetailPage.network.interface')}</TableHead>
                        <TableHead>{t('NVRDetailPage.network.ipAddress')}</TableHead>
                        <TableHead>{t('NVRDetailPage.network.subnet')}</TableHead>
                        <TableHead>{t('NVRDetailPage.network.gateway')}</TableHead>
                        <TableHead>DNS</TableHead>
                        <TableHead>MAC</TableHead>
                        <TableHead>MTU</TableHead>
                        <TableHead>{t('NVRDetailPage.network.speed')}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {netData.interfaces.map((iface: NetworkInterface, idx: number) => (
                        <TableRow key={iface.id ?? idx}>
                          <TableCell className="font-medium">eth{iface.id ?? idx}</TableCell>
                          <TableCell className="font-mono text-xs">{iface.ip_address || '-'}</TableCell>
                          <TableCell className="font-mono text-xs">{iface.subnet_mask || '-'}</TableCell>
                          <TableCell className="font-mono text-xs">{iface.gateway || '-'}</TableCell>
                          <TableCell className="font-mono text-xs">
                            {iface.primary_dns || '-'}
                            {iface.secondary_dns && <>, {iface.secondary_dns}</>}
                          </TableCell>
                          <TableCell className="font-mono text-xs">{iface.mac_address || '-'}</TableCell>
                          <TableCell className="text-xs">{iface.mtu || '-'}</TableCell>
                          <TableCell className="text-xs">
                            {iface.speed ? `${iface.speed} ${iface.duplex ?? ''}` : iface.auto_negotiate ? t('NVRDetailPage.network.auto') : '-'}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </Card>
              )}
            </>
          )}
        </TabsContent>

        {/* ════════════ PLAYBACK TAB ════════════ */}
        <TabsContent value="playback" className="mt-4">
          <PlaybackPanel
            nvrId={id!}
            nvrName={nvr.name}
            nvrVendor={nvr.vendor}
            channels={channels}
            isOnline={isOnline}
            preselectChannelId={playbackChannelId}
            onPreselectConsumed={() => setPlaybackChannelId(null)}
          />
        </TabsContent>

        {/* ════════════ CHANNEL STATUS TAB ════════════ */}
        <TabsContent value="ch-status" className="mt-4">
          <ChannelStatusPanel nvrId={id!} />
        </TabsContent>

        {/* ════════════ HOLIDAYS TAB ════════════ */}
        <TabsContent value="holidays" className="mt-4">
          <HolidaysPanel nvrId={id!} isOnline={isOnline} active={activeTab === 'holidays'} />
        </TabsContent>
      </Tabs>

      {/* Settings Dialog */}
      <SettingsDialog open={showSettings} onOpenChange={setShowSettings} nvr={nvr} nvrId={id!} />

      {/* Reboot confirmation */}
      <AlertDialog open={confirmReboot} onOpenChange={setConfirmReboot}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('NVRDetailPage.confirmReboot.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('NVRDetailPage.confirmReboot.description', { name: nvr.name })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('NVRDetailPage.confirmReboot.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-amber-500 text-white hover:bg-amber-500/90"
              onClick={() => rebootMut.mutate()}
            >
              {t('NVRDetailPage.confirmReboot.confirm')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete confirmation */}
      <AlertDialog open={confirmDelete} onOpenChange={setConfirmDelete}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('NVRDetailPage.confirmDelete.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('NVRDetailPage.confirmDelete.description', { name: nvr.name })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('NVRDetailPage.confirmDelete.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => deleteMut.mutate()}
            >
              {t('NVRDetailPage.confirmDelete.confirm')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Playback Panel
// ═══════════════════════════════════════════════════════════════════════════════

function PlaybackPanel({ nvrId, nvrName, nvrVendor, channels, isOnline, preselectChannelId, onPreselectConsumed }: {
  nvrId: string;
  nvrName: string;
  nvrVendor?: string;
  channels: ChannelData[];
  isOnline: boolean;
  preselectChannelId?: string | null;
  onPreselectConsumed?: () => void;
}) {
  const { t } = useTranslation('cameras');
  const { toast } = useToast();
  const [selectedChannel, setSelectedChannel] = useState<string>('');
  const [selectedChannelNum, setSelectedChannelNum] = useState<number>(1);
  const [startDate, setStartDate] = useState(() => {
    const d = new Date(); d.setHours(0, 0, 0, 0); return d.toISOString().slice(0, 16);
  });
  const [endDate, setEndDate] = useState(() => new Date().toISOString().slice(0, 16));
  const [hasSearched, setHasSearched] = useState(false);
  // Inline recorded player: the camera UUID + the ISO instant to play from.
  const [playerStartIso, setPlayerStartIso] = useState<string | null>(null);
  // Recorded HLS unavailable (classic NVR / non-Hikvision returns 501), fall
  // back to the copy-RTSP-URL affordance.
  const [playerUnavailable, setPlayerUnavailable] = useState<string | null>(null);

  // Set initial channel from available channels
  useEffect(() => {
    if (channels.length > 0 && !selectedChannel) {
      setSelectedChannel(channels[0].id);
      setSelectedChannelNum(channels[0].channel_id ?? 1);
    }
  }, [channels, selectedChannel]);

  // Preselect the channel requested from the Channels tab's "Open playback".
  useEffect(() => {
    if (!preselectChannelId) return;
    const ch = channels.find(c => c.id === preselectChannelId);
    if (ch) {
      setSelectedChannel(ch.id);
      setSelectedChannelNum(ch.channel_id ?? 1);
      setHasSearched(false);
      setPlayerStartIso(null);
      setPlayerUnavailable(null);
    }
    onPreselectConsumed?.();
  }, [preselectChannelId, channels, onPreselectConsumed]);

  const searchMut = useMutation({
    mutationFn: () => nvrApi.searchRecordings(nvrId, {
      channel: selectedChannelNum,
      start_time: new Date(startDate).toISOString(),
      end_time: new Date(endDate).toISOString(),
      max_results: 200,
    }),
    onSuccess: () => setHasSearched(true),
    onError: () => { toast({ title: t('NVRDetailPage.toasts.searchFailed'), variant: 'destructive' as any }); },
  });

  const recordings: RecordingSegment[] = searchMut.data?.data?.data?.recordings ?? [];
  const playbackUrl: string = searchMut.data?.data?.data?.playback_url ?? '';

  const handleChannelChange = (cameraId: string) => {
    setSelectedChannel(cameraId);
    const ch = channels.find(c => c.id === cameraId);
    setSelectedChannelNum(ch?.channel_id ?? 1);
    setHasSearched(false);
    setPlayerStartIso(null);
    setPlayerUnavailable(null);
  };

  // ── Scrubber-driven player engine (single camera) ───────────────────────
  // playhead = the timeline position; playerStartIso = the instant the smooth
  // HLS player is anchored to (re-set on play/seek/skip so it doesn't re-mount
  // on the per-second advance).
  const [playhead, setPlayhead] = useState<Date>(() => new Date(Date.now() - 60 * 60 * 1000));
  const [isPlaying, setIsPlaying] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const playheadRef = useRef(playhead);
  playheadRef.current = playhead;
  const isPlayingRef = useRef(isPlaying);
  isPlayingRef.current = isPlaying;

  // Frame-exact playhead: the player reports its real position (startTime +
  // video.currentTime) on each timeupdate; we track it while playing. No
  // wall-clock timer, the playhead is the actual frame being shown.
  const onPlayheadTime = (wallMs: number) => {
    if (!isPlayingRef.current) return;
    const clamped = Math.min(wallMs, Date.now());
    if (Math.abs(clamped - playheadRef.current.getTime()) > 250) setPlayhead(new Date(clamped));
  };

  const seekTo = (d: Date) => {
    const clamped = new Date(Math.min(d.getTime(), Date.now()));
    setPlayhead(clamped);
    setPlayerStartIso(clamped.toISOString());
    setPlayerUnavailable(null);
  };
  const skip = (seconds: number) => seekTo(new Date(playheadRef.current.getTime() + seconds * 1000));
  const togglePlay = () => {
    setIsPlaying((p) => {
      if (!p) { setPlayerStartIso(playheadRef.current.toISOString()); setPlayerUnavailable(null); }
      return !p;
    });
  };

  // Segment "Play" buttons (advanced list) seek the main player + start playing.
  const playFrom = (iso: string) => {
    seekTo(new Date(iso));
    setIsPlaying(true);
  };

  const exportRecordingsCsv = () => {
    if (recordings.length === 0) return;
    const chLabel = channels.find(c => c.id === selectedChannel)?.name ?? String(selectedChannelNum);
    downloadCsv(
      `${slugify(nvrName)}-recordings-${slugify(chLabel)}`,
      toCsv(recordings, [
        { key: 'start_time', header: t('NVRDetailPage.csv.startTime'), value: (r) => r.start_time ?? '' },
        { key: 'end_time', header: t('NVRDetailPage.csv.endTime'), value: (r) => r.end_time ?? '' },
        {
          key: 'duration', header: t('NVRDetailPage.csv.durationSeconds'), value: (r) => {
            if (!r.start_time || !r.end_time) return '';
            return Math.max(0, Math.round((new Date(r.end_time).getTime() - new Date(r.start_time).getTime()) / 1000));
          },
        },
        { key: 'recording_type', header: t('NVRDetailPage.csv.type'), value: (r) => r.recording_type ?? '' },
        { key: 'codec', header: t('NVRDetailPage.csv.codec'), value: (r) => r.codec ?? '' },
      ]),
    );
  };

  if (!isOnline) {
    return (
      <Card>
        <CardContent noOffset className="p-8 text-center">
          <Play className="h-10 w-10 text-muted-foreground/30 mx-auto mb-3" />
          <p className="text-sm text-muted-foreground">{t('NVRDetailPage.playback.offline')}</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <VendorCapabilityNote vendor={nvrVendor} feature="playback" />

      {/* ── Player: channel · video · scrubber · transport ── */}
      <Card>
        <CardContent noOffset className="p-0">
          {/* Header */}
          <div className="flex flex-wrap items-center justify-between gap-2 border-b p-3">
            <Select value={selectedChannel} onValueChange={handleChannelChange}>
              <SelectTrigger className="h-8 w-56 text-xs">
                <SelectValue placeholder={t('NVRDetailPage.playback.selectChannel')} />
              </SelectTrigger>
              <SelectContent>
                {channels.map((ch) => (
                  <SelectItem key={ch.id} value={ch.id}>
                    {ch.channel_id != null ? t('NVRDetailPage.playback.chPrefix', { n: ch.channel_id }) : ''}{ch.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <div className="flex items-center gap-2">
              <RecordingCalendar cameraId={selectedChannel || undefined} value={playhead} onPick={seekTo} />
              <Button variant="outline" size="sm" className="h-8 text-xs" onClick={() => seekTo(new Date())}>
                {t('NVRDetailPage.playback.jumpNow')}
              </Button>
            </div>
          </div>

          {/* Video */}
          <div className="relative bg-black">
            {selectedChannel ? (
              <RecordedHlsPlayer
                key={`${selectedChannel}-${playerStartIso ?? 'init'}`}
                cameraId={selectedChannel}
                startTime={playerStartIso ?? playhead.toISOString()}
                quality="low"
                durationS={600}
                paused={!isPlaying}
                className="aspect-video w-full"
                onUnavailable={(reason) => setPlayerUnavailable(reason)}
                onPlayheadTime={onPlayheadTime}
              />
            ) : (
              <div className="flex aspect-video items-center justify-center text-sm text-white/40">
                {t('NVRDetailPage.playback.selectChannelPrompt')}
              </div>
            )}
            {playerUnavailable && (
              <div className="absolute inset-x-0 bottom-0 bg-black/70 px-3 py-1.5 text-center text-xs text-white/70">
                {t('NVRDetailPage.playback.inlinePlayerUnavailable', { reason: playerUnavailable })}
              </div>
            )}
          </div>

          {/* Timeline scrubber */}
          {selectedChannel && (
            <div className="border-t p-3">
              <RecordingTimeline cameraId={selectedChannel} playbackTime={playhead} onSeek={seekTo} height={64} showControls />
            </div>
          )}

          {/* Transport, cohesive segmented cluster + live time readout */}
          <div className="flex flex-wrap items-center gap-2 border-t p-3">
            <div className="flex items-center gap-0.5 rounded-lg border bg-muted/40 p-1">
              <Button variant="ghost" size="icon" className="h-8 w-8" disabled={!selectedChannel} onClick={() => skip(-60)} title={t('NVRDetailPage.playback.back1m')}><Rewind className="h-3.5 w-3.5" /></Button>
              <Button variant="ghost" size="icon" className="h-8 w-8" disabled={!selectedChannel} onClick={() => skip(-10)} title={t('NVRDetailPage.playback.back10s')}><SkipBack className="h-3.5 w-3.5" /></Button>
              <Button variant={isPlaying ? 'default' : 'secondary'} size="icon" className="h-9 w-9 rounded-md" disabled={!selectedChannel} onClick={togglePlay}>{isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}</Button>
              <Button variant="ghost" size="icon" className="h-8 w-8" disabled={!selectedChannel} onClick={() => skip(10)} title={t('NVRDetailPage.playback.fwd10s')}><SkipForward className="h-3.5 w-3.5" /></Button>
              <Button variant="ghost" size="icon" className="h-8 w-8" disabled={!selectedChannel} onClick={() => skip(60)} title={t('NVRDetailPage.playback.fwd1m')}><FastForward className="h-3.5 w-3.5" /></Button>
            </div>
            <div className="flex items-center gap-1.5 rounded bg-muted px-2 py-1 font-mono text-xs">
              <Clock className="h-3 w-3 text-muted-foreground" />{playhead.toLocaleString()}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Advanced: recording search · segments · RTSP */}
      <button
        type="button"
        onClick={() => setShowAdvanced((s) => !s)}
        className="flex w-full items-center justify-between rounded-md border px-3 py-2 text-sm font-medium hover:bg-muted/50"
      >
        <span className="flex items-center gap-2"><Search className="h-4 w-4" /> {t('NVRDetailPage.playback.advancedTitle')}</span>
        <ChevronDown className={cn('h-4 w-4 transition-transform', showAdvanced && 'rotate-180')} />
      </button>
      {showAdvanced && (
      <div className="space-y-4">
      {/* Search Controls */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2"><Search className="h-4 w-4" /> {t('NVRDetailPage.playback.searchTitle')}</CardTitle>
          <CardDescription>{t('NVRDetailPage.playback.searchDescription')}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
            <div className="space-y-2">
              <Label className="text-xs">{t('NVRDetailPage.playback.channel')}</Label>
              <Select value={selectedChannel} onValueChange={handleChannelChange}>
                <SelectTrigger>
                  <SelectValue placeholder={t('NVRDetailPage.playback.selectChannel')} />
                </SelectTrigger>
                <SelectContent>
                  {channels.map(ch => (
                    <SelectItem key={ch.id} value={ch.id}>
                      {ch.channel_id != null ? t('NVRDetailPage.playback.chPrefix', { n: ch.channel_id }) : ''}{ch.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label className="text-xs">{t('NVRDetailPage.playback.start')}</Label>
              <Input type="datetime-local" value={startDate} onChange={e => setStartDate(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label className="text-xs">{t('NVRDetailPage.playback.end')}</Label>
              <Input type="datetime-local" value={endDate} onChange={e => setEndDate(e.target.value)} />
            </div>
            <Button onClick={() => searchMut.mutate()} disabled={searchMut.isPending || !selectedChannel}>
              {searchMut.isPending ? (
                <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> {t('NVRDetailPage.playback.searching')}</>
              ) : (
                <><Search className="h-4 w-4 mr-2" /> {t('NVRDetailPage.playback.search')}</>
              )}
            </Button>
          </div>
          {/* Inline-player quick start: play recorded video from the chosen start time. */}
          {selectedChannel && (
            <div className="mt-3 flex items-center gap-2">
              <Button
                variant="secondary"
                size="sm"
                onClick={() => playFrom(new Date(startDate).toISOString())}
              >
                <Play className="h-4 w-4 mr-2" /> {t('NVRDetailPage.playback.playFromStart')}
              </Button>
              {playerStartIso && (
                <Button variant="ghost" size="sm" onClick={() => { setPlayerStartIso(null); setPlayerUnavailable(null); }}>
                  <X className="h-4 w-4 mr-2" /> {t('NVRDetailPage.playback.closePlayer')}
                </Button>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Playback URL */}
      {playbackUrl && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2"><Play className="h-4 w-4" /> {t('NVRDetailPage.playback.streamTitle')}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="bg-muted/50 rounded-lg p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">{t('NVRDetailPage.playback.rtspUrl')}</span>
                <Button variant="outline" size="sm" onClick={() => {
                  navigator.clipboard.writeText(playbackUrl.replace(/\/\/([^:]+):([^@]+)@/, '//***:***@'));
                  toast({ title: t('NVRDetailPage.toasts.redactedUrlCopied') });
                }}>
                  {t('NVRDetailPage.playback.copyUrl')}
                </Button>
              </div>
              <code className="block text-xs font-mono bg-background p-3 rounded border break-all select-all">
                {playbackUrl.replace(/\/\/([^:]+):([^@]+)@/, '//***:***@')}
              </code>
              <p className="text-[11px] text-muted-foreground">
                {t('NVRDetailPage.playback.vlcHint')}
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Results */}
      {hasSearched && (
        <Card>
          <CardHeader className="pb-2 flex-row items-center justify-between space-y-0">
            <CardTitle className="text-base flex items-center gap-2">
              <FileVideo className="h-4 w-4" /> {t('NVRDetailPage.playback.segmentsTitle', { n: recordings.length })}
            </CardTitle>
            {recordings.length > 0 && (
              <Button variant="outline" size="sm" onClick={exportRecordingsCsv}>
                <Download className="h-4 w-4 mr-2" /> {t('NVRDetailPage.playback.exportCsv')}
              </Button>
            )}
          </CardHeader>
          {recordings.length === 0 ? (
            <CardContent className="p-6 text-center">
              <FileVideo className="h-8 w-8 text-muted-foreground/30 mx-auto mb-2" />
              <p className="text-sm text-muted-foreground">{t('NVRDetailPage.playback.noRecordings')}</p>
            </CardContent>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>#</TableHead>
                  <TableHead>{t('NVRDetailPage.playback.startTime')}</TableHead>
                  <TableHead>{t('NVRDetailPage.playback.endTime')}</TableHead>
                  <TableHead>{t('NVRDetailPage.playback.duration')}</TableHead>
                  <TableHead>{t('NVRDetailPage.playback.type')}</TableHead>
                  <TableHead>{t('NVRDetailPage.playback.codec')}</TableHead>
                  <TableHead>{t('NVRDetailPage.playback.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recordings.map((rec, idx) => {
                  const start = rec.start_time ? new Date(rec.start_time) : null;
                  const end = rec.end_time ? new Date(rec.end_time) : null;
                  const durationMs = start && end ? end.getTime() - start.getTime() : 0;
                  const durationMin = Math.floor(durationMs / 60_000);
                  const durationSec = Math.floor((durationMs % 60_000) / 1_000);
                  return (
                    <TableRow key={idx}>
                      <TableCell className="text-muted-foreground">{idx + 1}</TableCell>
                      <TableCell className="text-xs font-mono">{start ? start.toLocaleString() : '-'}</TableCell>
                      <TableCell className="text-xs font-mono">{end ? end.toLocaleString() : '-'}</TableCell>
                      <TableCell className="text-sm">
                        {durationMs > 0 ? t('NVRDetailPage.playback.durationValue', { m: durationMin, s: durationSec }) : '-'}
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="text-[10px]">
                          {rec.recording_type?.includes('CMR') ? t('NVRDetailPage.playback.recTypeContinuous') :
                           rec.recording_type?.includes('VMD') ? t('NVRDetailPage.playback.recTypeMotion') :
                           rec.recording_type?.includes('ALARM') ? t('NVRDetailPage.playback.recTypeAlarm') : t('NVRDetailPage.playback.recTypeRecording')}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{rec.codec || '-'}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          {rec.start_time && (
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-7 text-xs"
                              onClick={() => playFrom(new Date(rec.start_time!).toISOString())}
                            >
                              <Play className="h-3 w-3 mr-1" /> {t('NVRDetailPage.playback.play')}
                            </Button>
                          )}
                          {rec.playback_uri && (
                            <Button variant="ghost" size="sm" className="h-7 text-xs text-muted-foreground" onClick={() => {
                              navigator.clipboard.writeText(rec.playback_uri!.replace(/\/\/([^:]+):([^@]+)@/, '//***:***@'));
                              toast({ title: t('NVRDetailPage.toasts.redactedUrlCopiedShort') });
                            }}>
                              <Link2 className="h-3 w-3 mr-1" /> {t('NVRDetailPage.playback.copyUrl')}
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </Card>
      )}
      </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Channel Status Panel
// ═══════════════════════════════════════════════════════════════════════════════

function ChannelStatusPanel({ nvrId }: { nvrId: string }) {
  const { t } = useTranslation('cameras');
  const { data, isLoading, isError } = useQuery({
    queryKey: ['nvr', nvrId, 'channel-status'],
    queryFn: () => nvrApi.getChannelStatus(nvrId).then(r => r.data),
    refetchInterval: 15_000,
  });

  if (isLoading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {Array.from({ length: 16 }).map((_, i) => (
          <Card key={i} className="animate-pulse">
            <CardContent noOffset className="p-4 h-16" />
          </Card>
        ))}
      </div>
    );
  }

  if (isError) {
    return (
      <div className="rounded-md border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive">
        {t('NVRDetailPage.channelStatus.error')}
      </div>
    );
  }

  const channels = data?.channels ?? [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium">{t('NVRDetailPage.channelStatus.title', { n: channels.length })}</h3>
        <div className="flex items-center gap-4 text-xs text-muted-foreground">
          <span className="flex items-center gap-1.5"><div className="h-2 w-2 rounded-full bg-emerald-500" /> {t('NVRDetailPage.channelStatus.online')}</span>
          <span className="flex items-center gap-1.5"><div className="h-2 w-2 rounded-full bg-red-500" /> {t('NVRDetailPage.channelStatus.offline')}</span>
        </div>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
        {channels.map((ch) => (
          <Card key={ch.id} className={cn(
            "transition-colors",
            ch.online ? "border-emerald-500/30 bg-emerald-500/5" : "border-red-500/30 bg-red-500/5 opacity-70"
          )}>
            <CardContent noOffset className="p-3">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-mono font-medium">{t('NVRDetailPage.channels.chShort', { n: ch.id })}</span>
                <div className={cn("h-2 w-2 rounded-full", ch.online ? "bg-emerald-500" : "bg-red-500")} />
              </div>
              <p className="text-[11px] text-muted-foreground truncate">{ch.name || t('NVRDetailPage.channelStatus.channelN', { n: ch.id })}</p>
              {ch.ip_address && <p className="text-[10px] text-muted-foreground font-mono">{ch.ip_address}</p>}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Holidays Panel
// ═══════════════════════════════════════════════════════════════════════════════

// Valid Hikvision holiday modes.
const HOLIDAY_MODES = ['date', 'week', 'month'] as const;

function HolidaysPanel({ nvrId, isOnline, active }: { nvrId: string; isOnline: boolean; active: boolean }) {
  const { t } = useTranslation('cameras');
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['nvr-holidays', nvrId],
    queryFn: () => nvrApi.getHolidays(nvrId).then(r => r.data),
    enabled: !!nvrId && isOnline && active,
    staleTime: 120_000,
  });

  // Local editable copy of the holiday list, plus a dirty flag so Save only
  // sends when the operator has actually changed something.
  const [draft, setDraft] = useState<HolidayEntry[]>([]);
  const [dirty, setDirty] = useState(false);
  useEffect(() => {
    if (data?.holidays) { setDraft(data.holidays); setDirty(false); }
  }, [data?.holidays]);

  const saveMut = useMutation({
    mutationFn: (holidays: HolidayEntry[]) =>
      nvrApi.setHolidays(nvrId, { holidays }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['nvr-holidays', nvrId] });
      setDirty(false);
      toast({ title: t('NVRDetailPage.holidays.saveSuccess') });
    },
    onError: (err: unknown) => {
      toast({ title: getApiErrorMessage(err, t('NVRDetailPage.holidays.saveError')), variant: 'destructive' as any });
    },
  });

  // ── Draft mutators ──
  const patchHoliday = (id: number, patch: Partial<HolidayEntry>) => {
    setDraft(prev => prev.map(h => (h.id === id ? { ...h, ...patch } : h)));
    setDirty(true);
  };

  const toggleEnabled = (id: number) => {
    setDraft(prev => prev.map(h => (h.id === id ? { ...h, enabled: !h.enabled } : h)));
    setDirty(true);
  };

  const deleteHoliday = (id: number) => {
    setDraft(prev => prev.filter(h => h.id !== id));
    setDirty(true);
  };

  const addHoliday = () => {
    setDraft(prev => {
      // Pick the next free id (Hikvision indexes holidays 1..N).
      const nextId = prev.reduce((m, h) => Math.max(m, h.id ?? 0), 0) + 1;
      return [
        ...prev,
        {
          id: nextId,
          enabled: true,
          name: t('NVRDetailPage.holidays.newHolidayName'),
          mode: 'date',
          start_month: 1,
          start_day: 1,
          end_month: 1,
          end_day: 1,
        },
      ];
    });
    setDirty(true);
  };

  if (!isOnline) {
    return (
      <Card>
        <CardContent noOffset className="p-8 text-center">
          <CalendarDays className="h-10 w-10 text-muted-foreground/30 mx-auto mb-3" />
          <p className="text-sm text-muted-foreground">{t('NVRDetailPage.holidays.offline')}</p>
        </CardContent>
      </Card>
    );
  }

  if (isLoading) {
    return (
      <Card>
        <CardContent noOffset className="p-8 text-center">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground mx-auto mb-3" />
          <p className="text-sm text-muted-foreground">{t('NVRDetailPage.holidays.loading')}</p>
        </CardContent>
      </Card>
    );
  }

  if (isError) {
    return (
      <Card>
        <ErrorState message={t('NVRDetailPage.holidays.loadError')} onRetry={() => refetch()} />
      </Card>
    );
  }

  // Clamp a month/day input to a sane range for the given field.
  const clampMonth = (v: number) => Math.min(12, Math.max(1, v || 1));
  const clampDay = (v: number) => Math.min(31, Math.max(1, v || 1));

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between gap-2">
          <div>
            <CardTitle className="text-base flex items-center gap-2">
              <CalendarDays className="h-4 w-4" /> {t('NVRDetailPage.holidays.title', { n: draft.length })}
            </CardTitle>
            <CardDescription>{t('NVRDetailPage.holidays.descriptionEditable')}</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={addHoliday} disabled={saveMut.isPending}>
              <Plus className="h-4 w-4 mr-2" /> {t('NVRDetailPage.holidays.add')}
            </Button>
            <Button
              size="sm"
              disabled={saveMut.isPending || !dirty}
              onClick={() => saveMut.mutate(draft)}
            >
              {saveMut.isPending
                ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> {t('NVRDetailPage.holidays.saving')}</>
                : <><Save className="h-4 w-4 mr-2" /> {t('NVRDetailPage.holidays.save')}</>}
            </Button>
          </div>
        </div>
      </CardHeader>
      {draft.length === 0 ? (
        <CardContent>
          <EmptyState
            variant="compact"
            icon={CalendarDays}
            title={t('NVRDetailPage.holidays.emptyTitle')}
            description={t('NVRDetailPage.holidays.emptyEditable')}
            action={{
              label: t('NVRDetailPage.holidays.add'),
              icon: Plus,
              onClick: addHoliday,
            }}
          />
        </CardContent>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-12">{t('NVRDetailPage.holidays.colId')}</TableHead>
              <TableHead className="min-w-[10rem]">{t('NVRDetailPage.holidays.colName')}</TableHead>
              <TableHead className="w-28">{t('NVRDetailPage.holidays.colMode')}</TableHead>
              <TableHead>{t('NVRDetailPage.holidays.colStart')}</TableHead>
              <TableHead>{t('NVRDetailPage.holidays.colEnd')}</TableHead>
              <TableHead className="w-24">{t('NVRDetailPage.holidays.colEnabled')}</TableHead>
              <TableHead className="w-12 text-right">{t('NVRDetailPage.holidays.colActions')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {draft.map((h, i) => (
              <TableRow key={h.id ?? i}>
                <TableCell className="font-mono text-xs">{h.id ?? '-'}</TableCell>
                <TableCell>
                  <Input
                    value={h.name ?? ''}
                    onChange={e => patchHoliday(h.id, { name: e.target.value })}
                    placeholder={t('NVRDetailPage.holidays.namePlaceholder')}
                    className="h-8"
                    maxLength={32}
                    aria-label={t('NVRDetailPage.holidays.nameAria', { n: h.id })}
                  />
                </TableCell>
                <TableCell>
                  <Select value={h.mode || 'date'} onValueChange={v => patchHoliday(h.id, { mode: v })}>
                    <SelectTrigger className="h-8">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {HOLIDAY_MODES.map(m => (
                        <SelectItem key={m} value={m}>{t(`NVRDetailPage.holidays.mode.${m}`)}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-1.5">
                    <Input
                      type="number" min={1} max={12}
                      value={h.start_month ?? 1}
                      onChange={e => patchHoliday(h.id, { start_month: clampMonth(Number(e.target.value)) })}
                      className="h-8 w-16"
                      aria-label={t('NVRDetailPage.holidays.startMonthAria', { n: h.id })}
                    />
                    <span className="text-muted-foreground text-xs">/</span>
                    <Input
                      type="number" min={1} max={31}
                      value={h.start_day ?? 1}
                      onChange={e => patchHoliday(h.id, { start_day: clampDay(Number(e.target.value)) })}
                      className="h-8 w-16"
                      aria-label={t('NVRDetailPage.holidays.startDayAria', { n: h.id })}
                    />
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-1.5">
                    <Input
                      type="number" min={1} max={12}
                      value={h.end_month ?? 1}
                      onChange={e => patchHoliday(h.id, { end_month: clampMonth(Number(e.target.value)) })}
                      className="h-8 w-16"
                      aria-label={t('NVRDetailPage.holidays.endMonthAria', { n: h.id })}
                    />
                    <span className="text-muted-foreground text-xs">/</span>
                    <Input
                      type="number" min={1} max={31}
                      value={h.end_day ?? 1}
                      onChange={e => patchHoliday(h.id, { end_day: clampDay(Number(e.target.value)) })}
                      className="h-8 w-16"
                      aria-label={t('NVRDetailPage.holidays.endDayAria', { n: h.id })}
                    />
                  </div>
                </TableCell>
                <TableCell>
                  <label className="inline-flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      className="h-4 w-4 rounded border-input accent-primary"
                      checked={!!h.enabled}
                      onChange={() => toggleEnabled(h.id)}
                      aria-label={t('NVRDetailPage.holidays.toggleAria', { name: h.name || String(h.id) })}
                    />
                    <span className="text-xs text-muted-foreground">
                      {h.enabled ? t('NVRDetailPage.common.yes') : t('NVRDetailPage.common.no')}
                    </span>
                  </label>
                </TableCell>
                <TableCell className="text-right">
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8 text-destructive hover:text-destructive"
                    onClick={() => deleteHoliday(h.id)}
                    aria-label={t('NVRDetailPage.holidays.deleteAria', { name: h.name || String(h.id) })}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      {dirty && (
        <CardContent className="pt-3">
          <p className="text-[11px] text-amber-500">{t('NVRDetailPage.holidays.unsavedNote')}</p>
        </CardContent>
      )}
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Settings Dialog
// ═══════════════════════════════════════════════════════════════════════════════

function SettingsDialog({ open, onOpenChange, nvr, nvrId }: {
  open: boolean; onOpenChange: (o: boolean) => void; nvr: NVRData; nvrId: string;
}) {
  const { t } = useTranslation('cameras');
  const { toast } = useToast();
  const qc = useQueryClient();
  const [name, setName] = useState(nvr.name);
  const [port, setPort] = useState(String(nvr.port));
  const [description, setDescription] = useState(nvr.description ?? '');

  useEffect(() => {
    if (open) {
      setName(nvr.name);
      setPort(String(nvr.port));
      setDescription(nvr.description ?? '');
    }
  }, [open, nvr]);

  const saveMut = useMutation({
    mutationFn: () => {
      const portNum = Number(port);
      if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
        return Promise.reject(new Error('Port must be 1-65535'));
      }
      return nvrApi.update(nvrId, { name, port: portNum, description: description || undefined });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['nvr-detail', nvrId] });
      onOpenChange(false);
    },
    onError: () => {
      toast({ title: t('NVRDetailPage.toasts.saveSettingsFailed'), variant: 'destructive' as any });
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{t('NVRDetailPage.settings.title')}</DialogTitle>
          <DialogDescription>{t('NVRDetailPage.settings.description')}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-2">
            <Label>{t('NVRDetailPage.settings.name')}</Label>
            <Input value={name} onChange={e => setName(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label>{t('NVRDetailPage.settings.descriptionLabel')}</Label>
            <Input value={description} onChange={e => setDescription(e.target.value)} placeholder={t('NVRDetailPage.settings.descriptionPlaceholder')} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>{t('NVRDetailPage.settings.port')}</Label>
              <Input type="number" min={1} max={65535} value={port} onChange={e => setPort(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label>{t('NVRDetailPage.settings.ipAddress')}</Label>
              <Input value={nvr.ip_address} disabled className="text-muted-foreground" />
            </div>
          </div>
          <div className="space-y-2">
            <Label>{t('NVRDetailPage.settings.serialNumber')}</Label>
            <Input value={nvr.serial_number ?? '-'} disabled className="text-muted-foreground font-mono text-xs" />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('NVRDetailPage.settings.cancel')}</Button>
          <Button onClick={() => saveMut.mutate()} disabled={!name.trim() || saveMut.isPending}>
            {saveMut.isPending ? t('NVRDetailPage.settings.saving') : t('NVRDetailPage.settings.save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
