// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Enterprise Cameras Management Page
 *
 * UniFi Protect / Hikvision / Blue Iris-inspired surveillance dashboard:
 *  - Enterprise camera wall supporting up to 64 simultaneous feeds
 *  - Adaptive snapshot refresh (fewer cameras → faster refresh)
 *  - Staggered request scheduling (prevents burst loading)
 *  - Grid / List / Live Wall view modes
 *  - Advanced sidebar filters (status, vendor, PTZ, audio)
 *  - Camera groups with CRUD + saved views
 *  - Focus mode with MJPEG live stream
 *  - Fullscreen, auto-cycle, keyboard shortcuts
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import {
  Video,
  VideoOff,
  Camera,
  Play,
  Settings,
  MoreHorizontal,
  CheckCircle,
  XCircle,
  AlertCircle,
  Activity,
  Search,
  Grid3X3,
  List,
  Plus,
  Eye,
  Move,
  Filter,
  Folder,
  FolderPlus,
  Trash2,
  Monitor,
  X,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  LayoutGrid,
  Grip,
  Layers,
  Bookmark,
  Bell,
  HeartPulse,
  CheckCheck,
  Wifi,
  WifiOff,
  Gauge,
  RefreshCw,
  AlertTriangle,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Input } from '@/components/ui/input';
import { DataTable, DataTableColumn } from '@/components/ui/data-table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { Badge } from '@/components/ui/badge';
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
import { Checkbox } from '@/components/ui/checkbox';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { CameraLiveViewModal, AddDeviceDialog } from '@/components/cameras';
import { CameraWall, type WallLayout } from '@/components/cameras/wall';
import { camerasApi } from '@/lib/api';
import { cn } from '@/lib/utils';
import { EmptyState } from '@/components/ui/empty-state';
import { PageHeader } from '@/components/layout';
import { StatsGrid } from '@/components/ui/stats-grid';
import { SectionBoundary } from '@/components/SectionBoundary';
import { useToast } from '@/hooks/use-toast';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface CameraDevice {
  id: string | number;
  name: string;
  ip_address?: string;
  location?: string;
  floor?: string;
  zone?: string;
  model?: string;
  vendor?: string;
  camera_type?: string;
  status: 'online' | 'offline' | 'recording' | 'error' | 'unknown';
  is_recording?: boolean;
  has_ptz?: boolean;
  has_audio?: boolean;
  resolution_width?: number;
  resolution_height?: number;
  nvr_id?: string;
  nvr_channel?: number;
  nvr?: { id: string; name: string } | null;
}

interface CameraGroup {
  id: string;
  name: string;
  description?: string;
  color: string;
  icon: string;
  camera_count: number;
  is_default?: boolean;
}

interface CameraView {
  id: string;
  name: string;
  description?: string;
  layout: string;
  camera_ids: string[];
  filters: Record<string, unknown>;
  is_default?: boolean;
  is_shared?: boolean;
  is_owner?: boolean;
}

type ViewMode = 'grid' | 'list' | 'live' | 'events' | 'health';

interface Filters {
  status: string;
  vendor: string;
  hasPtz: boolean | null;
  hasAudio: boolean | null;
  search: string;
  groupId: string | null;
  floor: string;
  zone: string;
}

const DEFAULT_FILTERS: Filters = {
  status: 'all',
  vendor: 'all',
  hasPtz: null,
  hasAudio: null,
  search: '',
  groupId: null,
  floor: 'all',
  zone: 'all',
};

// ---------------------------------------------------------------------------
// Recording-template → RecordingScheduleUpdateRequest transform
// ---------------------------------------------------------------------------
// A saved template's `schedule` is a free-form JSON dict. The setRecordingSchedule
// endpoint expects { enabled, days: [{ id (1=Mon…7=Sun), action_type, time_blocks:
// [{ begin_time, end_time, record_type }] }] }. Normalize the known template shapes
// (FE-created {type, days:[weekday names], start, end}; documented
// [{day, blocks:[{start,end,type}]}]) into that request body.

const WEEKDAY_TO_ID: Record<string, number> = {
  mon: 1, tue: 2, wed: 3, thu: 4, fri: 5, sat: 6, sun: 7,
  monday: 1, tuesday: 2, wednesday: 3, thursday: 4, friday: 5, saturday: 6, sunday: 7,
};

function templateToRecordingSchedule(schedule: Record<string, unknown> | undefined | null) {
  const s = (schedule ?? {}) as Record<string, unknown>;

  const mkBlock = (start: unknown, end: unknown, type: unknown) => ({
    begin_time: typeof start === 'string' && start ? start : '00:00',
    end_time: typeof end === 'string' && end ? end : '23:59',
    record_type: typeof type === 'string' && type ? type : 'continuous',
  });

  // Shape A: explicit per-day array, either [{day,blocks}] or {days:[{day,blocks}]}
  const dayArray = Array.isArray(s.days)
    ? (s.days as unknown[])
    : Array.isArray((s as { schedule?: unknown }).schedule)
      ? ((s as { schedule: unknown[] }).schedule)
      : null;

  const isStructuredDays =
    dayArray != null &&
    dayArray.length > 0 &&
    typeof dayArray[0] === 'object' &&
    dayArray[0] !== null;

  if (isStructuredDays) {
    const days = (dayArray as Record<string, unknown>[]).map((d) => {
      const rawId = d.id ?? d.day;
      let id = typeof rawId === 'number' ? rawId : typeof rawId === 'string' ? WEEKDAY_TO_ID[rawId.toLowerCase()] ?? 0 : 0;
      // model docstring uses 0=Mon…6=Sun; backend NVR uses 1=Mon…7=Sun. Shift 0-based.
      if (typeof rawId === 'number' && rawId >= 0 && rawId <= 6) id = rawId + 1;
      const rawBlocks = Array.isArray(d.time_blocks)
        ? (d.time_blocks as Record<string, unknown>[])
        : Array.isArray(d.blocks)
          ? (d.blocks as Record<string, unknown>[])
          : [];
      const time_blocks = rawBlocks.length
        ? rawBlocks.map((b) => mkBlock(b.begin_time ?? b.start, b.end_time ?? b.end, b.record_type ?? b.type))
        : [mkBlock('00:00', '23:59', 'continuous')];
      return { id, action_type: typeof d.action_type === 'string' ? d.action_type : 'record', time_blocks };
    });
    return { enabled: true, days };
  }

  // Shape B: FE-created {type, days:[weekday names], start, end}
  const weekdayNames = Array.isArray(s.days) ? (s.days as unknown[]) : ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'];
  const block = mkBlock(s.start, s.end, s.type);
  const days = weekdayNames
    .map((w) => (typeof w === 'string' ? WEEKDAY_TO_ID[w.toLowerCase()] : typeof w === 'number' ? w : 0))
    .filter((id): id is number => typeof id === 'number' && id >= 1 && id <= 7)
    .map((id) => ({ id, action_type: 'record', time_blocks: [block] }));

  return { enabled: true, days: days.length ? days : [{ id: 1, action_type: 'record', time_blocks: [block] }] };
}

// ---------------------------------------------------------------------------
// Status Badge
// ---------------------------------------------------------------------------

function StatusBadge({ status }: { status: CameraDevice['status'] }) {
  const { t } = useTranslation('cameras');
  const config: Record<string, { icon: typeof CheckCircle; label: string; className: string }> = {
    online: { icon: CheckCircle, label: t('CamerasPage.status.online'), className: 'bg-success/10 text-success border-success/20' },
    offline: { icon: XCircle, label: t('CamerasPage.status.offline'), className: 'bg-destructive/10 text-destructive border-destructive/20' },
    recording: { icon: Activity, label: t('CamerasPage.status.recording'), className: 'bg-info/10 text-info border-info/20 animate-pulse' },
    error: { icon: AlertCircle, label: t('CamerasPage.status.error'), className: 'bg-warning/10 text-warning border-warning/20' },
    unknown: { icon: AlertCircle, label: t('CamerasPage.status.unknown'), className: 'bg-muted text-muted-foreground border-muted' },
  };
  const { icon: Icon, label, className } = config[status] || config.unknown;
  return (
    <Badge variant="outline" className={cn('gap-1', className)}>
      <Icon className="h-3 w-3" />
      {label}
    </Badge>
  );
}

// ---------------------------------------------------------------------------
// Snapshot Thumbnail · auto-refreshes only when visible (IntersectionObserver)
// Uses staggered intervals so 16+ cameras don't burst request simultaneously.
// ---------------------------------------------------------------------------

let _staggerCounter = 0;

function SnapshotThumbnail({ cameraId, status, paused = false }: { cameraId: string; status: string; paused?: boolean }) {
  const { t } = useTranslation('cameras');
  const [src, setSrc] = useState<string | null>(null);
  const [error, setError] = useState(false);
  const timerRef = useRef<ReturnType<typeof setInterval>>(undefined);
  const containerRef = useRef<HTMLDivElement>(null);
  const isVisibleRef = useRef(false);
  const isOnline = status === 'online' || status === 'recording';

  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  const refresh = useCallback(() => {
    if (!isOnline || !isVisibleRef.current || pausedRef.current) return;
    setError(false);
    // Use short-lived stream token for snapshot URL
    camerasApi.getSnapshotUrlAsync(cameraId).then((url) => {
      setSrc(`${url}&_t=${Date.now()}`);
    }).catch(() => {
      // Stream token fetch failed · show error state
      setError(true);
    });
  }, [cameraId, isOnline]);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const observer = new IntersectionObserver(
      ([entry]) => {
        isVisibleRef.current = entry.isIntersecting;
        if (entry.isIntersecting && !src && isOnline) {
          refresh();
        }
      },
      { threshold: 0.1 },
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [refresh, src, isOnline]);

  useEffect(() => {
    if (!isOnline || paused) return;
    // Stagger: each camera gets a slight offset (0-2s) to avoid burst
    const stagger = ((_staggerCounter++) % 10) * 200;
    const startTimer = setTimeout(() => {
      refresh();
      timerRef.current = setInterval(refresh, 15_000);
    }, stagger);
    return () => {
      clearTimeout(startTimer);
      clearInterval(timerRef.current);
    };
  }, [refresh, isOnline, paused]);

  if (!isOnline || error) {
    return (
      <div ref={containerRef} className="absolute inset-0 bg-muted flex items-center justify-center">
        <VideoOff className="h-10 w-10 text-muted-foreground/40" />
      </div>
    );
  }

  return (
    <div ref={containerRef} className="absolute inset-0">
      {src && (
        <img
          src={src}
          alt={t('CamerasPage.snapshot.alt')}
          className="absolute inset-0 w-full h-full object-cover"
          onError={() => setError(true)}
          loading="lazy"
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Camera Card for Grid View · with live snapshot thumbnail
// ---------------------------------------------------------------------------

function CameraCard({
  camera,
  onViewStream,
  onOpenDetail,
  selected,
  onSelect,
  selectionMode,
  snapshotPaused,
  healthData,
}: {
  camera: CameraDevice;
  onViewStream: (c: CameraDevice) => void;
  onOpenDetail: (c: CameraDevice) => void;
  selected?: boolean;
  onSelect?: (id: string, checked: boolean) => void;
  selectionMode?: boolean;
  snapshotPaused?: boolean;
  healthData?: { is_online: boolean; frame_rate?: number; bitrate_kbps?: number };
}) {
  const { t } = useTranslation('cameras');
  const isOnline = camera.status === 'online' || camera.status === 'recording';

  // Health dot: green (healthy), amber (degraded fps < 10 or no data), red (offline/error)
  const healthColor = !isOnline
    ? 'bg-muted-foreground'
    : healthData
      ? (healthData.frame_rate && healthData.frame_rate >= 10 ? 'bg-emerald-400' : 'bg-amber-400')
      : 'bg-emerald-400'; // online but no health data yet = assume OK

  return (
    <Card
      className={cn(
        'overflow-hidden group cursor-pointer transition-all',
        selected && 'ring-2 ring-primary',
      )}
      onClick={() => (selectionMode ? onSelect?.(String(camera.id), !selected) : onOpenDetail(camera))}
    >
      <div className="relative aspect-video bg-muted">
        <SnapshotThumbnail cameraId={String(camera.id)} status={camera.status} paused={snapshotPaused} />
        <div className="absolute inset-0 bg-gradient-to-t from-black/70 via-transparent to-transparent" />

        {selectionMode && (
          <div className="absolute top-2 left-2 z-10">
            <Checkbox
              checked={selected}
              onCheckedChange={(v) => onSelect?.(String(camera.id), !!v)}
              onClick={(e) => e.stopPropagation()}
              className="bg-background/80"
            />
          </div>
        )}

        {camera.is_recording && (
          <div className="absolute top-2 right-2 z-10 flex items-center gap-1 bg-red-600/90 text-white text-[10px] font-bold px-1.5 py-0.5 rounded">
            <span className="h-1.5 w-1.5 rounded-full bg-white animate-pulse" />
            REC
          </div>
        )}

        <div className="absolute bottom-0 left-0 right-0 p-2 flex items-center justify-between">
          <span className="text-white text-sm font-medium truncate max-w-[60%]">{camera.name}</span>
          <StatusBadge status={camera.status} />
        </div>

        {isOnline && !selectionMode && (
          <div className="absolute inset-0 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity bg-black/40 z-10">
            <Button
              variant="secondary"
              size="sm"
              onClick={(e) => { e.stopPropagation(); onViewStream(camera); }}
              className="gap-2"
            >
              <Play className="h-4 w-4" />
              {t('CamerasPage.actions.liveView')}
            </Button>
          </div>
        )}
      </div>

      <CardContent noOffset className="p-2.5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5 min-w-0">
            <span className={cn('h-2 w-2 rounded-full shrink-0', healthColor)} title={
              !isOnline ? t('CamerasPage.status.offline') : healthData?.frame_rate ? t('CamerasPage.card.healthTitle', { fps: healthData.frame_rate, kbps: healthData.bitrate_kbps ?? '?' }) : t('CamerasPage.status.online')
            } />
            <span className="text-xs text-muted-foreground truncate">
              {camera.location || camera.ip_address || '-'}
            </span>
          </div>
          <div className="flex gap-1">
            {camera.has_ptz && <Badge variant="secondary" className="text-[10px] px-1 py-0">PTZ</Badge>}
            {camera.has_audio && <Badge variant="secondary" className="text-[10px] px-1 py-0">{t('CamerasPage.features.audio')}</Badge>}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Create / Edit Group Dialog
// ---------------------------------------------------------------------------

function GroupDialog({
  open,
  onOpenChange,
  existingGroup,
  cameras,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  existingGroup?: CameraGroup | null;
  cameras: CameraDevice[];
}) {
  const { t } = useTranslation('cameras');
  const qc = useQueryClient();
  const { toast } = useToast();
  const [name, setName] = useState(existingGroup?.name || '');
  const [description, setDescription] = useState(existingGroup?.description || '');
  const [color, setColor] = useState(existingGroup?.color || '#3b82f6');
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState('');
  const [filterNvr, setFilterNvr] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');

  // Fetch existing group members when editing
  const { data: groupDetail } = useQuery({
    queryKey: ['camera-group-detail', existingGroup?.id],
    queryFn: () => existingGroup ? camerasApi.getGroup(existingGroup.id) : null,
    enabled: open && !!existingGroup,
  });

  useEffect(() => {
    if (open) {
      setName(existingGroup?.name || '');
      setDescription(existingGroup?.description || '');
      setColor(existingGroup?.color || '#3b82f6');
      setSearch('');
      setFilterNvr('all');
      setFilterStatus('all');
      // Pre-populate members from fetched group detail
      if (existingGroup && groupDetail?.data?.cameras) {
        setSelectedIds(new Set(groupDetail.data.cameras.map((c: { camera_id: string }) => c.camera_id)));
      } else {
        setSelectedIds(new Set());
      }
    }
  }, [open, existingGroup, groupDetail]);

  // Derive unique NVR list from cameras for filter dropdown
  const nvrOptions = useMemo(() => {
    const map = new Map<string, string>();
    cameras.forEach((cam) => {
      if (cam.nvr?.id && cam.nvr?.name) {
        map.set(cam.nvr.id, cam.nvr.name);
      }
    });
    return Array.from(map, ([id, label]) => ({ id, label }));
  }, [cameras]);


  // Filter cameras for the checklist
  const filteredCameras = useMemo(() => {
    let list = cameras;
    if (search) {
      const q = search.toLowerCase();
      list = list.filter((c) =>
        c.name.toLowerCase().includes(q) ||
        c.ip_address?.toLowerCase().includes(q) ||
        c.location?.toLowerCase().includes(q)
      );
    }
    if (filterNvr !== 'all') {
      if (filterNvr === 'standalone') {
        list = list.filter((c) => !c.nvr_id);
      } else {
        list = list.filter((c) => c.nvr_id === filterNvr || c.nvr?.id === filterNvr);
      }
    }
    if (filterStatus !== 'all') {
      list = list.filter((c) => c.status === filterStatus);
    }
    return list;
  }, [cameras, search, filterNvr, filterStatus]);

  const allFilteredSelected = filteredCameras.length > 0 && filteredCameras.every((c) => selectedIds.has(String(c.id)));
  const someFilteredSelected = filteredCameras.some((c) => selectedIds.has(String(c.id)));

  const toggleSelectAll = () => {
    const next = new Set(selectedIds);
    if (allFilteredSelected) {
      // Deselect all visible
      filteredCameras.forEach((c) => next.delete(String(c.id)));
    } else {
      // Select all visible
      filteredCameras.forEach((c) => next.add(String(c.id)));
    }
    setSelectedIds(next);
  };

  const createMut = useMutation({
    mutationFn: () =>
      existingGroup
        ? camerasApi.updateGroup(existingGroup.id, { name, description: description || undefined, color, camera_ids: [...selectedIds] })
        : camerasApi.createGroup({ name, description: description || undefined, color, camera_ids: [...selectedIds] }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['camera-groups'] });
      if (existingGroup) qc.invalidateQueries({ queryKey: ['camera-group-detail', existingGroup.id] });
      onOpenChange(false);
    },
    onError: () => {
      toast({ title: existingGroup ? t('CamerasPage.toasts.updateGroupFailed') : t('CamerasPage.toasts.createGroupFailed'), variant: 'destructive' as any });
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{existingGroup ? t('CamerasPage.groupDialog.editTitle') : t('CamerasPage.groupDialog.createTitle')}</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 py-2">
          {/* Name */}
          <div className="space-y-2">
            <Label>{t('CamerasPage.groupDialog.nameLabel')}</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder={t('CamerasPage.groupDialog.namePlaceholder')} />
          </div>

          {/* Description */}
          <div className="space-y-2">
            <Label>{t('CamerasPage.groupDialog.descriptionLabel')} <span className="text-muted-foreground text-xs">{t('CamerasPage.groupDialog.optional')}</span></Label>
            <Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder={t('CamerasPage.groupDialog.descriptionPlaceholder')} />
          </div>

          {/* Color picker */}
          <div className="space-y-2">
            <Label>{t('CamerasPage.groupDialog.colorLabel')}</Label>
            <div className="flex gap-2">
              {['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4', '#84cc16'].map((c) => (
                <button
                  key={c}
                  type="button"
                  aria-label={t('CamerasPage.groupDialog.selectColor', { color: c })}
                  aria-pressed={color === c}
                  className={cn('h-7 w-7 rounded-full border-2 transition-transform', color === c ? 'border-foreground scale-110' : 'border-transparent')}
                  style={{ backgroundColor: c }}
                  onClick={() => setColor(c)}
                />
              ))}
            </div>
          </div>

          {/* Camera Selection */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label>{t('CamerasPage.groupDialog.selectCameras')}</Label>
              <Badge variant="secondary" className="text-xs">{t('CamerasPage.groupDialog.selectedCount', { count: selectedIds.size })}</Badge>
            </div>

            {/* Search + Filters */}
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                <Input
                  className="pl-7 h-8 text-sm"
                  placeholder={t('CamerasPage.searchPlaceholder')}
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </div>
              {nvrOptions.length > 0 && (
                <Select value={filterNvr} onValueChange={setFilterNvr}>
                  <SelectTrigger className="w-[140px] h-8 text-xs">
                    <SelectValue placeholder={t('CamerasPage.filters.allNvrs')} />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">{t('CamerasPage.filters.allNvrs')}</SelectItem>
                    {nvrOptions.map((n) => (
                      <SelectItem key={n.id} value={n.id}>{n.label}</SelectItem>
                    ))}
                    <SelectItem value="standalone">{t('CamerasPage.filters.standalone')}</SelectItem>
                  </SelectContent>
                </Select>
              )}
              <Select value={filterStatus} onValueChange={setFilterStatus}>
                <SelectTrigger className="w-[110px] h-8 text-xs">
                  <SelectValue placeholder={t('CamerasPage.filters.all')} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{t('CamerasPage.filters.allStatus')}</SelectItem>
                  <SelectItem value="online">{t('CamerasPage.status.online')}</SelectItem>
                  <SelectItem value="offline">{t('CamerasPage.status.offline')}</SelectItem>
                  <SelectItem value="recording">{t('CamerasPage.status.recording')}</SelectItem>
                  <SelectItem value="error">{t('CamerasPage.status.error')}</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Select All / Deselect All */}
            <div className="flex items-center justify-between px-1">
              <label className="flex items-center gap-2 cursor-pointer text-sm text-muted-foreground">
                <Checkbox
                  checked={allFilteredSelected}
                  // @ts-expect-error -- indeterminate is valid DOM attr
                  indeterminate={someFilteredSelected && !allFilteredSelected}
                  onCheckedChange={toggleSelectAll}
                />
                {allFilteredSelected ? t('CamerasPage.groupDialog.deselectAll') : t('CamerasPage.groupDialog.selectAll', { count: filteredCameras.length })}
              </label>
              {selectedIds.size > 0 && (
                <button
                  className="text-xs text-destructive hover:underline"
                  onClick={() => setSelectedIds(new Set())}
                >
                  {t('CamerasPage.groupDialog.clearSelection')}
                </button>
              )}
            </div>

            {/* Camera List */}
            <ScrollArea className="h-56 border rounded-md">
              {filteredCameras.length === 0 ? (
                <EmptyState
                  icon={Camera}
                  title={t('CamerasPage.groupDialog.noMatchTitle')}
                  description={t('CamerasPage.groupDialog.noMatchDescription')}
                  variant="compact"
                />
              ) : (
                <div className="p-1">
                  {filteredCameras.map((cam) => (
                    <label
                      key={cam.id}
                      className={cn(
                        'flex items-center gap-2 py-1.5 px-2 cursor-pointer rounded transition-colors',
                        selectedIds.has(String(cam.id)) ? 'bg-primary/10' : 'hover:bg-muted/50'
                      )}
                    >
                      <Checkbox
                        checked={selectedIds.has(String(cam.id))}
                        onCheckedChange={(v) => {
                          const next = new Set(selectedIds);
                          if (v) next.add(String(cam.id)); else next.delete(String(cam.id));
                          setSelectedIds(next);
                        }}
                      />
                      <div className="flex-1 min-w-0">
                        <span className="text-sm truncate block">{cam.name}</span>
                        <span className="text-xs text-muted-foreground truncate block">
                          {[cam.nvr?.name, cam.location, cam.ip_address].filter(Boolean).join(' · ')}
                        </span>
                      </div>
                      <StatusBadge status={cam.status} />
                    </label>
                  ))}
                </div>
              )}
            </ScrollArea>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('CamerasPage.actions.cancel')}</Button>
          <Button onClick={() => createMut.mutate()} disabled={!name.trim() || createMut.isPending}>
            {createMut.isPending ? t('CamerasPage.actions.saving') : existingGroup ? t('CamerasPage.actions.update') : t('CamerasPage.actions.create')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Save View Dialog
// ---------------------------------------------------------------------------

function SaveViewDialog({
  open,
  onOpenChange,
  liveCameraIds,
  layout,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  liveCameraIds: string[];
  layout: string;
}) {
  const { t } = useTranslation('cameras');
  const qc = useQueryClient();
  const { toast } = useToast();
  const [name, setName] = useState('');
  const [shared, setShared] = useState(false);

  const saveMut = useMutation({
    mutationFn: () =>
      camerasApi.createView({
        name,
        layout,
        camera_ids: liveCameraIds,
        is_shared: shared,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['camera-views'] });
      onOpenChange(false);
    },
    onError: () => {
      toast({ title: t('CamerasPage.toasts.saveViewFailed'), variant: 'destructive' as any });
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>{t('CamerasPage.saveViewDialog.title')}</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-2">
            <Label>{t('CamerasPage.saveViewDialog.nameLabel')}</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder={t('CamerasPage.saveViewDialog.namePlaceholder')} />
          </div>
          <div className="flex items-center justify-between">
            <Label>{t('CamerasPage.saveViewDialog.shareLabel')}</Label>
            <Switch checked={shared} onCheckedChange={setShared} />
          </div>
          <p className="text-xs text-muted-foreground">
            {t('CamerasPage.saveViewDialog.summary', { layout, count: liveCameraIds.length })}
          </p>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('CamerasPage.actions.cancel')}</Button>
          <Button onClick={() => saveMut.mutate()} disabled={!name.trim() || saveMut.isPending}>
            {saveMut.isPending ? t('CamerasPage.actions.saving') : t('CamerasPage.actions.saveView')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Create Recording Template Dialog · replaces native prompt()
// ---------------------------------------------------------------------------

function CreateTemplateDialog({
  open,
  onOpenChange,
  onSubmit,
  isPending,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onSubmit: (values: { name: string; description?: string }) => void;
  isPending: boolean;
}) {
  const { t } = useTranslation('cameras');
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');

  // Reset fields each time the dialog opens.
  useEffect(() => {
    if (open) { setName(''); setDescription(''); }
  }, [open]);

  const submit = () => {
    const trimmed = name.trim();
    if (!trimmed) return;
    onSubmit({ name: trimmed, description: description.trim() || undefined });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>{t('CamerasPage.templates.createDialogTitle')}</DialogTitle>
          <DialogDescription>{t('CamerasPage.templates.createDialogDescription')}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-2">
            <Label>{t('CamerasPage.templates.nameLabel')} <span className="text-red-500">*</span></Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={t('CamerasPage.templates.namePlaceholder')}
              autoFocus
              onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); submit(); } }}
            />
          </div>
          <div className="space-y-2">
            <Label>{t('CamerasPage.templates.descriptionLabel')} <span className="text-muted-foreground text-xs">{t('CamerasPage.groupDialog.optional')}</span></Label>
            <Input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder={t('CamerasPage.templates.descriptionPlaceholder')}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('CamerasPage.actions.cancel')}</Button>
          <Button onClick={submit} disabled={!name.trim() || isPending}>
            {isPending ? t('CamerasPage.actions.saving') : t('CamerasPage.actions.create')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Sidebar · Groups + Filters
// ---------------------------------------------------------------------------

function CameraSidebar({
  filters,
  onFiltersChange,
  groups,
  cameras,
  onCreateGroup,
  onDeleteGroup,
}: {
  filters: Filters;
  onFiltersChange: (f: Filters) => void;
  groups: CameraGroup[];
  cameras: CameraDevice[];
  onCreateGroup: () => void;
  onDeleteGroup: (group: CameraGroup) => void;
}) {
  const { t } = useTranslation('cameras');
  const vendors = useMemo(
    () => [...new Set(cameras.map((c) => c.vendor).filter(Boolean))] as string[],
    [cameras],
  );

  const floors = useMemo(
    () => [...new Set(cameras.map((c) => c.floor).filter(Boolean))] as string[],
    [cameras],
  );

  const zones = useMemo(
    () => [...new Set(cameras.map((c) => c.zone).filter(Boolean))] as string[],
    [cameras],
  );

  const [filtersExpanded, setFiltersExpanded] = useState(true);
  const [groupsExpanded, setGroupsExpanded] = useState(true);

  const activeFilterCount = [
    filters.status !== 'all',
    filters.vendor !== 'all',
    filters.hasPtz !== null,
    filters.hasAudio !== null,
    filters.groupId !== null,
    filters.floor !== 'all',
    filters.zone !== 'all',
  ].filter(Boolean).length;

  return (
    <aside className="w-60 flex-shrink-0 space-y-1 overflow-y-auto max-h-[calc(100vh-120px)] pr-1 hidden lg:block">
      {/* Groups */}
      <div className="rounded-lg border bg-card">
        <button
          onClick={() => setGroupsExpanded(!groupsExpanded)}
          className="flex items-center justify-between w-full p-3 text-sm font-medium hover:bg-muted/50 rounded-t-lg"
        >
          <span className="flex items-center gap-2"><Folder className="h-4 w-4" /> {t('CamerasPage.sidebar.groups')}</span>
          {groupsExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </button>
        {groupsExpanded && (
          <div className="px-2 pb-2 space-y-0.5">
            <button
              onClick={() => onFiltersChange({ ...filters, groupId: null })}
              className={cn(
                'w-full flex items-center justify-between rounded px-2 py-1.5 text-sm hover:bg-muted/50',
                filters.groupId === null && 'bg-primary/10 text-primary font-medium',
              )}
            >
              <span>{t('CamerasPage.sidebar.allCameras')}</span>
              <Badge variant="secondary" className="text-[10px] px-1.5">{cameras.length}</Badge>
            </button>

            {groups.map((g) => (
              <div
                key={g.id}
                role="button"
                tabIndex={0}
                aria-pressed={filters.groupId === g.id}
                className={cn(
                  'flex items-center justify-between rounded px-2 py-1.5 text-sm hover:bg-muted/50 cursor-pointer group/g',
                  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                  filters.groupId === g.id && 'bg-primary/10 text-primary font-medium',
                )}
                onClick={() => onFiltersChange({ ...filters, groupId: g.id })}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onFiltersChange({ ...filters, groupId: g.id }); }
                }}
              >
                <span className="flex items-center gap-2">
                  <span className="h-2.5 w-2.5 rounded-full flex-shrink-0" style={{ backgroundColor: g.color }} />
                  <span className="truncate">{g.name}</span>
                </span>
                <div className="flex items-center gap-1">
                  <Badge variant="secondary" className="text-[10px] px-1.5">{g.camera_count}</Badge>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-5 w-5 opacity-0 group-hover/g:opacity-100"
                    aria-label={t('CamerasPage.sidebar.deleteGroupAria', { name: g.name })}
                    onClick={(e) => { e.stopPropagation(); onDeleteGroup(g); }}
                  >
                    <Trash2 className="h-3 w-3 text-muted-foreground" />
                  </Button>
                </div>
              </div>
            ))}

            <Button variant="ghost" size="sm" className="w-full justify-start gap-2 text-xs" onClick={onCreateGroup}>
              <FolderPlus className="h-3.5 w-3.5" /> {t('CamerasPage.sidebar.newGroup')}
            </Button>
          </div>
        )}
      </div>

      {/* Filters */}
      <div className="rounded-lg border bg-card">
        <button
          onClick={() => setFiltersExpanded(!filtersExpanded)}
          className="flex items-center justify-between w-full p-3 text-sm font-medium hover:bg-muted/50 rounded-t-lg"
        >
          <span className="flex items-center gap-2">
            <Filter className="h-4 w-4" />
            {t('CamerasPage.sidebar.filters')}
            {activeFilterCount > 0 && (
              <Badge variant="default" className="text-[10px] px-1.5 py-0">{activeFilterCount}</Badge>
            )}
          </span>
          {filtersExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </button>
        {filtersExpanded && (
          <div className="px-3 pb-3 space-y-3">
            <div className="space-y-1">
              <Label className="text-xs text-muted-foreground">{t('CamerasPage.filters.statusLabel')}</Label>
              <Select value={filters.status} onValueChange={(v) => onFiltersChange({ ...filters, status: v })}>
                <SelectTrigger className="h-8 text-xs">
                  <SelectValue placeholder={t('CamerasPage.filters.all')} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{t('CamerasPage.filters.allStatuses')}</SelectItem>
                  <SelectItem value="online">{t('CamerasPage.status.online')}</SelectItem>
                  <SelectItem value="offline">{t('CamerasPage.status.offline')}</SelectItem>
                  <SelectItem value="recording">{t('CamerasPage.status.recording')}</SelectItem>
                  <SelectItem value="error">{t('CamerasPage.status.error')}</SelectItem>
                  <SelectItem value="unknown">{t('CamerasPage.status.unknown')}</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {vendors.length > 0 && (
              <div className="space-y-1">
                <Label className="text-xs text-muted-foreground">{t('CamerasPage.filters.vendorLabel')}</Label>
                <Select value={filters.vendor} onValueChange={(v) => onFiltersChange({ ...filters, vendor: v })}>
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue placeholder={t('CamerasPage.filters.all')} />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">{t('CamerasPage.filters.allVendors')}</SelectItem>
                    {vendors.map((v) => (
                      <SelectItem key={v} value={v}>{v}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            {floors.length > 0 && (
              <div className="space-y-1">
                <Label className="text-xs text-muted-foreground">{t('CamerasPage.filters.floorLabel')}</Label>
                <Select value={filters.floor} onValueChange={(v) => onFiltersChange({ ...filters, floor: v })}>
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue placeholder={t('CamerasPage.filters.all')} />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">{t('CamerasPage.filters.allFloors')}</SelectItem>
                    {floors.map((f) => (
                      <SelectItem key={f} value={f}>{f}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            {zones.length > 0 && (
              <div className="space-y-1">
                <Label className="text-xs text-muted-foreground">{t('CamerasPage.filters.zoneLabel')}</Label>
                <Select value={filters.zone} onValueChange={(v) => onFiltersChange({ ...filters, zone: v })}>
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue placeholder={t('CamerasPage.filters.all')} />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">{t('CamerasPage.filters.allZones')}</SelectItem>
                    {zones.map((z) => (
                      <SelectItem key={z} value={z}>{z}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            <div className="space-y-2">
              <Label className="text-xs text-muted-foreground">{t('CamerasPage.filters.featuresLabel')}</Label>
              <label className="flex items-center gap-2 text-xs cursor-pointer">
                <Checkbox
                  checked={filters.hasPtz === true}
                  onCheckedChange={(v) => onFiltersChange({ ...filters, hasPtz: v ? true : null })}
                />
                {t('CamerasPage.filters.ptzOnly')}
              </label>
              <label className="flex items-center gap-2 text-xs cursor-pointer">
                <Checkbox
                  checked={filters.hasAudio === true}
                  onCheckedChange={(v) => onFiltersChange({ ...filters, hasAudio: v ? true : null })}
                />
                {t('CamerasPage.filters.audioOnly')}
              </label>
            </div>

            {activeFilterCount > 0 && (
              <Button
                variant="ghost"
                size="sm"
                className="w-full text-xs"
                onClick={() => onFiltersChange({ ...DEFAULT_FILTERS, search: filters.search })}
              >
                {t('CamerasPage.filters.clearFilters')}
              </Button>
            )}
          </div>
        )}
      </div>
    </aside>
  );
}

// ===========================================================================
// MAIN PAGE COMPONENT
// ===========================================================================

const VALID_VIEW_MODES = new Set<ViewMode>(['grid', 'list', 'live', 'events', 'health']);
const VALID_LAYOUTS = new Set(['1x1', '1+5', '2x2', '3x3', '4x4', '5x5', '6x6', '8x8']);

export default function CamerasPage() {
  const { t } = useTranslation('cameras');
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();
  const queryClient = useQueryClient();
  const { toast } = useToast();

  // Top-level 2-tab split: Dashboard (visual modes) vs List (canonical table).
  // Pathname drives the active tab so it survives reload + bookmark.
  const isListTab = location.pathname === '/cameras/list';
  const activeTab: 'dashboard' | 'list' = isListTab ? 'list' : 'dashboard';
  const handleTabChange = useCallback((v: string) => {
    navigate(v === 'list' ? '/cameras/list' : '/cameras', { replace: true });
  }, [navigate]);

  // Deep-link: read initial state from URL search params
  const [viewMode, setViewModeState] = useState<ViewMode>(() => {
    if (location.pathname === '/cameras/list') return 'list';
    const v = searchParams.get('view') as ViewMode;
    return v && VALID_VIEW_MODES.has(v) ? v : 'grid';
  });
  const [filters, setFilters] = useState<Filters>(() => ({
    ...DEFAULT_FILTERS,
    status: searchParams.get('status') || 'all',
    search: searchParams.get('search') || '',
    groupId: searchParams.get('group') || null,
  }));
  const [wallLayout, setWallLayoutState] = useState<WallLayout>(() => {
    const l = searchParams.get('layout') || '4x4';
    return VALID_LAYOUTS.has(l) ? (l as WallLayout) : '4x4';
  });
  const [wallCameraIds, setWallCameraIdsState] = useState<string[]>(() => {
    const c = searchParams.get('cameras');
    return c ? c.split(',').filter(Boolean) : [];
  });
  const [selectedCamera, setSelectedCamera] = useState<CameraDevice | null>(null);
  const [liveViewOpen, setLiveViewOpen] = useState(false);
  const [streamingPaused, setStreamingPaused] = useState(false);
  const [showAddDevice, setShowAddDevice] = useState(false);
  const [showGroupDialog, setShowGroupDialog] = useState(false);
  const [showSaveView, setShowSaveView] = useState(false);
  const [selectionMode, setSelectionMode] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  // Confirmation / prompt dialogs (replace native confirm()/prompt())
  const [deleteGroupTarget, setDeleteGroupTarget] = useState<CameraGroup | null>(null);
  const [deleteViewTarget, setDeleteViewTarget] = useState<CameraView | null>(null);
  const [deleteTemplateTarget, setDeleteTemplateTarget] = useState<{ id: string; name: string } | null>(null);
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false);
  const [showCreateTemplate, setShowCreateTemplate] = useState(false);

  // Deep-link: sync state → URL search params
  const setViewMode = useCallback((mode: ViewMode) => {
    setViewModeState(mode);
    // Clear event selection when leaving events tab to avoid stale state
    if (mode !== 'events') setSelectedEventIds(new Set());
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (mode === 'grid') next.delete('view'); else next.set('view', mode);
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  // Force list viewMode + always-on selection when on /cameras/list
  useEffect(() => {
    if (isListTab && viewMode !== 'list') setViewModeState('list');
    if (!isListTab && viewMode === 'list') setViewModeState('grid');
  }, [isListTab, viewMode]);
  useEffect(() => {
    if (isListTab) setSelectionMode(true);
  }, [isListTab]);

  const setWallLayout = useCallback((layout: WallLayout) => {
    setWallLayoutState(layout);
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (layout === '4x4') next.delete('layout'); else next.set('layout', layout);
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  const setWallCameraIds = useCallback((ids: string[]) => {
    setWallCameraIdsState(ids);
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (ids.length === 0) next.delete('cameras'); else next.set('cameras', ids.join(','));
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  // Site context
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // ---- Server-driven list pagination ----
  // The camera fleet can exceed the backend page cap (100), so the list is paged
  // server-side: search + status + site are forwarded to the backend (and live in
  // the queryKey), `total` comes back in the response, and prev/next walk `offset`.
  // This makes every camera reachable and keeps search/status filtering correct
  // across the whole fleet (not just the first page).
  const PAGE_SIZE = 100; // backend Query(le=100) cap
  const [listOffset, setListOffset] = useState(0);

  // Debounce the free-text search so we don't fire a request per keystroke.
  const [debouncedSearch, setDebouncedSearch] = useState(filters.search);
  useEffect(() => {
    const h = setTimeout(() => setDebouncedSearch(filters.search), 300);
    return () => clearTimeout(h);
  }, [filters.search]);

  // Reset to the first page whenever a server-side filter (search/status/site)
  // changes, otherwise we could land on an out-of-range offset.
  useEffect(() => {
    setListOffset(0);
  }, [debouncedSearch, filters.status, selectedSiteId]);

  // Data queries
  const { data: camerasData, isLoading, isError, error: camerasError, refetch } = useQuery({
    queryKey: [
      'cameras',
      {
        siteId: selectedSiteId,
        search: debouncedSearch || undefined,
        status: filters.status !== 'all' ? filters.status : undefined,
        limit: PAGE_SIZE,
        offset: listOffset,
      },
    ],
    queryFn: async () =>
      (
        await camerasApi.getAll({
          site_id: selectedSiteId || undefined,
          search: debouncedSearch || undefined,
          status: filters.status !== 'all' ? filters.status : undefined,
          limit: PAGE_SIZE,
          offset: listOffset,
        })
      ).data,
    refetchInterval: 30_000,   // auto-refresh status every 30s
    staleTime: 10_000,          // avoid unnecessary refetches within 10s
  });

  const { data: groupsData } = useQuery({
    queryKey: ['camera-groups', { siteId: selectedSiteId }],
    queryFn: async () => (await camerasApi.listGroups()).data,
  });

  const { data: viewsData } = useQuery({
    queryKey: ['camera-views', { siteId: selectedSiteId }],
    queryFn: async () => (await camerasApi.listViews()).data,
  });

  // Fetch group members for filtering when a group is selected
  const { data: activeGroupData } = useQuery({
    queryKey: ['camera-group-detail', filters.groupId],
    queryFn: () => filters.groupId ? camerasApi.getGroup(filters.groupId) : null,
    enabled: !!filters.groupId,
  });

  const cameras: CameraDevice[] = useMemo(() => camerasData?.items ?? [], [camerasData?.items]);
  // Server-reported total under the active search/status/site filters (for paging).
  const totalCameras: number = camerasData?.total ?? cameras.length;
  const groups: CameraGroup[] = groupsData?.items || [];
  const views: CameraView[] = viewsData?.items || [];

  // Mutations
  const deleteGroupMut = useMutation({
    mutationFn: (id: string) => camerasApi.deleteGroup(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['camera-groups'] });
      if (filters.groupId) setFilters((f) => ({ ...f, groupId: null }));
    },
    onError: () => {
      toast({ title: t('CamerasPage.toasts.deleteGroupFailed'), variant: 'destructive' as any, duration: 5000 });
    },
  });

  const deleteViewMut = useMutation({
    mutationFn: (id: string) => camerasApi.deleteView(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['camera-views'] }),
    onError: () => {
      toast({ title: t('CamerasPage.toasts.deleteViewFailed'), variant: 'destructive' as any, duration: 5000 });
    },
  });

  // ----------- Events queries -----------
  const [eventFilters, setEventFilters] = useState<{
    event_type: string; acknowledged: string; limit: number; offset: number;
  }>({ event_type: 'all', acknowledged: 'all', limit: 50, offset: 0 });

  const { data: eventsData, refetch: refetchEvents, isLoading: eventsLoading, isError: eventsError } = useQuery({
    queryKey: ['camera-events', eventFilters],
    queryFn: async () => {
      const params: Record<string, unknown> = { limit: eventFilters.limit, offset: eventFilters.offset };
      if (eventFilters.event_type !== 'all') params.event_type = eventFilters.event_type;
      if (eventFilters.acknowledged === 'true') params.acknowledged = true;
      if (eventFilters.acknowledged === 'false') params.acknowledged = false;
      return (await camerasApi.getEvents(params as any)).data;
    },
    enabled: viewMode === 'events',
    refetchInterval: viewMode === 'events' ? 15_000 : false,
  });

  const { data: unackCountData } = useQuery({
    queryKey: ['camera-events-unack-count'],
    queryFn: async () => (await camerasApi.getUnacknowledgedCount()).data,
    refetchInterval: 30_000,
  });
  const unacknowledgedCount = unackCountData?.count ?? 0;

  const [selectedEventIds, setSelectedEventIds] = useState<Set<string>>(new Set());

  const ackEventMut = useMutation({
    mutationFn: (eventId: string) => camerasApi.acknowledgeEvent(eventId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['camera-events'] });
      queryClient.invalidateQueries({ queryKey: ['camera-events-unack-count'] });
    },
    onError: () => toast({ title: t('CamerasPage.toasts.ackEventFailed'), variant: 'destructive' as any }),
  });

  const bulkAckMut = useMutation({
    mutationFn: (ids: string[]) => camerasApi.bulkAcknowledgeEvents(ids),
    onSuccess: (_, ids) => {
      queryClient.invalidateQueries({ queryKey: ['camera-events'] });
      queryClient.invalidateQueries({ queryKey: ['camera-events-unack-count'] });
      setSelectedEventIds(new Set());
      toast({ title: t('CamerasPage.toasts.eventsAcknowledged', { count: ids.length }) });
    },
    onError: () => toast({ title: t('CamerasPage.toasts.ackEventsFailed'), variant: 'destructive' as any }),
  });

  // ----------- Fleet health query -----------
  const { data: fleetHealthData, isLoading: healthLoading, isError: healthError } = useQuery({
    queryKey: ['camera-fleet-health'],
    queryFn: async () => (await camerasApi.getFleetHealth()).data,
    enabled: viewMode === 'health',
    refetchInterval: viewMode === 'health' ? 30_000 : false,
  });

  // Per-camera health for cards (lightweight poll)
  const { data: cameraHealthMap } = useQuery({
    queryKey: ['camera-health-batch', cameras.map((c) => c.id).join(',')],
    queryFn: async () => {
      const onlineCams = cameras.filter((c) => c.status === 'online' || c.status === 'recording').slice(0, 50);
      const results = await Promise.allSettled(
        onlineCams.map((c) => camerasApi.getHealth(String(c.id)).then((r) => ({ id: String(c.id), ...r.data }))),
      );
      const map: Record<string, { is_online: boolean; frame_rate?: number; bitrate_kbps?: number }> = {};
      for (const r of results) {
        if (r.status === 'fulfilled' && r.value) {
          const v = r.value;
          map[v.id] = {
            is_online: v.is_online,
            frame_rate: v.frame_rate ?? undefined,
            bitrate_kbps: v.bitrate_kbps ?? undefined,
          };
        }
      }
      return map;
    },
    enabled: cameras.length > 0,
    refetchInterval: 60_000,
    staleTime: 30_000,
  });

  // ----------- Recording templates -----------
  const { data: templatesData, refetch: refetchTemplates } = useQuery({
    queryKey: ['recording-templates'],
    queryFn: async () => (await camerasApi.listRecordingTemplates()).data,
  });
  const templates: { id: string; name: string; description?: string; is_builtin?: boolean; schedule: Record<string, unknown> }[] = templatesData || [];

  const deleteTemplateMut = useMutation({
    mutationFn: (id: string) => camerasApi.deleteRecordingTemplate(id),
    onSuccess: () => { refetchTemplates(); toast({ title: t('CamerasPage.toasts.templateDeleted') }); },
    onError: () => toast({ title: t('CamerasPage.toasts.deleteTemplateFailed'), variant: 'destructive' as any }),
  });

  const createTemplateMut = useMutation({
    mutationFn: ({ name, description }: { name: string; description?: string }) =>
      camerasApi.createRecordingTemplate({
        name,
        description,
        schedule: { type: 'continuous', days: ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'], start: '00:00', end: '23:59' },
      }),
    onSuccess: (_res, vars) => {
      refetchTemplates();
      setShowCreateTemplate(false);
      toast({ title: t('CamerasPage.toasts.templateCreated', { name: vars.name }) });
    },
    onError: () => toast({ title: t('CamerasPage.toasts.createTemplateFailed'), variant: 'destructive' as any }),
  });

  // ----------- Bulk camera mutations -----------
  const bulkDeleteMut = useMutation({
    mutationFn: async (ids: string[]) => {
      const results = await Promise.allSettled(ids.map((id) => camerasApi.delete(id)));
      const failed = results.filter((r) => r.status === 'rejected').length;
      return { total: ids.length, failed };
    },
    onSuccess: ({ total, failed }) => {
      queryClient.invalidateQueries({ queryKey: ['cameras'] });
      setSelectedIds(new Set());
      setSelectionMode(false);
      if (failed === 0) {
        toast({ title: t('CamerasPage.toasts.camerasDeleted', { count: total }) });
      } else {
        toast({ title: t('CamerasPage.toasts.camerasDeletedPartial', { succeeded: total - failed, total, failed }), variant: 'destructive' as any });
      }
    },
    onError: () => toast({ title: t('CamerasPage.toasts.deleteCamerasFailed'), variant: 'destructive' as any }),
  });

  const bulkGroupAssignMut = useMutation({
    mutationFn: async ({ groupId, cameraIds }: { groupId: string; cameraIds: string[] }) => {
      const group = await camerasApi.getGroup(groupId);
      const existing: string[] = group.data?.cameras?.map((c: any) => c.camera_id) || [];
      const merged = [...new Set([...existing, ...cameraIds])];
      await camerasApi.updateGroup(groupId, { camera_ids: merged });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['camera-groups'] });
      setSelectedIds(new Set());
      toast({ title: t('CamerasPage.toasts.camerasAddedToGroup') });
    },
    onError: () => toast({ title: t('CamerasPage.toasts.assignGroupFailed'), variant: 'destructive' as any }),
  });

  // Stats · `total` uses the server count (whole fleet); the status breakdowns are
  // computed over the loaded page (per-status fleet totals would need a dedicated
  // stats endpoint, /cameras/stats exists but isn't wired into this card yet).
  const stats = useMemo(() => ({
    total: totalCameras,
    online: cameras.filter((c) => c.status === 'online').length,
    offline: cameras.filter((c) => c.status === 'offline').length,
    recording: cameras.filter((c) => c.status === 'recording' || c.is_recording).length,
    error: cameras.filter((c) => c.status === 'error').length,
  }), [cameras, totalCameras]);

  // Real-time camera event toasts (throttled per camera, max 1 per 10s)
  const toastThrottleRef = useRef<Map<string, number>>(new Map());
  const camerasRef = useRef(cameras);
  camerasRef.current = cameras;

  useEffect(() => {
    const eventLabels: Record<string, string> = {
      motion: t('CamerasPage.eventToasts.motion'),
      line_cross: t('CamerasPage.eventToasts.lineCross'),
      intrusion: t('CamerasPage.eventToasts.intrusion'),
      tamper: t('CamerasPage.eventToasts.tamper'),
      video_loss: t('CamerasPage.eventToasts.videoLoss'),
      face_detect: t('CamerasPage.eventToasts.faceDetect'),
      audio_detect: t('CamerasPage.eventToasts.audioDetect'),
    };
    const throttleMap = toastThrottleRef.current;
    const THROTTLE_MS = 10_000;
    const handler = (e: Event) => {
      const detail = (e as CustomEvent).detail;
      if (!detail?.camera_id) return;

      // Per-camera throttle to prevent UI spam
      const now = Date.now();
      const lastToast = throttleMap.get(detail.camera_id) || 0;
      if (now - lastToast < THROTTLE_MS) return;
      throttleMap.set(detail.camera_id, now);

      const cam = camerasRef.current.find((c) => String(c.id) === detail.camera_id);
      const cameraName = cam?.name || t('CamerasPage.unknownCamera');
      const label = eventLabels[detail.event_type] || detail.event_type || t('CamerasPage.eventToasts.genericEvent');
      toast({
        title: `${label} · ${cameraName}`,
        description: detail.description || cam?.location || cam?.ip_address || undefined,
        duration: 8000,
      });
    };
    window.addEventListener('freesdn:camera-event', handler);
    return () => window.removeEventListener('freesdn:camera-event', handler);
  }, [toast, t]);

  // Filtering · includes group membership check
  const groupCameraIds = useMemo(() => {
    if (!filters.groupId || !activeGroupData?.data?.cameras) return null;
    return new Set(activeGroupData.data.cameras.map((c: { camera_id: string }) => c.camera_id));
  }, [filters.groupId, activeGroupData]);

  const filteredCameras = useMemo(() => {
    let result = cameras;

    // NOTE: free-text search + status are applied SERVER-side (forwarded into the
    // query) so they span the whole fleet, not just the loaded page. The filters
    // below are client-side refinements over the current server page, the backend
    // /cameras list API does not (yet) accept vendor/ptz/audio/floor/zone/group.

    // Group filter · only show cameras in the selected group
    if (groupCameraIds) {
      result = result.filter((c) => groupCameraIds.has(String(c.id)));
    }

    if (filters.vendor !== 'all') {
      result = result.filter((c) => c.vendor === filters.vendor);
    }

    if (filters.hasPtz === true) {
      result = result.filter((c) => c.has_ptz);
    }

    if (filters.hasAudio === true) {
      result = result.filter((c) => c.has_audio);
    }

    if (filters.floor !== 'all') {
      result = result.filter((c) => c.floor === filters.floor);
    }

    if (filters.zone !== 'all') {
      result = result.filter((c) => c.zone === filters.zone);
    }

    return result;
  }, [cameras, filters, groupCameraIds]);

  // Grid pagination · 24 cameras per *grid* page to cap simultaneous snapshot
  // polling. This sub-pages WITHIN the current server page (up to PAGE_SIZE=100);
  // when the user pages past the loaded set, the server `offset` advances to fetch
  // the next slice of the fleet (see grid pager below).
  const CAMERAS_PER_PAGE = 24;
  const [gridPage, setGridPage] = useState(0);

  // Reset the grid sub-page whenever the loaded server page or client refinements
  // change (new offset, new filter result, etc.).
  useEffect(() => { setGridPage(0); }, [filters, listOffset]);

  const paginatedCameras = useMemo(() => {
    const start = gridPage * CAMERAS_PER_PAGE;
    return filteredCameras.slice(start, start + CAMERAS_PER_PAGE);
  }, [filteredCameras, gridPage]);

  const gridPageCount = Math.ceil(filteredCameras.length / CAMERAS_PER_PAGE);

  // Server-page navigation (shared by grid + list). `total` is the server count
  // under the active search/status/site filters; client-only refinements (vendor,
  // ptz, audio, floor, zone, group) narrow the current page but don't change it.
  const hasPrevServerPage = listOffset > 0;
  const hasNextServerPage = listOffset + cameras.length < totalCameras;
  const serverPageNum = Math.floor(listOffset / PAGE_SIZE) + 1;
  const serverPageCount = Math.max(1, Math.ceil(totalCameras / PAGE_SIZE));
  const goPrevServerPage = useCallback(
    () => setListOffset((o) => Math.max(0, o - PAGE_SIZE)),
    [],
  );
  const goNextServerPage = useCallback(() => setListOffset((o) => o + PAGE_SIZE), []);

  // Whether client refinements are active (vendor/ptz/audio/floor/zone/group). When
  // they are, prev/next still walk the fleet but we annotate that the page is filtered.
  const clientRefinementActive =
    filters.vendor !== 'all' ||
    filters.hasPtz !== null ||
    filters.hasAudio !== null ||
    filters.floor !== 'all' ||
    filters.zone !== 'all' ||
    filters.groupId !== null;

  // Handlers
  const handleViewStream = useCallback((camera: CameraDevice) => {
    setSelectedCamera(camera);
    setLiveViewOpen(true);
  }, []);

  const handleOpenDetail = useCallback((camera: CameraDevice) => {
    navigate(`/cameras/${camera.id}`);
  }, [navigate]);

  const handleSelect = useCallback((id: string, checked: boolean) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (checked) next.add(id); else next.delete(id);
      return next;
    });
  }, []);

  const handlePlayAll = useCallback(() => {
    setViewMode('live');
    // eslint-disable-next-line react-hooks/exhaustive-deps -- setState is stable
  }, []);

  const handleLoadView = useCallback((view: CameraView) => {
    setWallCameraIds(view.camera_ids);
    setWallLayout((view.layout || '4x4') as WallLayout);
    setViewMode('live');
    // eslint-disable-next-line react-hooks/exhaustive-deps -- setState is stable
  }, []);

  const handleAddToLive = useCallback(() => {
    setWallCameraIds([...selectedIds]);
    setSelectedIds(new Set());
    setSelectionMode(false);
    setViewMode('live');
    // eslint-disable-next-line react-hooks/exhaustive-deps -- setState is stable
  }, [selectedIds]);

  /** Open camera live view modal (from wall enlarge button) */
  const handleWallLiveView = useCallback((cameraId: string) => {
    const cam = cameras.find((c) => String(c.id) === cameraId);
    if (cam) {
      setSelectedCamera(cam);
      setLiveViewOpen(true);
    }
  }, [cameras]);

  /** Open camera detail page (from wall double-click) */
  const handleWallOpenDetail = useCallback((cameraId: string) => {
    navigate(`/cameras/${cameraId}`);
  }, [navigate]);

  // Table columns
  const columns: DataTableColumn<CameraDevice>[] = useMemo(() => [
    {
      id: 'name',
      header: t('CamerasPage.columns.camera'),
      accessorFn: (camera) => camera.name?.toLowerCase() ?? '',
      cell: (camera) => (
        <div className="flex items-center gap-3">
          <div className="relative h-10 w-16 rounded bg-muted overflow-hidden flex-shrink-0">
            <SnapshotThumbnail cameraId={String(camera.id)} status={camera.status} paused={streamingPaused} />
          </div>
          <div>
            <div className="font-medium">{camera.name}</div>
            <div className="text-xs text-muted-foreground">{camera.model || camera.vendor || t('CamerasPage.unknown')}</div>
          </div>
        </div>
      ),
    },
    {
      id: 'ip_address',
      header: t('CamerasPage.columns.ipAddress'),
      accessorFn: (camera) => camera.ip_address ?? '',
      cell: (camera) => <code className="text-xs">{camera.ip_address || '-'}</code>,
    },
    {
      id: 'location',
      header: t('CamerasPage.columns.location'),
      accessorFn: (camera) => camera.location?.toLowerCase() ?? '',
      cell: (camera) => <span className="text-sm">{camera.location || '-'}</span>,
    },
    {
      id: 'status',
      header: t('CamerasPage.columns.status'),
      accessorFn: (camera) => camera.status,
      cell: (camera) => <StatusBadge status={camera.status} />,
    },
    {
      id: 'features',
      header: t('CamerasPage.columns.features'),
      sortable: false,
      cell: (camera) => (
        <div className="flex gap-1">
          {camera.has_ptz && <Badge variant="outline" className="text-[10px]">PTZ</Badge>}
          {camera.has_audio && <Badge variant="outline" className="text-[10px]">{t('CamerasPage.features.audio')}</Badge>}
          {camera.is_recording && <Badge variant="outline" className="text-[10px] text-red-500">REC</Badge>}
        </div>
      ),
    },
    {
      id: 'actions',
      header: '',
      sortable: false,
      cell: (camera) => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-8 w-8">
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => handleOpenDetail(camera)}>
              <Eye className="h-4 w-4 mr-2" /> {t('CamerasPage.actions.detail')}
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => handleViewStream(camera)}>
              <Video className="h-4 w-4 mr-2" /> {t('CamerasPage.actions.liveView')}
            </DropdownMenuItem>
            {camera.has_ptz && (
              <DropdownMenuItem onClick={() => navigate(`/cameras/${camera.id}`)}>
                <Move className="h-4 w-4 mr-2" /> {t('CamerasPage.actions.ptzControl')}
              </DropdownMenuItem>
            )}
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => navigate(`/cameras/${camera.id}`)}>
              <Settings className="h-4 w-4 mr-2" /> {t('CamerasPage.actions.settings')}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    },
  ], [handleOpenDetail, handleViewStream, navigate, streamingPaused, t]);

  // Wall cameras, convert CameraDevice[] to the shape CameraWall expects
  const wallCameras = useMemo(() =>
    cameras.map((c) => ({
      id: String(c.id),
      name: c.name,
      status: c.status as 'online' | 'offline' | 'recording' | 'error',
      ip_address: c.ip_address,
      location: c.location,
      has_ptz: c.has_ptz || false,
      has_audio: c.has_audio || false,
      is_recording: c.is_recording || c.status === 'recording',
      nvr_id: c.nvr_id,
    })),
    [cameras],
  );

  // ===========================================================================
  // RENDER
  // ===========================================================================

  return (
    <div className="space-y-4">
      {/* Header */}
      <PageHeader
        icon={Camera}
        title={t('CamerasPage.title')}
        description={t('CamerasPage.headerDescription', { total: stats.total, online: stats.online })}
        onRefresh={() => refetch()}
        refreshing={isLoading}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => navigate('/cameras/display?fill=true&mode=live')} className="gap-1.5">
              <Monitor className="h-4 w-4" /> {t('CamerasPage.actions.displayWall')}
            </Button>
            <Button variant="outline" size="sm" onClick={() => navigate('/cameras/playback')} className="gap-1.5">
              <Layers className="h-4 w-4" /> {t('CamerasPage.actions.multiPlayback')}
            </Button>
            <Button variant="outline" size="sm" onClick={handlePlayAll} className="gap-1.5">
              <Play className="h-4 w-4" /> {t('CamerasPage.actions.liveWall')}
            </Button>
            {!isListTab && (
              <Button
                variant={selectionMode ? 'secondary' : 'outline'}
                size="sm"
                onClick={() => { setSelectionMode(!selectionMode); setSelectedIds(new Set()); }}
                className="gap-1.5"
              >
                <Grip className="h-4 w-4" /> {t('CamerasPage.actions.select')}
              </Button>
            )}
            <Button size="sm" onClick={() => setShowAddDevice(true)} className="gap-1.5">
              <Plus className="h-4 w-4" /> {t('CamerasPage.actions.addCamera')}
            </Button>
          </div>
        }
      />

      <StatsGrid
        columns={4}
        isLoading={isLoading}
        stats={[
          {
            title: t('CamerasPage.stats.totalCameras'),
            value: stats.total,
            icon: Camera,
            variant: 'primary',
            description: t('CamerasPage.stats.allRegistered'),
          },
          {
            title: t('CamerasPage.stats.online'),
            value: stats.online,
            icon: CheckCircle,
            variant: 'success',
            description: stats.total > 0 ? t('CamerasPage.stats.reachable', { percent: Math.round((stats.online / stats.total) * 100) }) : t('CamerasPage.stats.noCameras'),
          },
          {
            title: t('CamerasPage.stats.recording'),
            value: stats.recording,
            icon: Activity,
            variant: 'info',
            description: t('CamerasPage.stats.activelyRecording'),
          },
          {
            title: t('CamerasPage.stats.issues'),
            value: stats.offline + stats.error,
            icon: AlertCircle,
            variant: 'destructive',
            description: t('CamerasPage.stats.issuesDescription', { offline: stats.offline, errors: stats.error }),
          },
        ]}
      />

      {/* Top-level tab strip · Dashboard (visual modes) vs List (canonical table) */}
      <Tabs value={activeTab} onValueChange={handleTabChange}>
        <TabsList>
          <TabsTrigger value="dashboard" className="gap-1.5">
            <LayoutGrid className="h-4 w-4" />
            {t('CamerasPage.tabs.dashboard')}
          </TabsTrigger>
          <TabsTrigger value="list" className="gap-1.5">
            <List className="h-4 w-4" />
            {t('CamerasPage.tabs.list')}
            <span className="ml-1 rounded-full bg-muted px-1.5 py-0.5 text-[10px] font-medium leading-none text-muted-foreground">
              {clientRefinementActive ? filteredCameras.length : totalCameras}
            </span>
          </TabsTrigger>
        </TabsList>
        <TabsContent value="dashboard" />
        <TabsContent value="list" />
      </Tabs>

      {/* Toolbar */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder={t('CamerasPage.searchPlaceholder')}
            value={filters.search}
            onChange={(e) => setFilters((f) => ({ ...f, search: e.target.value }))}
            className="pl-9 h-9"
          />
        </div>

        <Select value={filters.status} onValueChange={(v) => setFilters((f) => ({ ...f, status: v }))}>
          <SelectTrigger className="w-[130px] h-9 text-xs lg:hidden">
            <SelectValue placeholder={t('CamerasPage.filters.statusLabel')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('CamerasPage.filters.all')}</SelectItem>
            <SelectItem value="online">{t('CamerasPage.status.online')}</SelectItem>
            <SelectItem value="offline">{t('CamerasPage.status.offline')}</SelectItem>
            <SelectItem value="recording">{t('CamerasPage.status.recording')}</SelectItem>
            <SelectItem value="error">{t('CamerasPage.status.error')}</SelectItem>
            <SelectItem value="unknown">{t('CamerasPage.status.unknown')}</SelectItem>
          </SelectContent>
        </Select>

        <div className="flex-1" />

        {/* Saved views */}
        {views.length > 0 && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" className="gap-1.5 hidden sm:flex">
                <Layers className="h-4 w-4" /> {t('CamerasPage.actions.views')}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-52">
              {views.map((v) => (
                <DropdownMenuItem key={v.id} onClick={() => handleLoadView(v)} className="justify-between">
                  <span className="truncate">{v.name}</span>
                  <div className="flex items-center gap-1">
                    <Badge variant="secondary" className="text-[10px] px-1">{v.layout}</Badge>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-5 w-5"
                      aria-label={t('CamerasPage.actions.deleteViewAria', { name: v.name })}
                      onClick={(e) => { e.stopPropagation(); setDeleteViewTarget(v); }}
                    >
                      <X className="h-3 w-3" />
                    </Button>
                  </div>
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        )}

        {/* Save View (shown when live wall active) */}
        {viewMode === 'live' && (
          <Button variant="outline" size="sm" className="gap-1.5" onClick={() => setShowSaveView(true)}>
            <Bookmark className="h-4 w-4" /> {t('CamerasPage.actions.saveView')}
          </Button>
        )}

        {/* View mode toggle · only on Dashboard tab; List moved to top-level tab */}
        {!isListTab && (
          <div className="flex items-center gap-0.5 border rounded-lg p-0.5">
            <Button variant={viewMode === 'grid' ? 'secondary' : 'ghost'} size="icon" className="h-8 w-8" onClick={() => setViewMode('grid')} title={t('CamerasPage.viewModes.grid')}>
              <Grid3X3 className="h-4 w-4" />
            </Button>
            <Button variant={viewMode === 'live' ? 'secondary' : 'ghost'} size="icon" className="h-8 w-8" onClick={() => setViewMode('live')} title={t('CamerasPage.viewModes.liveWall')}>
              <LayoutGrid className="h-4 w-4" />
            </Button>
            <div className="w-px h-5 bg-border mx-0.5" />
            <Button variant={viewMode === 'events' ? 'secondary' : 'ghost'} size="sm" className="h-8 px-2 text-xs gap-1.5 relative" onClick={() => setViewMode('events')} title={t('CamerasPage.viewModes.events')}>
              <Bell className="h-4 w-4" />
              <span className="hidden sm:inline">{t('CamerasPage.viewModes.events')}</span>
              {unacknowledgedCount > 0 && (
                <span className="absolute -top-1 -right-1 h-4 min-w-4 px-1 rounded-full bg-destructive text-destructive-foreground text-[10px] font-bold flex items-center justify-center">
                  {unacknowledgedCount > 99 ? '99+' : unacknowledgedCount}
                </span>
              )}
            </Button>
            <Button variant={viewMode === 'health' ? 'secondary' : 'ghost'} size="sm" className="h-8 px-2 text-xs gap-1.5" onClick={() => setViewMode('health')} title={t('CamerasPage.viewModes.fleetHealth')}>
              <HeartPulse className="h-4 w-4" />
              <span className="hidden sm:inline">{t('CamerasPage.viewModes.health')}</span>
            </Button>
          </div>
        )}
      </div>

      {/* Main content area */}
      <div className="flex gap-4">
        {/* Sidebar · hidden on events/health views */}
        {viewMode !== 'events' && viewMode !== 'health' && (
          <CameraSidebar
            filters={filters}
            onFiltersChange={setFilters}
            groups={groups}
            cameras={cameras}
            onCreateGroup={() => setShowGroupDialog(true)}
            onDeleteGroup={(group) => setDeleteGroupTarget(group)}
          />
        )}

        {/* Content */}
        <div className="flex-1 min-w-0">
          {/* Loading skeleton */}
          {isLoading && viewMode === 'grid' && (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
              {Array.from({ length: 8 }).map((_, i) => (
                <Card key={`skeleton-${i}`} className="overflow-hidden">
                  <div className="aspect-video bg-muted animate-pulse" />
                  <CardContent noOffset className="p-2.5">
                    <div className="h-4 bg-muted animate-pulse rounded w-3/4" />
                  </CardContent>
                </Card>
              ))}
            </div>
          )}

          {/* Error banner */}
          {isError && (
            <Card className="border-destructive/50 bg-destructive/5 mb-4">
              <CardContent noOffset className="p-4 flex items-center gap-3">
                <AlertCircle className="h-5 w-5 text-destructive flex-shrink-0" />
                <div>
                  <p className="font-medium text-destructive">{t('CamerasPage.error.loadCamerasTitle')}</p>
                  <p className="text-sm text-muted-foreground">
                    {(camerasError as Error)?.message || t('CamerasPage.error.unexpected')}
                  </p>
                </div>
                <Button variant="outline" size="sm" className="ml-auto" onClick={() => refetch()}>
                  {t('CamerasPage.actions.retry')}
                </Button>
              </CardContent>
            </Card>
          )}

          {viewMode === 'grid' && !isLoading && (
            <SectionBoundary resetKeys={[viewMode]}>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
                {paginatedCameras.map((camera) => (
                  <CameraCard
                    key={camera.id}
                    camera={camera}
                    onViewStream={handleViewStream}
                    onOpenDetail={handleOpenDetail}
                    selected={selectedIds.has(String(camera.id))}
                    onSelect={handleSelect}
                    selectionMode={selectionMode}
                    snapshotPaused={streamingPaused}
                    healthData={cameraHealthMap?.[String(camera.id)]}
                  />
                ))}
                {filteredCameras.length === 0 && !isLoading && (
                  <div className="col-span-full">
                    <EmptyState
                      icon={Camera}
                      title={t('CamerasPage.empty.noCamerasTitle')}
                      description={t('CamerasPage.empty.noCamerasDescription')}
                    />
                  </div>
                )}
              </div>

              {/* Grid pagination · Prev/Next walk the 24-card grid sub-pages first,
                  then roll over to the previous/next server page so the WHOLE
                  fleet is reachable (no longer capped at the first 50/100). */}
              {(gridPageCount > 1 || hasPrevServerPage || hasNextServerPage) && (
                <div className="flex items-center justify-center gap-2 pt-4">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={gridPage === 0 && !hasPrevServerPage}
                    onClick={() => {
                      if (gridPage > 0) setGridPage((p) => p - 1);
                      else goPrevServerPage(); // roll back to previous server page
                    }}
                  >
                    <ChevronLeft className="h-4 w-4 mr-1" />
                    {t('CamerasPage.pagination.previous')}
                  </Button>
                  <span className="text-sm text-muted-foreground px-2">
                    {t('CamerasPage.pagination.pageOf', { current: gridPage + 1, total: Math.max(1, gridPageCount) })}
                    {serverPageCount > 1 && (
                      <span className="text-xs ml-1.5">
                        {t('CamerasPage.pagination.serverPage', {
                          current: serverPageNum,
                          total: serverPageCount,
                          defaultValue: `(set ${serverPageNum}/${serverPageCount})`,
                        })}
                      </span>
                    )}
                    <span className="text-xs ml-1.5">
                      {clientRefinementActive
                        ? t('CamerasPage.pagination.cameraCount', { count: filteredCameras.length })
                        : t('CamerasPage.pagination.cameraTotal', { count: totalCameras, defaultValue: `${totalCameras} cameras` })}
                    </span>
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={gridPage >= gridPageCount - 1 && !hasNextServerPage}
                    onClick={() => {
                      if (gridPage < gridPageCount - 1) setGridPage((p) => p + 1);
                      else goNextServerPage(); // advance to next server page (offset += PAGE_SIZE)
                    }}
                  >
                    {t('CamerasPage.pagination.next')}
                    <ChevronRight className="h-4 w-4 ml-1" />
                  </Button>
                </div>
              )}
            </SectionBoundary>
          )}

          {viewMode === 'list' && (
            <SectionBoundary resetKeys={[viewMode]}>
              {/* DataTable paginates 25/page WITHIN the loaded server page so only
                  the current page's live SnapshotThumbnails mount. The server-page
                  bar below walks `offset` so the whole fleet is reachable (the list
                  is no longer truncated to the first 50/100 cameras). */}
              <DataTable
                data={filteredCameras}
                columns={columns}
                isLoading={isLoading}
                selectable={selectionMode}
                onSelectionChange={(rows) => setSelectedIds(new Set(rows.map((r) => String(r.id))))}
                searchable={false}
                paginated
                defaultPageSize={25}
                itemName={t('CamerasPage.itemNameCameras')}
                getRowId={(row) => String(row.id)}
              />

              {/* Server-page navigation, reachability across the full fleet */}
              {(hasPrevServerPage || hasNextServerPage) && (
                <div className="flex items-center justify-center gap-2 pt-4">
                  <Button variant="outline" size="sm" disabled={!hasPrevServerPage} onClick={goPrevServerPage}>
                    <ChevronLeft className="h-4 w-4 mr-1" />
                    {t('CamerasPage.pagination.previous')}
                  </Button>
                  <span className="text-sm text-muted-foreground px-2">
                    {t('CamerasPage.pagination.serverPage', {
                      current: serverPageNum,
                      total: serverPageCount,
                      defaultValue: `set ${serverPageNum}/${serverPageCount}`,
                    })}
                    <span className="text-xs ml-1.5">
                      {t('CamerasPage.pagination.cameraTotal', { count: totalCameras, defaultValue: `${totalCameras} cameras` })}
                    </span>
                  </span>
                  <Button variant="outline" size="sm" disabled={!hasNextServerPage} onClick={goNextServerPage}>
                    {t('CamerasPage.pagination.next')}
                    <ChevronRight className="h-4 w-4 ml-1" />
                  </Button>
                </div>
              )}
            </SectionBoundary>
          )}

          {viewMode === 'live' && (
            <SectionBoundary resetKeys={[viewMode]}>
              <CameraWall
                cameras={wallCameras}
                initialLayout={wallLayout}
                initialCameraIds={wallCameraIds}
                onOpenDetail={handleWallOpenDetail}
                onOpenLiveView={handleWallLiveView}
                onLayoutChange={setWallLayout}
                onCameraIdsChange={setWallCameraIds}
                height="calc(100vh - 280px)"
              />
            </SectionBoundary>
          )}

          {/* EVENTS VIEW */}
          {viewMode === 'events' && (
            <SectionBoundary resetKeys={[viewMode]}>
            <div className="space-y-4">
              {/* Event filters */}
              <div className="flex items-center gap-3 flex-wrap">
                <Select value={eventFilters.event_type} onValueChange={(v) => setEventFilters((f) => ({ ...f, event_type: v, offset: 0 }))}>
                  <SelectTrigger className="w-[160px] h-9 text-xs">
                    <SelectValue placeholder={t('CamerasPage.events.eventTypePlaceholder')} />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">{t('CamerasPage.events.allTypes')}</SelectItem>
                    <SelectItem value="motion">{t('CamerasPage.events.types.motion')}</SelectItem>
                    <SelectItem value="line_cross">{t('CamerasPage.events.types.lineCross')}</SelectItem>
                    <SelectItem value="intrusion">{t('CamerasPage.events.types.intrusion')}</SelectItem>
                    <SelectItem value="tamper">{t('CamerasPage.events.types.tamper')}</SelectItem>
                    <SelectItem value="video_loss">{t('CamerasPage.events.types.videoLoss')}</SelectItem>
                    <SelectItem value="face_detect">{t('CamerasPage.events.types.faceDetect')}</SelectItem>
                    <SelectItem value="audio_detect">{t('CamerasPage.events.types.audioDetect')}</SelectItem>
                  </SelectContent>
                </Select>

                <Select value={eventFilters.acknowledged} onValueChange={(v) => setEventFilters((f) => ({ ...f, acknowledged: v, offset: 0 }))}>
                  <SelectTrigger className="w-[160px] h-9 text-xs">
                    <SelectValue placeholder={t('CamerasPage.filters.statusLabel')} />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">{t('CamerasPage.filters.allStatus')}</SelectItem>
                    <SelectItem value="false">{t('CamerasPage.events.unacknowledged')}</SelectItem>
                    <SelectItem value="true">{t('CamerasPage.events.acknowledged')}</SelectItem>
                  </SelectContent>
                </Select>

                <div className="flex-1" />

                {selectedEventIds.size > 0 && (
                  <Button
                    size="sm"
                    onClick={() => bulkAckMut.mutate([...selectedEventIds])}
                    disabled={bulkAckMut.isPending}
                    className="gap-1.5"
                  >
                    <CheckCheck className="h-4 w-4" />
                    {t('CamerasPage.events.acknowledgeN', { count: selectedEventIds.size })}
                  </Button>
                )}

                <Button size="sm" variant="outline" onClick={() => refetchEvents()} className="gap-1.5">
                  <RefreshCw className="h-3.5 w-3.5" /> {t('CamerasPage.actions.refresh')}
                </Button>
              </div>

              {/* Event list */}
              <Card>
                <div className="divide-y">
                  {eventsLoading && (
                    <div className="space-y-2 p-4">
                      {Array.from({ length: 6 }).map((_, i) => (
                        <div key={i} className="flex items-center gap-3">
                          <Skeleton className="h-10 w-10 rounded-md" />
                          <div className="flex-1 space-y-1.5">
                            <Skeleton className="h-4 w-2/3" />
                            <Skeleton className="h-3 w-1/3" />
                          </div>
                          <Skeleton className="h-5 w-16 rounded-full" />
                        </div>
                      ))}
                    </div>
                  )}
                  {eventsError && (
                    <div className="flex items-center gap-2 p-4 text-sm text-red-500 bg-red-500/10 rounded-md m-4">
                      <AlertTriangle className="h-4 w-4 shrink-0" />
                      {t('CamerasPage.events.loadFailed')} <Button size="sm" variant="outline" className="ml-2 h-7 text-xs" onClick={() => refetchEvents()}>{t('CamerasPage.actions.retry')}</Button>
                    </div>
                  )}
                  {!eventsLoading && !eventsError && (eventsData?.items ?? []).length === 0 && (
                    <div className="p-8">
                      <EmptyState
                        icon={Bell}
                        title={t('CamerasPage.events.emptyTitle')}
                        description={t('CamerasPage.events.emptyDescription')}
                      />
                    </div>
                  )}
                  {(eventsData?.items ?? []).map((event: any) => {
                    const cam = cameras.find((c) => String(c.id) === String(event.camera_id));
                    const eventTypeLabels: Record<string, { label: string; color: string }> = {
                      motion: { label: t('CamerasPage.events.types.motion'), color: 'bg-blue-500/10 text-blue-500' },
                      line_cross: { label: t('CamerasPage.events.types.lineCross'), color: 'bg-purple-500/10 text-purple-500' },
                      intrusion: { label: t('CamerasPage.events.types.intrusion'), color: 'bg-red-500/10 text-red-500' },
                      tamper: { label: t('CamerasPage.events.types.tamper'), color: 'bg-amber-500/10 text-amber-500' },
                      video_loss: { label: t('CamerasPage.events.types.videoLoss'), color: 'bg-red-500/10 text-red-500' },
                      face_detect: { label: t('CamerasPage.events.types.face'), color: 'bg-cyan-500/10 text-cyan-500' },
                      audio_detect: { label: t('CamerasPage.features.audio'), color: 'bg-teal-500/10 text-teal-500' },
                    };
                    const typeInfo = eventTypeLabels[event.event_type] || { label: event.event_type, color: 'bg-muted-foreground/10 text-muted-foreground' };

                    return (
                      <div key={event.id} className="flex items-center gap-3 px-4 py-3 hover:bg-muted/30 transition-colors">
                        <Checkbox
                          checked={selectedEventIds.has(event.id)}
                          disabled={event.is_acknowledged}
                          onCheckedChange={(v) => {
                            setSelectedEventIds((prev) => {
                              const next = new Set(prev);
                              if (v) next.add(event.id); else next.delete(event.id);
                              return next;
                            });
                          }}
                        />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <Badge variant="secondary" className={cn('text-[10px]', typeInfo.color)}>
                              {typeInfo.label}
                            </Badge>
                            <span className="text-sm font-medium truncate">{cam?.name || t('CamerasPage.unknownCamera')}</span>
                          </div>
                          {event.description && (
                            <p className="text-xs text-muted-foreground mt-0.5 truncate">{event.description}</p>
                          )}
                        </div>
                        <div className="flex items-center gap-3 shrink-0">
                          <span className="text-xs text-muted-foreground">
                            {event.timestamp ? new Date(event.timestamp).toLocaleString() : '—'}
                          </span>
                          {event.is_acknowledged ? (
                            <Badge variant="outline" className="text-[10px] gap-1 text-emerald-500 border-emerald-500/30">
                              <CheckCircle className="h-3 w-3" /> {t('CamerasPage.events.ack')}
                            </Badge>
                          ) : (
                            <Button
                              size="sm"
                              variant="outline"
                              className="h-7 text-xs"
                              onClick={() => ackEventMut.mutate(event.id)}
                              disabled={ackEventMut.isPending}
                            >
                              {t('CamerasPage.events.acknowledge')}
                            </Button>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Pagination */}
                {(eventsData?.total ?? 0) > eventFilters.limit && (
                  <div className="flex items-center justify-center gap-2 p-3 border-t">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={eventFilters.offset === 0}
                      onClick={() => setEventFilters((f) => ({ ...f, offset: Math.max(0, f.offset - f.limit) }))}
                    >
                      <ChevronLeft className="h-4 w-4" /> {t('CamerasPage.pagination.previous')}
                    </Button>
                    <span className="text-xs text-muted-foreground">
                      {t('CamerasPage.pagination.range', { from: eventFilters.offset + 1, to: Math.min(eventFilters.offset + eventFilters.limit, eventsData?.total ?? 0), total: eventsData?.total ?? 0 })}
                    </span>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={eventFilters.offset + eventFilters.limit >= (eventsData?.total ?? 0)}
                      onClick={() => setEventFilters((f) => ({ ...f, offset: f.offset + f.limit }))}
                    >
                      {t('CamerasPage.pagination.next')} <ChevronRight className="h-4 w-4" />
                    </Button>
                  </div>
                )}
              </Card>
            </div>
            </SectionBoundary>
          )}

          {/* HEALTH VIEW */}
          {viewMode === 'health' && (
            <SectionBoundary resetKeys={[viewMode]}>
            <div className="space-y-4">
              {healthLoading && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                    {Array.from({ length: 5 }).map((_, i) => (
                      <Skeleton key={i} className="h-24 rounded-xl" />
                    ))}
                  </div>
                  <Skeleton className="h-[280px] w-full rounded-xl" />
                </div>
              )}
              {healthError && (
                <div className="flex items-center gap-2 p-4 text-sm text-red-500 bg-red-500/10 rounded-md">
                  <AlertTriangle className="h-4 w-4 shrink-0" />
                  {t('CamerasPage.health.loadFailed')}
                </div>
              )}
              {/* Fleet summary cards */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                <Card>
                  <CardContent noOffset className="p-3 flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-blue-500/10">
                      <Camera className="h-5 w-5 text-blue-500" />
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">{t('CamerasPage.health.total')}</p>
                      <p className="text-xl font-bold">{fleetHealthData?.total_cameras ?? stats.total}</p>
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent noOffset className="p-3 flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-emerald-500/10">
                      <Wifi className="h-5 w-5 text-emerald-500" />
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">{t('CamerasPage.status.online')}</p>
                      <p className="text-xl font-bold">{fleetHealthData?.online_cameras ?? stats.online}</p>
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent noOffset className="p-3 flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-red-500/10">
                      <WifiOff className="h-5 w-5 text-red-500" />
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">{t('CamerasPage.status.offline')}</p>
                      <p className="text-xl font-bold">{fleetHealthData?.offline_cameras ?? stats.offline}</p>
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent noOffset className="p-3 flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-purple-500/10">
                      <Gauge className="h-5 w-5 text-purple-500" />
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">{t('CamerasPage.health.avgBitrate')}</p>
                      <p className="text-xl font-bold">{fleetHealthData?.avg_bitrate_kbps ? `${Math.round(fleetHealthData.avg_bitrate_kbps)}` : '-'}<span className="text-xs font-normal ml-0.5">kbps</span></p>
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent noOffset className="p-3 flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-amber-500/10">
                      <Activity className="h-5 w-5 text-amber-500" />
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">{t('CamerasPage.health.totalBandwidth')}</p>
                      <p className="text-xl font-bold">{fleetHealthData?.total_bandwidth_mbps ? `${fleetHealthData.total_bandwidth_mbps.toFixed(1)}` : '-'}<span className="text-xs font-normal ml-0.5">Mbps</span></p>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Per-camera health table */}
              <Card>
                <CardContent className="p-0">
                  <div className="px-4 py-3 border-b flex items-center justify-between">
                    <h3 className="text-sm font-semibold">{t('CamerasPage.health.perCameraTitle')}</h3>
                    <div className="flex items-center gap-3 text-xs text-muted-foreground">
                      <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-emerald-400" /> {t('CamerasPage.health.healthy')}</span>
                      <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-amber-400" /> {t('CamerasPage.health.degraded')}</span>
                      <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-muted-foreground" /> {t('CamerasPage.status.offline')}</span>
                    </div>
                  </div>
                  <div className="divide-y max-h-[500px] overflow-y-auto">
                    {filteredCameras.map((cam) => {
                      const h = cameraHealthMap?.[String(cam.id)];
                      const isOn = cam.status === 'online' || cam.status === 'recording';
                      const dotColor = !isOn ? 'bg-muted-foreground' : h?.frame_rate && h.frame_rate >= 10 ? 'bg-emerald-400' : 'bg-amber-400';

                      return (
                        <div key={cam.id} className="flex items-center gap-3 px-4 py-2.5 hover:bg-muted/30 text-sm">
                          <span className={cn('h-2.5 w-2.5 rounded-full shrink-0', dotColor)} />
                          <span className="font-medium truncate min-w-[180px]">{cam.name}</span>
                          <span className="text-xs text-muted-foreground w-24">{cam.status}</span>
                          <span className="text-xs font-mono w-20 text-right">
                            {h?.frame_rate != null ? `${h.frame_rate} fps` : '-'}
                          </span>
                          <span className="text-xs font-mono w-24 text-right">
                            {h?.bitrate_kbps != null ? `${h.bitrate_kbps} kbps` : '-'}
                          </span>
                          <span className="text-xs text-muted-foreground truncate flex-1">
                            {cam.location || cam.ip_address || ''}
                          </span>
                        </div>
                      );
                    })}
                    {cameras.length === 0 && (
                      <div className="p-8">
                        <EmptyState icon={HeartPulse} title={t('CamerasPage.health.emptyTitle')} description={t('CamerasPage.health.emptyDescription')} />
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>

              {/* Recording Templates */}
              <Card>
                <CardContent className="p-0">
                  <div className="px-4 py-3 border-b flex items-center justify-between">
                    <h3 className="text-sm font-semibold">{t('CamerasPage.templates.title')}</h3>
                    <Button
                      size="sm"
                      variant="outline"
                      className="gap-1.5 h-7 text-xs"
                      onClick={() => setShowCreateTemplate(true)}
                    >
                      <Plus className="h-3.5 w-3.5" /> {t('CamerasPage.templates.newTemplate')}
                    </Button>
                  </div>
                  <div className="divide-y">
                    {templates.length === 0 && (
                      <div className="p-6 text-center text-sm text-muted-foreground">
                        {t('CamerasPage.templates.empty')}
                      </div>
                    )}
                    {templates.map((tpl) => (
                      <div key={tpl.id} className="flex items-center justify-between px-4 py-3 hover:bg-muted/30">
                        <div>
                          <p className="text-sm font-medium">{tpl.name}</p>
                          {tpl.description && <p className="text-xs text-muted-foreground">{tpl.description}</p>}
                        </div>
                        <div className="flex items-center gap-2">
                          {tpl.is_builtin && <Badge variant="secondary" className="text-[10px]">{t('CamerasPage.templates.builtIn')}</Badge>}
                          {selectionMode && selectedIds.size > 0 && (
                            <Button
                              size="sm"
                              variant="outline"
                              className="h-7 text-xs gap-1"
                              onClick={async () => {
                                const ids = [...selectedIds];
                                const body = templateToRecordingSchedule(tpl.schedule);
                                const results = await Promise.allSettled(
                                  ids.map((camId) => camerasApi.setRecordingSchedule(camId, body as any)),
                                );
                                const failed = results.filter((r) => r.status === 'rejected').length;
                                if (failed === 0) {
                                  toast({ title: t('CamerasPage.toasts.scheduleApplied', { count: ids.length }) });
                                } else {
                                  // Some or all failed, never report unconditional success.
                                  toast({ title: t('CamerasPage.toasts.applyScheduleFailed'), variant: 'destructive' as any });
                                }
                              }}
                            >
                              {t('CamerasPage.templates.applyToSelected', { count: selectedIds.size })}
                            </Button>
                          )}
                          {!tpl.is_builtin && (
                            <Button
                              size="icon"
                              variant="ghost"
                              className="h-7 w-7"
                              aria-label={t('CamerasPage.templates.deleteTemplateAria', { name: tpl.name })}
                              onClick={() => setDeleteTemplateTarget({ id: tpl.id, name: tpl.name })}
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </Button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
            </SectionBoundary>
          )}
        </div>
      </div>

      {/* Canonical bulk actions bar (fixed pill, bottom-center) */}
      <BulkActionsBar
        selectedCount={selectedIds.size}
        onClear={() => setSelectedIds(new Set())}
        itemName={t('CamerasPage.itemNameCamera')}
        actions={[
          {
            label: t('CamerasPage.bulk.openInLiveWall'),
            icon: Monitor,
            onClick: handleAddToLive,
          },
          {
            label: t('CamerasPage.actions.delete'),
            icon: Trash2,
            variant: 'destructive',
            onClick: () => setBulkDeleteOpen(true),
          },
        ]}
      >
        {/* Group picker · sits inline with the canonical actions */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              className="inline-flex items-center gap-2 rounded-full px-3 py-1.5 text-sm font-medium transition-colors hover:bg-background/10 disabled:opacity-50"
              disabled={groups.length === 0}
            >
              <Folder className="h-4 w-4" />
              {t('CamerasPage.bulk.assignGroup')}
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" side="top">
            {groups.length === 0 && (
              <DropdownMenuItem disabled>{t('CamerasPage.bulk.noGroups')}</DropdownMenuItem>
            )}
            {groups.map((g) => (
              <DropdownMenuItem
                key={g.id}
                onClick={() => bulkGroupAssignMut.mutate({ groupId: g.id, cameraIds: [...selectedIds] })}
              >
                {g.name}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      </BulkActionsBar>

      {/* Dialogs */}
      <AddDeviceDialog open={showAddDevice} onOpenChange={setShowAddDevice} onSuccess={() => refetch()} />

      {selectedCamera && (
        <CameraLiveViewModal
          open={liveViewOpen}
          onOpenChange={(open) => {
            setLiveViewOpen(open);
            if (!open) setSelectedCamera(null);
          }}
          onStreamingChange={setStreamingPaused}
          camera={{
            id: String(selectedCamera.id),
            name: selectedCamera.name,
            ip_address: selectedCamera.ip_address,
            location: selectedCamera.location,
            model: selectedCamera.model,
            vendor: selectedCamera.vendor,
            status: selectedCamera.status,
            is_recording: selectedCamera.is_recording,
            has_ptz: selectedCamera.has_ptz || false,
            has_audio: selectedCamera.has_audio || false,
          }}
        />
      )}

      <GroupDialog open={showGroupDialog} onOpenChange={setShowGroupDialog} cameras={cameras} />

      <SaveViewDialog
        open={showSaveView}
        onOpenChange={setShowSaveView}
        liveCameraIds={wallCameraIds}
        layout={wallLayout}
      />

      {/* Create recording template (replaces native prompt) */}
      <CreateTemplateDialog
        open={showCreateTemplate}
        onOpenChange={setShowCreateTemplate}
        onSubmit={(values) => createTemplateMut.mutate(values)}
        isPending={createTemplateMut.isPending}
      />

      {/* Delete group confirmation (replaces native confirm) */}
      <AlertDialog open={!!deleteGroupTarget} onOpenChange={(o) => !o && setDeleteGroupTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('CamerasPage.deleteDialog.groupTitle')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('CamerasPage.deleteDialog.groupDescription', { name: deleteGroupTarget?.name })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteGroupMut.isPending}>{t('CamerasPage.actions.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              disabled={deleteGroupMut.isPending}
              onClick={() => {
                if (deleteGroupTarget) deleteGroupMut.mutate(deleteGroupTarget.id);
                setDeleteGroupTarget(null);
              }}
            >
              {t('CamerasPage.actions.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete saved view confirmation */}
      <AlertDialog open={!!deleteViewTarget} onOpenChange={(o) => !o && setDeleteViewTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('CamerasPage.deleteDialog.viewTitle')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('CamerasPage.deleteDialog.viewDescription', { name: deleteViewTarget?.name })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteViewMut.isPending}>{t('CamerasPage.actions.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              disabled={deleteViewMut.isPending}
              onClick={() => {
                if (deleteViewTarget) deleteViewMut.mutate(deleteViewTarget.id);
                setDeleteViewTarget(null);
              }}
            >
              {t('CamerasPage.actions.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete recording template confirmation */}
      <AlertDialog open={!!deleteTemplateTarget} onOpenChange={(o) => !o && setDeleteTemplateTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('CamerasPage.deleteDialog.templateTitle')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('CamerasPage.deleteDialog.templateDescription', { name: deleteTemplateTarget?.name })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteTemplateMut.isPending}>{t('CamerasPage.actions.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              disabled={deleteTemplateMut.isPending}
              onClick={() => {
                if (deleteTemplateTarget) deleteTemplateMut.mutate(deleteTemplateTarget.id);
                setDeleteTemplateTarget(null);
              }}
            >
              {t('CamerasPage.actions.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Bulk delete cameras confirmation */}
      <AlertDialog open={bulkDeleteOpen} onOpenChange={(o) => !o && setBulkDeleteOpen(false)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('CamerasPage.deleteDialog.bulkTitle')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('CamerasPage.deleteDialog.bulkDescription', { count: selectedIds.size })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={bulkDeleteMut.isPending}>{t('CamerasPage.actions.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              disabled={bulkDeleteMut.isPending}
              onClick={() => {
                bulkDeleteMut.mutate([...selectedIds]);
                setBulkDeleteOpen(false);
              }}
            >
              {t('CamerasPage.actions.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
