// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Camera Detail / Control Page
 *
 * Full camera management with live view, PTZ, image tuning, recordings and events.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState, useCallback, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Activity,
  ArrowLeft,
  Camera,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronUp,
  Circle,
  Download,
  Eye,
  HardDrive,
  ShieldCheck,
  Trash2,
  Home,
  Image as ImageIcon,
  Info,
  Loader2,
  Monitor,
  Move,
  RefreshCw,
  RotateCcw,
  Save,
  Settings,
  Sliders,
  Square,
  Sun,
  Video,
  VideoOff,
  VolumeX,
  Wifi,
  WifiOff,
  ZoomIn,
  ZoomOut,
  Shield,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import { Slider } from '@/components/ui/slider';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import { camerasApi, evidenceApi, getApiErrorMessage, type EvidenceArchive } from '@/lib/api';
import { PageHeader } from '@/components/layout';
import { EventFeedPanel } from '@/components/cameras/CameraEventAlerts';
import { VendorCapabilityNote } from '@/components/cameras/VendorCapabilityNote';
import DetectionConfigPanel from '@/components/cameras/DetectionConfigPanel';
import RecordingSchedulePanel from '@/components/cameras/RecordingSchedulePanel';
import HolidaySchedulePanel from '@/components/cameras/HolidaySchedulePanel';
import PTZToursPanel from '@/components/cameras/PTZToursPanel';
import CameraHealthPanel from '@/components/cameras/CameraHealthPanel';
import { CameraAccessPanel } from '@/components/cameras/CameraAccessPanel';
import { useToast } from '@/hooks/use-toast';

// ─── Types ──────────────────────────────────────────────────────────────────

interface CameraDetail {
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
  camera_type: string;
  device_type?: string;
  status: 'online' | 'offline' | 'recording' | 'error' | 'unknown';
  is_recording: boolean;
  has_ptz: boolean;
  has_audio: boolean;
  has_two_way_audio: boolean;
  has_ir: boolean;
  resolution_width?: number;
  resolution_height?: number;
  location?: string;
  floor?: string;
  channel_id?: number;
  nvr_id?: string;
  site_id: string;
  last_seen?: string;
  motion_detection_enabled: boolean;
  rtsp_main_stream?: string;
  rtsp_sub_stream?: string;
  // Backend returns a boolean 'configured' flag here, never the key string.
  stream_encryption_key?: boolean;
  settings?: Record<string, any>;
  created_at?: string;
  updated_at?: string;
}

interface ImageSettings {
  brightness: number;
  contrast: number;
  saturation: number;
  sharpness: number;
  hue: number;
  wdr_enabled?: boolean;
  wdr_level?: number;
  noise_reduction_enabled?: boolean;
  noise_reduction_level?: number;
  ir_cut_filter?: string;
  exposure_mode?: string;
  backlight_mode?: string;
}

interface PTZPreset {
  id: number;
  name: string;
  enabled?: boolean;
}

// ─── Constants ──────────────────────────────────────────────────────────────

const VALID_TABS = new Set(['overview', 'stream', 'ptz', 'image', 'recordings', 'events', 'detection', 'schedule', 'health', 'holidays', 'access']);
const DEFAULT_TAB = 'overview';

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function CameraDetailPage() {
  const { t } = useTranslation('cameras');
  const { id, tab } = useParams<{ id: string; tab?: string }>();
  const navigate = useNavigate();
  const activeTab = tab && VALID_TABS.has(tab) ? tab : DEFAULT_TAB;

  // ── Camera data ─────────────────────────────────────────
  const {
    data: cameraRes,
    isLoading,
    isError,
    refetch,
  } = useQuery({
    queryKey: ['camera', id],
    queryFn: () => camerasApi.getById(id!),
    enabled: !!id,
    refetchInterval: 30_000,
  });

  const camera: CameraDetail | undefined = cameraRes?.data;

  // ── Tab change via URL ──────────────────────────────────
  const handleTabChange = useCallback(
    (value: string) => {
      navigate(`/cameras/${id}/${value}`, { replace: true });
    },
    [id, navigate],
  );

  // ── Loading state ───────────────────────────────────────
  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <Skeleton className="h-10 w-10 rounded-lg" />
          <div className="space-y-2">
            <Skeleton className="h-6 w-48" />
            <Skeleton className="h-4 w-32" />
          </div>
        </div>
        <Skeleton className="h-96 w-full" />
      </div>
    );
  }

  // ── Error / Not Found ──────────────────────────────────
  if (isError || !camera) {
    return (
      <EmptyState
        icon={VideoOff}
        title={t('CameraDetailPage.notFound.title')}
        description={t('CameraDetailPage.notFound.description')}
        action={{
          label: t('CameraDetailPage.notFound.backToCameras'),
          icon: ArrowLeft,
          onClick: () => navigate('/cameras'),
        }}
      />
    );
  }

  const isHikvision = camera.device_type === 'hikvision';

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        icon={Camera}
        title={camera.name}
        subtitle={[
          camera.model,
          camera.ip_address,
          camera.channel_id != null
            ? t('CameraDetailPage.header.channel', { channel: camera.channel_id })
            : null,
        ]
          .filter(Boolean)
          .join(' · ')}
        onRefresh={() => refetch()}
        actions={
          <div className="flex items-center gap-2">
            <StatusBadge status={camera.status} />
            <Button variant="outline" onClick={() => navigate('/cameras')}>
              <ArrowLeft className="h-4 w-4 mr-2" />
              {t('CameraDetailPage.header.back')}
            </Button>
          </div>
        }
      />

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={handleTabChange}>
        <TabsList>
          <TabsTrigger value="overview" className="gap-1.5">
            <Info className="h-3.5 w-3.5" />
            {t('CameraDetailPage.tabs.overview')}
          </TabsTrigger>
          <TabsTrigger value="stream" className="gap-1.5">
            <Video className="h-3.5 w-3.5" />
            {t('CameraDetailPage.tabs.liveView')}
          </TabsTrigger>
          {camera.has_ptz && (
            <TabsTrigger value="ptz" className="gap-1.5">
              <Move className="h-3.5 w-3.5" />
              {t('CameraDetailPage.tabs.ptz')}
            </TabsTrigger>
          )}
          {isHikvision && (
            <TabsTrigger value="image" className="gap-1.5">
              <Sliders className="h-3.5 w-3.5" />
              {t('CameraDetailPage.tabs.image')}
            </TabsTrigger>
          )}
          <TabsTrigger value="recordings" className="gap-1.5">
            <HardDrive className="h-3.5 w-3.5" />
            {t('CameraDetailPage.tabs.recordings')}
          </TabsTrigger>
          <TabsTrigger value="events" className="gap-1.5">
            <Monitor className="h-3.5 w-3.5" />
            {t('CameraDetailPage.tabs.events')}
          </TabsTrigger>
          {isHikvision && (
            <TabsTrigger value="detection" className="gap-1.5">
              <Eye className="h-3.5 w-3.5" />
              {t('CameraDetailPage.tabs.detection')}
            </TabsTrigger>
          )}
          {isHikvision && (
            <TabsTrigger value="schedule" className="gap-1.5">
              <HardDrive className="h-3.5 w-3.5" />
              {t('CameraDetailPage.tabs.schedule')}
            </TabsTrigger>
          )}
          <TabsTrigger value="health" className="gap-1.5">
            <Activity className="h-3.5 w-3.5" />
            {t('CameraDetailPage.tabs.health')}
          </TabsTrigger>
          <TabsTrigger value="access" className="gap-1.5">
            <Shield className="h-3.5 w-3.5" />
            {t('CameraDetailPage.tabs.access')}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-4">
          <OverviewTab camera={camera} />
        </TabsContent>

        <TabsContent value="stream" className="mt-4">
          <StreamTab camera={camera} />
        </TabsContent>

        {camera.has_ptz && (
          <TabsContent value="ptz" className="mt-4">
            <PTZTab camera={camera} />
          </TabsContent>
        )}

        {isHikvision && (
          <TabsContent value="image" className="mt-4">
            <ImageSettingsTab camera={camera} />
          </TabsContent>
        )}

        <TabsContent value="recordings" className="mt-4">
          <RecordingsTab camera={camera} />
        </TabsContent>

        <TabsContent value="events" className="mt-4">
          <EventsTab camera={camera} />
        </TabsContent>

        {isHikvision && (
          <TabsContent value="detection" className="mt-4">
            <DetectionConfigPanel cameraId={camera.id} vendor={camera.vendor} />
          </TabsContent>
        )}

        {isHikvision && (
          <TabsContent value="schedule" className="mt-4">
            <div className="space-y-6">
              <RecordingSchedulePanel cameraId={camera.id} />
              <HolidaySchedulePanel cameraId={camera.id} nvrId={camera.nvr_id} />
            </div>
          </TabsContent>
        )}

        <TabsContent value="health" className="mt-4">
          <CameraHealthPanel cameraId={camera.id} />
        </TabsContent>

        <TabsContent value="access" className="mt-4">
          <CameraAccessPanel cameraId={camera.id} cameraName={camera.name} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ─── Status Badge ───────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const { t } = useTranslation('cameras');
  const cfg: Record<string, { icon: typeof Wifi; label: string; cls: string }> = {
    online: { icon: Wifi, label: t('CameraDetailPage.status.online'), cls: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' },
    offline: { icon: WifiOff, label: t('CameraDetailPage.status.offline'), cls: 'bg-red-500/10 text-red-500 border-red-500/20' },
    recording: { icon: Circle, label: t('CameraDetailPage.status.recording'), cls: 'bg-blue-500/10 text-blue-500 border-blue-500/20 animate-pulse' },
    error: { icon: WifiOff, label: t('CameraDetailPage.status.error'), cls: 'bg-amber-500/10 text-amber-500 border-amber-500/20' },
    unknown: { icon: WifiOff, label: t('CameraDetailPage.status.unknown'), cls: 'bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20' },
  };
  const c = cfg[status] || cfg.unknown;
  const Icon = c.icon;
  return (
    <Badge variant="outline" className={cn('gap-1', c.cls)}>
      <Icon className="h-3 w-3" />
      {c.label}
    </Badge>
  );
}

// ─── Overview Tab ───────────────────────────────────────────────────────────

function OverviewTab({ camera }: { camera: CameraDetail }) {
  const { t } = useTranslation('cameras');
  const queryClient = useQueryClient();
  // stream_encryption_key on the camera is a boolean 'configured' flag, never the key
  // string. The editable input is always independent and starts blank.
  const [encryptionKey, setEncryptionKey] = useState('');
  const [showKey, setShowKey] = useState(false);

  const { toast } = useToast();
  const encKeyMut = useMutation({
    mutationFn: (key: string) => camerasApi.update(camera.id, { stream_encryption_key: key || '' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['camera', camera.id] });
      toast({ title: t('CameraDetailPage.overview.encryption.savedToast') });
    },
    onError: () => {
      toast({ title: t('CameraDetailPage.overview.encryption.saveFailedToast'), variant: 'destructive' as any });
    },
  });

  const isHikvision = (camera.vendor || '').toLowerCase().includes('hikvision');
  const keyConfigured = !!camera.stream_encryption_key;
  const keyChanged = encryptionKey !== '';

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Camera info card */}
      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Info className="h-4 w-4" />
            {t('CameraDetailPage.overview.deviceInformation')}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-x-8 gap-y-3 text-sm">
            <InfoRow label={t('CameraDetailPage.overview.fields.name')} value={camera.name} />
            <InfoRow label={t('CameraDetailPage.overview.fields.ipAddress')} value={camera.ip_address} mono />
            <InfoRow label={t('CameraDetailPage.overview.fields.port')} value={String(camera.port)} mono />
            <InfoRow label={t('CameraDetailPage.overview.fields.macAddress')} value={camera.mac_address} mono />
            <InfoRow label={t('CameraDetailPage.overview.fields.vendor')} value={camera.vendor} />
            <InfoRow label={t('CameraDetailPage.overview.fields.model')} value={camera.model} />
            <InfoRow label={t('CameraDetailPage.overview.fields.firmware')} value={camera.firmware_version} />
            <InfoRow label={t('CameraDetailPage.overview.fields.serialNumber')} value={camera.serial_number} mono />
            <InfoRow label={t('CameraDetailPage.overview.fields.cameraType')} value={camera.camera_type?.replace('_', ' ')} />
            <InfoRow label={t('CameraDetailPage.overview.fields.deviceType')} value={camera.device_type} />
            <InfoRow label={t('CameraDetailPage.overview.fields.location')} value={camera.location} />
            <InfoRow label={t('CameraDetailPage.overview.fields.floor')} value={camera.floor} />
            {camera.channel_id != null && (
              <InfoRow label={t('CameraDetailPage.overview.fields.nvrChannel')} value={String(camera.channel_id)} />
            )}
            <InfoRow
              label={t('CameraDetailPage.overview.fields.lastSeen')}
              value={camera.last_seen ? new Date(camera.last_seen).toLocaleString() : undefined}
            />
            <InfoRow
              label={t('CameraDetailPage.overview.fields.created')}
              value={camera.created_at ? new Date(camera.created_at).toLocaleString() : undefined}
            />
          </div>
        </CardContent>
      </Card>

      {/* Capabilities card */}
      <div className="space-y-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Settings className="h-4 w-4" />
              {t('CameraDetailPage.overview.capabilities.title')}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <CapabilityRow label={t('CameraDetailPage.overview.capabilities.ptz')} enabled={camera.has_ptz} />
            <CapabilityRow label={t('CameraDetailPage.overview.capabilities.audio')} enabled={camera.has_audio} />
            <CapabilityRow label={t('CameraDetailPage.overview.capabilities.twoWayAudio')} enabled={camera.has_two_way_audio} />
            <CapabilityRow label={t('CameraDetailPage.overview.capabilities.infrared')} enabled={camera.has_ir} />
            <CapabilityRow label={t('CameraDetailPage.overview.capabilities.motionDetection')} enabled={camera.motion_detection_enabled} />
            <CapabilityRow label={t('CameraDetailPage.overview.capabilities.recording')} enabled={camera.is_recording} />
          </CardContent>
        </Card>

        {camera.resolution_width && camera.resolution_height && (
          <Card>
            <CardHeader>
              <CardTitle className="text-base">{t('CameraDetailPage.overview.resolution')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {camera.resolution_width} × {camera.resolution_height}
              </div>
            </CardContent>
          </Card>
        )}

        {camera.rtsp_main_stream && (
          <Card>
            <CardHeader>
              <CardTitle className="text-base">{t('CameraDetailPage.overview.streamUrls.title')}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-xs">
              {camera.rtsp_main_stream && (
                <div>
                  <Label className="text-xs text-muted-foreground">{t('CameraDetailPage.overview.streamUrls.mainStream')}</Label>
                  <code className="block truncate mt-0.5">{camera.rtsp_main_stream}</code>
                </div>
              )}
              {camera.rtsp_sub_stream && (
                <div>
                  <Label className="text-xs text-muted-foreground">{t('CameraDetailPage.overview.streamUrls.subStream')}</Label>
                  <code className="block truncate mt-0.5">{camera.rtsp_sub_stream}</code>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Stream Encryption Key · Hikvision cameras with encrypted streams */}
        {isHikvision && (
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Settings className="h-4 w-4" />
                {t('CameraDetailPage.overview.encryption.title')}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-xs text-muted-foreground">
                {t('CameraDetailPage.overview.encryption.description')}
              </p>
              <form onSubmit={e => e.preventDefault()}>
                <div className="space-y-2">
                  <Label htmlFor="enc-key" className="text-xs">{t('CameraDetailPage.overview.encryption.keyLabel')}</Label>
                  <div className="flex gap-2">
                    <Input
                      id="enc-key"
                      type={showKey ? 'text' : 'password'}
                      placeholder={t('CameraDetailPage.overview.encryption.keyPlaceholder')}
                      value={encryptionKey}
                      onChange={(e) => setEncryptionKey(e.target.value)}
                      className="font-mono text-xs"
                      autoComplete="off"
                    />
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => setShowKey(!showKey)}
                      className="shrink-0"
                    >
                      {showKey ? <VolumeX className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                    </Button>
                  </div>
                </div>
              </form>
              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  disabled={!keyChanged || encKeyMut.isPending}
                  onClick={() => encKeyMut.mutate(encryptionKey)}
                >
                  {encKeyMut.isPending ? (
                    <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Save className="mr-1.5 h-3.5 w-3.5" />
                  )}
                  {t('CameraDetailPage.overview.encryption.saveKey')}
                </Button>
                {keyConfigured && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => { setEncryptionKey(''); encKeyMut.mutate(''); }}
                  >
                    {t('CameraDetailPage.overview.encryption.removeKey')}
                  </Button>
                )}
                {encKeyMut.isSuccess && !keyChanged && (
                  <span className="text-xs text-green-600">{t('CameraDetailPage.overview.encryption.saved')}</span>
                )}
              </div>
              {keyConfigured && (
                <div className="flex items-center gap-1.5">
                  <Badge variant="outline" className="text-xs bg-success/10 text-success border-success/20">
                    {t('CameraDetailPage.overview.encryption.keyConfigured')}
                  </Badge>
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}

function InfoRow({ label, value, mono }: { label: string; value?: string | null; mono?: boolean }) {
  return (
    <div>
      <span className="text-muted-foreground">{label}</span>
      <div className={cn('font-medium', mono && 'font-mono text-xs', !value && 'text-muted-foreground')}>
        {value || '-'}
      </div>
    </div>
  );
}

function CapabilityRow({ label, enabled }: { label: string; enabled: boolean }) {
  const { t } = useTranslation('cameras');
  return (
    <div className="flex items-center justify-between">
      <span className="text-sm">{label}</span>
      <Badge variant={enabled ? 'default' : 'outline'} className="text-xs">
        {enabled ? t('CameraDetailPage.common.yes') : t('CameraDetailPage.common.no')}
      </Badge>
    </div>
  );
}

// ─── Live View Tab ──────────────────────────────────────────────────────────

function StreamTab({ camera }: { camera: CameraDetail }) {
  const { t } = useTranslation('cameras');
  const [quality, setQuality] = useState<'main' | 'sub'>('sub');
  const [streamError, setStreamError] = useState(false);
  const [streamLoading, setStreamLoading] = useState(true);
  const [isSnapshotSaving, setIsSnapshotSaving] = useState(false);
  const [retryCount, setRetryCount] = useState(0);

  const isOnline = camera.status === 'online' || camera.status === 'recording';
  const [streamUrl, setStreamUrl] = useState('');

  // Fetch a short-lived stream token for the MJPEG URL
  useEffect(() => {
    if (!isOnline) {
      setStreamUrl('');
      return;
    }
    let cancelled = false;
    setStreamLoading(true);
    setStreamError(false);
    camerasApi.getMjpegStreamUrlAsync(camera.id, quality).then((url) => {
      if (!cancelled) setStreamUrl(url);
    }).catch(() => {
      // Stream token fetch failed · show error state
      if (!cancelled) {
        setStreamUrl('');
        setStreamError(true);
        setStreamLoading(false);
      }
    });
    return () => { cancelled = true; };
  }, [camera.id, isOnline, quality, retryCount]);

  // Reset loading/error state when stream URL changes
  useEffect(() => {
    if (streamUrl) {
      setStreamLoading(true);
      setStreamError(false);
    }
  }, [streamUrl]);

  const handleStreamLoad = useCallback(() => {
    setStreamLoading(false);
    setStreamError(false);
  }, []);

  const handleStreamError = useCallback(() => {
    setStreamLoading(false);
    setStreamError(true);
  }, []);

  const handleRetry = useCallback(() => {
    setStreamError(false);
    setStreamLoading(true);
    setRetryCount((c) => c + 1);
  }, []);

  const handleDownloadSnapshot = useCallback(async () => {
    try {
      setIsSnapshotSaving(true);
      const res = await camerasApi.getSnapshot(camera.id);
      const blob = res.data as Blob;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${camera.name.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}.jpg`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch {
      // ignore
    } finally {
      setIsSnapshotSaving(false);
    }
  }, [camera.id, camera.name]);

  return (
    <Card>
      <CardContent className="p-0">
        <div className="relative aspect-video bg-black rounded-lg overflow-hidden flex items-center justify-center">
          {isOnline ? (
            <>
              {/* MJPEG stream via <img> · browsers render multipart/x-mixed-replace natively */}
              {!streamError && (
                <img
                  key={`${camera.id}-${quality}`}
                  src={streamUrl}
                  alt={camera.name}
                  className="w-full h-full object-contain"
                  onLoad={handleStreamLoad}
                  onError={handleStreamError}
                />
              )}

              {/* Loading spinner */}
              {streamLoading && !streamError && (
                <div className="absolute inset-0 flex items-center justify-center">
                  <div className="text-center text-white/60">
                    <Loader2 className="h-10 w-10 mx-auto mb-3 animate-spin" />
                    <p className="text-sm">{t('CameraDetailPage.stream.connecting')}</p>
                    <p className="text-xs text-white/40 mt-1">
                      {quality === 'main'
                        ? t('CameraDetailPage.stream.mainStreamHd')
                        : t('CameraDetailPage.stream.subStreamSd')}
                    </p>
                  </div>
                </div>
              )}

              {/* Stream error */}
              {streamError && (
                <div className="text-center text-white/60">
                  <VideoOff className="h-16 w-16 mx-auto mb-4 text-red-400/60" />
                  <p className="text-sm">{t('CameraDetailPage.stream.unavailable')}</p>
                  <p className="text-xs text-white/40 mt-1 mb-3">{camera.ip_address}</p>
                  <Button
                    size="sm"
                    variant="outline"
                    className="text-white border-white/30 hover:bg-white/10"
                    onClick={handleRetry}
                  >
                    <RefreshCw className="h-3 w-3 mr-1" />
                    {t('CameraDetailPage.stream.retry')}
                  </Button>
                </div>
              )}
            </>
          ) : (
            <div className="text-center text-white/60">
              <VideoOff className="h-16 w-16 mx-auto mb-4" />
              <p className="text-sm">{t('CameraDetailPage.stream.offline')}</p>
              <p className="text-xs text-white/40 mt-1">{t('CameraDetailPage.stream.unableToConnect')}</p>
            </div>
          )}

          {/* Timestamp overlay */}
          <div className="absolute top-3 left-3 bg-black/60 px-2 py-1 rounded text-xs text-white font-mono">
            {camera.name} &middot; {new Date().toLocaleString()}
          </div>

          {/* Recording indicator */}
          {camera.is_recording && (
            <div className="absolute top-3 right-3 flex items-center gap-2 bg-red-600/80 px-2 py-1 rounded">
              <Circle className="h-2 w-2 fill-white text-white animate-pulse" />
              <span className="text-xs text-white font-medium">REC</span>
            </div>
          )}

          {/* Controls */}
          <div className="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/80 to-transparent p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <StatusBadge status={camera.status} />
                {camera.has_ptz && (
                  <Badge variant="outline" className="text-white border-white/30 text-xs">
                    <Move className="h-3 w-3 mr-1" />
                    PTZ
                  </Badge>
                )}
              </div>
              <div className="flex items-center gap-1">
                {/* Quality toggle */}
                {isOnline && (
                  <TooltipProvider>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-white hover:bg-white/20 h-8 text-xs px-2"
                          onClick={() => setQuality(q => q === 'sub' ? 'main' : 'sub')}
                        >
                          {quality === 'main' ? 'HD' : 'SD'}
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>
                        {quality === 'main'
                          ? t('CameraDetailPage.stream.switchToSub')
                          : t('CameraDetailPage.stream.switchToMain')}
                      </TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                )}
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="text-white hover:bg-white/20 h-8 w-8"
                        onClick={handleDownloadSnapshot}
                        disabled={isSnapshotSaving || !isOnline}
                      >
                        {isSnapshotSaving
                          ? <Loader2 className="h-4 w-4 animate-spin" />
                          : <Download className="h-4 w-4" />
                        }
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent>{t('CameraDetailPage.stream.downloadSnapshot')}</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── PTZ Control Tab ────────────────────────────────────────────────────────

function PTZTab({ camera }: { camera: CameraDetail }) {
  const { t } = useTranslation('cameras');
  const { toast } = useToast();
  const [speed, setSpeed] = useState(50);
  const isOnline = camera.status === 'online' || camera.status === 'recording';

  // Fetch presets
  const { data: presetsRes } = useQuery({
    queryKey: ['camera-ptz-presets', camera.id],
    queryFn: () => camerasApi.getPTZPresets(camera.id),
    enabled: isOnline && camera.has_ptz,
  });

  const presets: PTZPreset[] = presetsRes?.data?.items || [];

  // PTZ mutations
  const ptzMutation = useMutation({
    mutationFn: ({ action, pSpeed, preset }: { action: string; pSpeed?: number; preset?: number }) =>
      camerasApi.ptzControl(camera.id, action, pSpeed ?? speed, preset),
    onError: () => {
      toast({ title: t('CameraDetailPage.ptz.commandFailed'), variant: 'destructive' as any });
    },
  });

  const handleMove = (direction: string) => {
    ptzMutation.mutate({ action: direction, pSpeed: speed });
  };

  const handleStop = () => {
    ptzMutation.mutate({ action: 'stop' });
  };

  const handleGotoPreset = (presetId: number) => {
    ptzMutation.mutate({ action: 'preset', preset: presetId });
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Stream preview */}
      <div className="lg:col-span-2">
        <StreamTab camera={camera} />
      </div>

      {/* PTZ Controls panel */}
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Move className="h-4 w-4" />
              {t('CameraDetailPage.ptz.control')}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Direction pad */}
            <div className="flex justify-center">
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-1.5">
                <div />
                <Button
                  variant="secondary"
                  size="icon"
                  className="h-12 w-12"
                  disabled={!isOnline}
                  onMouseDown={() => handleMove('up')}
                  onMouseUp={handleStop}
                  onMouseLeave={handleStop}
                >
                  <ChevronUp className="h-6 w-6" />
                </Button>
                <div />
                <Button
                  variant="secondary"
                  size="icon"
                  className="h-12 w-12"
                  disabled={!isOnline}
                  onMouseDown={() => handleMove('left')}
                  onMouseUp={handleStop}
                  onMouseLeave={handleStop}
                >
                  <ChevronLeft className="h-6 w-6" />
                </Button>
                <Button
                  variant="secondary"
                  size="icon"
                  className="h-12 w-12"
                  disabled={!isOnline}
                  onClick={handleStop}
                >
                  <Square className="h-4 w-4" />
                </Button>
                <Button
                  variant="secondary"
                  size="icon"
                  className="h-12 w-12"
                  disabled={!isOnline}
                  onMouseDown={() => handleMove('right')}
                  onMouseUp={handleStop}
                  onMouseLeave={handleStop}
                >
                  <ChevronRight className="h-6 w-6" />
                </Button>
                <div />
                <Button
                  variant="secondary"
                  size="icon"
                  className="h-12 w-12"
                  disabled={!isOnline}
                  onMouseDown={() => handleMove('down')}
                  onMouseUp={handleStop}
                  onMouseLeave={handleStop}
                >
                  <ChevronDown className="h-6 w-6" />
                </Button>
                <div />
              </div>
            </div>

            {/* Zoom */}
            <div className="flex items-center justify-center gap-3">
              <Button
                variant="outline"
                size="icon"
                className="h-10 w-10"
                disabled={!isOnline}
                onMouseDown={() => handleMove('zoom_out')}
                onMouseUp={handleStop}
                onMouseLeave={handleStop}
              >
                <ZoomOut className="h-5 w-5" />
              </Button>
              <span className="text-sm text-muted-foreground font-medium w-12 text-center">{t('CameraDetailPage.ptz.zoom')}</span>
              <Button
                variant="outline"
                size="icon"
                className="h-10 w-10"
                disabled={!isOnline}
                onMouseDown={() => handleMove('zoom_in')}
                onMouseUp={handleStop}
                onMouseLeave={handleStop}
              >
                <ZoomIn className="h-5 w-5" />
              </Button>
            </div>

            <Separator />

            {/* Speed slider */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label className="text-sm">{t('CameraDetailPage.ptz.speed')}</Label>
                <span className="text-sm text-muted-foreground font-mono">{speed}%</span>
              </div>
              <Slider
                value={[speed]}
                min={1}
                max={100}
                step={1}
                onValueChange={([v]) => setSpeed(v)}
              />
            </div>
          </CardContent>
        </Card>

        {/* Presets */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Home className="h-4 w-4" />
              {t('CameraDetailPage.ptz.presets')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {presets.length > 0 ? (
              <div className="grid grid-cols-2 gap-2">
                {presets.map((p) => (
                  <Button
                    key={p.id}
                    variant="outline"
                    size="sm"
                    className="text-xs h-9 justify-start"
                    disabled={!isOnline}
                    onClick={() => handleGotoPreset(p.id)}
                  >
                    <span className="font-mono text-muted-foreground mr-1.5">{p.id}.</span>
                    {p.name || t('CameraDetailPage.ptz.presetName', { id: p.id })}
                  </Button>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground text-center py-4">
                {t('CameraDetailPage.ptz.noPresets')}
              </p>
            )}
          </CardContent>
        </Card>

        {/* PTZ Tours */}
        <PTZToursPanel cameraId={camera.id} isOnline={isOnline} />
      </div>
    </div>
  );
}

// ─── Image Settings Tab ─────────────────────────────────────────────────────

function ImageSettingsTab({ camera }: { camera: CameraDetail }) {
  const { t } = useTranslation('cameras');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [localSettings, setLocalSettings] = useState<ImageSettings | null>(null);
  const [isDirty, setIsDirty] = useState(false);

  const {
    data: imgRes,
    isLoading,
    refetch,
  } = useQuery({
    queryKey: ['camera-image-settings', camera.id],
    queryFn: () => camerasApi.getImageSettings(camera.id),
    enabled: camera.device_type === 'hikvision',
  });

  const serverSettings: ImageSettings | undefined = imgRes?.data;

  // Sync local state when server data arrives
  useEffect(() => {
    if (serverSettings && !isDirty) {
      setLocalSettings(serverSettings);
    }
  }, [serverSettings, isDirty]);

  const saveMutation = useMutation({
    mutationFn: (data: Record<string, any>) => camerasApi.setImageSettings(camera.id, data),
    onSuccess: () => {
      setIsDirty(false);
      queryClient.invalidateQueries({ queryKey: ['camera-image-settings', camera.id] });
    },
    onError: () => toast({ title: t('CameraDetailPage.image.saveFailedToast'), variant: 'destructive' as any }),
  });

  const handleChange = (key: keyof ImageSettings, value: number) => {
    if (!localSettings) return;
    setLocalSettings({ ...localSettings, [key]: value });
    setIsDirty(true);
  };

  const handleReset = () => {
    if (serverSettings) {
      setLocalSettings(serverSettings);
      setIsDirty(false);
    }
  };

  const handleSave = () => {
    if (!localSettings) return;
    saveMutation.mutate({
      brightness: localSettings.brightness,
      contrast: localSettings.contrast,
      saturation: localSettings.saturation,
      sharpness: localSettings.sharpness,
    });
  };

  if (isLoading) {
    return (
      <Card>
        <CardContent noOffset className="py-12">
          <div className="flex items-center justify-center gap-2 text-muted-foreground">
            <Loader2 className="h-5 w-5 animate-spin" />
            {t('CameraDetailPage.image.loading')}
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!localSettings) {
    return (
      <Card>
        <CardContent noOffset className="py-12 text-center">
          <ImageIcon className="h-12 w-12 text-muted-foreground mx-auto mb-3" />
          <p className="text-muted-foreground">
            {t('CameraDetailPage.image.unavailable')}
          </p>
          <Button variant="outline" className="mt-4" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            {t('CameraDetailPage.image.retry')}
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Stream preview */}
      <div className="lg:col-span-2">
        <StreamTab camera={camera} />
      </div>

      {/* Image controls */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-base flex items-center gap-2">
              <Sliders className="h-4 w-4" />
              {t('CameraDetailPage.image.title')}
            </CardTitle>
            {isDirty && (
              <Badge variant="secondary" className="text-xs">{t('CameraDetailPage.image.unsaved')}</Badge>
            )}
          </div>
        </CardHeader>
        <CardContent className="space-y-6">
          <ImageSlider
            label={t('CameraDetailPage.image.brightness')}
            icon={<Sun className="h-4 w-4" />}
            value={localSettings.brightness}
            onChange={(v) => handleChange('brightness', v)}
          />
          <ImageSlider
            label={t('CameraDetailPage.image.contrast')}
            icon={<Circle className="h-4 w-4" />}
            value={localSettings.contrast}
            onChange={(v) => handleChange('contrast', v)}
          />
          <ImageSlider
            label={t('CameraDetailPage.image.saturation')}
            icon={<ImageIcon className="h-4 w-4" />}
            value={localSettings.saturation}
            onChange={(v) => handleChange('saturation', v)}
          />
          <ImageSlider
            label={t('CameraDetailPage.image.sharpness')}
            icon={<Settings className="h-4 w-4" />}
            value={localSettings.sharpness}
            onChange={(v) => handleChange('sharpness', v)}
          />

          {localSettings.hue !== undefined && (
            <ImageSlider
              label={t('CameraDetailPage.image.hue')}
              icon={<RotateCcw className="h-4 w-4" />}
              value={localSettings.hue}
              onChange={(v) => handleChange('hue', v)}
            />
          )}

          <Separator />

          {/* Extra info */}
          {localSettings.exposure_mode && (
            <InfoRow label={t('CameraDetailPage.image.exposureMode')} value={localSettings.exposure_mode} />
          )}
          {localSettings.ir_cut_filter && (
            <InfoRow label={t('CameraDetailPage.image.irCutFilter')} value={localSettings.ir_cut_filter} />
          )}
          {localSettings.backlight_mode && (
            <InfoRow label={t('CameraDetailPage.image.backlight')} value={localSettings.backlight_mode} />
          )}
          {localSettings.wdr_enabled !== undefined && (
            <InfoRow label={t('CameraDetailPage.image.wdr')} value={localSettings.wdr_enabled ? t('CameraDetailPage.common.enabled') : t('CameraDetailPage.common.disabled')} />
          )}
          {localSettings.noise_reduction_enabled !== undefined && (
            <InfoRow
              label={t('CameraDetailPage.image.noiseReduction')}
              value={localSettings.noise_reduction_enabled ? t('CameraDetailPage.common.enabled') : t('CameraDetailPage.common.disabled')}
            />
          )}

          <Separator />

          {/* Action buttons */}
          <div className="flex gap-2">
            <Button
              variant="outline"
              className="flex-1"
              disabled={!isDirty}
              onClick={handleReset}
            >
              <RotateCcw className="h-4 w-4 mr-2" />
              {t('CameraDetailPage.image.reset')}
            </Button>
            <Button
              className="flex-1"
              disabled={!isDirty || saveMutation.isPending}
              onClick={handleSave}
            >
              {saveMutation.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Save className="h-4 w-4 mr-2" />
              )}
              {t('CameraDetailPage.image.save')}
            </Button>
          </div>

          {saveMutation.isError && (
            <p className="text-xs text-destructive text-center">
              {t('CameraDetailPage.image.saveError')}
            </p>
          )}
          {saveMutation.isSuccess && !isDirty && (
            <p className="text-xs text-emerald-500 text-center">
              {t('CameraDetailPage.image.saveSuccess')}
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function ImageSlider({
  label,
  icon,
  value,
  onChange,
  min = 0,
  max = 100,
}: {
  label: string;
  icon: React.ReactNode;
  value: number;
  onChange: (v: number) => void;
  min?: number;
  max?: number;
}) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm">
          {icon}
          <span>{label}</span>
        </div>
        <span className="text-sm font-mono text-muted-foreground w-8 text-right">{value}</span>
      </div>
      <Slider
        value={[value]}
        min={min}
        max={max}
        step={1}
        onValueChange={([v]) => onChange(v)}
      />
    </div>
  );
}

// ─── Recordings Tab ─────────────────────────────────────────────────────────

function RecordingsTab({ camera }: { camera: CameraDetail }) {
  const { t } = useTranslation('cameras');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');

  // Export clip state
  const [exportStart, setExportStart] = useState('');
  const [exportEnd, setExportEnd] = useState('');
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [exportSuccess, setExportSuccess] = useState(false);
  // Chain-of-custody: burn operator + export time into the clip (default on).
  const [exportWatermark, setExportWatermark] = useState(true);

  // ── Evidence holds (legal hold) ──
  const qc = useQueryClient();
  const { toast } = useToast();
  const { data: evidenceHolds } = useQuery({
    queryKey: ['evidence', camera.id],
    queryFn: () => evidenceApi.list(camera.id).then((r) => r.data.items),
    refetchInterval: 10_000,
  });
  const holdMut = useMutation({
    mutationFn: () =>
      evidenceApi.create({
        camera_id: camera.id,
        start_time: new Date(exportStart).toISOString(),
        end_time: new Date(exportEnd).toISOString(),
        watermark: exportWatermark,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['evidence', camera.id] });
      toast({ title: t('CameraDetailPage.recordings.evidence.held') });
    },
    onError: (err) =>
      toast({
        title: t('CameraDetailPage.recordings.evidence.holdFailed'),
        description: getApiErrorMessage(err, ''),
        variant: 'destructive',
      }),
  });
  const deleteHoldMut = useMutation({
    mutationFn: (holdId: string) => evidenceApi.remove(holdId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['evidence', camera.id] }),
  });
  const exportSuccessTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  useEffect(() => {
    return () => { clearTimeout(exportSuccessTimerRef.current); };
  }, []);

  // Recording AVAILABILITY comes from the live NVR (adapter.search_recordings via
  // GET /cameras/{id}/timeline), NOT the DB recordings table, FreeSDN doesn't
  // itself record, so that table is always empty. This mirrors RecordingTimeline.tsx;
  // querying getRecordings() here was the reason this list always showed "none".
  const { data: timelineRes, isLoading } = useQuery({
    queryKey: ['camera-recordings-timeline', camera.id, startDate, endDate],
    queryFn: async () => {
      const now = Date.now();
      const startISO = startDate
        ? new Date(`${startDate}T00:00:00`).toISOString()
        : new Date(now - 24 * 60 * 60 * 1000).toISOString();
      const endISO = endDate
        ? new Date(`${endDate}T23:59:59`).toISOString()
        : new Date(now).toISOString();
      const { data } = await camerasApi.getCameraTimeline(camera.id, startISO, endISO);
      return data;
    },
  });

  // supported=false → the NVR/vendor has no recording search (distinct from "none found").
  const recordingSupported = timelineRes ? timelineRes.supported !== false : true;
  const recordings = (Array.isArray(timelineRes?.segments) ? timelineRes!.segments : []).map(
    (s: { start: string; end: string; type?: string }, i: number) => {
      const startMs = new Date(s.start).getTime();
      const endMs = new Date(s.end).getTime();
      return {
        id: `${s.start}-${i}`,
        start_time: s.start,
        end_time: s.end,
        duration: Math.max(0, Math.round((endMs - startMs) / 1000)),
        recording_type: s.type,
      };
    },
  );

  // Pre-fill export range from a recording row
  const prefillExport = useCallback((rec: any) => {
    if (rec.start_time) {
      const start = new Date(rec.start_time);
      setExportStart(start.toISOString().slice(0, 16));
      if (rec.end_time) {
        setExportEnd(new Date(rec.end_time).toISOString().slice(0, 16));
      } else if (rec.duration) {
        const end = new Date(start.getTime() + rec.duration * 1000);
        setExportEnd(end.toISOString().slice(0, 16));
      }
    }
  }, []);

  // Export handler · downloads clip as .mp4
  const handleExport = useCallback(async () => {
    if (!exportStart || !exportEnd) return;
    setExporting(true);
    setExportError(null);
    setExportSuccess(false);
    try {
      const startISO = new Date(exportStart).toISOString();
      const endISO = new Date(exportEnd).toISOString();

      // Validate: end > start, max 4 hours
      const diffMs = new Date(endISO).getTime() - new Date(startISO).getTime();
      if (diffMs <= 0) {
        setExportError(t('CameraDetailPage.recordings.errors.endAfterStart'));
        return;
      }
      if (diffMs > 4 * 60 * 60 * 1000) {
        setExportError(t('CameraDetailPage.recordings.errors.maxDuration'));
        return;
      }

      const resp = await camerasApi.exportVideoClip(camera.id, {
        start_time: startISO,
        end_time: endISO,
        watermark: exportWatermark,
      });

      // Download blob as file
      const blob = resp.data instanceof Blob ? resp.data : new Blob([resp.data]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const ts = exportStart.replace(/[:.]/g, '-');
      a.download = `${camera.name.replace(/\s+/g, '_')}_${ts}.mp4`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setExportSuccess(true);
      clearTimeout(exportSuccessTimerRef.current);
      exportSuccessTimerRef.current = setTimeout(() => setExportSuccess(false), 5000);
    } catch (err: unknown) {
      setExportError(getApiErrorMessage(err, t('CameraDetailPage.recordings.errors.exportFailed')));
    } finally {
      setExporting(false);
    }
  }, [camera.id, camera.name, exportStart, exportEnd, exportWatermark, t]);

  return (
    <div className="space-y-4">
      <VendorCapabilityNote vendor={camera.vendor} feature="recordings" />
      {/* ── Export Clip Card ── */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Download className="h-4 w-4" />
            {t('CameraDetailPage.recordings.exportClip.title')}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap items-end gap-3">
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">{t('CameraDetailPage.recordings.exportClip.start')}</label>
              <Input
                type="datetime-local"
                value={exportStart}
                onChange={(e) => { setExportStart(e.target.value); setExportError(null); }}
                className="h-9 text-xs w-52"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">{t('CameraDetailPage.recordings.exportClip.end')}</label>
              <Input
                type="datetime-local"
                value={exportEnd}
                onChange={(e) => { setExportEnd(e.target.value); setExportError(null); }}
                className="h-9 text-xs w-52"
              />
            </div>
            <Button
              size="sm"
              disabled={!exportStart || !exportEnd || exporting}
              onClick={handleExport}
              className="gap-1.5"
            >
              {exporting ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  {t('CameraDetailPage.recordings.exportClip.exporting')}
                </>
              ) : (
                <>
                  <Download className="h-4 w-4" />
                  {t('CameraDetailPage.recordings.exportClip.downloadClip')}
                </>
              )}
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={!exportStart || !exportEnd || holdMut.isPending}
              onClick={() => holdMut.mutate()}
              className="gap-1.5"
              title={t('CameraDetailPage.recordings.evidence.holdHint')}
            >
              <ShieldCheck className="h-4 w-4" />
              {t('CameraDetailPage.recordings.evidence.hold')}
            </Button>
            <label className="flex items-center gap-1.5 text-xs text-muted-foreground cursor-pointer select-none">
              <input
                type="checkbox"
                checked={exportWatermark}
                onChange={(e) => setExportWatermark(e.target.checked)}
                className="h-3.5 w-3.5 accent-primary"
              />
              {t('CameraDetailPage.recordings.exportClip.watermark')}
            </label>
          </div>
          <p className="text-[11px] text-muted-foreground mt-2">
            {t('CameraDetailPage.recordings.exportClip.custodyHint')}
          </p>
          {exportError && (
            <p className="text-xs text-destructive mt-2">{exportError}</p>
          )}
          {exportSuccess && (
            <p className="text-xs text-green-600 mt-2">{t('CameraDetailPage.recordings.exportClip.downloadSuccess')}</p>
          )}
          {exportStart && exportEnd && !exportError && (
            <p className="text-xs text-muted-foreground mt-2">
              {t('CameraDetailPage.recordings.exportClip.duration')}: {(() => {
                const diffMs = new Date(exportEnd).getTime() - new Date(exportStart).getTime();
                if (diffMs <= 0) return '-';
                const mins = Math.round(diffMs / 60000);
                return mins >= 60 ? `${Math.floor(mins / 60)}h ${mins % 60}m` : `${mins}m`;
              })()}
              {' '}{t('CameraDetailPage.recordings.exportClip.maxHours')}
            </p>
          )}
        </CardContent>
      </Card>

      {/* ── Recording List Card ── */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-base flex items-center gap-2">
              <HardDrive className="h-4 w-4" />
              {t('CameraDetailPage.recordings.list.title')}
            </CardTitle>
            <div className="flex items-center gap-2">
              <Input
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="h-8 text-xs w-36"
                placeholder={t('CameraDetailPage.recordings.list.startDate')}
              />
              <span className="text-muted-foreground text-xs">{t('CameraDetailPage.recordings.list.to')}</span>
              <Input
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                className="h-8 text-xs w-36"
                placeholder={t('CameraDetailPage.recordings.list.endDate')}
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-2">
              {[0, 1, 2].map((i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          ) : recordings.length > 0 ? (
            <div className="divide-y rounded-lg border">
              {recordings.map((rec: any, idx: number) => (
                <div key={rec.id || idx} className="flex items-center justify-between px-4 py-3">
                  <div>
                    <div className="text-sm font-medium">
                      {rec.start_time ? new Date(rec.start_time).toLocaleString() : t('CameraDetailPage.recordings.list.unknown')}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {t('CameraDetailPage.recordings.list.durationLabel')}: {rec.duration ? `${Math.round(rec.duration / 60)}m` : '-'}
                      {rec.file_size ? ` · ${(rec.file_size / 1024 / 1024).toFixed(1)} MB` : ''}
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8"
                      title={t('CameraDetailPage.recordings.list.exportThisClip')}
                      onClick={() => prefillExport(rec)}
                    >
                      <Download className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : !recordingSupported ? (
            <div className="text-center py-8 text-muted-foreground">
              <HardDrive className="h-10 w-10 mx-auto mb-3 opacity-40" />
              <p className="text-sm">{t('CameraDetailPage.recordings.list.notSupported')}</p>
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <HardDrive className="h-10 w-10 mx-auto mb-3 opacity-40" />
              <p className="text-sm">{t('CameraDetailPage.recordings.list.empty')}</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── Evidence Holds (legal hold / chain-of-custody) ── */}
      {evidenceHolds && evidenceHolds.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <ShieldCheck className="h-4 w-4" />
              {t('CameraDetailPage.recordings.evidence.title')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="divide-y rounded-lg border">
              {evidenceHolds.map((h: EvidenceArchive) => (
                <div key={h.id} className="flex items-center justify-between gap-3 px-4 py-3">
                  <div className="min-w-0">
                    <div className="text-sm font-medium">
                      {new Date(h.start_time).toLocaleString()} → {new Date(h.end_time).toLocaleTimeString()}
                    </div>
                    <div className="text-xs text-muted-foreground flex items-center gap-2 flex-wrap mt-0.5">
                      {h.status === 'ready' ? (
                        <span className="inline-flex items-center gap-1 text-green-600">
                          <ShieldCheck className="h-3 w-3" />
                          {t('CameraDetailPage.recordings.evidence.statusReady')}
                        </span>
                      ) : h.status === 'failed' ? (
                        <span className="text-destructive">
                          {t('CameraDetailPage.recordings.evidence.statusFailed')}
                          {h.error ? `: ${h.error}` : ''}
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1">
                          <Loader2 className="h-3 w-3 animate-spin" />
                          {t('CameraDetailPage.recordings.evidence.statusArchiving')}
                        </span>
                      )}
                      {h.file_size ? <span>· {(h.file_size / 1024 / 1024).toFixed(1)} MB</span> : null}
                      {h.watermarked ? <span>· {t('CameraDetailPage.recordings.evidence.watermarked')}</span> : null}
                    </div>
                    {h.sha256 && (
                      <div className="text-[10px] font-mono text-muted-foreground truncate mt-0.5" title={h.sha256}>
                        SHA-256 {h.sha256}
                      </div>
                    )}
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    {h.status === 'ready' && (
                      <a href={evidenceApi.downloadUrl(h.id)} title={t('CameraDetailPage.recordings.evidence.download')}>
                        <Button variant="ghost" size="icon" className="h-8 w-8">
                          <Download className="h-4 w-4" />
                        </Button>
                      </a>
                    )}
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8 text-destructive"
                      title={t('CameraDetailPage.recordings.evidence.release')}
                      disabled={deleteHoldMut.isPending}
                      onClick={() => {
                        if (window.confirm(t('CameraDetailPage.recordings.evidence.confirmRelease'))) {
                          deleteHoldMut.mutate(h.id);
                        }
                      }}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
            <p className="text-[11px] text-muted-foreground mt-2">
              {t('CameraDetailPage.recordings.evidence.hint')}
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Events Tab ─────────────────────────────────────────────────────────────

function EventsTab({ camera }: { camera: CameraDetail }) {
  return <EventFeedPanel cameraId={camera.id} limit={100} />;
}
