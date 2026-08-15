// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MultiPlaybackPage · Synchronized multi-camera recording playback
 *
 * Enterprise-grade incident investigation tool:
 *  - Select 2-4 cameras for side-by-side recording playback
 *  - Synchronized timeline scrubber across all cameras
 *  - Shared playback controls (play/pause, speed, seek)
 *  - Per-camera recording segment visualization
 *  - Deep-linkable: /cameras/playback?cameras=id1,id2&time=2024-03-15T10:30:00Z&range=4h
 *  - Video clip export for evidence preservation
 *
 * Inspired by Hikvision iVMS-4200, Milestone XProtect, and Genetec Security Center.
 */

import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  Camera,
  ArrowLeft,
  AlertCircle,
  Loader2,
  Play,
  Pause,
  SkipBack,
  SkipForward,
  FastForward,
  Rewind,
  X,
  Clock,
  ChevronDown,
  Film,
  Image as ImageIcon,
} from 'lucide-react';
import { PageHeader } from '@/components/layout';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Card, CardContent } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';
import { camerasApi } from '@/lib/api';
import { API_URL } from '@/lib/api/client';
import { isDemoMode } from '@/demo/mode';
import { getDemoCameraSnapshotPath } from '@/demo/fixtures';
import { useSiteStore } from '@/stores/siteStore';
import { mapToWallCameras } from '@/components/cameras/wall/mapToWallCamera';
import type { WallCamera } from '@/components/cameras/wall/types';
import { VendorCapabilityNote } from '@/components/cameras/VendorCapabilityNote';
import { RecordingCalendar } from '@/components/cameras/RecordingCalendar';
import { isNativeVendor } from '@/lib/cameraVendors';
import {
  useCameraSegments,
  segmentAt,
  nextSegmentStart,
  nearestInstant,
  type Seg,
} from '@/lib/recordingSegments';
import { RecordingTimeline } from '@/components/cameras/RecordingTimeline';
import { EvidenceExportPanel } from '@/components/cameras/EvidenceExportPanel';
import { RecordedHlsPlayer } from '@/components/cameras/RecordedHlsPlayer';

// ---------------------------------------------------------------------------
// Types & constants
// ---------------------------------------------------------------------------

type TimeRangePreset = '1h' | '4h' | '12h' | '24h' | '3d' | '7d';
type PlaybackSpeed = 0.25 | 0.5 | 1 | 2 | 4 | 8 | 16;
/** How each cell renders the recording: smooth HLS video vs per-second JPEG stepping. */
type PlaybackMode = 'smooth' | 'frames';

const RANGE_PRESETS: Record<TimeRangePreset, { labelKey: string; hours: number }> = {
  '1h': { labelKey: 'ranges.1h', hours: 1 },
  '4h': { labelKey: 'ranges.4h', hours: 4 },
  '12h': { labelKey: 'ranges.12h', hours: 12 },
  '24h': { labelKey: 'ranges.24h', hours: 24 },
  '3d': { labelKey: 'ranges.3d', hours: 72 },
  '7d': { labelKey: 'ranges.7d', hours: 168 },
};

const SPEED_OPTIONS: PlaybackSpeed[] = [0.25, 0.5, 1, 2, 4, 8, 16];
const MAX_CAMERAS = 4;

// ---------------------------------------------------------------------------
// PlaybackCell · single camera playback tile
// ---------------------------------------------------------------------------

function PlaybackCell({
  camera,
  playbackTime,
  mode,
  playFromIso,
  fellBack,
  isPlaying,
  onSeek,
  onRemove,
  onUnavailable,
  onPlayheadTime,
}: {
  camera: WallCamera;
  playbackTime: Date;
  /** Global render mode. In 'smooth' the cell renders HLS video unless it has fallen back. */
  mode: PlaybackMode;
  /** Explicit play-from instant for the HLS player; changes only on user play/seek/skip, NOT per tick. */
  playFromIso: string;
  /** True once this camera's recorded HLS proved unavailable, render frames for the rest of the session. */
  fellBack: boolean;
  isPlaying: boolean;
  onSeek: (time: Date) => void;
  onRemove: () => void;
  /** Report that smooth playback is unavailable for this camera so the parent degrades it to frames. */
  onUnavailable: (cameraId: string) => void;
  /** Frame-exact playhead report (wall-clock ms), set only on the representative cell. */
  onPlayheadTime?: (wallClockMs: number) => void;
}) {
  const { t } = useTranslation('cameras');
  const { t: tc } = useTranslation('common');
  const [frameUrl, setFrameUrl] = useState('');
  const [error, setError] = useState(false);
  const isOnline = camera.status === 'online' || camera.status === 'recording';
  // Smooth HLS video when the global mode is 'smooth' AND this camera hasn't degraded to frames.
  const useSmooth = mode === 'smooth' && !fellBack;

  // Cache one stream-token per camera and reuse it for ~50s. Stream tokens are
  // short-lived but valid for several minutes; re-minting one per frame (1/s)
  // hammered the NVR with a POST every second per camera. We only POST when the
  // cache is empty/expired or after an <img> error (likely an expired token).
  const tokenRef = useRef<{ value: string; fetchedAt: number } | null>(null);
  const TOKEN_TTL_MS = 50_000;

  const getToken = useCallback(async (forceRefresh = false): Promise<string> => {
    const cached = tokenRef.current;
    if (!forceRefresh && cached && Date.now() - cached.fetchedAt < TOKEN_TTL_MS) {
      return cached.value;
    }
    const value = await camerasApi.getStreamToken(camera.id);
    tokenRef.current = { value, fetchedAt: Date.now() };
    return value;
  }, [camera.id]);

  // Reset the cached token if the camera identity changes
  useEffect(() => {
    tokenRef.current = null;
  }, [camera.id]);

  // Quantize the playhead to whole seconds, the playback timer advances
  // every 100ms, but we only need a new recorded frame once per second.
  // This also keeps the NVR's recording-seek load bounded.
  const playbackSecond = Math.floor(playbackTime.getTime() / 1000);

  // Gap-awareness: know where this camera actually has footage so we never (a)
  // show a stale frame in dead air or (b) fire a frame request for a timestamp
  // with no recording, which makes the NVR block until ffmpeg times out. When
  // the timeline is loaded and the playhead is NOT inside a segment, we render an
  // honest "no recording" state and skip the fetch entirely.
  const { segments, loaded: segmentsLoaded } = useCameraSegments(camera.id, playbackTime, 4);
  const inGap = isOnline && !useSmooth && segmentsLoaded && segmentAt(playbackSecond * 1000, segments) === null;

  // Build the RECORDED-frame URL at the playhead (GET /cameras/{id}/playback-frame
  // ?time=&token=). We only swap the &time= query param each second and reuse the
  // cached token, this is the actual recording, not live.
  const safeId = encodeURIComponent(camera.id);
  useEffect(() => {
    if (!isOnline) return;
    // In smooth mode the HLS player owns playback, don't fetch per-second JPEG frames.
    if (useSmooth) return;
    // No recording at this instant → don't fetch (avoids the NVR-side timeout hang)
    // and clear any stale frame so the gap overlay shows instead.
    if (inGap) { setFrameUrl(''); setError(false); return; }
    // Demo build: this <img src> would otherwise emit a real same-origin
    // /api/v1/cameras/.../playback-frame GET, bypassing the demo axios adapter.
    // Serve the static demo snapshot asset and skip the stream-token POST,
    // same flag/asset the cameras API helper uses for getPlaybackFrameUrlAsync.
    if (isDemoMode) {
      // decodeURIComponent(safeId) === camera.id; use safeId so the effect's
      // dependency set stays unchanged (safeId already tracks the camera id).
      setFrameUrl(getDemoCameraSnapshotPath(decodeURIComponent(safeId)));
      setError(false);
      return;
    }
    const iso = new Date(playbackSecond * 1000).toISOString();

    let cancelled = false;
    getToken().then((token) => {
      if (cancelled) return;
      setFrameUrl(
        `${API_URL}/api/v1/cameras/${safeId}/playback-frame?time=${encodeURIComponent(iso)}&token=${encodeURIComponent(token)}`,
      );
      setError(false);
    }).catch(() => {
      if (!cancelled) setError(true);
    });
    return () => { cancelled = true; };
  }, [safeId, isOnline, playbackSecond, getToken, useSmooth, inGap]);

  // On <img> error, re-mint the token once (covers expiry / 401-403) and retry
  // the current frame before declaring "no recording".
  const retriedRef = useRef(false);
  const handleFrameError = useCallback(() => {
    // Demo build never makes a real frame request, so an <img> error here can't
    // be an expired token, don't re-mint/rebuild a direct /api URL; just degrade.
    if (isDemoMode) {
      setError(true);
      return;
    }
    if (retriedRef.current) {
      setError(true);
      return;
    }
    retriedRef.current = true;
    const iso = new Date(playbackSecond * 1000).toISOString();
    getToken(true).then((token) => {
      setFrameUrl(
        `${API_URL}/api/v1/cameras/${safeId}/playback-frame?time=${encodeURIComponent(iso)}&token=${encodeURIComponent(token)}`,
      );
    }).catch(() => setError(true));
  }, [getToken, playbackSecond, safeId]);

  // Allow a fresh retry whenever the playhead moves to a new second
  useEffect(() => {
    retriedRef.current = false;
  }, [playbackSecond]);

  return (
    <div className="relative bg-black rounded-lg overflow-hidden flex flex-col">
      {/* Camera header */}
      <div className="absolute top-0 left-0 right-0 z-10 flex items-center justify-between px-3 py-1.5 bg-gradient-to-b from-black/70 to-transparent">
        <div className="flex items-center gap-2">
          <Camera className="h-3.5 w-3.5 text-white/70" />
          <span className="text-white text-xs font-medium">{camera.name}</span>
          <Badge
            variant="outline"
            className={cn(
              'text-[10px] border-white/30',
              isOnline ? 'text-emerald-400' : 'text-red-400',
            )}
          >
            {isOnline ? t('MultiPlaybackPage.status.online') : t('MultiPlaybackPage.status.offline')}
          </Badge>
          {/* Honesty marker: badge REC when smooth HLS is active, or when a recorded frame loaded */}
          {isOnline && !inGap && (useSmooth || (frameUrl && !error)) && (
            <Badge variant="outline" className="text-[10px] border-white/30 text-red-400 gap-1">
              <span className="h-1.5 w-1.5 rounded-full bg-red-500 inline-block" />
              {tc('CameraLiveViewModal.rec')}
            </Badge>
          )}
        </div>
        <Button
          variant="ghost"
          size="icon"
          className="h-6 w-6 text-white/60 hover:text-white hover:bg-white/10"
          onClick={onRemove}
        >
          <X className="h-3.5 w-3.5" />
        </Button>
      </div>

      {/* Video area */}
      <div className="flex-1 min-h-0 flex items-center justify-center">
        {!isOnline ? (
          <div className="text-white/30 text-sm flex flex-col items-center gap-2">
            <Camera className="h-8 w-8" />
            <span>{t('MultiPlaybackPage.cell.cameraOffline')}</span>
          </div>
        ) : useSmooth ? (
          // Smooth recorded HLS video. Keyed on playFromIso so it only re-mounts on an
          // explicit user play/seek/skip, the video advances itself between those.
          // On the device returning 501 (classic NVR / non-Hikvision) this cell falls back
          // to per-second frame stepping for the rest of the session.
          <RecordedHlsPlayer
            key={playFromIso}
            cameraId={camera.id}
            startTime={playFromIso}
            quality="low"
            durationS={600}
            paused={!isPlaying}
            className="w-full h-full"
            onUnavailable={() => onUnavailable(camera.id)}
            onPlayheadTime={onPlayheadTime}
          />
        ) : inGap ? (
          // No footage at this instant (timeline gap), honest, instant, no NVR hit.
          <div className="text-white/40 text-sm flex flex-col items-center gap-2">
            <Clock className="h-8 w-8" />
            <span>{t('MultiPlaybackPage.cell.noRecording')}</span>
          </div>
        ) : error ? (
          // Honest "no recording at this time", distinct from live snapshot
          <div className="text-white/40 text-sm flex flex-col items-center gap-2">
            <Clock className="h-8 w-8" />
            <span>{tc('WallCell.replay.unavailable')}</span>
          </div>
        ) : frameUrl ? (
          <img
            src={frameUrl}
            alt={camera.name}
            className="w-full h-full object-contain"
            onError={handleFrameError}
            draggable={false}
          />
        ) : (
          <Loader2 className="h-6 w-6 animate-spin text-white/30" />
        )}
      </div>

      {/* Timestamp overlay */}
      <div className="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/70 to-transparent px-3 py-1.5">
        <span className="text-white/80 text-[11px] font-mono">
          {playbackTime.toLocaleString()}
        </span>
      </div>

      {/* Per-camera timeline */}
      <div className="bg-muted/20 px-2 py-1">
        <RecordingTimeline
          cameraId={camera.id}
          playbackTime={playbackTime}
          onSeek={onSeek}
          height={28}
          showControls={false}
        />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Camera Picker Sidebar
// ---------------------------------------------------------------------------

function CameraPicker({
  cameras,
  selectedIds,
  onToggle,
  maxReached,
}: {
  cameras: WallCamera[];
  selectedIds: Set<string>;
  onToggle: (id: string) => void;
  maxReached: boolean;
}) {
  const { t } = useTranslation('cameras');
  const [search, setSearch] = useState('');

  const filtered = useMemo(
    () =>
      cameras.filter((c) =>
        c.name.toLowerCase().includes(search.toLowerCase()) ||
        (c.ip_address && c.ip_address.includes(search))
      ),
    [cameras, search],
  );

  return (
    <Card className="w-64 shrink-0">
      <CardContent noOffset className="p-3 space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium">{t('MultiPlaybackPage.picker.title')}</span>
          <Badge variant="secondary" className="text-[10px]">
            {selectedIds.size}/{MAX_CAMERAS}
          </Badge>
        </div>
        <Input
          placeholder={t('MultiPlaybackPage.picker.searchPlaceholder')}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="h-8 text-xs"
        />
        <ScrollArea className="h-[calc(100vh-400px)] min-h-[200px]">
          <div className="space-y-1 pr-2">
            {filtered.map((cam) => {
              const isSelected = selectedIds.has(cam.id);
              const isOnline = cam.status === 'online' || cam.status === 'recording';
              return (
                <button
                  key={cam.id}
                  onClick={() => onToggle(cam.id)}
                  disabled={!isSelected && maxReached}
                  className={cn(
                    'w-full flex items-center gap-2 px-2 py-1.5 rounded text-left text-xs transition-colors',
                    isSelected
                      ? 'bg-primary/10 text-primary border border-primary/30'
                      : 'hover:bg-muted/50',
                    !isSelected && maxReached && 'opacity-40 cursor-not-allowed',
                  )}
                >
                  <div
                    className={cn(
                      'h-2 w-2 rounded-full shrink-0',
                      isOnline ? 'bg-emerald-500' : 'bg-red-500',
                    )}
                  />
                  <span className="truncate flex-1">{cam.name}</span>
                  {isSelected && (
                    <Badge variant="secondary" className="text-[9px] px-1">
                      {t('MultiPlaybackPage.picker.active')}
                    </Badge>
                  )}
                </button>
              );
            })}
            {filtered.length === 0 && (
              <p className="text-xs text-muted-foreground text-center py-4">{t('MultiPlaybackPage.picker.noCamerasFound')}</p>
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Shared playback controls
// ---------------------------------------------------------------------------

function PlaybackControls({
  playbackTime,
  cameraId,
  isPlaying,
  speed,
  rangePreset,
  onPlayPause,
  onSpeedChange,
  onSeek,
  onSkip,
  onRangeChange,
}: {
  playbackTime: Date;
  cameraId?: string;
  isPlaying: boolean;
  speed: PlaybackSpeed;
  rangePreset: TimeRangePreset;
  onPlayPause: () => void;
  onSpeedChange: (speed: PlaybackSpeed) => void;
  onSeek: (time: Date) => void;
  onSkip: (seconds: number) => void;
  onRangeChange: (preset: TimeRangePreset) => void;
}) {
  const { t } = useTranslation('cameras');
  return (
    <Card>
      <CardContent noOffset className="p-3">
        <div className="flex items-center gap-3 flex-wrap">
          {/* Transport controls, one cohesive segmented cluster */}
          <div className="flex items-center gap-0.5 rounded-lg border bg-muted/40 p-1">
            <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => onSkip(-60)} title={t('MultiPlaybackPage.controls.back1Minute')}>
              <Rewind className="h-3.5 w-3.5" />
            </Button>
            <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => onSkip(-10)} title={t('MultiPlaybackPage.controls.back10Seconds')}>
              <SkipBack className="h-3.5 w-3.5" />
            </Button>
            <Button
              variant={isPlaying ? 'default' : 'secondary'}
              size="icon"
              className="h-9 w-9 rounded-md"
              onClick={onPlayPause}
            >
              {isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
            </Button>
            <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => onSkip(10)} title={t('MultiPlaybackPage.controls.forward10Seconds')}>
              <SkipForward className="h-3.5 w-3.5" />
            </Button>
            <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => onSkip(60)} title={t('MultiPlaybackPage.controls.forward1Minute')}>
              <FastForward className="h-3.5 w-3.5" />
            </Button>
          </div>

          {/* Current time display */}
          <div className="flex items-center gap-1.5 px-2 py-1 bg-muted rounded text-xs font-mono">
            <Clock className="h-3 w-3 text-muted-foreground" />
            {playbackTime.toLocaleString(undefined, {
              year: 'numeric',
              month: '2-digit',
              day: '2-digit',
              hour: '2-digit',
              minute: '2-digit',
              second: '2-digit',
            })}
          </div>

          {/* Calendar day-picker (footage days dotted) */}
          <RecordingCalendar cameraId={cameraId} value={playbackTime} onPick={onSeek} />

          {/* Speed selector */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" className="h-8 text-xs gap-1">
                <FastForward className="h-3 w-3" />
                {speed}x
                <ChevronDown className="h-3 w-3" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start">
              {SPEED_OPTIONS.map((s) => (
                <DropdownMenuItem key={s} onClick={() => onSpeedChange(s)}>
                  <span className={cn(s === speed && 'font-bold')}>{s}x</span>
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>

          <div className="flex-1" />

          {/* Time range selector */}
          <Select value={rangePreset} onValueChange={(v) => onRangeChange(v as TimeRangePreset)}>
            <SelectTrigger className="h-8 w-[120px] text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {Object.entries(RANGE_PRESETS).map(([key, { labelKey }]) => (
                <SelectItem key={key} value={key}>{t(`MultiPlaybackPage.${labelKey}`)}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Shared Timeline Ruler
// ---------------------------------------------------------------------------

function SharedTimeline({
  cameraIds,
  playbackTime,
  rangePreset,
  onSeek,
}: {
  cameraIds: string[];
  playbackTime: Date;
  rangePreset: TimeRangePreset;
  onSeek: (time: Date) => void;
}) {
  const { t } = useTranslation('cameras');
  if (cameraIds.length === 0) return null;

  return (
    <Card>
      <CardContent noOffset className="p-3 space-y-2">
        <div className="flex items-center gap-2">
          <Clock className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-xs font-medium">{t('MultiPlaybackPage.timeline.shared')}</span>
          <Badge variant="outline" className="text-[10px]">
            {t(`MultiPlaybackPage.${RANGE_PRESETS[rangePreset].labelKey}`)}
          </Badge>
        </div>
        {/* Stacked timelines · one per camera */}
        <div className="space-y-1">
          {cameraIds.map((cameraId) => (
            <RecordingTimeline
              key={cameraId}
              cameraId={cameraId}
              playbackTime={playbackTime}
              onSeek={onSeek}
              height={24}
              showControls={false}
            />
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Main Page
// ---------------------------------------------------------------------------

export default function MultiPlaybackPage() {
  const { t } = useTranslation('cameras');
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // Deep-link: parse initial state from URL
  const [selectedCameraIds, setSelectedCameraIdsState] = useState<string[]>(() => {
    const c = searchParams.get('cameras');
    return c ? c.split(',').filter(Boolean).slice(0, MAX_CAMERAS) : [];
  });

  const [rangePreset, setRangePresetState] = useState<TimeRangePreset>(() => {
    const r = searchParams.get('range') as TimeRangePreset;
    return r && r in RANGE_PRESETS ? r : '4h';
  });

  const [playbackTime, setPlaybackTime] = useState<Date>(() => {
    const t = searchParams.get('time');
    if (t) {
      const d = new Date(t);
      if (!isNaN(d.getTime())) return d;
    }
    // Default: 1 hour ago
    return new Date(Date.now() - 60 * 60 * 1000);
  });

  // Render mode: 'frames' (per-second JPEG stepping, works on every NVR) is the default;
  // 'smooth' is the HLS-video path. Deep-linkable via ?mode=smooth.
  const [mode, setModeState] = useState<PlaybackMode>(() =>
    searchParams.get('mode') === 'smooth' ? 'smooth' : 'frames',
  );

  // The instant smooth-HLS playback starts from. It tracks the playhead ONLY on explicit
  // user actions (play / seek / skip), never on the per-tick auto-advance, otherwise the
  // RecordedHlsPlayer (keyed on this) would re-mount every second and restart playback.
  const [playFrom, setPlayFrom] = useState<Date>(playbackTime);

  // Cameras whose recorded HLS proved unavailable (501 / start failure): degrade to frames
  // for the rest of the session. Cleared when the camera selection changes.
  const [fellBackIds, setFellBackIds] = useState<Set<string>>(() => new Set());

  const [isPlaying, setIsPlaying] = useState(false);
  const [speed, setSpeed] = useState<PlaybackSpeed>(1);
  const playIntervalRef = useRef<ReturnType<typeof setInterval>>(undefined);

  // Deep-link: sync state → URL
  const setSelectedCameraIds = useCallback((ids: string[]) => {
    setSelectedCameraIdsState(ids);
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (ids.length === 0) next.delete('cameras'); else next.set('cameras', ids.join(','));
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  const setRangePreset = useCallback((preset: TimeRangePreset) => {
    setRangePresetState(preset);
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (preset === '4h') next.delete('range'); else next.set('range', preset);
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  // Sync playback time to URL periodically (not on every tick)
  // Use ref to avoid recreating interval when playbackTime changes
  const playbackTimeRef = useRef(playbackTime);
  playbackTimeRef.current = playbackTime;

  // Representative recording segments (first selected camera) drive gap-skip on
  // play and snap-to-footage on seek, so the shared playhead never crawls through
  // dead air or strands the whole grid on a no-recording instant.
  const { segments: sharedSegments } = useCameraSegments(
    selectedCameraIds[0],
    playbackTime,
    RANGE_PRESETS[rangePreset].hours,
  );
  const sharedSegmentsRef = useRef<Seg[]>([]);
  sharedSegmentsRef.current = sharedSegments;
  const modeRef = useRef(mode);
  modeRef.current = mode;

  // Switching mode re-anchors smooth playback at the current playhead and clears any
  // per-camera fallbacks (re-attempt smooth on the cameras that previously degraded).
  const setMode = useCallback((next: PlaybackMode) => {
    setModeState(next);
    setFellBackIds(new Set());
    setPlayFrom(playbackTimeRef.current);
    setSearchParams((prev) => {
      const p = new URLSearchParams(prev);
      if (next === 'frames') p.delete('mode'); else p.set('mode', next);
      return p;
    }, { replace: true });
  }, [setSearchParams]);

  useEffect(() => {
    const timer = setInterval(() => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        next.set('time', playbackTimeRef.current.toISOString());
        return next;
      }, { replace: true });
    }, 5000);
    return () => clearInterval(timer);
  }, [setSearchParams]);

  // Playback timer · advances playbackTime when playing
  useEffect(() => {
    if (!isPlaying) {
      clearInterval(playIntervalRef.current);
      return;
    }

    const interval = 100; // 10 ticks per second
    playIntervalRef.current = setInterval(() => {
      setPlaybackTime((prev) => {
        // In smooth mode the representative cell's video drives the playhead
        // (frame-exact via onPlayheadTime); the timer only advances frames mode.
        if (modeRef.current !== 'frames') return prev;
        let next = prev.getTime() + interval * speed;
        const now = Date.now();
        // Clamp at the live edge, you can't play recordings into the future.
        if (next >= now) {
          setIsPlaying(false);
          return new Date(now);
        }
        // Frames mode: the playhead drives the displayed frame, so skip dead air,
        // jump to the next recording, or stop at the live edge if footage ran out.
        // (Smooth mode lets the HLS video own continuity; we don't jump its clock.)
        const segs = sharedSegmentsRef.current;
        if (modeRef.current === 'frames' && speed > 0 && segs.length > 0 && segmentAt(next, segs) === null) {
          const ns = nextSegmentStart(next, segs);
          if (ns !== null && ns < now) {
            next = ns;
          } else {
            setIsPlaying(false);
            return new Date(now);
          }
        }
        return new Date(next);
      });
    }, interval);

    return () => clearInterval(playIntervalRef.current);
  }, [isPlaying, speed]);

  // Fetch cameras
  const { data: camerasData, isLoading, isError } = useQuery({
    queryKey: ['cameras', 'multi-playback', selectedSiteId],
    queryFn: async () => {
      const { data } = await camerasApi.getAll({
        site_id: selectedSiteId || undefined,
        limit: 100,
      });
      return data;
    },
  });

  const cameras = useMemo(() => mapToWallCameras(camerasData), [camerasData]);

  const selectedCameraIdsRef = useRef(selectedCameraIds);
  selectedCameraIdsRef.current = selectedCameraIds;

  const handleToggleCamera = useCallback((cameraId: string) => {
    const ids = selectedCameraIdsRef.current;
    setSelectedCameraIds(
      ids.includes(cameraId)
        ? ids.filter((id) => id !== cameraId)
        : ids.length >= MAX_CAMERAS
          ? ids
          : [...ids, cameraId],
    );
  }, [setSelectedCameraIds]);

  const handleRemoveCamera = useCallback((cameraId: string) => {
    setSelectedCameraIds(selectedCameraIdsRef.current.filter((id) => id !== cameraId));
  }, [setSelectedCameraIds]);

  const selectedCameras = useMemo(
    () => selectedCameraIds.map((id) => cameras.find((c) => c.id === id)).filter(Boolean) as WallCamera[],
    [selectedCameraIds, cameras],
  );

  const selectedSet = useMemo(() => new Set(selectedCameraIds), [selectedCameraIds]);

  // Prune the fallback set to currently-selected cameras: a removed-then-re-added camera
  // gets a fresh smooth attempt rather than being stuck on frames.
  useEffect(() => {
    setFellBackIds((prev) => {
      if (prev.size === 0) return prev;
      const next = new Set([...prev].filter((id) => selectedSet.has(id)));
      return next.size === prev.size ? prev : next;
    });
  }, [selectedSet]);

  const handlePlayPause = useCallback(() => {
    setIsPlaying((p) => {
      // Pressing Play (frames mode timer OR re-anchoring the smooth video) is an explicit
      // user action: re-anchor smooth playback at the current playhead.
      if (!p) setPlayFrom(playbackTimeRef.current);
      return !p;
    });
  }, []);

  // Recordings only exist in the past, never let the playhead pass the present.
  // Seek is an explicit user action → re-anchor smooth playback at the sought instant.
  const handleSeek = useCallback((time: Date) => {
    const segs = sharedSegmentsRef.current;
    let target = Math.min(time.getTime(), Date.now());
    // Snap a click that lands in a gap to the nearest real footage (no-op when the
    // click is already inside a recorded segment), so a seek always shows video.
    if (segs.length > 0) {
      const snapped = nearestInstant(target, segs);
      if (snapped !== null) target = Math.min(snapped, Date.now());
    }
    const clamped = new Date(target);
    setPlaybackTime(clamped);
    setPlayFrom(clamped);
  }, []);

  // Skip is an explicit user action → re-anchor smooth playback at the new instant.
  const handleSkip = useCallback((seconds: number) => {
    const next = new Date(Math.min(playbackTimeRef.current.getTime() + seconds * 1000, Date.now()));
    setPlaybackTime(next);
    setPlayFrom(next);
  }, []);

  // Frame-exact shared playhead: the representative (first) camera's smooth video
  // reports its true position; we track it while playing in smooth mode so the
  // timeline reflects the actual frame, not a wall-clock timer.
  const handleRepPlayheadTime = useCallback((wallMs: number) => {
    if (modeRef.current !== 'smooth') return;
    const clamped = Math.min(wallMs, Date.now());
    if (Math.abs(clamped - playbackTimeRef.current.getTime()) > 250) setPlaybackTime(new Date(clamped));
  }, []);

  // A cell whose recorded HLS proved unavailable degrades to frames for the rest of the session.
  const handleCellUnavailable = useCallback((cameraId: string) => {
    setFellBackIds((prev) => {
      if (prev.has(cameraId)) return prev;
      const next = new Set(prev);
      next.add(cameraId);
      return next;
    });
  }, []);

  // Grid layout: 1 = full, 2 = side-by-side, 3-4 = 2x2
  const gridClass = selectedCameras.length <= 1
    ? 'grid-cols-1'
    : selectedCameras.length <= 2
      ? 'grid-cols-2'
      : 'grid-cols-2 grid-rows-2';

  return (
    <div className="space-y-3 p-4">
      {selectedCameras.some((c) => !isNativeVendor(c.vendor)) && (
        <VendorCapabilityNote vendor="onvif" feature="playback" />
      )}
      <PageHeader
        title={t('MultiPlaybackPage.header.title')}
        description={t('MultiPlaybackPage.header.description')}
        actions={
          <div className="flex items-center gap-2">
            {/* Playback-mode toggle: Frames (per-second JPEG, works on every NVR) vs Smooth (HLS video). */}
            <div
              className="inline-flex items-center rounded-md border bg-muted/40 p-0.5"
              role="group"
              aria-label={t('MultiPlaybackPage.mode.label')}
              title={t('MultiPlaybackPage.mode.smoothHint')}
            >
              <Button
                variant={mode === 'frames' ? 'default' : 'ghost'}
                size="sm"
                className="h-7 gap-1.5 text-xs"
                aria-pressed={mode === 'frames'}
                onClick={() => setMode('frames')}
              >
                <ImageIcon className="h-3.5 w-3.5" />
                {t('MultiPlaybackPage.mode.frames')}
              </Button>
              <Button
                variant={mode === 'smooth' ? 'default' : 'ghost'}
                size="sm"
                className="h-7 gap-1.5 text-xs"
                aria-pressed={mode === 'smooth'}
                onClick={() => setMode('smooth')}
              >
                <Film className="h-3.5 w-3.5" />
                {t('MultiPlaybackPage.mode.smooth')}
              </Button>
            </div>
            <Button variant="outline" size="sm" onClick={() => navigate('/cameras')}>
              <ArrowLeft className="h-4 w-4 mr-1.5" />
              {t('MultiPlaybackPage.actions.backToCameras')}
            </Button>
          </div>
        }
      />

      {isLoading && (
        <div className="flex gap-4">
          <Skeleton className="h-[480px] w-64 rounded-md" />
          <div className="flex-1 grid grid-cols-2 gap-3">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="aspect-video rounded-md" />
            ))}
          </div>
        </div>
      )}

      {isError && (
        <div className="rounded-md bg-destructive/10 border border-destructive/20 px-4 py-3 flex items-center gap-2">
          <AlertCircle className="h-4 w-4 text-destructive" />
          <span className="text-sm text-destructive">{t('MultiPlaybackPage.error.loadFailed')}</span>
        </div>
      )}

      {!isLoading && !isError && (
        <div className="flex gap-4">
          {/* Camera Picker Sidebar */}
          <CameraPicker
            cameras={cameras}
            selectedIds={selectedSet}
            onToggle={handleToggleCamera}
            maxReached={selectedCameraIds.length >= MAX_CAMERAS}
          />

          {/* Main Content */}
          <div className="flex-1 min-w-0 space-y-3">
            {selectedCameras.length === 0 ? (
              <EmptyState
                icon={Camera}
                title={t('MultiPlaybackPage.empty.title')}
                description={t('MultiPlaybackPage.empty.description')}
              />
            ) : (
              <>
                {/* Playback Grid */}
                <div
                  className={cn('grid gap-2', gridClass)}
                  style={{
                    height: 'calc(100vh - 460px)',
                    minHeight: 300,
                  }}
                >
                  {selectedCameras.map((cam, i) => (
                    <PlaybackCell
                      key={cam.id}
                      camera={cam}
                      playbackTime={playbackTime}
                      mode={mode}
                      playFromIso={playFrom.toISOString()}
                      fellBack={fellBackIds.has(cam.id)}
                      isPlaying={isPlaying}
                      onSeek={handleSeek}
                      onRemove={() => handleRemoveCamera(cam.id)}
                      onUnavailable={handleCellUnavailable}
                      onPlayheadTime={i === 0 ? handleRepPlayheadTime : undefined}
                    />
                  ))}
                </div>

                {/* Shared Timeline */}
                <SharedTimeline
                  cameraIds={selectedCameraIds}
                  playbackTime={playbackTime}
                  rangePreset={rangePreset}
                  onSeek={handleSeek}
                />

                {/* Playback Controls */}
                <PlaybackControls
                  playbackTime={playbackTime}
                  cameraId={selectedCameraIds[0]}
                  isPlaying={isPlaying}
                  speed={speed}
                  rangePreset={rangePreset}
                  onPlayPause={handlePlayPause}
                  onSpeedChange={setSpeed}
                  onSeek={handleSeek}
                  onSkip={handleSkip}
                  onRangeChange={setRangePreset}
                />

                {/* Evidence export, batch legal-hold of the whole grid over a window */}
                <EvidenceExportPanel
                  cameraIds={selectedCameraIds}
                  playheadMs={playbackTime.getTime()}
                />
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
