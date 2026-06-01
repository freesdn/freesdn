// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Camera Live View Modal
 * 
 * Full-screen camera viewer with PTZ controls and recording playback.
 */

import { useState, useRef, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { camerasApi } from '@/lib/api';
import {
  Maximize2,
  Minimize2,
  Volume2,
  Camera,
  VideoOff,
  Play,
  Pause,
  Download,
  ChevronUp,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ZoomIn,
  ZoomOut,
  Home,
  Loader2,
  Move,
  Circle,
  RefreshCw,
  RectangleHorizontal,
  Scan,
  Square,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import { MseLivePlayer } from './MseLivePlayer';

interface CameraDevice {
  id: string | number;
  name: string;
  ip_address?: string;
  location?: string;
  model?: string;
  vendor?: string;
  status: 'online' | 'offline' | 'recording' | 'error' | 'unknown';
  is_recording?: boolean;
  has_ptz?: boolean;
  has_audio?: boolean;
  stream_url?: string;
}

type StreamFit = 'contain' | 'cover' | 'fill';

interface CameraLiveViewProps {
  camera: CameraDevice | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Called when streaming starts/stops so parent can pause background polling */
  onStreamingChange?: (streaming: boolean) => void;
}

// PTZ Control pad component
function PTZControls({
  onMove,
  onZoom,
  onHome,
  onStop,
  disabled = false,
}: {
  onMove: (direction: 'up' | 'down' | 'left' | 'right') => void;
  onZoom: (direction: 'in' | 'out') => void;
  onHome: () => void;
  onStop: () => void;
  disabled?: boolean;
}) {
  const { t } = useTranslation('common');
  return (
    <div className="flex flex-col items-center gap-4">
      <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
        {t('CameraLiveViewModal.ptz.control')}
      </div>

      {/* Direction pad */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-1" role="group" aria-label={t('CameraLiveViewModal.ptz.directionControls')}>
        <div />
        <Button
          variant="secondary"
          size="icon"
          className="h-10 w-10"
          disabled={disabled}
          onMouseDown={() => onMove('up')}
          onMouseUp={onStop}
          onMouseLeave={onStop}
          aria-label={t('CameraLiveViewModal.ptz.panUp')}
        >
          <ChevronUp className="h-5 w-5" />
        </Button>
        <div />
        <Button
          variant="secondary"
          size="icon"
          className="h-10 w-10"
          disabled={disabled}
          onMouseDown={() => onMove('left')}
          onMouseUp={onStop}
          onMouseLeave={onStop}
          aria-label={t('CameraLiveViewModal.ptz.panLeft')}
        >
          <ChevronLeft className="h-5 w-5" />
        </Button>
        <Button
          variant="secondary"
          size="icon"
          className="h-10 w-10"
          disabled={disabled}
          onClick={onHome}
          aria-label={t('CameraLiveViewModal.ptz.home')}
        >
          <Home className="h-4 w-4" />
        </Button>
        <Button
          variant="secondary"
          size="icon"
          className="h-10 w-10"
          disabled={disabled}
          onMouseDown={() => onMove('right')}
          onMouseUp={onStop}
          onMouseLeave={onStop}
          aria-label={t('CameraLiveViewModal.ptz.panRight')}
        >
          <ChevronRight className="h-5 w-5" />
        </Button>
        <div />
        <Button
          variant="secondary"
          size="icon"
          className="h-10 w-10"
          disabled={disabled}
          onMouseDown={() => onMove('down')}
          onMouseUp={onStop}
          onMouseLeave={onStop}
          aria-label={t('CameraLiveViewModal.ptz.panDown')}
        >
          <ChevronDown className="h-5 w-5" />
        </Button>
        <div />
      </div>

      {/* Zoom controls */}
      <div className="flex items-center gap-2">
        <Button
          variant="secondary"
          size="icon"
          className="h-8 w-8"
          disabled={disabled}
          onMouseDown={() => onZoom('out')}
          onMouseUp={onStop}
          onMouseLeave={onStop}
          aria-label={t('CameraLiveViewModal.ptz.zoomOut')}
        >
          <ZoomOut className="h-4 w-4" />
        </Button>
        <span className="text-xs text-muted-foreground w-12 text-center">{t('CameraLiveViewModal.ptz.zoom')}</span>
        <Button
          variant="secondary"
          size="icon"
          className="h-8 w-8"
          disabled={disabled}
          onMouseDown={() => onZoom('in')}
          onMouseUp={onStop}
          onMouseLeave={onStop}
          aria-label={t('CameraLiveViewModal.ptz.zoomIn')}
        >
          <ZoomIn className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}

// Preset buttons
function PresetButtons({ 
  presets,
  onSelectPreset,
  disabled = false,
}: {
  presets: { id: number; name: string }[];
  onSelectPreset: (id: number) => void;
  disabled?: boolean;
}) {
  const { t } = useTranslation('common');
  return (
    <div className="space-y-2">
      <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
        {t('CameraLiveViewModal.presets.title')}
      </div>
      <div className="grid grid-cols-2 gap-1.5">
        {presets.map((preset) => (
          <Button
            key={preset.id}
            variant="outline"
            size="sm"
            className="text-xs h-8"
            disabled={disabled}
            onClick={() => onSelectPreset(preset.id)}
          >
            {preset.name}
          </Button>
        ))}
      </div>
    </div>
  );
}

export function CameraLiveViewModal({ camera, open, onOpenChange, onStreamingChange }: CameraLiveViewProps) {
  const { t } = useTranslation('common');
  const [isPlaying, setIsPlaying] = useState(true);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [showControls, setShowControls] = useState(true);
  const [controlsHovered, setControlsHovered] = useState(false);
  const [quality, setQuality] = useState<'main' | 'sub'>('sub');
  const [streamFit, setStreamFit] = useState<StreamFit>('contain');
  const [streamLoading, setStreamLoading] = useState(true);
  const [streamError, setStreamError] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const videoRef = useRef<HTMLDivElement>(null);
  const imgRef = useRef<HTMLImageElement>(null);
  const [clockTime, setClockTime] = useState(() => new Date());

  const isOnline = camera?.status === 'online' || camera?.status === 'recording';
  const [streamUrl, setStreamUrl] = useState('');
  // Layered live transports, best → most-compatible:
  //   1. MSE (sub-second, go2rtc WebSocket)  → mseError flips on failure
  //   2. progressive fMP4 <video> (go2rtc)   → videoError flips on failure
  //   3. MJPEG snapshot stream (works anywhere)
  const [mseError, setMseError] = useState(false);
  const [videoError, setVideoError] = useState(false);
  const liveVideoRef = useRef<HTMLVideoElement>(null);
  const liveVideoUrl =
    camera && isOnline ? camerasApi.getLiveVideoUrl(String(camera.id), quality) : '';

  // Stable ref for onStreamingChange to avoid infinite re-render loops
  // when parent passes an inline callback
  const onStreamingChangeRef = useRef(onStreamingChange);
  onStreamingChangeRef.current = onStreamingChange;

  // Notify parent when modal opens/closes (for pausing background polling)
  useEffect(() => {
    if (open) onStreamingChangeRef.current?.(true);
    return () => { onStreamingChangeRef.current?.(false); };
  }, [open]);

  // Reset transient state when camera changes
  const prevCameraId = useRef(camera?.id);
  useEffect(() => {
    if (camera?.id !== prevCameraId.current) {
      prevCameraId.current = camera?.id;
      setQuality('sub');
      setStreamFit('contain');
      setStreamError(false);
      setMseError(false);
      setVideoError(false);
      setRefreshKey(0);
    }
  }, [camera?.id]);

  // Re-attempt the best transport whenever the source identity changes (quality
  // switch or an explicit Retry/refresh) before falling back down the chain.
  useEffect(() => {
    setMseError(false);
    setVideoError(false);
  }, [quality, refreshKey]);

  // Stall watchdog for the LAYER-2 progressive fMP4 <video>. A go2rtc-fed
  // <video> whose NVR source freezes mid-stream keeps the buffered last frame
  // on screen and fires NO 'error' event (the connection stays open), so the
  // existing onError → videoError fallback never triggers. Track playback
  // progress and flip to videoError after STALL_MS of no advancement so the UI
  // falls through to the MJPEG/snapshot path instead of a silently frozen frame.
  const videoIsActive = mseError && !videoError && isPlaying && !!liveVideoUrl;
  useEffect(() => {
    if (!videoIsActive) return;
    const video = liveVideoRef.current;
    if (!video) return;
    const STALL_MS = 20_000;
    let lastProgressAt = Date.now();
    const markProgress = () => { lastProgressAt = Date.now(); };
    video.addEventListener('timeupdate', markProgress);
    video.addEventListener('progress', markProgress);
    video.addEventListener('playing', markProgress);
    const timer = window.setInterval(() => {
      // While genuinely paused the watchdog should not fire; isPlaying gates the
      // effect, but guard against an unexpected paused state too.
      if (!video.paused && Date.now() - lastProgressAt > STALL_MS) {
        setVideoError(true);
      }
    }, 5_000);
    return () => {
      video.removeEventListener('timeupdate', markProgress);
      video.removeEventListener('progress', markProgress);
      video.removeEventListener('playing', markProgress);
      window.clearInterval(timer);
    };
  }, [videoIsActive, quality, refreshKey]);

  // Fetch a short-lived stream token for the MJPEG URL, only once we've fallen
  // back from true video (videoError), so we don't open snapshot loops on the
  // NVR while the <video> path is working.
  useEffect(() => {
    if (!camera || !isOnline || !videoError) {
      setStreamUrl('');
      return;
    }
    let cancelled = false;
    setStreamLoading(true);
    setStreamError(false);
    camerasApi.getMjpegStreamUrlAsync(String(camera.id), quality).then((url) => {
      if (!cancelled) setStreamUrl(url);
    }).catch(() => {
      // Stream token fetch failed · show error state
      if (!cancelled) {
        setStreamUrl('');
        setStreamError(true);
        setStreamLoading(false);
      }
    });
    const imgEl = imgRef.current;
    return () => {
      cancelled = true;
      // Abort the MJPEG HTTP connection by clearing the img src
      if (imgEl) imgEl.src = '';
    };
  }, [camera, isOnline, quality, refreshKey, videoError]);

  // Reset loading/error when stream URL changes
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

  // Live clock for timestamp overlay (1s interval) · only when online
  useEffect(() => {
    if (!open || !isOnline) return;
    const timer = setInterval(() => setClockTime(new Date()), 1_000);
    return () => clearInterval(timer);
  }, [open, isOnline]);

  // Sync fullscreen state when user presses Escape or exits via browser
  useEffect(() => {
    const onFsChange = () => setIsFullscreen(!!document.fullscreenElement);
    document.addEventListener('fullscreenchange', onFsChange);
    return () => document.removeEventListener('fullscreenchange', onFsChange);
  }, []);

  // Auto-hide controls · never fade while the pointer is over the control bar
  useEffect(() => {
    if (!showControls || controlsHovered) return;
    const timeout = setTimeout(() => setShowControls(false), 3000);
    return () => clearTimeout(timeout);
  }, [showControls, controlsHovered]);

  const handleFullscreen = () => {
    // State is driven solely by the `fullscreenchange` listener so it stays
    // truthful even if the request is rejected or the user exits via Escape.
    if (!document.fullscreenElement) {
      videoRef.current?.requestFullscreen().catch(() => {});
    } else {
      document.exitFullscreen().catch(() => {});
    }
  };

  const handlePTZMove = async (direction: 'up' | 'down' | 'left' | 'right') => {
    if (!camera) return;
    try {
      await camerasApi.ptzControl(String(camera.id), direction, 50);
    } catch (error) {
      console.error('PTZ move failed:', error);
    }
  };

  const handlePTZZoom = async (direction: 'in' | 'out') => {
    if (!camera) return;
    try {
      await camerasApi.ptzControl(String(camera.id), direction === 'in' ? 'zoom_in' : 'zoom_out', 50);
    } catch (error) {
      console.error('PTZ zoom failed:', error);
    }
  };

  const handlePTZHome = async () => {
    if (!camera) return;
    try {
      await camerasApi.ptzControl(String(camera.id), 'preset', 50, 1);
    } catch (error) {
      console.error('PTZ home failed:', error);
    }
  };

  const handlePTZStop = async () => {
    if (!camera) return;
    try {
      await camerasApi.ptzControl(String(camera.id), 'stop', 50);
    } catch (error) {
      console.error('PTZ stop failed:', error);
    }
  };

  const handleSnapshot = useCallback(async () => {
    if (!camera) return;
    try {
      const res = await camerasApi.getSnapshot(String(camera.id));
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
    }
  }, [camera]);

  const presets = [
    { id: 1, name: t('CameraLiveViewModal.presets.entrance') },
    { id: 2, name: t('CameraLiveViewModal.presets.parking') },
    { id: 3, name: t('CameraLiveViewModal.presets.wideView') },
    { id: 4, name: t('CameraLiveViewModal.presets.zoom') },
  ];

  if (!camera) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-6xl h-[85vh] p-0 gap-0 flex flex-col">
        <DialogHeader className="p-4 border-b">
          <div className="flex items-center justify-between pr-8">
            <div className="flex items-center gap-3">
              <div className="flex items-center justify-center h-9 w-9 rounded-lg bg-primary/10">
                <Camera className="h-5 w-5 text-primary" />
              </div>
              <div>
                <DialogTitle className="text-base">{camera.name}</DialogTitle>
                {camera.location && (
                  <p className="text-sm text-muted-foreground">{camera.location}</p>
                )}
              </div>
            </div>
            <div className="flex items-center gap-2">
              {camera.is_recording && (
                <Badge variant="destructive" className="gap-1 animate-pulse">
                  <Circle className="h-2 w-2 fill-current" />
                  {t('CameraLiveViewModal.rec')}
                </Badge>
              )}
              <Badge
                variant={camera.status === 'online' || camera.status === 'recording' ? 'default' : 'secondary'}
                className={cn(
                  'gap-1.5 capitalize',
                  (camera.status === 'online' || camera.status === 'recording') && 'bg-emerald-600 hover:bg-emerald-600 text-white',
                  camera.status === 'offline' && 'bg-muted text-muted-foreground',
                  camera.status === 'error' && 'bg-red-600 hover:bg-red-600 text-white',
                )}
              >
                <span className={cn(
                  'h-1.5 w-1.5 rounded-full',
                  (camera.status === 'online' || camera.status === 'recording') && 'bg-white animate-pulse',
                  camera.status === 'offline' && 'bg-muted-foreground',
                  camera.status === 'error' && 'bg-white',
                  camera.status === 'unknown' && 'bg-muted-foreground',
                )} />
                {camera.status}
              </Badge>
            </div>
          </div>
        </DialogHeader>

        <div className="flex flex-1 min-h-0 overflow-hidden">
          {/* Video Player Area */}
          <div 
            ref={videoRef}
            className="relative flex-1 bg-black flex items-center justify-center"
            onMouseMove={() => setShowControls(true)}
          >
            {/* Live MJPEG stream */}
            {isOnline ? (
              <div className="absolute inset-0 flex items-center justify-center">
                {/* LAYER 1: sub-second live via MSE (go2rtc WebSocket). On any
                    failure → mseError, fall to the progressive fMP4 <video>. */}
                {!mseError && isPlaying && (
                  <MseLivePlayer
                    key={`mse-${camera.id}-${quality}-${refreshKey}`}
                    cameraId={String(camera.id)}
                    quality={quality}
                    muted
                    className={cn('w-full h-full', {
                      'object-contain': streamFit === 'contain',
                      'object-cover': streamFit === 'cover',
                      'object-fill': streamFit === 'fill',
                    })}
                    onError={() => setMseError(true)}
                  />
                )}

                {/* LAYER 2: progressive fMP4 <video> (go2rtc). On a decode/
                    playback error → videoError, fall back to MJPEG snapshots. */}
                {mseError && !videoError && isPlaying && liveVideoUrl && (
                  <video
                    ref={liveVideoRef}
                    key={`v-${camera.id}-${quality}-${refreshKey}`}
                    src={liveVideoUrl}
                    autoPlay
                    muted
                    playsInline
                    className={cn('w-full h-full', {
                      'object-contain': streamFit === 'contain',
                      'object-cover': streamFit === 'cover',
                      'object-fill': streamFit === 'fill',
                    })}
                    onError={() => setVideoError(true)}
                  />
                )}

                {/* FALLBACK: MJPEG snapshot stream · gated on videoError +
                    isPlaying so Pause freezes the feed (unmounting the <img>
                    aborts the multipart connection rather than just hiding it). */}
                {videoError && !streamError && streamUrl && isPlaying && (
                  <img
                    ref={imgRef}
                    key={`${camera.id}-${quality}-${refreshKey}`}
                    src={streamUrl}
                    alt={camera.name}
                    className={cn('w-full h-full', {
                      'object-contain': streamFit === 'contain',
                      'object-cover': streamFit === 'cover',
                      'object-fill': streamFit === 'fill',
                    })}
                    onLoad={handleStreamLoad}
                    onError={handleStreamError}
                  />
                )}

                {/* Paused · show a static "paused" hint over the frozen frame */}
                {!isPlaying && (
                  <div className="absolute inset-0 flex items-center justify-center text-white/60">
                    <div className="text-center">
                      <Pause className="h-12 w-12 mx-auto mb-2" />
                      <p className="text-sm">{t('CameraLiveViewModal.stream.paused')}</p>
                    </div>
                  </div>
                )}

                {/* Loading (MJPEG fallback fetch) */}
                {videoError && streamLoading && !streamError && isPlaying && (
                  <div className="absolute inset-0 flex items-center justify-center">
                    <div className="text-center text-white/60">
                      <Loader2 className="h-10 w-10 mx-auto mb-3 animate-spin" />
                      <p className="text-sm">{t('CameraLiveViewModal.stream.connecting')}</p>
                    </div>
                  </div>
                )}

                {/* Error, both true video AND the MJPEG fallback failed */}
                {videoError && streamError && (
                  <div className="text-center text-white/60">
                    <VideoOff className="h-16 w-16 mx-auto mb-4 text-red-400/60" />
                    <p className="text-sm">{t('CameraLiveViewModal.stream.unavailable')}</p>
                    <Button
                      size="sm"
                      variant="outline"
                      className="mt-3 text-white border-white/30 hover:bg-white/10"
                      onClick={() => setRefreshKey((k) => k + 1)}
                    >
                      <RefreshCw className="h-3 w-3 mr-1" />
                      {t('CameraLiveViewModal.stream.retry')}
                    </Button>
                  </div>
                )}

                {/* Timestamp overlay (browser-local wall clock, NOT NVR time) */}
                <div className="absolute top-4 left-4 bg-black/60 px-2 py-1 rounded text-xs text-white font-mono flex items-center gap-1.5">
                  <span>{clockTime.toLocaleString()}</span>
                  <span className="text-[9px] uppercase tracking-wide text-white/50">{t('CameraLiveViewModal.stream.localTime')}</span>
                </div>
                {/* Recording indicator (NVR-managed) */}
                {camera.is_recording && (
                  <div className="absolute top-4 right-4 flex items-center gap-2 bg-red-600/80 px-2 py-1 rounded">
                    <Circle className="h-2 w-2 fill-white text-white animate-pulse" />
                    <span className="text-xs text-white font-medium">{t('CameraLiveViewModal.rec')}</span>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center text-white/60">
                <VideoOff className="h-16 w-16 mx-auto mb-4" />
                <p className="text-sm">{t('CameraLiveViewModal.offline.title')}</p>
                <p className="text-xs text-white/40 mt-1">{t('CameraLiveViewModal.offline.description')}</p>
              </div>
            )}

            {/* Video Controls Overlay */}
            <div
              className={cn(
                'absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/80 to-transparent p-4 transition-opacity',
                showControls ? 'opacity-100' : 'opacity-0'
              )}
              onMouseEnter={() => { setControlsHovered(true); setShowControls(true); }}
              onMouseLeave={() => setControlsHovered(false)}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {/* Play/Pause */}
                  <TooltipProvider>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="text-white hover:bg-white/20"
                          onClick={() => {
                            if (isPlaying) {
                              // Pause: abort the multipart MJPEG connection
                              if (imgRef.current) imgRef.current.src = '';
                              setIsPlaying(false);
                            } else {
                              // Resume: re-fetch a fresh stream URL/token
                              setIsPlaying(true);
                              setRefreshKey((k) => k + 1);
                            }
                          }}
                          aria-label={isPlaying ? t('CameraLiveViewModal.controls.pause') : t('CameraLiveViewModal.controls.play')}
                        >
                          {isPlaying ? (
                            <Pause className="h-5 w-5" />
                          ) : (
                            <Play className="h-5 w-5" />
                          )}
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>{isPlaying ? t('CameraLiveViewModal.controls.pause') : t('CameraLiveViewModal.controls.play')}</TooltipContent>
                    </Tooltip>
                  </TooltipProvider>

                  {/* Refresh */}
                  <TooltipProvider>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="text-white hover:bg-white/20"
                          onClick={() => { setStreamUrl(''); setRefreshKey((k) => k + 1); }}
                          aria-label={t('CameraLiveViewModal.controls.refreshStream')}
                        >
                          <RefreshCw className="h-4 w-4" />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>{t('CameraLiveViewModal.controls.refreshStream')}</TooltipContent>
                    </Tooltip>
                  </TooltipProvider>

                  {/* No audio control: MJPEG-over-snapshot carries no audio,
                      so a volume/mute affordance here would be misleading. */}
                </div>

                <div className="flex items-center gap-2">
                  {/* Snapshot */}
                  <TooltipProvider>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="text-white hover:bg-white/20"
                          onClick={handleSnapshot}
                          aria-label={t('CameraLiveViewModal.controls.takeSnapshot')}
                        >
                          <Download className="h-4 w-4" />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>{t('CameraLiveViewModal.controls.takeSnapshot')}</TooltipContent>
                    </Tooltip>
                  </TooltipProvider>

                  {/* Record indicator · recording is managed by NVR schedule */}
                  {camera.is_recording && (
                    <TooltipProvider>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <div className="flex items-center gap-1 text-red-500 px-1">
                            <Circle className="h-3 w-3 fill-current animate-pulse" />
                            <span className="text-[10px] font-bold">{t('CameraLiveViewModal.rec')}</span>
                          </div>
                        </TooltipTrigger>
                        <TooltipContent>{t('CameraLiveViewModal.controls.recordingManaged')}</TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  )}

                  {/* Stream fit mode */}
                  <div className="flex items-center bg-white/10 rounded-md">
                    <TooltipProvider>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Button
                            variant="ghost"
                            size="icon"
                            className={cn('h-8 w-8 text-white hover:bg-white/20', streamFit === 'contain' && 'bg-white/20')}
                            onClick={() => setStreamFit('contain')}
                            aria-label={t('CameraLiveViewModal.fit.contain')}
                          >
                            <RectangleHorizontal className="h-3.5 w-3.5" />
                          </Button>
                        </TooltipTrigger>
                        <TooltipContent>{t('CameraLiveViewModal.fit.contain')}</TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                    <TooltipProvider>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Button
                            variant="ghost"
                            size="icon"
                            className={cn('h-8 w-8 text-white hover:bg-white/20', streamFit === 'cover' && 'bg-white/20')}
                            onClick={() => setStreamFit('cover')}
                            aria-label={t('CameraLiveViewModal.fit.coverAria')}
                          >
                            <Scan className="h-3.5 w-3.5" />
                          </Button>
                        </TooltipTrigger>
                        <TooltipContent>{t('CameraLiveViewModal.fit.cover')}</TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                    <TooltipProvider>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Button
                            variant="ghost"
                            size="icon"
                            className={cn('h-8 w-8 text-white hover:bg-white/20', streamFit === 'fill' && 'bg-white/20')}
                            onClick={() => setStreamFit('fill')}
                            aria-label={t('CameraLiveViewModal.fit.fillAria')}
                          >
                            <Square className="h-3.5 w-3.5" />
                          </Button>
                        </TooltipTrigger>
                        <TooltipContent>{t('CameraLiveViewModal.fit.fill')}</TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  </div>

                  {/* Fullscreen */}
                  <TooltipProvider>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="text-white hover:bg-white/20"
                          onClick={handleFullscreen}
                          aria-label={isFullscreen ? t('CameraLiveViewModal.controls.exitFullscreen') : t('CameraLiveViewModal.controls.fullscreen')}
                        >
                          {isFullscreen ? (
                            <Minimize2 className="h-4 w-4" />
                          ) : (
                            <Maximize2 className="h-4 w-4" />
                          )}
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>{isFullscreen ? t('CameraLiveViewModal.controls.exitFullscreen') : t('CameraLiveViewModal.controls.fullscreen')}</TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                </div>
              </div>
            </div>
          </div>

          {/* Side Panel - PTZ Controls */}
          {camera.has_ptz && (
            <div className="w-48 border-l p-4 space-y-6 bg-muted/30">
              <PTZControls
                onMove={handlePTZMove}
                onZoom={handlePTZZoom}
                onHome={handlePTZHome}
                onStop={handlePTZStop}
                disabled={camera.status === 'offline'}
              />
              <PresetButtons
                presets={presets}
                onSelectPreset={(id) => {
                  camerasApi.ptzControl(String(camera.id), 'preset', 50, id).catch(() => {});
                }}
                disabled={camera.status === 'offline'}
              />
            </div>
          )}
        </div>

        {/* Footer Info */}
        <div className="px-4 py-2 border-t bg-muted/30 flex items-center justify-between text-xs shrink-0">
          <div className="flex items-center gap-3 text-muted-foreground">
            {camera.ip_address && (
              <span className="font-mono">{camera.ip_address}</span>
            )}
            {(camera.vendor || camera.model) && (
              <>
                {camera.ip_address && <span className="text-muted-foreground/40">|</span>}
                <span>{[camera.vendor, camera.model].filter(Boolean).join(' ')}</span>
              </>
            )}
            {camera.has_ptz && (
              <Badge variant="outline" className="gap-1 text-[10px] h-5 px-1.5">
                <Move className="h-2.5 w-2.5" />
                {t('CameraLiveViewModal.badges.ptz')}
              </Badge>
            )}
            {camera.has_audio && (
              <Badge variant="outline" className="gap-1 text-[10px] h-5 px-1.5">
                <Volume2 className="h-2.5 w-2.5" />
                {t('CameraLiveViewModal.badges.audio')}
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-1">
            <span className="text-muted-foreground mr-1">{t('CameraLiveViewModal.stream.label')}</span>
            <Button
              variant={quality === 'sub' ? 'secondary' : 'ghost'}
              size="sm"
              className="h-6 px-2 text-[10px]"
              onClick={() => setQuality('sub')}
            >
              {t('CameraLiveViewModal.stream.sub')}
            </Button>
            <Button
              variant={quality === 'main' ? 'secondary' : 'ghost'}
              size="sm"
              className="h-6 px-2 text-[10px]"
              onClick={() => setQuality('main')}
            >
              {t('CameraLiveViewModal.stream.main')}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default CameraLiveViewModal;
