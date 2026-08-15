// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * CameraDisplayWall · Immersive kiosk-mode camera wall
 *
 * Purpose-built for security monitors, NOC displays, and dedicated screens.
 * Inspired by Hikvision iVMS-4200 Live View, Milestone XProtect Smart Wall,
 * and UniFi Protect's full-screen mode.
 *
 * Key design principles:
 *  - Zero distraction: pure black background, no sidebar, no page chrome
 *  - Auto-hiding controls: toolbar appears on mouse hover at top, fades after 3s
 *  - Edge-to-edge grid: cameras fill the entire viewport
 *  - Fullscreen API: one-click true fullscreen (hides browser chrome)
 *  - Persistent config: layout + cameras persisted in URL for bookmarkable display configs
 *  - Clock overlay: optional live time display for surveillance compliance
 *  - Auto-fill: automatically populates grid with online cameras
 *
 * Routes:
 *   /cameras/display                          · empty wall, user assigns cameras
 *   /cameras/display?layout=4x4&cameras=a,b   · bookmarked configuration
 *   /cameras/display?layout=4x4&fill=true     · auto-fill with online cameras
 *   /cameras/display?mode=live&labels=false    · live mode, no labels
 */

import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  Maximize2,
  Minimize2,
  LayoutGrid,
  Video,
  ImageIcon,
  ArrowLeft,
  RefreshCw,
  MonitorPlay,
  Settings2,
  Clock,
  ChevronLeft,
  ChevronRight,
  Loader2,
  AlertTriangle,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
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
  DropdownMenuSeparator,
  DropdownMenuLabel,
  DropdownMenuCheckboxItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { TooltipProvider } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import { camerasApi } from '@/lib/api';
import { useSiteStore } from '@/stores/siteStore';
import { WallCell } from '@/components/cameras/wall/WallCell';
import { useSnapshotEngine } from '@/components/cameras/wall/useSnapshotEngine';
import { getTargetFps } from '@/components/cameras/wall/useCanvasStream';
import { mapToWallCameras } from '@/components/cameras/wall/mapToWallCamera';
import type {
  WallLayout,
  WallCamera,
  CellHighlight,
  CellReplay,
} from '@/components/cameras/wall/types';
import { LAYOUT_CELL_COUNT, LAYOUT_LABELS } from '@/components/cameras/wall/types';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VALID_LAYOUTS = new Set<WallLayout>(['1x1', '1+5', '2x2', '3x3', '4x4', '5x5', '6x6', '8x8']);

const GRID_CLASSES: Record<WallLayout, string> = {
  '1x1': 'grid-cols-1 grid-rows-1',
  '1+5': 'grid-cols-3 grid-rows-3',
  '2x2': 'grid-cols-2 grid-rows-2',
  '3x3': 'grid-cols-3 grid-rows-3',
  '4x4': 'grid-cols-4 grid-rows-4',
  '5x5': 'grid-cols-5 grid-rows-5',
  '6x6': 'grid-cols-6 grid-rows-6',
  '8x8': 'grid-cols-8 grid-rows-8',
};

const COMPACT_THRESHOLD = 16;
const TOOLBAR_HIDE_DELAY = 3000;
const TOOLBAR_HEIGHT = 48;

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function CameraDisplayWall() {
  const { t } = useTranslation('cameras');
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // ── Parse URL params ──
  const initialLayout = useMemo((): WallLayout => {
    const l = searchParams.get('layout') || '4x4';
    return VALID_LAYOUTS.has(l as WallLayout) ? (l as WallLayout) : '4x4';
  }, [searchParams]);

  const initialCameraIds = useMemo(() => {
    const c = searchParams.get('cameras');
    return c ? c.split(',').filter(Boolean) : [];
  }, [searchParams]);

  const initialMode = useMemo(() => {
    return searchParams.get('mode') === 'live' ? 'live' as const : 'snapshot' as const;
  }, [searchParams]);

  const initialLabels = useMemo(() => {
    return searchParams.get('labels') !== 'false';
  }, [searchParams]);

  const autoFill = useMemo(() => {
    return searchParams.get('fill') === 'true';
  }, [searchParams]);

  // ── State ──
  const [layout, setLayoutState] = useState<WallLayout>(initialLayout);
  const [cameraIds, setCameraIdsState] = useState<string[]>(initialCameraIds);
  const [streamMode, setStreamMode] = useState<'snapshot' | 'live'>(initialMode);
  const [streamQuality, setStreamQuality] = useState<'sub' | 'main'>('sub');
  const [showLabels, setShowLabels] = useState(initialLabels);
  const [showClock, setShowClock] = useState(true);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [toolbarVisible, setToolbarVisible] = useState(true);
  const [page, setPage] = useState(0);
  const [clockTime, setClockTime] = useState(() => new Date());
  const [focusedCameraId, setFocusedCameraId] = useState<string | null>(null);

  // Highlight and replay state (minimal · display wall is view-only)
  const [highlightedCells] = useState<Record<number, CellHighlight>>({});
  const [replayState] = useState<Record<number, CellReplay>>({});

  const containerRef = useRef<HTMLDivElement>(null);
  const hideTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const mouseActiveRef = useRef(false);

  // ── URL sync helpers ──
  const setLayout = useCallback((l: WallLayout) => {
    setLayoutState(l);
    setPage(0);
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set('layout', l);
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  const setCameraIds = useCallback((ids: string[]) => {
    setCameraIdsState(ids);
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (ids.length === 0) next.delete('cameras'); else next.set('cameras', ids.join(','));
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  // ── Data ──
  const { data: camerasData, isLoading, isError } = useQuery({
    queryKey: ['cameras', 'display-wall', selectedSiteId],
    queryFn: async () => {
      const { data } = await camerasApi.getAll({
        site_id: selectedSiteId || undefined,
        limit: 100,
      });
      return data;
    },
    refetchInterval: 30_000,
  });

  const cameras = useMemo(() => mapToWallCameras(camerasData), [camerasData]);
  const onlineCameras = useMemo(() => cameras.filter((c) => c.status === 'online' || c.status === 'recording'), [cameras]);

  // ── Auto-fill on first load if requested ──
  useEffect(() => {
    if (autoFill && onlineCameras.length > 0 && cameraIds.length === 0) {
      const cellCount = LAYOUT_CELL_COUNT[layout];
      const ids = onlineCameras.slice(0, cellCount).map((c) => c.id);
      setCameraIds(ids);
    }
  }, [autoFill, onlineCameras, cameraIds.length, layout, setCameraIds]);

  // ── Grid computation ──
  const cellCount = LAYOUT_CELL_COUNT[layout];
  const pageCount = Math.max(1, Math.ceil(cameraIds.length / cellCount));
  const compact = cellCount > COMPACT_THRESHOLD;

  const currentCameraIds = useMemo((): (string | null)[] => {
    const start = page * cellCount;
    const result: (string | null)[] = cameraIds.slice(start, start + cellCount);
    // Pad with nulls to fill grid
    while (result.length < cellCount) result.push(null);
    return result;
  }, [cameraIds, page, cellCount]);

  const cameraMap = useMemo(() => {
    const map = new Map<string, WallCamera>();
    cameras.forEach((c) => map.set(c.id, c));
    return map;
  }, [cameras]);

  const cellCameras = useMemo(
    () => currentCameraIds.map((id) => (id ? cameraMap.get(id) || null : null)),
    [currentCameraIds, cameraMap],
  );

  const activeCellCount = useMemo(
    () => currentCameraIds.filter((id) => id !== null).length,
    [currentCameraIds],
  );

  const targetFps = useMemo(() => getTargetFps(activeCellCount), [activeCellCount]);
  const isAsymmetric = layout === '1+5';

  // ── Progressive live loading ──
  const MAX_LIVE_CELLS = 16;
  const LIVE_BATCH_SIZE = 4;
  const LIVE_BATCH_DELAY_MS = 2000;
  const [liveBudget, setLiveBudget] = useState<number>(Infinity);
  const activeCellCountRef = useRef(activeCellCount);
  activeCellCountRef.current = activeCellCount;

  useEffect(() => {
    if (streamMode !== 'live') {
      setLiveBudget(Infinity);
      return;
    }
    let budget = LIVE_BATCH_SIZE;
    setLiveBudget(budget);
    const timer = setInterval(() => {
      budget += LIVE_BATCH_SIZE;
      setLiveBudget(budget);
      if (budget >= Math.min(activeCellCountRef.current, MAX_LIVE_CELLS)) clearInterval(timer);
    }, LIVE_BATCH_DELAY_MS);
    return () => clearInterval(timer);
  }, [streamMode]);  

  // ── Snapshot engine ──
  const snapshotEngine = useSnapshotEngine(
    currentCameraIds,
    activeCellCount,
    streamMode === 'live' || !!focusedCameraId,
    cameraMap,
  );

  // ── Live clock ──
  useEffect(() => {
    if (!showClock) return;
    const timer = setInterval(() => setClockTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, [showClock]);

  // ── Fullscreen sync ──
  useEffect(() => {
    const handler = () => setIsFullscreen(!!document.fullscreenElement);
    document.addEventListener('fullscreenchange', handler);
    return () => document.removeEventListener('fullscreenchange', handler);
  }, []);

  const toggleFullscreen = useCallback(() => {
    if (document.fullscreenElement) {
      document.exitFullscreen();
    } else {
      containerRef.current?.requestFullscreen();
    }
  }, []);

  // ── Auto-hide toolbar ──
  const showToolbar = useCallback(() => {
    setToolbarVisible(true);
    mouseActiveRef.current = true;
    clearTimeout(hideTimerRef.current);
    hideTimerRef.current = setTimeout(() => {
      if (!mouseActiveRef.current) return;
      mouseActiveRef.current = false;
      setToolbarVisible(false);
    }, TOOLBAR_HIDE_DELAY);
  }, []);

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      // Only show toolbar when mouse is near the top
      if (e.clientY < TOOLBAR_HEIGHT + 40) {
        showToolbar();
      }
    };
    const handleMouseLeave = () => {
      mouseActiveRef.current = false;
      clearTimeout(hideTimerRef.current);
      hideTimerRef.current = setTimeout(() => setToolbarVisible(false), 1000);
    };

    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseleave', handleMouseLeave);
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseleave', handleMouseLeave);
      clearTimeout(hideTimerRef.current);
    };
  }, [showToolbar]);

  // Show toolbar initially, then hide after delay
  useEffect(() => {
    hideTimerRef.current = setTimeout(() => setToolbarVisible(false), TOOLBAR_HIDE_DELAY);
    return () => clearTimeout(hideTimerRef.current);
  }, []);

  // ── Keyboard shortcuts ──
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;

      switch (e.key) {
        case 'Escape':
          if (focusedCameraId) {
            setFocusedCameraId(null);
          } else if (isFullscreen) {
            document.exitFullscreen();
          }
          break;
        case 'f':
        case 'F':
          if (!e.ctrlKey && !e.metaKey) {
            e.preventDefault();
            toggleFullscreen();
          }
          break;
        case 'l':
        case 'L':
          if (!e.ctrlKey && !e.metaKey) {
            e.preventDefault();
            setStreamMode((m) => m === 'live' ? 'snapshot' : 'live');
          }
          break;
        case 'h':
        case 'H':
          if (!e.ctrlKey && !e.metaKey) {
            e.preventDefault();
            setShowLabels((v) => !v);
          }
          break;
        case 'ArrowLeft':
          if (page > 0) setPage((p) => p - 1);
          break;
        case 'ArrowRight':
          if (page < pageCount - 1) setPage((p) => p + 1);
          break;
      }
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [focusedCameraId, isFullscreen, page, pageCount, toggleFullscreen]);

  // ── Cell handlers ──
  const handleFocusCamera = useCallback((cameraId: string) => {
    setFocusedCameraId((prev) => (prev === cameraId ? null : cameraId));
  }, []);

  const handleRemoveCell = useCallback((index: number) => {
    const next = [...cameraIds];
    const globalIndex = page * cellCount + index;
    if (globalIndex < next.length) {
      next.splice(globalIndex, 1);
      setCameraIds(next);
    }
  }, [cameraIds, page, cellCount, setCameraIds]);

  const handleCameraAssign = useCallback((cellIndex: number, cameraId: string) => {
    const next: (string | null)[] = [...cameraIds];
    const globalIndex = page * cellCount + cellIndex;
    while (next.length <= globalIndex) next.push(null);

    // Remove from previous position if already assigned
    const existing = next.indexOf(cameraId);
    if (existing !== -1 && existing !== globalIndex) {
      next[existing] = next[globalIndex];
    }
    next[globalIndex] = cameraId;
    setCameraIds(next.filter((id): id is string => id !== null));
  }, [cameraIds, page, cellCount, setCameraIds]);

  const handleFillWall = useCallback(() => {
    const ids = onlineCameras.slice(0, cellCount).map((c) => c.id);
    setCameraIds(ids);
  }, [onlineCameras, cellCount, setCameraIds]);

  const handleOpenDetail = useCallback((cameraId: string) => {
    window.open(`/cameras/${cameraId}`, '_blank', 'noopener,noreferrer');
  }, []);

  // ── Loading state ──
  if (isLoading) {
    return (
      <div className="h-screen w-screen bg-black flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-white/30" />
      </div>
    );
  }

  // ── Render ──
  return (
    <TooltipProvider delayDuration={300}>
      <div
        ref={containerRef}
        className="h-screen w-screen bg-black text-white overflow-hidden select-none relative"
        onMouseMove={toolbarVisible ? undefined : showToolbar}
      >
        {/* ── Auto-hiding Toolbar ── */}
        <div
          className={cn(
            'absolute top-0 left-0 right-0 z-50 transition-all duration-300',
            toolbarVisible
              ? 'opacity-100 translate-y-0'
              : 'opacity-0 -translate-y-full pointer-events-none',
          )}
          onMouseEnter={showToolbar}
          style={{ height: TOOLBAR_HEIGHT }}
        >
          <div className="h-full bg-gradient-to-b from-black/90 via-black/70 to-transparent px-4 flex items-center gap-2">
            {/* Back button */}
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 text-white/60 hover:text-white hover:bg-white/10"
              onClick={() => navigate('/cameras/wall')}
            >
              <ArrowLeft className="h-4 w-4" />
            </Button>

            {/* Layout selector */}
            <Select value={layout} onValueChange={(v) => setLayout(v as WallLayout)}>
              <SelectTrigger className="w-[85px] h-8 text-xs bg-white/5 border-white/10 text-white">
                <LayoutGrid className="h-3.5 w-3.5 mr-1.5" />
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(Object.entries(LAYOUT_LABELS) as [WallLayout, string][]).map(([key, label]) => (
                  <SelectItem key={key} value={key}>
                    <span className="flex items-center justify-between w-full gap-3">
                      <span>{label}</span>
                      <span className="text-muted-foreground text-[10px]">{LAYOUT_CELL_COUNT[key]}</span>
                    </span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            {/* Fill wall */}
            <Button
              variant="ghost"
              size="sm"
              className="h-8 text-xs text-white/60 hover:text-white hover:bg-white/10 gap-1"
              onClick={handleFillWall}
            >
              <MonitorPlay className="h-3.5 w-3.5" />
              {t('CameraDisplayWall.toolbar.fill', { count: cellCount })}
            </Button>

            {/* Stream mode toggle */}
            <div className="flex items-center rounded-md border border-white/10">
              <button
                className={cn(
                  'px-2.5 py-1 text-xs flex items-center gap-1 rounded-l-md transition-colors',
                  streamMode === 'snapshot' ? 'bg-white/20 text-white' : 'text-white/40 hover:text-white/70',
                )}
                onClick={() => setStreamMode('snapshot')}
              >
                <ImageIcon className="h-3 w-3" />
                {t('CameraDisplayWall.toolbar.snapshots')}
              </button>
              <button
                className={cn(
                  'px-2.5 py-1 text-xs flex items-center gap-1 rounded-r-md transition-colors',
                  streamMode === 'live' ? 'bg-white/20 text-white' : 'text-white/40 hover:text-white/70',
                )}
                onClick={() => setStreamMode('live')}
              >
                <Video className="h-3 w-3" />
                {t('CameraDisplayWall.toolbar.live')}
              </button>
            </div>

            {/* Page navigation */}
            {pageCount > 1 && (
              <div className="flex items-center gap-1">
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 text-white/60 hover:text-white hover:bg-white/10"
                  onClick={() => setPage(Math.max(0, page - 1))}
                  disabled={page === 0}
                >
                  <ChevronLeft className="h-3.5 w-3.5" />
                </Button>
                <span className="text-xs text-white/40 min-w-[40px] text-center">
                  {page + 1}/{pageCount}
                </span>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 text-white/60 hover:text-white hover:bg-white/10"
                  onClick={() => setPage(Math.min(pageCount - 1, page + 1))}
                  disabled={page >= pageCount - 1}
                >
                  <ChevronRight className="h-3.5 w-3.5" />
                </Button>
              </div>
            )}

            <div className="flex-1" />

            {/* Status */}
            <Badge variant="secondary" className="text-[10px] bg-white/10 text-white/60 border-white/10 gap-1">
              {t('CameraDisplayWall.status.summary', {
                active: activeCellCount,
                online: onlineCameras.length,
                total: cameras.length,
              })}
            </Badge>

            {/* Display options */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" className="h-8 w-8 text-white/60 hover:text-white hover:bg-white/10">
                  <Settings2 className="h-3.5 w-3.5" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-48">
                <DropdownMenuLabel className="text-xs">{t('CameraDisplayWall.display.heading')}</DropdownMenuLabel>
                <DropdownMenuCheckboxItem
                  checked={showLabels}
                  onCheckedChange={(v) => setShowLabels(!!v)}
                >
                  {t('CameraDisplayWall.display.cameraLabels')}
                </DropdownMenuCheckboxItem>
                <DropdownMenuCheckboxItem
                  checked={showClock}
                  onCheckedChange={(v) => setShowClock(!!v)}
                >
                  {t('CameraDisplayWall.display.clockOverlay')}
                </DropdownMenuCheckboxItem>
                <DropdownMenuSeparator />
                <DropdownMenuLabel className="text-xs">{t('CameraDisplayWall.streamQuality.heading')}</DropdownMenuLabel>
                <DropdownMenuCheckboxItem
                  checked={streamQuality === 'sub'}
                  onCheckedChange={() => setStreamQuality('sub')}
                >
                  {t('CameraDisplayWall.streamQuality.sub')}
                </DropdownMenuCheckboxItem>
                <DropdownMenuCheckboxItem
                  checked={streamQuality === 'main'}
                  onCheckedChange={() => setStreamQuality('main')}
                >
                  {t('CameraDisplayWall.streamQuality.main')}
                </DropdownMenuCheckboxItem>
                <DropdownMenuSeparator />
                <DropdownMenuLabel className="text-xs">{t('CameraDisplayWall.shortcuts.heading')}</DropdownMenuLabel>
                <DropdownMenuItem disabled className="text-[10px] text-muted-foreground">
                  {t('CameraDisplayWall.shortcuts.row1')}
                </DropdownMenuItem>
                <DropdownMenuItem disabled className="text-[10px] text-muted-foreground">
                  {t('CameraDisplayWall.shortcuts.row2')}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>

            {/* Refresh (snapshot mode) */}
            {streamMode === 'snapshot' && (
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8 text-white/60 hover:text-white hover:bg-white/10"
                onClick={snapshotEngine.forceRefresh}
              >
                <RefreshCw className="h-3.5 w-3.5" />
              </Button>
            )}

            {/* Fullscreen */}
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 text-white/60 hover:text-white hover:bg-white/10"
              onClick={toggleFullscreen}
            >
              {isFullscreen
                ? <Minimize2 className="h-4 w-4" />
                : <Maximize2 className="h-4 w-4" />
              }
            </Button>
          </div>
        </div>

        {/* ── Clock Overlay ── */}
        {showClock && (
          <div className="absolute top-2 right-3 z-40 pointer-events-none">
            <div className={cn(
              'flex items-center gap-1.5 text-white/50 font-mono text-xs transition-opacity duration-300',
              toolbarVisible ? 'opacity-0' : 'opacity-100',
            )}>
              <Clock className="h-3 w-3" />
              {clockTime.toLocaleTimeString()}
            </div>
          </div>
        )}

        {/* ── Camera Grid ── */}
        <div
          className={cn(
            'absolute inset-0 grid',
            compact ? 'gap-px' : 'gap-0.5',
            !isAsymmetric && GRID_CLASSES[layout],
          )}
          style={{
            padding: compact ? 0 : 2,
            ...(isAsymmetric
              ? {
                  display: 'grid',
                  gridTemplateColumns: '2fr 1fr 1fr',
                  gridTemplateRows: '1fr 1fr 1fr',
                }
              : {}),
          }}
        >
          {cellCameras.map((camera, i) => {
            const cameraId = currentCameraIds[i];
            const isOnline = camera && (camera.status === 'online' || camera.status === 'recording');

            return (
              <div
                key={cameraId ? `${cameraId}-${i}` : `empty-${i}`}
                className={cn(
                  isAsymmetric && i === 0 && 'row-span-2 col-span-2',
                )}
              >
                <WallCell
                  camera={camera}
                  snapshotSrc={isOnline ? snapshotEngine.getSnapshotSrc(cameraId) : ''}
                  snapshotLoading={snapshotEngine.isLoading(cameraId)}
                  snapshotError={snapshotEngine.hasError(cameraId)}
                  index={i}
                  focused={camera?.id === focusedCameraId}
                  streamQuality={streamQuality}
                  streamMode={streamMode}
                  showLabel={showLabels}
                  showStatus={false}
                  compact={compact}
                  highlighted={highlightedCells[i] || null}
                  replay={replayState[i] || null}
                  onFocus={handleFocusCamera}
                  onRemove={handleRemoveCell}
                  onOpenDetail={handleOpenDetail}
                  onCameraAssign={handleCameraAssign}
                  targetFps={targetFps}
                  staggerMs={i * 150}
                  withinLiveBudget={i < liveBudget && i < MAX_LIVE_CELLS}
                />
              </div>
            );
          })}
        </div>

        {/* ── Error overlay (camera list failed to load) ── */}
        {isError && (
          <div className="absolute inset-0 flex items-center justify-center z-40 pointer-events-none">
            <div className="text-center pointer-events-auto">
              <AlertTriangle className="h-12 w-12 text-destructive/60 mx-auto mb-3" />
              <p className="text-destructive text-sm">{t('CameraWallPage.errors.loadFailed')}</p>
            </div>
          </div>
        )}

        {/* ── Empty state (no cameras assigned) ── */}
        {activeCellCount === 0 && !isLoading && !isError && (
          <div className="absolute inset-0 flex items-center justify-center z-30 pointer-events-none">
            <div className="text-center pointer-events-auto">
              <MonitorPlay className="h-12 w-12 text-white/15 mx-auto mb-3" />
              <p className="text-white/30 text-sm mb-3">{t('CameraDisplayWall.empty.title')}</p>
              <Button
                variant="outline"
                size="sm"
                className="bg-white/5 border-white/20 text-white/60 hover:text-white hover:bg-white/10"
                onClick={handleFillWall}
              >
                <MonitorPlay className="h-4 w-4 mr-1.5" />
                {t('CameraDisplayWall.empty.autoFill')}
              </Button>
            </div>
          </div>
        )}
      </div>
    </TooltipProvider>
  );
}
