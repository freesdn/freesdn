// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * CameraWall · Enterprise-grade multi-channel surveillance wall
 *
 * Handles up to 64 simultaneous camera feeds with:
 *  - Adaptive snapshot refresh (fewer cameras → faster refresh)
 *  - Live MJPEG mode (all cells stream simultaneously)
 *  - Staggered request scheduling (prevents burst loading)
 *  - Focus mode (click enlarge → MJPEG live stream)
 *  - Event-triggered cell highlighting (pulsing red border + badge)
 *  - Drag-and-drop camera placement from sidebar
 *  - Right-click context menu with instant replay
 *  - Auto-cycle through camera pages
 *  - Pop-out wall to new window
 *  - Fullscreen with dark theme enforcement
 *  - Layout presets: 1×1, 1+5, 2×2, 3×3, 4×4, 5×5, 6×6, 8×8
 *  - Display controls: labels, status indicators, stream quality
 *  - Keyboard shortcuts: Esc = exit focus, F = fullscreen, arrows = page
 *
 * Inspired by UniFi Protect, Hikvision iVMS-4200, and Blue Iris.
 */

import { useState, useCallback, useMemo, useRef, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { cn } from '@/lib/utils';
import { getApiErrorMessage } from '@/lib/api';
import { useToastHelpers } from '@/components/ui/toast';
import { camerasApi, type StreamStats } from '@/lib/api/cameras';
import {
  type WallLayout,
  type WallCamera,
  type WallState,
  type CellHighlight,
  type CellReplay,
  DEFAULT_WALL_STATE,
  LAYOUT_CELL_COUNT,
} from './types';
import { getTargetFps } from './useCanvasStream';
import { useSnapshotEngine } from './useSnapshotEngine';
import { WallCell } from './WallCell';
import { WallToolbar } from './WallToolbar';
import { WallCameraSidebar } from './WallCameraSidebar';

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface CameraWallProps {
  /** All available cameras (the wall pages through online ones) */
  cameras: WallCamera[];
  /** Initial layout override */
  initialLayout?: WallLayout;
  /** Initial camera IDs to show */
  initialCameraIds?: string[];
  /** Initial stream mode */
  initialStreamMode?: 'snapshot' | 'live';
  /** Called when user double-clicks a cell for detail view */
  onOpenDetail?: (cameraId: string) => void;
  /** Called when user clicks "enlarge" to open the full live view modal */
  onOpenLiveView?: (cameraId: string) => void;
  /** Sync layout changes back to parent (e.g. for save-view) */
  onLayoutChange?: (layout: WallLayout) => void;
  /** Sync camera IDs back to parent (e.g. for save-view) */
  onCameraIdsChange?: (ids: string[]) => void;
  /** Height of the wall container (default: fills available viewport) */
  height?: string;
  /** CSS class for the root wrapper */
  className?: string;
  // minimal prop reserved for future popout toolbar customization
}

// ---------------------------------------------------------------------------
// Grid CSS classes for each layout
// ---------------------------------------------------------------------------

const GRID_CLASSES: Record<WallLayout, string> = {
  '1x1': 'grid-cols-1 grid-rows-1',
  '1+5': 'grid-cols-3 grid-rows-3',  // custom template handled inline
  '2x2': 'grid-cols-2 grid-rows-2',
  '3x3': 'grid-cols-3 grid-rows-3',
  '4x4': 'grid-cols-4 grid-rows-4',
  '5x5': 'grid-cols-5 grid-rows-5',
  '6x6': 'grid-cols-6 grid-rows-6',
  '8x8': 'grid-cols-8 grid-rows-8',
};

// Threshold: above this cell count, switch to compact mode
const COMPACT_THRESHOLD = 16;

// Highlight auto-clear duration
const HIGHLIGHT_DURATION_MS = 10_000;

// ===========================================================================
// Component
// ===========================================================================

export function CameraWall({
  cameras,
  initialLayout = '4x4',
  initialCameraIds,
  initialStreamMode,
  onOpenDetail,
  onOpenLiveView,
  onLayoutChange,
  onCameraIdsChange,
  height,
  className,
}: CameraWallProps) {
  const wallRef = useRef<HTMLDivElement>(null);
  const { t } = useTranslation('cameras');
  const toast = useToastHelpers();

  // ── State ──
  const [state, setState] = useState<WallState>(() => ({
    ...DEFAULT_WALL_STATE,
    layout: initialLayout,
    cameraIds: initialCameraIds || [],
    streamMode: initialStreamMode || DEFAULT_WALL_STATE.streamMode,
  }));

  // Event-triggered highlights per cell index
  const [highlightedCells, setHighlightedCells] = useState<Record<number, CellHighlight>>({});
  const highlightTimersRef = useRef<Map<number, ReturnType<typeof setTimeout>>>(new Map());
  const alertSoundRef = useRef(state.alertSoundEnabled);
  alertSoundRef.current = state.alertSoundEnabled;
  const alertAudioRef = useRef<HTMLAudioElement | null>(null);

  // Replay state per cell index
  const [replayState, setReplayState] = useState<Record<number, CellReplay>>({});
  const replayStateRef = useRef(replayState);
  replayStateRef.current = replayState;

  // Derived
  const cellCount = LAYOUT_CELL_COUNT[state.layout];
  const compact = cellCount > COMPACT_THRESHOLD;

  const onlineCameras = useMemo(
    () => cameras.filter((c) => c.status === 'online' || c.status === 'recording'),
    [cameras],
  );

  const pageCount = useMemo(
    () => Math.max(1, Math.ceil(onlineCameras.length / cellCount)),
    [onlineCameras.length, cellCount],
  );
  const pageCountRef = useRef(pageCount);
  pageCountRef.current = pageCount;

  // Build the camera ID array for current page
  const currentCameraIds = useMemo(() => {
    // If we have explicit camera IDs (user-populated or from saved view), use them
    if (state.cameraIds.length > 0 && !state.autoCycle) {
      const result: (string | null)[] = [];
      for (let i = 0; i < cellCount; i++) {
        result.push(state.cameraIds[i] || null);
      }
      return result;
    }

    // Auto-fill from online cameras (paginated)
    const start = state.page * cellCount;
    const pageOnline = onlineCameras.slice(start, start + cellCount);
    const result: (string | null)[] = pageOnline.map((c) => c.id);
    // Pad with nulls for empty slots
    while (result.length < cellCount) result.push(null);
    return result;
  }, [state.cameraIds, state.autoCycle, state.page, cellCount, onlineCameras]);

  // Count active (non-null) cells for adaptive refresh & FPS
  const activeCellCount = useMemo(
    () => currentCameraIds.filter((id) => id !== null).length,
    [currentCameraIds],
  );

  // Target FPS for canvas-based live streaming (scales down with more cameras)
  const targetFps = useMemo(() => getTargetFps(activeCellCount), [activeCellCount]);

  // ── Progressive live loading ──
  // When switching to live mode, ramp up connections in batches of 4
  // to avoid overwhelming NVRs with simultaneous connection bursts.
  const MAX_LIVE_CELLS = 16;
  const LIVE_BATCH_SIZE = 4;
  const LIVE_BATCH_DELAY_MS = 2000;

  const [liveBudget, setLiveBudget] = useState<number>(Infinity);
  const activeCellCountRef = useRef(activeCellCount);
  activeCellCountRef.current = activeCellCount;

  useEffect(() => {
    if (state.streamMode !== 'live') {
      setLiveBudget(Infinity);
      return;
    }

    // Ramp up connections in batches when entering live mode.
    // Only re-ramp when streamMode changes · NOT on page change (activeCellCount change),
    // which would cause a visible flash where live streams temporarily drop to 4.
    let budget = LIVE_BATCH_SIZE;
    setLiveBudget(budget);

    const timer = setInterval(() => {
      budget += LIVE_BATCH_SIZE;
      setLiveBudget(budget);
      if (budget >= Math.min(activeCellCountRef.current, MAX_LIVE_CELLS)) {
        clearInterval(timer);
      }
    }, LIVE_BATCH_DELAY_MS);

    return () => clearInterval(timer);
  }, [state.streamMode]);  

  // Resolve camera objects for each cell
  const cameraMap = useMemo(() => {
    const map = new Map<string, WallCamera>();
    cameras.forEach((c) => map.set(c.id, c));
    return map;
  }, [cameras]);

  const cellCameras = useMemo(
    () => currentCameraIds.map((id) => (id ? cameraMap.get(id) || null : null)),
    [currentCameraIds, cameraMap],
  );

  // ── NVR load stats polling (live mode only, every 10s) ──
  const [nvrLoadStats, setNvrLoadStats] = useState<StreamStats | null>(null);
  useEffect(() => {
    if (state.streamMode !== 'live') {
      setNvrLoadStats(null);
      return;
    }
    let cancelled = false;
    const poll = async () => {
      try {
        const stats = await camerasApi.getStreamStats();
        if (!cancelled) setNvrLoadStats(stats);
      } catch { /* ignore polling errors */ }
    };
    poll();
    const timer = setInterval(poll, 10_000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [state.streamMode]);

  // ── Snapshot engine (paused when live mode or focused) ──
  const snapshotEngine = useSnapshotEngine(
    currentCameraIds,
    activeCellCount,
    state.streamMode === 'live' || !!state.focusedCameraId,
    cameraMap,
  );

  // ── State updaters ──
  const updateState = useCallback((patch: Partial<WallState>) => {
    setState((prev) => ({ ...prev, ...patch }));
  }, []);

  // Helper to revoke all active replay blob URLs
  const revokeAllReplayUrls = useCallback(() => {
    setReplayState((prev) => {
      Object.values(prev).forEach((entry) => {
        if (entry?.videoUrl) URL.revokeObjectURL(entry.videoUrl);
      });
      return {};
    });
  }, []);

  const handleLayoutChange = useCallback((layout: WallLayout) => {
    const newCellCount = LAYOUT_CELL_COUNT[layout];
    let trimmed: (string | null)[] = [];
    setState((prev) => {
      trimmed = prev.cameraIds.slice(0, newCellCount);
      return {
        ...prev,
        layout,
        page: 0,
        focusedCameraId: null,
        cameraIds: trimmed,
      };
    });
    revokeAllReplayUrls();
    onLayoutChange?.(layout);
    onCameraIdsChange?.(trimmed.filter(Boolean) as string[]);
  }, [onLayoutChange, onCameraIdsChange, revokeAllReplayUrls]);

  const handlePageChange = useCallback((page: number) => {
    updateState({ page, focusedCameraId: null });
    revokeAllReplayUrls();
  }, [updateState, revokeAllReplayUrls]);

  const handleFillWall = useCallback(() => {
    const start = state.page * cellCount;
    const pageCams = onlineCameras.slice(start, start + cellCount);
    const ids = pageCams.map((c) => c.id);
    setState((prev) => ({
      ...prev,
      cameraIds: ids,
      focusedCameraId: null,
    }));
    revokeAllReplayUrls();
    onCameraIdsChange?.(ids);
  }, [state.page, cellCount, onlineCameras, onCameraIdsChange, revokeAllReplayUrls]);

  const handleFocusCamera = useCallback((cameraId: string) => {
    if (onOpenLiveView) {
      onOpenLiveView(cameraId);
    } else {
      updateState({ focusedCameraId: cameraId });
    }
  }, [updateState, onOpenLiveView]);

  const handleRemoveCell = useCallback((index: number) => {
    let nextIds: (string | null)[] = [];
    setState((prev) => {
      const next = [...prev.cameraIds];
      while (next.length <= index) next.push(null);
      next[index] = null;
      nextIds = next;
      return { ...prev, cameraIds: next };
    });
    onCameraIdsChange?.(nextIds.filter(Boolean) as string[]);
    // Revoke replay blob URL for removed cell
    setReplayState((prev) => {
      const entry = prev[index];
      if (entry?.videoUrl) URL.revokeObjectURL(entry.videoUrl);
      const copy = { ...prev };
      delete copy[index];
      return copy;
    });
  }, [onCameraIdsChange]);

  const handleOpenDetail = useCallback(
    (cameraId: string) => onOpenDetail?.(cameraId),
    [onOpenDetail],
  );

  // ── Stream mode change ──
  const handleStreamModeChange = useCallback((mode: 'snapshot' | 'live') => {
    updateState({ streamMode: mode });
  }, [updateState]);

  // ── Sidebar toggle ──
  const handleToggleSidebar = useCallback(() => {
    setState((prev) => ({ ...prev, showSidebar: !prev.showSidebar }));
  }, []);

  // ── Alert sound toggle ──
  const handleToggleAlertSound = useCallback(() => {
    let nextVal = false;
    setState((prev) => {
      nextVal = !prev.alertSoundEnabled;
      return { ...prev, alertSoundEnabled: nextVal };
    });
    localStorage.setItem('freesdn-wall-alert-sound', String(nextVal));
  }, []);

  // ── Pop-out wall ──
  const handlePopOut = useCallback(() => {
    const params = new URLSearchParams({
      layout: state.layout,
      cameras: currentCameraIds.filter(Boolean).join(','),
      quality: state.streamQuality,
      mode: state.streamMode,
    });
    window.open(`/cameras/wall/popout?${params}`, 'freesdn-wall', 'width=1920,height=1080');
  }, [state.layout, currentCameraIds, state.streamQuality, state.streamMode]);

  // ── Drag-drop camera assignment ──
  const handleCameraAssign = useCallback((cellIndex: number, cameraId: string) => {
    let nextIds: (string | null)[] = [];
    let changed = false;
    setState((prev) => {
      const next = [...prev.cameraIds];
      // Ensure array is large enough
      while (next.length <= cellIndex) next.push(null);

      // Drag-to-same-cell: no-op
      if (next[cellIndex] === cameraId) return prev;

      // Check if camera was in another cell · swap
      const sourceIndex = next.indexOf(cameraId);
      if (sourceIndex !== -1 && sourceIndex !== cellIndex) {
        // Swap: put the camera from target cell into source cell
        next[sourceIndex] = next[cellIndex];
      }
      next[cellIndex] = cameraId;
      nextIds = next;
      changed = true;
      return { ...prev, cameraIds: next };
    });
    if (changed) {
      onCameraIdsChange?.(nextIds.filter(Boolean) as string[]);
    }
  }, [onCameraIdsChange]);

  // ── Instant replay ──
  const handleReplay = useCallback(async (cellIndex: number, seconds: number) => {
    const camera = cellCameras[cellIndex];
    if (!camera) return;

    const endTime = new Date().toISOString();
    const startTime = new Date(Date.now() - seconds * 1000).toISOString();

    // Revoke existing replay blob URL for this cell (prevents leak on re-replay)
    setReplayState((prev) => {
      const existing = prev[cellIndex];
      if (existing?.videoUrl) URL.revokeObjectURL(existing.videoUrl);
      return {
        ...prev,
        [cellIndex]: { startTime, endTime, loading: true },
      };
    });

    try {
      const blob = await camerasApi.exportVideoClip(camera.id, { start_time: startTime, end_time: endTime });
      const blobData = blob?.data instanceof Blob ? blob.data : blob?.data;
      if (blobData instanceof Blob && blobData.size > 0) {
        const url = URL.createObjectURL(blobData);
        setReplayState((prev) => ({
          ...prev,
          [cellIndex]: { startTime, endTime, videoUrl: url, loading: false },
        }));
      } else {
        setReplayState((prev) => ({
          ...prev,
          [cellIndex]: { startTime, endTime, loading: false },
        }));
      }
    } catch (error) {
      setReplayState((prev) => ({
        ...prev,
        [cellIndex]: { startTime, endTime, loading: false },
      }));
      // Instant replay (clip export) requires site-admin server-side; a lesser
      // role gets a 403. Previously this catch swallowed it, so the replay just
      // silently never appeared. Surface a clear permission message on 403, and
      // the generic API error otherwise.
      const status = (error as { response?: { status?: number } } | null)?.response?.status;
      if (status === 403) {
        toast.warning(t('wall.replay.forbidden'), t('wall.replay.forbiddenDetail'));
      } else {
        toast.error(t('wall.replay.failed'), getApiErrorMessage(error));
      }
    }
  }, [cellCameras, t, toast]);

  const handleCancelReplay = useCallback((cellIndex: number) => {
    setReplayState((prev) => {
      const entry = prev[cellIndex];
      if (entry?.videoUrl) {
        URL.revokeObjectURL(entry.videoUrl);
      }
      const copy = { ...prev };
      delete copy[cellIndex];
      return copy;
    });
  }, []);

  // ── Event highlight listener ──
  useEffect(() => {
    const timers = highlightTimersRef.current;
    const handler = (e: Event) => {
      const detail = (e as CustomEvent).detail;
      if (!detail?.camera_id) return;
      const idx = currentCameraIds.indexOf(detail.camera_id);
      if (idx === -1) return;

      // Highlight the cell
      setHighlightedCells((prev) => ({
        ...prev,
        [idx]: { type: detail.event_type || 'event', timestamp: Date.now() },
      }));

      // Clear any existing timer for this cell
      const existing = timers.get(idx);
      if (existing) clearTimeout(existing);

      // Auto-clear after duration
      const timer = setTimeout(() => {
        timers.delete(idx);
        setHighlightedCells((prev) => {
          const copy = { ...prev };
          delete copy[idx];
          return copy;
        });
      }, HIGHLIGHT_DURATION_MS);
      timers.set(idx, timer);

      // Play alert sound if enabled (use refs to avoid stale closure)
      if (alertSoundRef.current) {
        try {
          if (!alertAudioRef.current) alertAudioRef.current = new Audio('/sounds/alert.mp3');
          alertAudioRef.current.volume = 0.3;
          alertAudioRef.current.currentTime = 0;
          alertAudioRef.current.play().catch(() => { /* browser may block autoplay */ });
        } catch { /* ignore audio errors */ }
      }
    };
    window.addEventListener('freesdn:camera-event', handler);
    return () => {
      window.removeEventListener('freesdn:camera-event', handler);
      // Clean up all pending highlight timers
      timers.forEach((t) => clearTimeout(t));
      timers.clear();
    };
  }, [currentCameraIds]);

  // ── Cleanup replay blob URLs on unmount ──
  useEffect(() => {
    return () => {
      Object.values(replayStateRef.current).forEach((entry) => {
        if (entry?.videoUrl) URL.revokeObjectURL(entry.videoUrl);
      });
    };
  }, []);

  // ── Auto-cycle ──
  // Uses pageCountRef to avoid stale closure when pageCount changes mid-cycle
  useEffect(() => {
    if (!state.autoCycle || pageCount <= 1) return;
    const timer = setInterval(() => {
      // Revoke any active replay blob URLs before cycling · prevents memory leak
      // when replays are left open during auto-cycle
      revokeAllReplayUrls();
      setState((prev) => {
        const pc = pageCountRef.current;
        const nextPage = pc > 1 ? (prev.page + 1) % pc : 0;
        return { ...prev, page: nextPage };
      });
    }, state.autoCycleInterval * 1000);
    return () => clearInterval(timer);
  }, [state.autoCycle, state.autoCycleInterval, pageCount, revokeAllReplayUrls]);

  // ── Fullscreen ──
  const toggleFullscreen = useCallback(() => {
    if (!wallRef.current) return;
    if (!document.fullscreenElement) {
      wallRef.current.requestFullscreen().then(() => updateState({ isFullscreen: true })).catch(() => {});
    } else {
      document.exitFullscreen().then(() => updateState({ isFullscreen: false })).catch(() => {});
    }
  }, [updateState]);

  useEffect(() => {
    const onFsChange = () => {
      updateState({ isFullscreen: !!document.fullscreenElement });
    };
    document.addEventListener('fullscreenchange', onFsChange);
    return () => document.removeEventListener('fullscreenchange', onFsChange);
  }, [updateState]);

  // ── Keyboard shortcuts ──
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement)?.tagName === 'INPUT' || (e.target as HTMLElement)?.tagName === 'TEXTAREA') return;

      switch (e.key) {
        case 'Escape':
          if (state.focusedCameraId) {
            e.preventDefault();
            updateState({ focusedCameraId: null });
          }
          break;
        case 'f':
        case 'F':
          if (!e.ctrlKey && !e.metaKey) {
            e.preventDefault();
            toggleFullscreen();
          }
          break;
        case 'ArrowLeft':
          if (pageCount > 1) {
            e.preventDefault();
            handlePageChange(Math.max(0, state.page - 1));
          }
          break;
        case 'ArrowRight':
          if (pageCount > 1) {
            e.preventDefault();
            handlePageChange(Math.min(pageCount - 1, state.page + 1));
          }
          break;
        case 'l':
        case 'L':
          if (!e.ctrlKey && !e.metaKey) {
            e.preventDefault();
            handleStreamModeChange(state.streamMode === 'live' ? 'snapshot' : 'live');
          }
          break;
      }
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [state.focusedCameraId, state.page, state.streamMode, pageCount, updateState, toggleFullscreen, handlePageChange, handleStreamModeChange]);

  // ── Compute wall height ──
  const wallHeight = state.isFullscreen
    ? '100vh'
    : height || 'calc(100vh - 290px)';

  // ── Determine if using special 1+5 layout ──
  const isAsymmetric = state.layout === '1+5';

  // ===========================================================================
  // Render
  // ===========================================================================

  return (
    <div
      ref={wallRef}
      className={cn(
        'flex flex-col',
        state.isFullscreen && 'bg-black fixed inset-0 z-50 p-2',
        className,
      )}
    >
      {/* Toolbar */}
      <div className={cn('mb-2', state.isFullscreen && 'px-2 py-1')}>
        <WallToolbar
          state={state}
          totalCameras={cameras.length}
          onlineCameras={onlineCameras.length}
          pageCount={pageCount}
          activeCellCount={activeCellCount}
          nvrLoadStats={nvrLoadStats}
          onLayoutChange={handleLayoutChange}
          onPageChange={handlePageChange}
          onToggleAutoCycle={() => updateState({ autoCycle: !state.autoCycle })}
          onAutoCycleIntervalChange={(s) => updateState({ autoCycleInterval: s })}
          onToggleFullscreen={toggleFullscreen}
          onForceRefresh={snapshotEngine.forceRefresh}
          onStreamQualityChange={(q) => updateState({ streamQuality: q })}
          onToggleLabels={() => updateState({ showLabels: !state.showLabels })}
          onToggleStatus={() => updateState({ showStatus: !state.showStatus })}
          onFillWall={handleFillWall}
          onStreamModeChange={handleStreamModeChange}
          onToggleSidebar={handleToggleSidebar}
          onToggleAlertSound={handleToggleAlertSound}
          onPopOut={handlePopOut}
        />
      </div>

      {/* Content: Sidebar + Grid */}
      <div className="flex flex-1 gap-2 overflow-hidden">
        {/* Camera sidebar for drag-and-drop */}
        {state.showSidebar && (
          <WallCameraSidebar
            cameras={cameras}
            assignedCameraIds={currentCameraIds.filter(Boolean) as string[]}
            onClose={() => updateState({ showSidebar: false })}
          />
        )}

        {/* Grid */}
        <div
          className={cn(
            'grid flex-1',
            compact ? 'gap-0.5' : 'gap-1',
            !isAsymmetric && GRID_CLASSES[state.layout],
          )}
          style={{
            height: wallHeight,
            minHeight: 300,
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
                  focused={camera?.id === state.focusedCameraId}
                  streamQuality={state.streamQuality}
                  streamMode={state.streamMode}
                  showLabel={state.showLabels}
                  showStatus={state.showStatus}
                  compact={compact}
                  highlighted={highlightedCells[i] || null}
                  replay={replayState[i] || null}
                  onFocus={handleFocusCamera}
                  onRemove={handleRemoveCell}
                  onOpenDetail={handleOpenDetail}
                  onCameraAssign={handleCameraAssign}
                  onReplay={handleReplay}
                  onCancelReplay={handleCancelReplay}
                  targetFps={targetFps}
                  staggerMs={i * 150}
                  withinLiveBudget={i < liveBudget && i < MAX_LIVE_CELLS}
                />
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
