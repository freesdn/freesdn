// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * WallCell · Single cell in the camera wall grid
 *
 * Renders either:
 *  - Snapshot thumbnail (default, adaptive refresh via engine)
 *  - MJPEG sub-stream (when in focus/enlarged mode OR live stream mode)
 *  - Video replay (when instant replay is active)
 *  - Empty placeholder (no camera assigned)
 *
 * Supports:
 *  - Event-triggered highlight (pulsing red border + badge)
 *  - Drag-and-drop (accept cameras from sidebar, reorder between cells)
 *  - Right-click context menu (replay, live view, detail, remove)
 *
 * Optimised for 64-cell grids with:
 *  - CSS contain: layout style paint
 *  - CSS contain: content (GPU-friendly without layer promotion overhead)
 *  - Minimal re-renders via memo + stable callbacks
 */

import { memo, useCallback, useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import {
  Camera,
  VideoOff,
  Maximize2,
  X,
  Loader2,
  Volume2,
  Move,
  Circle,
  Rewind,
  ExternalLink,
  Info,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { MseLivePlayer } from '../MseLivePlayer';
import type { WallCamera, CellHighlight, CellReplay } from './types';
import { useCanvasStream } from './useCanvasStream';

// ---------------------------------------------------------------------------
// Event type labels for highlight badge
// ---------------------------------------------------------------------------

const EVENT_LABEL_KEYS: Record<string, string> = {
  motion: 'motion',
  line_cross: 'lineCross',
  intrusion: 'intrusion',
  tamper: 'tamper',
  video_loss: 'videoLoss',
  face_detect: 'face',
  audio_detect: 'audio',
};

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface WallCellProps {
  /** Camera to display (null = empty slot) */
  camera: WallCamera | null;
  /** Pre-fetched snapshot URL from the engine */
  snapshotSrc: string;
  /** Whether the snapshot is currently being refreshed */
  snapshotLoading: boolean;
  /** Whether the snapshot had an error */
  snapshotError: boolean;
  /** Cell index in the grid */
  index: number;
  /** Whether this cell is in focused (enlarged) mode */
  focused: boolean;
  /** Stream quality for MJPEG when focused or live mode */
  streamQuality: 'sub' | 'main';
  /** Stream mode: 'snapshot' or 'live' */
  streamMode: 'snapshot' | 'live';
  /** Whether to show camera label overlay */
  showLabel: boolean;
  /** Whether to show status indicator */
  showStatus: boolean;
  /** Whether this is a compact cell (high grid density) */
  compact: boolean;
  /** Event highlight state (null = not highlighted) */
  highlighted?: CellHighlight | null;
  /** Replay state (null = not replaying) */
  replay?: CellReplay | null;
  /** Called when user wants to focus/enlarge this cell */
  onFocus: (cameraId: string) => void;
  /** Called when user removes a camera from this cell */
  onRemove: (index: number) => void;
  /** Called when user double-clicks to open detail view */
  onOpenDetail: (cameraId: string) => void;
  /** Called when a camera is dropped onto this cell (drag-drop) */
  onCameraAssign?: (index: number, cameraId: string) => void;
  /** Called when user requests instant replay */
  onReplay?: (index: number, seconds: number) => void;
  /** Called when user cancels replay */
  onCancelReplay?: (index: number) => void;
  /** Target FPS for canvas-based streaming (adaptive based on cell count) */
  targetFps?: number;
  /** Stagger delay in ms for stream startup (prevents burst connections) */
  staggerMs?: number;
  /** Whether this cell is within the progressive live loading budget */
  withinLiveBudget?: boolean;
}

export const WallCell = memo(function WallCell({
  camera,
  snapshotSrc,
  snapshotLoading,
  snapshotError,
  index,
  focused,
  streamQuality,
  streamMode,
  showLabel,
  showStatus,
  compact,
  highlighted,
  replay,
  onFocus,
  onRemove,
  onOpenDetail,
  onCameraAssign,
  onReplay,
  onCancelReplay,
  targetFps = 10,
  staggerMs = 0,
  withinLiveBudget = true,
}: WallCellProps) {
  const { t } = useTranslation('common');
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const isOnline = camera && (camera.status === 'online' || camera.status === 'recording');
  const [dragOver, setDragOver] = useState(false);
  const [showContextMenu, setShowContextMenu] = useState(false);
  const [contextMenuPos, setContextMenuPos] = useState({ x: 0, y: 0 });
  const contextMenuRef = useRef<HTMLDivElement>(null);

  // Should this cell show a live stream? (focused OR live-mode AND within budget)
  const shouldShowLive = !!(focused || (streamMode === 'live' && withinLiveBudget)) && !!isOnline && !replay;

  // Preferred live transport = MSE (true video, go2rtc). On failure we fall back
  // to the canvas-MJPEG engine, then to snapshots. Reset when the camera changes.
  const [mseError, setMseError] = useState(false);
  const cellCameraId = camera?.id ?? null;
  useEffect(() => {
    setMseError(false);
  }, [cellCameraId]);
  const useMjpegFallback = shouldShowLive && mseError;

  // Canvas-based MJPEG streaming with auto-reconnect, only after MSE fails, so
  // we don't run two live transports per cell.
  const { isStreaming, hasError: canvasError, reconnecting, actualFps } = useCanvasStream({
    cameraId: useMjpegFallback && camera ? camera.id : null,
    canvasRef,
    enabled: useMjpegFallback,
    targetFps,
    quality: streamQuality,
    staggerMs,
  });

  // Close context menu on outside click
  useEffect(() => {
    if (!showContextMenu) return;
    const handler = (e: MouseEvent) => {
      if (contextMenuRef.current && !contextMenuRef.current.contains(e.target as Node)) {
        setShowContextMenu(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [showContextMenu]);

  const handleDoubleClick = useCallback(() => {
    if (camera) onOpenDetail(camera.id);
  }, [camera, onOpenDetail]);

  const handleFocus = useCallback(
    (e: React.MouseEvent) => {
      e.stopPropagation();
      if (camera && isOnline) onFocus(camera.id);
    },
    [camera, isOnline, onFocus],
  );

  const handleRemove = useCallback(
    (e: React.MouseEvent) => {
      e.stopPropagation();
      onRemove(index);
    },
    [index, onRemove],
  );

  // ── Drag-and-drop handlers ──
  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback(() => {
    setDragOver(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    // The payload originates from this app's own draggable cells/sidebar
    // (set via dataTransfer), so a format regex only rejected legitimate
    // non-UUID camera ids. Assign directly.
    const cameraId = e.dataTransfer.getData('text/plain');
    if (cameraId && onCameraAssign) {
      onCameraAssign(index, cameraId);
    }
  }, [index, onCameraAssign]);

  const handleDragStart = useCallback((e: React.DragEvent) => {
    if (!camera) return;
    e.dataTransfer.setData('text/plain', camera.id);
    e.dataTransfer.setData('application/x-wall-cell-index', String(index));
    e.dataTransfer.effectAllowed = 'move';
  }, [camera, index]);

  // ── Context menu ──
  const handleContextMenu = useCallback((e: React.MouseEvent) => {
    if (!camera || !isOnline) return;
    e.preventDefault();
    e.stopPropagation();
    // Clamp to viewport to prevent overflow
    const menuW = 200;
    const menuH = 260;
    const x = Math.min(e.clientX, window.innerWidth - menuW);
    const y = Math.min(e.clientY, window.innerHeight - menuH);
    setContextMenuPos({ x: Math.max(0, x), y: Math.max(0, y) });
    setShowContextMenu(true);
  }, [camera, isOnline]);

  const handleReplay = useCallback((seconds: number) => {
    setShowContextMenu(false);
    onReplay?.(index, seconds);
  }, [index, onReplay]);

  // ── Empty cell ──
  if (!camera) {
    return (
      <div
        className={cn(
          'relative w-full h-full bg-muted/30 border border-dashed rounded-sm flex items-center justify-center transition-colors',
          dragOver ? 'border-primary bg-primary/5 border-2' : 'border-muted-foreground/15',
        )}
        style={{ contain: 'layout style paint' }}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        <Camera className={cn('text-muted-foreground/20', compact ? 'h-4 w-4' : 'h-6 w-6')} />
      </div>
    );
  }

  // ── Offline cell ──
  if (!isOnline) {
    return (
      <div
        className={cn(
          'relative w-full h-full bg-muted rounded-sm overflow-hidden group',
          highlighted && 'ring-2 ring-red-500 animate-pulse',
        )}
        style={{ contain: 'layout style paint' }}
        onDoubleClick={handleDoubleClick}
        draggable
        onDragStart={handleDragStart}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        <div className="w-full h-full flex items-center justify-center">
          <VideoOff className={cn('text-muted-foreground/30', compact ? 'h-4 w-4' : 'h-8 w-8')} />
        </div>
        {showLabel && (
          <div className="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/60 to-transparent px-1.5 py-1">
            <span className={cn('text-white font-medium truncate block', compact ? 'text-[9px]' : 'text-xs')}>
              {camera.name}
            </span>
          </div>
        )}
        {showStatus && (
          <div className="absolute top-1 left-1">
            <Circle className="h-2 w-2 fill-red-500 text-red-500" />
          </div>
        )}
        {/* Remove button */}
        <div className="absolute top-1 right-1 opacity-0 group-hover:opacity-100 transition-opacity">
          <button
            onClick={handleRemove}
            className="h-5 w-5 rounded bg-black/60 hover:bg-black/80 flex items-center justify-center text-white/80 hover:text-white"
          >
            <X className="h-3 w-3" />
          </button>
        </div>
      </div>
    );
  }

  // ── Active cell: focused/live = MJPEG, else = snapshot, or replay mode ──
  return (
    <div
      className={cn(
        'relative w-full h-full bg-black rounded-sm overflow-hidden group',
        highlighted && 'ring-2 ring-red-500 animate-pulse',
        dragOver && 'ring-2 ring-primary',
      )}
      style={{ contain: 'layout style paint' }}
      onDoubleClick={handleDoubleClick}
      onContextMenu={handleContextMenu}
      draggable
      onDragStart={handleDragStart}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      {/* ── Replay mode ── */}
      {replay ? (
        <>
          {replay.loading ? (
            <div className="w-full h-full flex items-center justify-center bg-muted/50">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground/40" />
            </div>
          ) : replay.videoUrl ? (
            <video
              src={replay.videoUrl}
              autoPlay
              controls
              className="w-full h-full object-contain"
            />
          ) : (
            <div className="w-full h-full flex items-center justify-center bg-muted/50">
              <span className="text-xs text-muted-foreground">{t('WallCell.replay.unavailable')}</span>
            </div>
          )}
          {/* Replay overlay bar */}
          <div className="absolute top-0 left-0 right-0 bg-amber-600/90 px-2 py-0.5 flex items-center justify-between z-20">
            <span className="text-[10px] text-white font-medium flex items-center gap-1">
              <Rewind className="h-3 w-3" /> {t('WallCell.replay.label')}
            </span>
            <button
              onClick={(e) => { e.stopPropagation(); onCancelReplay?.(index); }}
              className="text-white/80 hover:text-white"
            >
              <X className="h-3 w-3" />
            </button>
          </div>
        </>
      ) : shouldShowLive && !mseError ? (
        /* Preferred: true live VIDEO via MSE (sub-stream keeps the grid cheap).
           On failure → mseError flips and we drop to the canvas-MJPEG engine. */
        <MseLivePlayer
          key={`mse-${camera.id}-${streamQuality}`}
          cameraId={camera.id}
          quality={streamQuality}
          muted
          className="w-full h-full object-contain"
          onError={() => setMseError(true)}
        />
      ) : shouldShowLive ? (
        /* Fallback: canvas-based MJPEG live stream */
        canvasError ? (
          /* Stream failed · fall back to snapshot */
          snapshotSrc ? (
            <img
              src={snapshotSrc}
              alt={camera.name}
              className="w-full h-full object-contain"
              draggable={false}
            />
          ) : (
            <div className="w-full h-full flex items-center justify-center bg-muted/50">
              <VideoOff className={cn('text-muted-foreground/30', compact ? 'h-4 w-4' : 'h-6 w-6')} />
            </div>
          )
        ) : (
          <>
            <canvas
              ref={canvasRef}
              className="w-full h-full object-contain"
              style={{ imageRendering: 'auto' }}
            />
            {!isStreaming && (
              <div className="absolute inset-0 flex items-center justify-center bg-muted/50">
                {reconnecting ? (
                  <div className="flex flex-col items-center gap-1">
                    <Loader2 className="h-5 w-5 animate-spin text-amber-400" />
                    {!compact && <span className="text-[10px] text-amber-400 font-medium">{t('WallCell.status.reconnecting')}</span>}
                  </div>
                ) : (
                  <Loader2 className="h-6 w-6 animate-spin text-muted-foreground/40" />
                )}
              </div>
            )}
          </>
        )
      ) : (
        /* Snapshot thumbnail with adaptive refresh */
        <>
          {snapshotSrc ? (
            <img
              src={snapshotSrc}
              alt={camera.name}
              className="w-full h-full object-contain"
              draggable={false}
            />
          ) : snapshotError ? (
            /* Snapshot fetch failed and we have no cached frame · honest
               "unavailable" state instead of a permanent spinner. */
            <div className="w-full h-full flex flex-col items-center justify-center gap-1 bg-muted/50 text-muted-foreground/40">
              <VideoOff className={cn(compact ? 'h-4 w-4' : 'h-6 w-6')} />
              {!compact && <span className="text-[10px]">{t('WallCell.status.snapshotUnavailable')}</span>}
            </div>
          ) : (
            <div className="w-full h-full flex items-center justify-center bg-muted/50">
              <Loader2 className={cn('animate-spin text-muted-foreground/40', compact ? 'h-4 w-4' : 'h-6 w-6')} />
            </div>
          )}

          {/* Loading indicator · subtle pulse on refresh */}
          {snapshotLoading && snapshotSrc && (
            <div className="absolute top-1 right-1">
              <div className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />
            </div>
          )}
        </>
      )}

      {/* ── Overlays ── */}

      {/* Event highlight badge */}
      {highlighted && !replay && (
        <div className="absolute top-1 left-1/2 -translate-x-1/2 z-30 bg-red-600/90 text-white text-[9px] font-bold px-2 py-0.5 rounded-full">
          {EVENT_LABEL_KEYS[highlighted.type] ? t(`WallCell.eventLabels.${EVENT_LABEL_KEYS[highlighted.type]}`) : highlighted.type}
        </div>
      )}

      {/* Live mode indicator with FPS + health */}
      {shouldShowLive && !focused && !replay && (
        <div className={cn(
          'absolute z-10 flex items-center gap-0.5 font-bold rounded',
          reconnecting
            ? 'bg-amber-600/90 text-white'
            : canvasError
              ? 'bg-red-600/90 text-white'
              : 'bg-blue-600/90 text-white',
          compact ? 'top-1 left-1 text-[7px] px-1 py-0' : 'top-1 left-1 text-[9px] px-1.5 py-0.5',
        )}>
          <span className={cn(
            'h-1.5 w-1.5 rounded-full animate-pulse',
            reconnecting ? 'bg-amber-200' : canvasError ? 'bg-red-200' : 'bg-white',
          )} />
          {reconnecting ? t('WallCell.status.retry') : canvasError ? t('WallCell.status.err') : t('WallCell.status.live')}{actualFps > 0 && !compact ? ` ${actualFps}fps` : ''}
        </div>
      )}

      {/* Recording indicator */}
      {camera.is_recording && !replay && (
        <div className={cn(
          'absolute top-1 z-10 flex items-center gap-0.5 bg-red-600/90 text-white font-bold rounded',
          compact ? 'right-1 text-[7px] px-1 py-0' : 'right-1 text-[9px] px-1.5 py-0.5',
        )}>
          <span className="h-1.5 w-1.5 rounded-full bg-white animate-pulse" />
          {t('WallCell.status.rec')}
        </div>
      )}

      {/* Status dot */}
      {showStatus && !camera.is_recording && !shouldShowLive && !replay && (
        <div className="absolute top-1 left-1 z-10">
          <Circle className="h-2 w-2 fill-emerald-500 text-emerald-500" />
        </div>
      )}

      {/* Camera name label */}
      {showLabel && !replay && (
        <div className="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/70 to-transparent z-10">
          <div className={cn('flex items-center justify-between', compact ? 'px-1 py-0.5' : 'px-2 py-1')}>
            <span className={cn('text-white font-medium truncate', compact ? 'text-[9px] max-w-[70%]' : 'text-xs max-w-[75%]')}>
              {camera.name}
            </span>
            {!compact && (
              <div className="flex items-center gap-1">
                {camera.has_ptz && <Move className="h-2.5 w-2.5 text-white/60" />}
                {camera.has_audio && <Volume2 className="h-2.5 w-2.5 text-white/60" />}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Hover controls */}
      {!replay && (
        <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity z-20">
          <div className="absolute top-1 right-1 flex gap-1">
            {!focused && isOnline && (
              <button
                onClick={handleFocus}
                className={cn(
                  'rounded bg-black/60 hover:bg-black/80 flex items-center justify-center text-white/80 hover:text-white',
                  compact ? 'h-5 w-5' : 'h-6 w-6',
                )}
                title={t('WallCell.actions.enlarge')}
              >
                <Maximize2 className={compact ? 'h-2.5 w-2.5' : 'h-3 w-3'} />
              </button>
            )}
            <button
              onClick={handleRemove}
              className={cn(
                'rounded bg-black/60 hover:bg-black/80 flex items-center justify-center text-white/80 hover:text-white',
                compact ? 'h-5 w-5' : 'h-6 w-6',
              )}
              title={t('WallCell.actions.remove')}
            >
              <X className={compact ? 'h-2.5 w-2.5' : 'h-3 w-3'} />
            </button>
          </div>
        </div>
      )}

      {/* ── Right-click context menu (portal to escape CSS containment) ── */}
      {showContextMenu && createPortal(
        <div
          ref={contextMenuRef}
          className="fixed z-50 bg-popover border border-border rounded-md shadow-lg py-1 min-w-[180px] text-sm"
          style={{ left: contextMenuPos.x, top: contextMenuPos.y }}
        >
          <div className="px-2 py-1 text-xs font-medium text-muted-foreground truncate border-b border-border mb-1">
            {camera.name}
          </div>
          {onReplay && (
            <>
              <button
                className="w-full px-3 py-1.5 text-left hover:bg-accent flex items-center gap-2"
                onClick={() => handleReplay(30)}
              >
                <Rewind className="h-3.5 w-3.5" /> {t('WallCell.menu.replayLast30s')}
              </button>
              <button
                className="w-full px-3 py-1.5 text-left hover:bg-accent flex items-center gap-2"
                onClick={() => handleReplay(60)}
              >
                <Rewind className="h-3.5 w-3.5" /> {t('WallCell.menu.replayLast1min')}
              </button>
              <button
                className="w-full px-3 py-1.5 text-left hover:bg-accent flex items-center gap-2"
                onClick={() => handleReplay(300)}
              >
                <Rewind className="h-3.5 w-3.5" /> {t('WallCell.menu.replayLast5min')}
              </button>
              <div className="border-t border-border my-1" />
            </>
          )}
          <button
            className="w-full px-3 py-1.5 text-left hover:bg-accent flex items-center gap-2"
            onClick={() => { setShowContextMenu(false); if (camera) onFocus(camera.id); }}
          >
            <Maximize2 className="h-3.5 w-3.5" /> {t('WallCell.menu.openLiveView')}
          </button>
          <button
            className="w-full px-3 py-1.5 text-left hover:bg-accent flex items-center gap-2"
            onClick={() => { setShowContextMenu(false); if (camera) onOpenDetail(camera.id); }}
          >
            <ExternalLink className="h-3.5 w-3.5" /> {t('WallCell.menu.openDetailPage')}
          </button>
          {camera.ip_address && (
            <div className="px-3 py-1 text-[10px] text-muted-foreground flex items-center gap-1">
              <Info className="h-3 w-3" /> {camera.ip_address}
            </div>
          )}
          <div className="border-t border-border my-1" />
          <button
            className="w-full px-3 py-1.5 text-left hover:bg-destructive/10 text-destructive flex items-center gap-2"
            onClick={(e) => { setShowContextMenu(false); handleRemove(e); }}
          >
            <X className="h-3.5 w-3.5" /> {t('WallCell.menu.removeFromWall')}
          </button>
        </div>,
        document.body,
      )}
    </div>
  );
});
