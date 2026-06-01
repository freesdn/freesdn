// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * RecordingTimeline · Visual recording timeline scrubber
 *
 * Enterprise-grade timeline component showing recording segments as colored bars:
 *  - Green = continuous recording
 *  - Blue = motion-triggered recording
 *  - Yellow = alarm recording
 *  - Transparent gaps = no recording
 *
 * Interactions:
 *  - Click on timeline to seek to that timestamp
 *  - Drag to select a time range (for export)
 *  - Scroll wheel to zoom in/out
 *  - Current playback position shown as a vertical red line
 */

import { useState, useCallback, useMemo, useRef, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Clock, ZoomIn, ZoomOut } from 'lucide-react';
import { cn } from '@/lib/utils';
import { camerasApi } from '@/lib/api';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface RecordingSegment {
  start_time: string;
  /** May be absent, some NVRs send `duration` (seconds) instead. */
  end_time?: string;
  /** Duration in seconds · used to derive end_time when end_time is absent. */
  duration?: number;
  recording_type?: string;
  size_bytes?: number;
}

interface RecordingTimelineProps {
  cameraId: string;
  /** Current playback position (null = no playhead) */
  playbackTime?: Date | null;
  /** Called when user clicks a point on the timeline */
  onSeek?: (timestamp: Date) => void;
  /** Called when user selects a range (drag) */
  onRangeSelect?: (start: Date, end: Date) => void;
  /** Height in pixels */
  height?: number;
  /** Whether to show the range controls */
  showControls?: boolean;
}

// ---------------------------------------------------------------------------
// Time range presets
// ---------------------------------------------------------------------------

type TimeRangePreset = '1h' | '4h' | '12h' | '24h' | '3d' | '7d';

const RANGE_PRESETS: Record<TimeRangePreset, { labelKey: string; hours: number }> = {
  '1h': { labelKey: 'ranges.1h', hours: 1 },
  '4h': { labelKey: 'ranges.4h', hours: 4 },
  '12h': { labelKey: 'ranges.12h', hours: 12 },
  '24h': { labelKey: 'ranges.24h', hours: 24 },
  '3d': { labelKey: 'ranges.3d', hours: 72 },
  '7d': { labelKey: 'ranges.7d', hours: 168 },
};

// Recording type → color
const SEGMENT_COLORS: Record<string, string> = {
  continuous: 'bg-emerald-500/70',
  schedule: 'bg-emerald-500/70',
  motion: 'bg-blue-500/70',
  alarm: 'bg-amber-500/70',
  event: 'bg-amber-500/70',
  manual: 'bg-purple-500/70',
};

// Hikvision (and ISAPI) uppercase recording-type codes → normalized type.
const HIK_TYPE_ALIASES: Record<string, string> = {
  cmr: 'continuous', // CMR = continuous/scheduled
  vmd: 'motion',     // VMD = video motion detection
  alarm: 'alarm',
  timing: 'continuous',
  manual: 'manual',
};

/** Normalize an NVR recording-type code to one of our canonical buckets. */
function normalizeRecordingType(type?: string): string | undefined {
  if (!type) return undefined;
  const lower = type.toLowerCase();
  return HIK_TYPE_ALIASES[lower] || lower;
}

function getSegmentColor(type?: string): string {
  const normalized = normalizeRecordingType(type);
  if (!normalized) return 'bg-emerald-500/70';
  return SEGMENT_COLORS[normalized] || 'bg-emerald-500/70';
}

/** Resolve a segment's end Date, deriving it from start_time + duration if needed. */
function segmentEnd(seg: RecordingSegment): Date {
  if (seg.end_time) return new Date(seg.end_time);
  const start = new Date(seg.start_time).getTime();
  const durationMs = (seg.duration ?? 0) * 1000;
  return new Date(start + durationMs);
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function RecordingTimeline({
  cameraId,
  playbackTime,
  onSeek,
  onRangeSelect,
  height = 60,
  showControls = true,
}: RecordingTimelineProps) {
  const { t } = useTranslation('common');
  const timelineRef = useRef<HTMLDivElement>(null);
  const [rangePreset, setRangePreset] = useState<TimeRangePreset>('24h');
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState<number | null>(null);
  const [dragEnd, setDragEnd] = useState<number | null>(null);
  const [hoverTime, setHoverTime] = useState<Date | null>(null);
  const [hoverX, setHoverX] = useState<number>(0);

  const rangeHours = RANGE_PRESETS[rangePreset].hours;
  const rangeWindowMs = rangeHours * 60 * 60 * 1000;

  // Center the playhead in the window so it reads as the standard VMS past/future
  // DIVIDER: recorded history to the left, upcoming time to the right (empty until
  // it becomes "now"). When there's no playhead, fall back to a trailing window.
  const playheadMs = playbackTime ? playbackTime.getTime() : null;

  // Calculate time range
  const timeRange = useMemo(() => {
    const now = Date.now();
    if (playheadMs === null) {
      return { start: new Date(now - rangeWindowMs), end: new Date(now) };
    }
    return {
      start: new Date(playheadMs - rangeWindowMs * 0.5),
      end: new Date(playheadMs + rangeWindowMs * 0.5),
    };
  }, [rangeWindowMs, playheadMs]);

  const rangeMs = timeRange.end.getTime() - timeRange.start.getTime();

  // Fetch recordings · query for the same playhead-anchored window. Bucket the
  // playhead to the hour so the queryKey doesn't churn on every tick.
  const playheadHourBucket = playheadMs !== null ? Math.floor(playheadMs / (60 * 60 * 1000)) : null;
  const { data: recordingsData, isError } = useQuery({
    queryKey: ['camera-recordings-timeline', cameraId, rangePreset, playheadHourBucket],
    queryFn: async () => {
      const now = Date.now();
      const start = playheadMs === null
        ? new Date(now - rangeWindowMs)
        : new Date(playheadMs - rangeWindowMs * 0.5);
      // Never query beyond now, the NVR has no future footage; the display
      // window still extends past it (shown as the empty "future" zone).
      const end = playheadMs === null
        ? new Date(now)
        : new Date(Math.min(now, playheadMs + rangeWindowMs * 0.5));
      // Real footage availability from the NVR (the camera-level /recordings
      // search is DB-backed and empty, FreeSDN doesn't record). Times are UTC.
      const { data } = await camerasApi.getCameraTimeline(
        cameraId,
        start.toISOString(),
        end.toISOString(),
      );
      return data;
    },
    refetchInterval: 60_000,
  });

  const segments: RecordingSegment[] = useMemo(() => {
    const segs = recordingsData?.segments;
    if (!Array.isArray(segs)) return [];
    return segs.map((s: { start: string; end: string; type?: string }) => ({
      start_time: s.start,
      end_time: s.end,
      recording_type: s.type,
    }));
  }, [recordingsData]);

  // Convert timestamp to X position (0-1)
  const timeToPosition = useCallback((time: Date): number => {
    return Math.max(0, Math.min(1, (time.getTime() - timeRange.start.getTime()) / rangeMs));
  }, [timeRange, rangeMs]);

  // Convert X position (0-1) to timestamp
  const positionToTime = useCallback((pos: number): Date => {
    return new Date(timeRange.start.getTime() + pos * rangeMs);
  }, [timeRange, rangeMs]);

  // Get X position from mouse event
  const getPositionFromEvent = useCallback((e: React.MouseEvent): number => {
    const rect = timelineRef.current?.getBoundingClientRect();
    if (!rect) return 0;
    return Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
  }, []);

  // Generate time markers
  const timeMarkers = useMemo(() => {
    const markers: { position: number; label: string }[] = [];
    const intervalHours = rangeHours <= 4 ? 1 : rangeHours <= 24 ? 3 : rangeHours <= 72 ? 12 : 24;
    const intervalMs = intervalHours * 60 * 60 * 1000;

    // Align to interval boundaries
    const startMs = Math.ceil(timeRange.start.getTime() / intervalMs) * intervalMs;
    for (let t = startMs; t < timeRange.end.getTime(); t += intervalMs) {
      const date = new Date(t);
      const pos = (t - timeRange.start.getTime()) / rangeMs;
      const label = rangeHours <= 24
        ? date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        : date.toLocaleDateString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
      markers.push({ position: pos, label });
    }
    return markers;
  }, [timeRange, rangeHours, rangeMs]);

  // Minor (unlabelled) ruler ticks, 4 per major interval for a finer ruler feel.
  const minorTicks = useMemo(() => {
    const positions: number[] = [];
    const majorH = rangeHours <= 4 ? 1 : rangeHours <= 24 ? 3 : rangeHours <= 72 ? 12 : 24;
    const minorMs = (majorH * 60 * 60 * 1000) / 4;
    const startMs = Math.ceil(timeRange.start.getTime() / minorMs) * minorMs;
    for (let mt = startMs; mt < timeRange.end.getTime(); mt += minorMs) {
      positions.push((mt - timeRange.start.getTime()) / rangeMs);
    }
    return positions;
  }, [timeRange, rangeHours, rangeMs]);

  // Zoom: step through the range presets (shortest → longest). Mirrors the
  // "1 Day / 1 Hour" zoomer on enterprise NVR scrubbers.
  const PRESET_KEYS = Object.keys(RANGE_PRESETS) as TimeRangePreset[];
  const presetIdx = PRESET_KEYS.indexOf(rangePreset);
  const zoomIn = () => presetIdx > 0 && setRangePreset(PRESET_KEYS[presetIdx - 1]);
  const zoomOut = () => presetIdx < PRESET_KEYS.length - 1 && setRangePreset(PRESET_KEYS[presetIdx + 1]);

  // Position of "now", everything to its right is the un-recordable future.
  const nowPos = Math.max(0, Math.min(1, (Date.now() - timeRange.start.getTime()) / rangeMs));

  // Mouse handlers
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    const pos = getPositionFromEvent(e);
    setIsDragging(true);
    setDragStart(pos);
    setDragEnd(pos);
  }, [getPositionFromEvent]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    const pos = getPositionFromEvent(e);
    setHoverTime(positionToTime(pos));
    setHoverX(e.clientX - (timelineRef.current?.getBoundingClientRect().left || 0));

    if (isDragging) {
      setDragEnd(pos);
    }
  }, [isDragging, getPositionFromEvent, positionToTime]);

  const handleMouseUp = useCallback(() => {
    if (isDragging && dragStart !== null && dragEnd !== null) {
      const startPos = Math.min(dragStart, dragEnd);
      const endPos = Math.max(dragStart, dragEnd);

      if (endPos - startPos < 0.005) {
        // Click (not drag) · seek to position
        onSeek?.(positionToTime(startPos));
      } else {
        // Drag · select range
        onRangeSelect?.(positionToTime(startPos), positionToTime(endPos));
      }
    }
    setIsDragging(false);
    setDragStart(null);
    setDragEnd(null);
  }, [isDragging, dragStart, dragEnd, positionToTime, onSeek, onRangeSelect]);

  const handleMouseLeave = useCallback(() => {
    setHoverTime(null);
    if (isDragging) {
      setIsDragging(false);
      setDragStart(null);
      setDragEnd(null);
    }
  }, [isDragging]);

  // ── Draggable playhead (grab the divider and scrub) ──────────────────────
  // While scrubbing we update a LOCAL fraction for instant visual feedback and
  // only commit onSeek on release, so the smooth HLS player (keyed on the seek
  // instant) doesn't re-mount on every pixel of the drag.
  const [scrubFrac, setScrubFrac] = useState<number | null>(null);
  const scrubbingRef = useRef(false);
  const scrubFracRef = useRef<number | null>(null);
  scrubFracRef.current = scrubFrac;

  const fracFromClientX = useCallback((clientX: number): number => {
    const rect = timelineRef.current?.getBoundingClientRect();
    if (!rect || rect.width === 0) return 0;
    return Math.max(0, Math.min(1, (clientX - rect.left) / rect.width));
  }, []);

  const startScrub = useCallback((e: React.PointerEvent) => {
    e.stopPropagation();
    e.preventDefault();
    scrubbingRef.current = true;
    setScrubFrac(fracFromClientX(e.clientX));
  }, [fracFromClientX]);

  useEffect(() => {
    const onMove = (e: PointerEvent) => {
      if (!scrubbingRef.current) return;
      setScrubFrac(fracFromClientX(e.clientX));
    };
    const onUp = () => {
      if (!scrubbingRef.current) return;
      scrubbingRef.current = false;
      const f = scrubFracRef.current;
      if (f !== null) onSeek?.(positionToTime(f));
      setScrubFrac(null);
    };
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    return () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
    };
  }, [fracFromClientX, onSeek, positionToTime]);

  // Playhead position, overridden by the live scrub fraction while dragging.
  const basePlayheadPos = playbackTime ? timeToPosition(playbackTime) : null;
  const playheadPos = scrubFrac ?? basePlayheadPos;
  const playheadTime = scrubFrac !== null ? positionToTime(scrubFrac) : playbackTime;

  // Drag selection bounds
  const selectionLeft = dragStart !== null && dragEnd !== null
    ? Math.min(dragStart, dragEnd)
    : null;
  const selectionWidth = dragStart !== null && dragEnd !== null
    ? Math.abs(dragEnd - dragStart)
    : null;

  return (
    <div className="space-y-1.5">
      {/* Controls: current-position readout · zoom · legend */}
      {showControls && (
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-1.5">
            <Clock className="h-3.5 w-3.5 text-muted-foreground" />
            {playbackTime && (
              <span className="font-mono text-xs tabular-nums">
                {playbackTime.toLocaleString([], {
                  year: 'numeric', month: '2-digit', day: '2-digit',
                  hour: '2-digit', minute: '2-digit', second: '2-digit',
                })}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {/* Zoom: − / level / + */}
            <div className="flex items-center rounded-md border text-muted-foreground">
              <button
                type="button" onClick={zoomOut} disabled={presetIdx >= PRESET_KEYS.length - 1}
                className="px-1.5 py-1 hover:bg-muted disabled:opacity-30 rounded-l-md"
                title={t('RecordingTimeline.zoomOut')}
              >
                <ZoomOut className="h-3.5 w-3.5" />
              </button>
              <span className="px-2 text-[11px] tabular-nums border-x min-w-[3rem] text-center">
                {t(`RecordingTimeline.${RANGE_PRESETS[rangePreset].labelKey}`)}
              </span>
              <button
                type="button" onClick={zoomIn} disabled={presetIdx <= 0}
                className="px-1.5 py-1 hover:bg-muted disabled:opacity-30 rounded-r-md"
                title={t('RecordingTimeline.zoomIn')}
              >
                <ZoomIn className="h-3.5 w-3.5" />
              </button>
            </div>
            {/* Legend */}
            <div className="hidden sm:flex items-center gap-2.5 text-[10px] text-muted-foreground">
              <span className="flex items-center gap-1"><span className="h-2 w-3 rounded-sm bg-emerald-500/80" /> {t('RecordingTimeline.legend.continuous')}</span>
              <span className="flex items-center gap-1"><span className="h-2 w-3 rounded-sm bg-blue-500/80" /> {t('RecordingTimeline.legend.motion')}</span>
              <span className="flex items-center gap-1"><span className="h-2 w-3 rounded-sm bg-amber-500/80" /> {t('RecordingTimeline.legend.alarm')}</span>
            </div>
          </div>
        </div>
      )}

      {/* Timeline bar */}
      <div
        ref={timelineRef}
        className="relative rounded-md border border-border bg-zinc-900/80 cursor-crosshair select-none overflow-hidden"
        style={{ height }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseLeave}
      >
        {/* Future zone (right of "now"), diagonal hatch marks un-recordable time. */}
        {nowPos < 1 && (
          <div
            className="absolute inset-y-0 pointer-events-none bg-[repeating-linear-gradient(45deg,transparent,transparent_4px,rgba(255,255,255,0.05)_4px,rgba(255,255,255,0.05)_8px)]"
            style={{ left: `${nowPos * 100}%`, right: 0 }}
          />
        )}

        {/* Minor ruler ticks */}
        {minorTicks.map((pos, i) => (
          <div key={`mt-${i}`} className="absolute top-0 h-1.5 w-px bg-muted-foreground/20" style={{ left: `${pos * 100}%` }} />
        ))}

        {/* Recording segments */}
        {segments.map((seg, i) => {
          const start = new Date(seg.start_time);
          const end = segmentEnd(seg);
          const left = timeToPosition(start);
          const width = timeToPosition(end) - left;
          if (width <= 0) return null;

          return (
            <div
              // Include type + index: overlapping segments (e.g. motion + alarm at
              // the same instant) share start/end and would otherwise collide,
              // making one disappear from the timeline.
              key={`${seg.start_time}-${end.getTime()}-${seg.recording_type ?? ''}-${i}`}
              className={cn('absolute inset-y-1 rounded-[2px]', getSegmentColor(seg.recording_type))}
              style={{
                left: `${left * 100}%`,
                width: `${Math.max(width * 100, 0.2)}%`,
              }}
            />
          );
        })}

        {/* Major time markers + labels */}
        {timeMarkers.map((marker, i) => (
          <div
            key={i}
            className="absolute top-0 bottom-0 border-l border-muted-foreground/25"
            style={{ left: `${marker.position * 100}%` }}
          >
            <span className="absolute bottom-0.5 left-1 text-[9px] font-mono text-muted-foreground/70 whitespace-nowrap">
              {marker.label}
            </span>
          </div>
        ))}

        {/* Hover indicator */}
        {hoverTime && !isDragging && (
          <>
            <div
              className="absolute top-0 bottom-0 w-px bg-foreground/40 pointer-events-none"
              style={{ left: `${timeToPosition(hoverTime) * 100}%` }}
            />
            <div
              className="absolute top-1 bg-popover border rounded px-1.5 py-0.5 text-[10px] pointer-events-none shadow-sm whitespace-nowrap z-30"
              style={{ left: hoverX, transform: 'translateX(-50%)' }}
            >
              {hoverTime.toLocaleTimeString()}
            </div>
          </>
        )}

        {/* Drag selection highlight */}
        {selectionLeft !== null && selectionWidth !== null && selectionWidth > 0.005 && (
          <div
            className="absolute top-0 bottom-0 bg-primary/20 border-x border-primary/50 pointer-events-none"
            style={{
              left: `${selectionLeft * 100}%`,
              width: `${selectionWidth * 100}%`,
            }}
          />
        )}

        {/* Playhead, the prominent, draggable past/future divider */}
        {playheadPos !== null && (
          <div
            className="absolute top-0 bottom-0 z-20"
            style={{ left: `${playheadPos * 100}%` }}
          >
            <div className="absolute inset-y-0 -translate-x-1/2 w-0.5 bg-red-500 shadow-[0_0_4px_rgba(239,68,68,0.7)] pointer-events-none" />
            {/* Grab handle, pointer-down to scrub the divider. Wider invisible hit
                area around the triangle so it's easy to grab. */}
            <div
              role="slider"
              aria-label="Playback position"
              aria-valuetext={playheadTime ? playheadTime.toLocaleString() : undefined}
              tabIndex={0}
              onPointerDown={startScrub}
              className={cn(
                'absolute -top-0.5 left-0 -translate-x-1/2 h-4 w-4 flex items-start justify-center',
                scrubFrac !== null ? 'cursor-grabbing' : 'cursor-grab',
              )}
            >
              <div className="h-0 w-0 border-l-[5px] border-r-[5px] border-t-[7px] border-l-transparent border-r-transparent border-t-red-500" />
            </div>
            {/* Time-at-playhead chip (rich instance only, avoids clutter on stacked rows) */}
            {showControls && playheadTime && (
              <div className="absolute top-0.5 left-0 -translate-x-1/2 rounded bg-red-500 px-1 py-0.5 text-[9px] font-mono leading-none text-white whitespace-nowrap pointer-events-none">
                {playheadTime.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
              </div>
            )}
          </div>
        )}

        {/* Empty / error state */}
        {isError ? (
          <div className="absolute inset-0 flex items-center justify-center text-xs text-destructive/60">
            {t('RecordingTimeline.errors.loadFailed')}
          </div>
        ) : recordingsData && recordingsData.supported === false ? (
          // Distinguish "this camera model can't be searched" from "no footage in
          // this window", otherwise a non-Hikvision camera looks like it simply
          // has no recordings.
          <div className="absolute inset-0 flex items-center justify-center text-xs text-muted-foreground/40">
            {t('RecordingTimeline.empty.notSupported')}
          </div>
        ) : segments.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center text-xs text-muted-foreground/40">
            {t('RecordingTimeline.empty.noRecordings')}
          </div>
        )}
      </div>
    </div>
  );
}
