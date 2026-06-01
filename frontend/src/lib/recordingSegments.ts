// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Recording-segment awareness for playback.
 *
 * Playback robustness hinges on knowing WHERE footage actually exists: without
 * it the UI shows a stale frame in dead air and, worse, fetching a frame for a
 * timestamp with no recording makes the NVR/ffmpeg block until timeout. This
 * module provides the live NVR segment list (via the timeline endpoint) plus pure
 * helpers so the player can skip gaps, snap seeks to real footage, and show an
 * honest "no recording here" state instantly instead of hanging.
 */
import { useQuery } from '@tanstack/react-query';
import { camerasApi } from '@/lib/api';

export interface Seg {
  startMs: number;
  endMs: number;
  type?: string;
}

/** Normalize a CameraTimelineResponse into sorted millisecond segments. */
export function toSegs(data: { segments?: Array<{ start: string; end: string; type?: string }> } | undefined): Seg[] {
  const raw = data?.segments;
  if (!Array.isArray(raw)) return [];
  return raw
    .map((s) => ({ startMs: new Date(s.start).getTime(), endMs: new Date(s.end).getTime(), type: s.type }))
    .filter((s) => Number.isFinite(s.startMs) && Number.isFinite(s.endMs) && s.endMs > s.startMs)
    .sort((a, b) => a.startMs - b.startMs);
}

/** The segment covering `ms`, or null if `ms` is in a gap. */
export function segmentAt(ms: number, segs: Seg[]): Seg | null {
  for (const s of segs) if (ms >= s.startMs && ms < s.endMs) return s;
  return null;
}

/** Start of the earliest segment beginning after `ms` (for skip-the-gap), or null. */
export function nextSegmentStart(ms: number, segs: Seg[]): number | null {
  let best: number | null = null;
  for (const s of segs) {
    if (s.startMs > ms && (best === null || s.startMs < best)) best = s.startMs;
  }
  return best;
}

/**
 * Nearest playable instant to `ms`: `ms` itself if inside a segment, else the
 * closest segment edge (so clicking a gap on the timeline snaps to real footage).
 * Returns null when there are no segments at all.
 */
export function nearestInstant(ms: number, segs: Seg[]): number | null {
  if (segs.length === 0) return null;
  if (segmentAt(ms, segs)) return ms;
  let best: number | null = null;
  let bestDist = Infinity;
  for (const s of segs) {
    for (const edge of [s.startMs, s.endMs - 1]) {
      const d = Math.abs(edge - ms);
      if (d < bestDist) {
        bestDist = d;
        best = edge;
      }
    }
  }
  return best;
}

/**
 * Live recording segments for a camera around the playhead. Window is anchored
 * 75% behind / 25% ahead of the playhead (matching RecordingTimeline) and bucketed
 * to the hour so the queryKey doesn't churn every tick. `loaded` distinguishes
 * "still fetching" from "genuinely no footage" so callers don't flash a false
 * empty state.
 */
export function useCameraSegments(
  cameraId: string | undefined,
  playbackTime: Date,
  windowHours: number,
): { segments: Seg[]; supported: boolean; loaded: boolean } {
  const playMs = playbackTime.getTime();
  const hourBucket = Math.floor(playMs / 3_600_000);
  const { data, isSuccess } = useQuery({
    queryKey: ['playback-segments', cameraId, windowHours, hourBucket],
    queryFn: async () => {
      const winMs = windowHours * 3_600_000;
      const start = new Date(playMs - winMs * 0.75).toISOString();
      const end = new Date(Math.min(Date.now(), playMs + winMs * 0.25)).toISOString();
      const res = await camerasApi.getCameraTimeline(cameraId as string, start, end);
      return res.data;
    },
    enabled: !!cameraId,
    refetchInterval: 60_000,
    staleTime: 30_000,
  });
  return {
    segments: toSegs(data),
    supported: data ? data.supported !== false : true,
    loaded: isSuccess,
  };
}
