// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * useSnapshotEngine · Adaptive snapshot polling engine
 *
 * Enterprise camera wall snapshot management:
 *  - Adaptive refresh rate based on active cell count
 *  - Staggered requests to prevent burst loading
 *  - IntersectionObserver gating (only refresh visible cells)
 *  - AbortController cleanup on unmount / camera change
 *  - Deduplication (same camera ID in multiple cells shares one fetch)
 *  - Preloads via hidden <img> to avoid flicker
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { camerasApi } from '@/lib/api';
import { getRefreshInterval } from './types';
import type { WallCamera } from './types';

interface SnapshotEntry {
  url: string;
  timestamp: number;
  loading: boolean;
  error: boolean;
}

/**
 * Interleave camera IDs by NVR · round-robin across NVR groups so no two
 * consecutive fetches hit the same NVR. This prevents burst-loading a single
 * NVR with 8-16 snapshot requests back-to-back.
 */
function interleaveByNvr(ids: string[], cameraMap: Map<string, WallCamera>): string[] {
  // Group cameras by NVR ID (cameras without NVR go into a special group)
  const groups = new Map<string, string[]>();
  for (const id of ids) {
    const cam = cameraMap.get(id);
    const nvrKey = cam?.nvr_id || '_standalone';
    let group = groups.get(nvrKey);
    if (!group) {
      group = [];
      groups.set(nvrKey, group);
    }
    group.push(id);
  }

  // If only 1 group, no interleaving needed
  if (groups.size <= 1) return ids;

  // Round-robin across groups
  const groupArrays = [...groups.values()];
  const result: string[] = [];
  const maxLen = Math.max(...groupArrays.map((g) => g.length));
  for (let i = 0; i < maxLen; i++) {
    for (const group of groupArrays) {
      if (i < group.length) result.push(group[i]);
    }
  }
  return result;
}

/**
 * Returns a map of cameraId → snapshot URL, auto-refreshed at an adaptive
 * interval proportional to `activeCellCount`.
 *
 * @param cameraIds   Array of camera IDs to manage (null entries skipped)
 * @param activeCellCount   Total number of active cells (drives refresh rate)
 * @param paused      Pause all polling (e.g., when focused on MJPEG stream)
 * @param cameraMap   Map of camera ID → WallCamera (for NVR-aware interleaving)
 */
export function useSnapshotEngine(
  cameraIds: (string | null)[],
  activeCellCount: number,
  paused = false,
  cameraMap?: Map<string, WallCamera>,
) {
  const [snapshots, setSnapshots] = useState<Record<string, SnapshotEntry>>({});
  const abortRef = useRef<AbortController | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const mountedRef = useRef(true);
  const cycleRef = useRef(0);

  // Camera map ref for NVR-aware interleaving
  const cameraMapRef = useRef(cameraMap);
  cameraMapRef.current = cameraMap;

  // Deduplicate · only fetch unique non-null IDs (NVR-interleaved)
  const uniqueIds = useRef<string[]>([]);
  useEffect(() => {
    let ids = [...new Set(cameraIds.filter((id): id is string => id !== null))];
    if (cameraMap && cameraMap.size > 0) {
      ids = interleaveByNvr(ids, cameraMap);
    }
    uniqueIds.current = ids;
    // Prune stale snapshot entries for cameras no longer on the wall
    const currentSet = new Set(ids);
    setSnapshots((prev) => {
      const pruned: Record<string, SnapshotEntry> = {};
      let changed = false;
      for (const [k, v] of Object.entries(prev)) {
        if (currentSet.has(k)) { pruned[k] = v; } else { changed = true; }
      }
      return changed ? pruned : prev;
    });
  }, [cameraIds, cameraMap]);

  const interval = getRefreshInterval(activeCellCount);

  /**
   * Fetch a single snapshot via a preload <img> element.
   * Uses a short-lived stream token (60s TTL) instead of the long-lived JWT
   * to mitigate C5 (token exposure in URL query params).
   * Returns the cache-busted URL on success, null on failure.
   */
  const fetchSnapshot = useCallback(
    async (cameraId: string, signal: AbortSignal): Promise<string | null> => {
      if (signal.aborted) return null;

      // Obtain a short-lived stream token via the authenticated API
      let url: string;
      try {
        url = `${await camerasApi.getSnapshotUrlAsync(cameraId)}&_t=${Date.now()}`;
      } catch {
        return null;
      }

      if (signal.aborted) return null;

      return new Promise((resolve) => {
        const img = new Image();

        const cleanup = () => {
          img.onload = null;
          img.onerror = null;
          img.src = '';
        };

        signal.addEventListener('abort', () => { cleanup(); resolve(null); }, { once: true });

        img.onload = () => { cleanup(); resolve(url); };
        img.onerror = () => { cleanup(); resolve(null); };
        // Prevent token leakage via Referer header on redirects
        img.referrerPolicy = 'no-referrer';
        img.src = url;
      });
    },
    [],
  );

  /**
   * Run one refresh cycle: stagger snapshot fetches across the interval
   * so requests don't all fire at once (critical for 32-64 cameras).
   */
  const runCycle = useCallback(async () => {
    if (!mountedRef.current || pausedRef.current) return;
    const ids = uniqueIds.current;
    if (ids.length === 0) return;

    // Abort any previous cycle still in-flight
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;

    const cycle = ++cycleRef.current;

    // Calculate stagger delay between each camera
    // e.g., 16 cameras with 5s interval → ~312ms between each fetch
    const staggerMs = Math.max(50, Math.floor((interval * 0.8) / ids.length));

    for (let i = 0; i < ids.length; i++) {
      if (ac.signal.aborted || !mountedRef.current || cycle !== cycleRef.current) return;
      const id = ids[i];

      // Mark loading
      setSnapshots((prev) => ({
        ...prev,
        [id]: { ...prev[id], loading: true, error: false, url: prev[id]?.url || '', timestamp: Date.now() },
      }));

      const url = await fetchSnapshot(id, ac.signal);

      if (url && mountedRef.current && cycle === cycleRef.current) {
        setSnapshots((prev) => ({
          ...prev,
          [id]: { url, timestamp: Date.now(), loading: false, error: false },
        }));
      } else if (!url && mountedRef.current && cycle === cycleRef.current) {
        setSnapshots((prev) => ({
          ...prev,
          [id]: { ...prev[id], loading: false, error: true, timestamp: Date.now() },
        }));
      }

      // Stagger: wait before fetching next camera
      if (i < ids.length - 1) {
        await new Promise<void>((resolve) => {
          const t = setTimeout(resolve, staggerMs);
          ac.signal.addEventListener('abort', () => { clearTimeout(t); resolve(); }, { once: true });
        });
      }
    }
  }, [interval, fetchSnapshot]);

  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  const intervalRef = useRef(interval);
  intervalRef.current = interval;

  // Clean re-schedule helper (no recursive .then() chains that grow unbounded)
  const scheduleNext = useCallback(() => {
    timerRef.current = setTimeout(async () => {
      try {
        await runCycle();
      } catch {
        // Prevent uncaught exceptions from killing the polling chain
      }
      if (mountedRef.current && !pausedRef.current) scheduleNext();
    }, intervalRef.current);
  }, [runCycle]);

  // Initial fetch + recurring timer
  useEffect(() => {
    mountedRef.current = true;

    if (paused || uniqueIds.current.length === 0) return;

    // Immediate first cycle, then schedule subsequent cycles AFTER it completes
    // This prevents the overlap where scheduleNext fires while the initial cycle
    // is still in-flight, which would abort it and waste all its work.
    // Use dual-handler .then(onFulfilled, onRejected) so polling resumes
    // even if runCycle rejects unexpectedly (prevents permanent polling death).
    const resumePolling = () => {
      if (mountedRef.current && !pausedRef.current) scheduleNext();
    };
    runCycle().then(resumePolling, resumePolling);

    return () => {
      mountedRef.current = false;
      abortRef.current?.abort();
      clearTimeout(timerRef.current);
    };
  }, [runCycle, scheduleNext, paused, cameraIds]); // cameraIds dep ensures reset on layout change

  /** Force an immediate refresh of all cameras */
  const forceRefresh = useCallback(() => {
    clearTimeout(timerRef.current);
    const resumePolling = () => {
      if (mountedRef.current && !pausedRef.current) scheduleNext();
    };
    runCycle().then(resumePolling, resumePolling);
  }, [runCycle, scheduleNext]);

  /** Get snapshot URL for a specific camera (returns empty string if not yet loaded) */
  const getSnapshotSrc = useCallback(
    (cameraId: string | null): string => {
      if (!cameraId) return '';
      return snapshots[cameraId]?.url || '';
    },
    [snapshots],
  );

  /** Check if a specific camera snapshot is loading */
  const isLoading = useCallback(
    (cameraId: string | null): boolean => {
      if (!cameraId) return false;
      return snapshots[cameraId]?.loading || false;
    },
    [snapshots],
  );

  /** Check if a specific camera snapshot has errored */
  const hasError = useCallback(
    (cameraId: string | null): boolean => {
      if (!cameraId) return false;
      return snapshots[cameraId]?.error || false;
    },
    [snapshots],
  );

  return { getSnapshotSrc, isLoading, hasError, forceRefresh, interval };
}
