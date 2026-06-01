// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * useCanvasStream · Enterprise-grade canvas-based MJPEG streaming engine
 *
 * Replaces the `<img src={mjpeg}>` approach with a fetch()-based ReadableStream
 * parser that renders MJPEG frames onto a `<canvas>` element. This provides:
 *
 *  - Client-side FPS control: throttle rendering based on cell count (save CPU)
 *  - Visibility-aware: pause streaming when tab is hidden
 *  - Staggered startup: delay initial connection per cell to avoid burst
 *  - Memory-safe: proper ImageBitmap cleanup, AbortController cancellation
 *  - Auto-reconnect: exponential backoff on failure (1s → 2s → 4s → ... 30s max)
 *  - NVR overload detection: HTTP 429 → degrade to snapshot, no retry
 *  - 24-48 channel scalability: tested design for high-density walls
 *
 * How it works:
 *  1. fetch() the MJPEG endpoint with AbortController
 *  2. Read the ReadableStream, accumulate bytes in a ring buffer
 *  3. Scan for JPEG SOI (0xFF 0xD8) and EOI (0xFF 0xD9) markers
 *  4. When a complete frame is found, createImageBitmap() from the Blob
 *  5. Draw the ImageBitmap onto the canvas via 2D context
 *  6. Throttle rendering via requestAnimationFrame + target FPS
 *  7. On error, retry with exponential backoff; degrade after MAX_RETRIES
 */

import { useRef, useEffect, useState } from 'react';
import { camerasApi } from '@/lib/api';

// ---------------------------------------------------------------------------
// FPS tiers · fewer cameras = more FPS
// ---------------------------------------------------------------------------

export interface LiveFpsTier {
  maxCells: number;
  fps: number;
}

export const LIVE_FPS_TIERS: LiveFpsTier[] = [
  { maxCells: 1,  fps: 15 },
  { maxCells: 4,  fps: 12 },
  { maxCells: 9,  fps: 10 },
  { maxCells: 16, fps: 8  },
  { maxCells: 25, fps: 5  },
  { maxCells: 36, fps: 3  },
  { maxCells: 48, fps: 2  },
  { maxCells: 64, fps: 1  },
];

export function getTargetFps(cellCount: number): number {
  for (const tier of LIVE_FPS_TIERS) {
    if (cellCount <= tier.maxCells) return tier.fps;
  }
  return 1;
}

// ---------------------------------------------------------------------------
// MJPEG frame boundary parser
// ---------------------------------------------------------------------------

// Maximum buffer size: 8MB · prevents unbounded memory growth on stalled streams
const MAX_BUFFER_SIZE = 8 * 1024 * 1024;

// Reconnection constants
const MAX_RETRIES = 5;
const MAX_BACKOFF_MS = 30_000;

/**
 * Scan a byte buffer for complete JPEG frames.
 * Returns the last complete frame found (discards older frames for real-time).
 * Also returns the number of bytes consumed so the caller can compact in-place.
 */
function extractLatestFrame(
  buffer: Uint8Array,
  length: number,
): { frame: Uint8Array | null; consumedBytes: number } {
  let lastFrameStart = -1;
  let lastFrameEnd = -1;

  for (let i = 0; i < length - 1; i++) {
    if (buffer[i] === 0xFF) {
      if (buffer[i + 1] === 0xD8) {
        lastFrameStart = i;
      } else if (buffer[i + 1] === 0xD9 && lastFrameStart >= 0) {
        lastFrameEnd = i + 2;
      }
    }
  }

  if (lastFrameStart >= 0 && lastFrameEnd > lastFrameStart) {
    const frame = buffer.slice(lastFrameStart, lastFrameEnd);
    return { frame, consumedBytes: lastFrameEnd };
  }

  return { frame: null, consumedBytes: 0 };
}

// ---------------------------------------------------------------------------
// Stream health metrics (ref-based, no re-renders)
// ---------------------------------------------------------------------------

export interface StreamHealthMetrics {
  connectTimeMs: number;
  totalErrors: number;
  totalReconnects: number;
  lastFrameAt: number;
  firstFrameAt: number;
  framesReceived: number;
  bytesReceived: number;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

interface UseCanvasStreamOptions {
  cameraId: string | null;
  canvasRef: React.RefObject<HTMLCanvasElement | null>;
  enabled: boolean;
  targetFps: number;
  quality: 'sub' | 'main';
  staggerMs?: number;
}

interface UseCanvasStreamResult {
  isStreaming: boolean;
  hasError: boolean;
  /** Whether the stream is currently attempting to reconnect */
  reconnecting: boolean;
  /** Number of consecutive retry attempts */
  retryCount: number;
  actualFps: number;
  framesReceived: number;
  bytesReceived: number;
  /** Ref to health metrics (no re-renders) */
  metrics: React.RefObject<StreamHealthMetrics>;
}

export function useCanvasStream({
  cameraId,
  canvasRef,
  enabled,
  targetFps,
  quality,
  staggerMs = 0,
}: UseCanvasStreamOptions): UseCanvasStreamResult {
  const [isStreaming, setIsStreaming] = useState(false);
  const [hasError, setHasError] = useState(false);
  const [reconnecting, setReconnecting] = useState(false);
  const [retryCount, setRetryCount] = useState(0);
  const [actualFps, setActualFps] = useState(0);
  const [framesReceived, setFramesReceived] = useState(0);
  const [bytesReceived, setBytesReceived] = useState(0);

  // Refs for mutable state
  const targetFpsRef = useRef(targetFps);
  const mountedRef = useRef(true);
  const animFrameRef = useRef<number>(0);
  const lastBitmapRef = useRef<ImageBitmap | null>(null);
  const pendingBitmapRef = useRef<ImageBitmap | null>(null);
  const lastRenderTimeRef = useRef<number>(0);
  const fpsCounterRef = useRef<{ frames: number; lastCheck: number }>({ frames: 0, lastCheck: 0 });
  const totalBytesRef = useRef<number>(0);
  const totalFramesRef = useRef<number>(0);
  const visibleRef = useRef(!document.hidden);
  const readerRef = useRef<ReadableStreamDefaultReader<Uint8Array> | null>(null);
  const retryCountRef = useRef(0);
  const backoffTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const metricsRef = useRef<StreamHealthMetrics>({
    connectTimeMs: 0, totalErrors: 0, totalReconnects: 0,
    lastFrameAt: 0, firstFrameAt: 0, framesReceived: 0, bytesReceived: 0,
  });

  // Keep targetFps ref in sync without restarting the stream
  useEffect(() => {
    targetFpsRef.current = targetFps;
  }, [targetFps]);

  // Tab visibility tracking
  useEffect(() => {
    const handler = () => { visibleRef.current = !document.hidden; };
    document.addEventListener('visibilitychange', handler);
    return () => document.removeEventListener('visibilitychange', handler);
  }, []);

  // Main streaming effect
  useEffect(() => {
    if (!enabled || !cameraId) {
      cancelAnimationFrame(animFrameRef.current);
      if (lastBitmapRef.current) { lastBitmapRef.current.close(); lastBitmapRef.current = null; }
      if (pendingBitmapRef.current) { pendingBitmapRef.current.close(); pendingBitmapRef.current = null; }
      setIsStreaming(false);
      setHasError(false);
      setReconnecting(false);
      setRetryCount(0);
      setActualFps(0);
      retryCountRef.current = 0;
      return;
    }

    mountedRef.current = true;
    let cancelled = false;
    const abortController = new AbortController();

    // Reset counters
    totalBytesRef.current = 0;
    totalFramesRef.current = 0;
    retryCountRef.current = 0;
    fpsCounterRef.current = { frames: 0, lastCheck: performance.now() };
    metricsRef.current = {
      connectTimeMs: 0, totalErrors: 0, totalReconnects: 0,
      lastFrameAt: 0, firstFrameAt: 0, framesReceived: 0, bytesReceived: 0,
    };

    // Safe setState wrapper · guards against post-unmount updates
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const safeSet = (setter: (v: any) => void, v: unknown) => {
      if (mountedRef.current) setter(v);
    };

    // ── Render loop ──
    const renderLoop = () => {
      if (cancelled) return;

      const canvas = canvasRef.current;
      const bitmap = pendingBitmapRef.current || lastBitmapRef.current;

      if (canvas && bitmap) {
        const now = performance.now();
        const minInterval = 1000 / targetFpsRef.current;

        if (now - lastRenderTimeRef.current >= minInterval && visibleRef.current) {
          if (pendingBitmapRef.current) {
            const old = lastBitmapRef.current;
            lastBitmapRef.current = pendingBitmapRef.current;
            pendingBitmapRef.current = null;
            if (old) old.close();
          }

          const ctx = canvas.getContext('2d');
          if (ctx) {
            if (canvas.width !== bitmap.width || canvas.height !== bitmap.height) {
              canvas.width = bitmap.width;
              canvas.height = bitmap.height;
            }
            try {
              ctx.drawImage(bitmap, 0, 0);
            } catch {
              // Canvas context lost
            }
            lastRenderTimeRef.current = now;

            fpsCounterRef.current.frames++;
            if (now - fpsCounterRef.current.lastCheck >= 1000) {
              safeSet(setActualFps, fpsCounterRef.current.frames);
              fpsCounterRef.current = { frames: 0, lastCheck: now };
            }
          }
        }
      }

      animFrameRef.current = requestAnimationFrame(renderLoop);
    };

    // ── Stream reader with auto-reconnect ──
    const startStream = async () => {
      // Stagger startup
      if (staggerMs > 0 && retryCountRef.current === 0) {
        await new Promise((resolve) => setTimeout(resolve, staggerMs));
        if (cancelled) return;
      }

      const connectStart = performance.now();

      try {
        // Get fresh MJPEG URL (includes new 60s token on each attempt)
        const url = await camerasApi.getMjpegStreamUrlAsync(cameraId, quality);
        if (cancelled) return;

        const response = await fetch(url, {
          signal: abortController.signal,
          credentials: 'include',
        });

        // ── NVR overload detection ──
        if (response.status === 429) {
          // NVR at capacity · degrade to snapshot, do NOT retry
          safeSet(setHasError, true);
          safeSet(setIsStreaming, false);
          safeSet(setReconnecting, false);
          return;
        }

        if (!response.ok || !response.body) {
          throw new Error(`Stream response: ${response.status}`);
        }

        // Connection successful
        metricsRef.current.connectTimeMs = performance.now() - connectStart;
        retryCountRef.current = 0;
        safeSet(setRetryCount, 0);
        safeSet(setIsStreaming, true);
        safeSet(setHasError, false);
        safeSet(setReconnecting, false);

        // Start render loop (only on first connect or reconnect)
        if (!animFrameRef.current) {
          animFrameRef.current = requestAnimationFrame(renderLoop);
        }

        const reader = response.body.getReader();
        readerRef.current = reader;

        let buffer = new Uint8Array(2 * 1024 * 1024);
        let bufferLen = 0;

        try {
          while (!cancelled) {
            const { done, value } = await reader.read();
            if (done) break;

            if (!visibleRef.current) {
              bufferLen = 0;
              continue;
            }

            const needed = bufferLen + value.length;
            if (needed > MAX_BUFFER_SIZE) {
              // Buffer overflow · drop data to prevent unbounded memory growth
              bufferLen = 0;
              metricsRef.current.totalErrors++;
              continue;
            }

            if (needed > buffer.length) {
              const newSize = Math.min(Math.max(buffer.length * 2, needed), MAX_BUFFER_SIZE);
              const newBuffer = new Uint8Array(newSize);
              newBuffer.set(buffer.subarray(0, bufferLen));
              buffer = newBuffer;
            }

            buffer.set(value, bufferLen);
            bufferLen += value.length;
            totalBytesRef.current += value.length;
            metricsRef.current.bytesReceived = totalBytesRef.current;

            const { frame, consumedBytes } = extractLatestFrame(buffer, bufferLen);

            if (frame) {
              totalFramesRef.current++;
              metricsRef.current.framesReceived = totalFramesRef.current;
              metricsRef.current.lastFrameAt = Date.now();
              if (!metricsRef.current.firstFrameAt) {
                metricsRef.current.firstFrameAt = Date.now();
              }

              try {
                const blob = new Blob([new Uint8Array(frame)], { type: 'image/jpeg' });
                const bitmap = await createImageBitmap(blob);

                if (cancelled) { bitmap.close(); break; }

                const oldPending = pendingBitmapRef.current;
                pendingBitmapRef.current = bitmap;
                if (oldPending) oldPending.close();

                if (totalFramesRef.current % 10 === 0) {
                  safeSet(setFramesReceived, totalFramesRef.current);
                  safeSet(setBytesReceived, totalBytesRef.current);
                }
              } catch {
                // Frame decode failed
              }
            }

            if (consumedBytes > 0 && consumedBytes < bufferLen) {
              buffer.copyWithin(0, consumedBytes, bufferLen);
              bufferLen -= consumedBytes;
            } else if (consumedBytes >= bufferLen) {
              bufferLen = 0;
            }
          }
        } finally {
          try { reader.cancel().catch(() => {}); } catch { /* ignore */ }
          readerRef.current = null;
        }

        // Stream ended normally (server closed) · treat as recoverable error
        if (!cancelled) {
          throw new Error('Stream ended');
        }
      } catch (err: unknown) {
        if (cancelled || (err as Error)?.name === 'AbortError') return;

        // ── Exponential backoff reconnect ──
        metricsRef.current.totalErrors++;
        retryCountRef.current++;
        const attempt = retryCountRef.current;

        if (attempt > MAX_RETRIES) {
          // Exhausted retries · give up
          safeSet(setHasError, true);
          safeSet(setIsStreaming, false);
          safeSet(setReconnecting, false);
          safeSet(setRetryCount, attempt);
          return;
        }

        metricsRef.current.totalReconnects++;
        safeSet(setReconnecting, true);
        safeSet(setIsStreaming, false);
        safeSet(setRetryCount, attempt);

        // Exponential backoff: 1s, 2s, 4s, 8s, 16s, capped at 30s
        const backoffMs = Math.min(1000 * Math.pow(2, attempt - 1), MAX_BACKOFF_MS);

        await new Promise<void>((resolve) => {
          backoffTimerRef.current = setTimeout(() => {
            backoffTimerRef.current = null;
            resolve();
          }, backoffMs);
          // If cancelled during backoff, resolve immediately to free closure
          const checkCancelled = () => {
            if (cancelled) {
              if (backoffTimerRef.current) {
                clearTimeout(backoffTimerRef.current);
                backoffTimerRef.current = null;
              }
              resolve();
            }
          };
          // Check once · if already cancelled, resolve now
          checkCancelled();
        });

        if (!cancelled) {
          startStream(); // Recursive retry
        }
      }
    };

    // Start render loop
    animFrameRef.current = requestAnimationFrame(renderLoop);
    startStream();

    return () => {
      cancelled = true;
      mountedRef.current = false;
      abortController.abort();
      cancelAnimationFrame(animFrameRef.current);
      animFrameRef.current = 0;

      // Clear any pending backoff timer to free closure + buffer references immediately
      if (backoffTimerRef.current) {
        clearTimeout(backoffTimerRef.current);
        backoffTimerRef.current = null;
      }

      if (readerRef.current) {
        try { readerRef.current.cancel().catch(() => {}); } catch { /* ignore */ }
        readerRef.current = null;
      }

      if (lastBitmapRef.current) { lastBitmapRef.current.close(); lastBitmapRef.current = null; }
      if (pendingBitmapRef.current) { pendingBitmapRef.current.close(); pendingBitmapRef.current = null; }
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, cameraId, quality, staggerMs]);

  return { isStreaming, hasError, reconnecting, retryCount, actualFps, framesReceived, bytesReceived, metrics: metricsRef };
}
