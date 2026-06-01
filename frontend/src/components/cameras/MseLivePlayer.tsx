// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MseLivePlayer, sub-second live video via the go2rtc MSE WebSocket proxy.
 *
 * Speaks go2rtc's MSE protocol over the authenticated FreeSDN proxy
 * (/cameras/{id}/live/mse): sends the codecs the browser supports, receives the
 * chosen mime + binary fragmented-MP4 segments, and feeds them to a MediaSource
 * SourceBuffer. Trims the buffer + nudges to the live edge to keep latency low.
 * On any failure it calls onError so the caller can fall back to the progressive
 * fMP4 <video> path (and then MJPEG snapshots).
 */
import { useEffect, useRef } from 'react';
import { camerasApi } from '@/lib/api';
import { isDemoMode } from '@/demo/mode';

// Candidate codecs advertised to go2rtc; it picks the best match for the source.
const CANDIDATE_CODECS = [
  'avc1.640029', 'avc1.64002A', 'avc1.4d402a', 'avc1.42e01e',
  'hvc1.1.6.L153.B0', 'hev1.1.6.L153.B0',
  'mp4a.40.2', 'mp4a.40.5', 'opus', 'flac',
];

interface MseLivePlayerProps {
  cameraId: string;
  quality: 'main' | 'sub';
  className?: string;
  muted?: boolean;
  onError?: (reason: string) => void;
  onPlaying?: () => void;
}

function supportedCodecs(): string {
  if (typeof MediaSource === 'undefined' || !MediaSource.isTypeSupported) return '';
  return CANDIDATE_CODECS.filter((c) => {
    const kind = c.startsWith('mp4a') || c === 'opus' || c === 'flac' ? 'audio' : 'video';
    try {
      return MediaSource.isTypeSupported(`${kind}/mp4; codecs="${c}"`);
    } catch {
      return false;
    }
  }).join(',');
}

export function MseLivePlayer({
  cameraId,
  quality,
  className,
  muted = true,
  onError,
  onPlaying,
}: MseLivePlayerProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const onErrorRef = useRef(onError);
  onErrorRef.current = onError;
  const onPlayingRef = useRef(onPlaying);
  onPlayingRef.current = onPlaying;

  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;
    if (typeof MediaSource === 'undefined') {
      onErrorRef.current?.('MediaSource unsupported');
      return;
    }

    let closed = false;
    let ws: WebSocket | null = null;
    let sb: SourceBuffer | null = null;
    const queue: ArrayBuffer[] = [];
    const mediaSource = new MediaSource();

    // Stall watchdog: a go2rtc WS can stay OPEN (answers pings) while the NVR's
    // RTSP source freezes mid-stream and forwards no further binary segments,
    // ws.onerror/onclose never fire, so without this the <video> shows a
    // silently frozen frame forever. Track the last binary segment time and
    // fail() after STALL_TIMEOUT_MS of no progress so the caller falls back to
    // the progressive fMP4 <video> (then MJPEG/snapshot).
    const STALL_TIMEOUT_MS = 20_000;
    let lastSegmentAt = Date.now();
    let stallTimer = 0;

    const fail = (reason: string) => {
      if (closed) return;
      closed = true;
      if (stallTimer) window.clearInterval(stallTimer);
      // Tear the upstream socket down immediately rather than waiting for the
      // parent to unmount us, avoids a lingering go2rtc WS between the error
      // and the transport fallback.
      try { ws?.close(); } catch { /* noop */ }
      onErrorRef.current?.(reason);
    };

    stallTimer = window.setInterval(() => {
      if (closed) return;
      if (Date.now() - lastSegmentAt > STALL_TIMEOUT_MS) fail('stream stalled');
    }, 5_000);

    const flush = () => {
      if (!sb || sb.updating || queue.length === 0 || closed) return;
      try {
        // Keep latency bounded: drop the oldest buffered range once it grows.
        const buf = sb.buffered;
        if (buf.length > 0) {
          const start = buf.start(0);
          const end = buf.end(buf.length - 1);
          if (end - start > 12 && video.currentTime - start > 8) {
            sb.remove(start, video.currentTime - 4);
            return; // resume appending on the next updateend
          }
        }
        const chunk = queue.shift();
        if (chunk) sb.appendBuffer(chunk);
      } catch (err) {
        if ((err as DOMException)?.name === 'QuotaExceededError' && sb && sb.buffered.length) {
          try {
            sb.remove(sb.buffered.start(0), Math.max(0, video.currentTime - 4));
          } catch {
            fail('buffer quota');
          }
        } else {
          fail('append failed');
        }
      }
    };

    const onSourceOpen = () => {
      URL.revokeObjectURL(video.src);
      const codecs = supportedCodecs();
      if (!codecs) {
        fail('no supported codecs');
        return;
      }
      const wsUrl = camerasApi.getLiveMseWsUrl(cameraId, quality);
      // Demo build (or any empty URL): never open a real WebSocket. Fall back to
      // the (demo-mocked) snapshot path so the static demo makes no live calls.
      if (isDemoMode || !wsUrl) {
        fail('live view unavailable');
        return;
      }
      ws = new WebSocket(wsUrl);
      ws.binaryType = 'arraybuffer';
      ws.onopen = () => ws?.send(JSON.stringify({ type: 'mse', value: codecs }));
      ws.onmessage = (ev) => {
        if (closed) return;
        if (typeof ev.data === 'string') {
          try {
            const msg = JSON.parse(ev.data);
            if (msg.type === 'mse' && msg.value && !sb && mediaSource.readyState === 'open') {
              sb = mediaSource.addSourceBuffer(msg.value);
              sb.mode = 'segments';
              sb.addEventListener('updateend', flush);
            } else if (msg.type === 'error') {
              fail(msg.value || 'go2rtc error');
            }
          } catch {
            /* ignore non-JSON control frames */
          }
        } else {
          lastSegmentAt = Date.now(); // progress, reset the stall watchdog
          queue.push(ev.data as ArrayBuffer);
          flush();
        }
      };
      ws.onerror = () => fail('websocket error');
      ws.onclose = () => fail('websocket closed');
    };

    const onCanPlay = () => {
      video.play().catch(() => {/* autoplay policy, muted should allow it */});
      onPlayingRef.current?.();
    };
    const onVideoError = () => fail('video element error');

    video.muted = muted;
    video.addEventListener('canplay', onCanPlay);
    video.addEventListener('error', onVideoError);
    mediaSource.addEventListener('sourceopen', onSourceOpen);
    video.src = URL.createObjectURL(mediaSource);

    return () => {
      closed = true;
      if (stallTimer) window.clearInterval(stallTimer);
      queue.length = 0; // drop any buffered segments so flush() can't append post-teardown
      video.removeEventListener('canplay', onCanPlay);
      video.removeEventListener('error', onVideoError);
      try { ws?.close(); } catch { /* noop */ }
      try {
        if (sb && mediaSource.readyState === 'open') mediaSource.removeSourceBuffer(sb);
      } catch { /* noop */ }
      try {
        if (mediaSource.readyState === 'open') mediaSource.endOfStream();
      } catch { /* noop */ }
      video.removeAttribute('src');
      video.load();
    };
  }, [cameraId, quality, muted]);

  return <video ref={videoRef} playsInline className={className} />;
}

export default MseLivePlayer;
