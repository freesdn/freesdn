// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * RecordedHlsPlayer, smooth recorded-video playback from an absolute instant.
 *
 * Owns the HLS session lifecycle (start → 15s heartbeat → stop) and feeds the
 * resulting playlist URL to <HLSPlayer>. Recorded HEVC decodes only on NVRs
 * whose media server emits valid parameter sets (e.g. Hikvision DeepinMind);
 * on devices that can't (classic NVR / non-Hikvision) the backend returns 501
 * and ``onUnavailable`` fires so the parent can fall back to the per-frame
 * snapshot playback path.
 */
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Loader2 } from 'lucide-react';
import { hlsStreamApi } from '@/lib/api/cameras';
import { API_URL } from '@/lib/api/client';
import { isDemoMode } from '@/demo/mode';
import { cn } from '@/lib/utils';
import { HLSPlayer } from './HLSPlayer';

interface RecordedHlsPlayerProps {
  cameraId: string;
  /** ISO 8601 instant to begin playback from. */
  startTime: string;
  quality?: 'low' | 'medium' | 'high' | 'source';
  /** Forward window per session in seconds (10..3600). */
  durationS?: number;
  className?: string;
  muted?: boolean;
  /** When true, freeze the video (the session/heartbeat stays alive). */
  paused?: boolean;
  /** Fires when the recorded stream can't be played (501 / start failure / decode error). */
  onUnavailable?: (reason: string) => void;
  /** Frame-exact playhead: the absolute wall-clock (ms) the video is currently
   *  showing, startTime + the player's currentTime. Lets the timeline track the
   *  real video position instead of a wall-clock timer. */
  onPlayheadTime?: (wallClockMs: number) => void;
}

export function RecordedHlsPlayer({
  cameraId,
  startTime,
  quality = 'low',
  durationS = 600,
  className,
  muted = true,
  paused = false,
  onUnavailable,
  onPlayheadTime,
}: RecordedHlsPlayerProps) {
  const { t } = useTranslation('cameras');
  const tRef = useRef(t);
  tRef.current = t;
  const onUnavailableRef = useRef(onUnavailable);
  onUnavailableRef.current = onUnavailable;
  const onPlayheadTimeRef = useRef(onPlayheadTime);
  onPlayheadTimeRef.current = onPlayheadTime;
  const startMs = new Date(startTime).getTime();

  const [playback, setPlayback] = useState<{ url: string; onError: (reason: string) => void } | null>(null);
  const [starting, setStarting] = useState(true);
  const [failed, setFailed] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let finished = false;
    let sessionId: string | null = null;
    let heartbeat: ReturnType<typeof setInterval> | null = null;
    let deadline: ReturnType<typeof setTimeout> | null = null;
    const manifest = new AbortController();
    setStarting(true);
    setFailed(null);
    setPlayback(null);

    // Each effect owns only its own session. Terminal failures must release it
    // even if the parent keeps this component mounted to display the error.
    const release = () => {
      if (heartbeat !== null) clearInterval(heartbeat);
      if (deadline !== null) clearTimeout(deadline);
      heartbeat = null;
      deadline = null;
      manifest.abort();
      const sid = sessionId;
      sessionId = null;
      if (sid) hlsStreamApi.stop(sid).catch(() => {});
    };
    const fail = (reason: string, notify = true) => {
      if (cancelled || finished) return;
      finished = true;
      release();
      setPlayback(null);
      setFailed(reason);
      setStarting(false);
      if (notify) onUnavailableRef.current?.(reason);
    };
    const close = () => {
      cancelled = true;
      release();
    };

    // Demo playback must never escape its mocked API transport via fetch/HLS.
    if (isDemoMode) {
      fail(tRef.current('RecordedHlsPlayer.notSupported'));
      return close;
    }

    const waitForPoll = () => new Promise<void>((resolve) => {
      if (manifest.signal.aborted) { resolve(); return; }
      const onAbort = () => { clearTimeout(timer); resolve(); };
      const timer = setTimeout(() => {
        manifest.signal.removeEventListener('abort', onAbort);
        resolve();
      }, 1200);
      manifest.signal.addEventListener('abort', onAbort, { once: true });
    });

    (async () => {
      try {
        const { data } = await hlsStreamApi.startPlayback(cameraId, {
          start_time: startTime,
          quality,
          duration_s: durationS,
        });
        if (cancelled || finished) {
          if (data?.session_id) hlsStreamApi.stop(data.session_id).catch(() => {});
          return;
        }
        sessionId = data.session_id;
        const url = `${API_URL}${data.playlist_url}`;
        heartbeat = setInterval(() => {
          const sid = sessionId;
          if (!sid || cancelled || finished) return;
          hlsStreamApi.heartbeat(sid).catch((err: unknown) => {
            const status = (err as { response?: { status?: number } })?.response?.status;
            if (status === 401 || status === 403 || status === 404) {
              // A permission refusal cannot be repaired by falling back to
              // snapshots. A missing session may use the existing fallback.
              fail(tRef.current('RecordedHlsPlayer.startFailed'), status === 404);
            }
          });
        }, 15_000);

        // A timer independent of fetch also bounds stalled response bodies.
        // Abort stops the owned request and any pending polling delay.
        deadline = setTimeout(() => fail(tRef.current('RecordedHlsPlayer.startFailed')), 30_000);
        while (!cancelled && !finished) {
          try {
            const res = await fetch(url, {
              credentials: 'include', cache: 'no-store', signal: manifest.signal,
            });
            if (cancelled || finished) return;
            if (res.status === 401 || res.status === 403) {
              fail(tRef.current('RecordedHlsPlayer.startFailed'), false);
              return;
            }
            if (res.ok && (await res.text()).includes('.ts')) {
              if (cancelled || finished) return;
              if (deadline !== null) clearTimeout(deadline);
              deadline = null;
              // This callback retains the effect's cancellation guard. A late
              // error from an old player cannot release a replacement session.
              setPlayback({ url, onError: (reason) => fail(reason) });
              setStarting(false);
              return;
            }
          } catch {
            if (cancelled || finished) return;
            // Transient network errors and not-ready manifests may retry.
          }
          await waitForPoll();
        }
      } catch (err: unknown) {
        if (cancelled || finished) return;
        const status = (err as { response?: { status?: number } })?.response?.status;
        if (status === 422) {
          fail(tRef.current('RecordedHlsPlayer.notDecodable'), false);
          return;
        }
        const reason = status === 501
          ? tRef.current('RecordedHlsPlayer.notSupported')
          : tRef.current('RecordedHlsPlayer.startFailed');
        fail(reason, status !== 401 && status !== 403);
      }
    })();

    return close;
  }, [cameraId, startTime, quality, durationS]);

  if (failed) {
    return (
      <div className={cn('relative flex items-center justify-center bg-black', className)}>
        <p className="px-4 text-center text-sm text-white/60">{failed}</p>
      </div>
    );
  }

  if (starting || !playback) {
    return (
      <div className={cn('relative flex items-center justify-center bg-black', className)}>
        <div className="text-center text-white/60">
          <Loader2 className="mx-auto mb-2 h-8 w-8 animate-spin" />
          <p className="text-sm">{t('RecordedHlsPlayer.starting')}</p>
        </div>
      </div>
    );
  }

  return (
    <HLSPlayer
      src={playback.url}
      className={className}
      autoPlay
      muted={muted}
      paused={paused}
      live={false}
      onError={playback.onError}
      onProgress={(sec) => onPlayheadTimeRef.current?.(startMs + sec * 1000)}
    />
  );
}

export default RecordedHlsPlayer;
