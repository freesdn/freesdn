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

  const [src, setSrc] = useState('');
  const [starting, setStarting] = useState(true);
  const [failed, setFailed] = useState<string | null>(null);
  const sessionRef = useRef<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let heartbeat: ReturnType<typeof setInterval> | null = null;
    setStarting(true);
    setFailed(null);
    setSrc('');

    // Demo build: the smooth-HLS path POSTs to start a session and then polls
    // ``${API_URL}${playlist_url}`` directly with fetch() + feeds it to hls.js,
    // both bypass the demo axios adapter and would emit real same-origin /api
    // requests from the static demo bundle. Never start a recorded-HLS session
    // in demo mode; surface "unavailable" so the parent (MultiPlaybackPage)
    // degrades this cell to the demo-mocked per-frame snapshot path.
    if (isDemoMode) {
      const unavailable = tRef.current('RecordedHlsPlayer.notSupported');
      setFailed(unavailable);
      setStarting(false);
      onUnavailableRef.current?.(unavailable);
      return () => { cancelled = true; };
    }

    (async () => {
      try {
        const { data } = await hlsStreamApi.startPlayback(cameraId, {
          start_time: startTime,
          quality,
          duration_s: durationS,
        });
        if (cancelled) {
          if (data?.session_id) hlsStreamApi.stop(data.session_id).catch(() => {});
          return;
        }
        sessionRef.current = data.session_id;
        const url = `${API_URL}${data.playlist_url}`;
        // Heartbeat immediately so the session isn't reaped during cold-start.
        heartbeat = setInterval(() => {
          if (sessionRef.current) hlsStreamApi.heartbeat(sessionRef.current).catch(() => {});
        }, 15_000);

        // Poll the manifest until ffmpeg has written the first segment before
        // handing the URL to hls.js. Transcoding a 4K-HEVC recording cold-starts
        // in ~3-15s; giving hls.js a not-ready (404) manifest makes it retry a
        // few times and fatally bail with "Network error: unable to load stream".
        // We wait here (the spinner shows) and only set src once a segment exists.
        const deadline = Date.now() + 30_000;
        while (Date.now() <= deadline) {
          if (cancelled) return;
          try {
            const res = await fetch(url, { credentials: 'include', cache: 'no-store' });
            if (res.ok && (await res.text()).includes('.ts')) {
              if (cancelled) return;
              setSrc(url);
              setStarting(false);
              return;
            }
          } catch {
            // network blip, keep polling until the deadline
          }
          await new Promise((r) => setTimeout(r, 1200));
        }
        // Cold-start exceeded the deadline, surface as unavailable so the
        // caller can fall back (e.g. to per-frame snapshot playback).
        if (cancelled) return;
        const timedOut = tRef.current('RecordedHlsPlayer.startFailed');
        setFailed(timedOut);
        setStarting(false);
        onUnavailableRef.current?.(timedOut);
      } catch (err: unknown) {
        if (cancelled) return;
        const status = (err as { response?: { status?: number } })?.response?.status;
        // 422 = the NVR's recorded stream is undecodable (a device limitation,
        // e.g. a classic NVR whose recorded HEVC has no decodable parameter sets).
        // The per-frame path fails the same way, so show an honest message and do
        // NOT call onUnavailable (no pointless fall-back to frames).
        if (status === 422) {
          setFailed(tRef.current('RecordedHlsPlayer.notDecodable'));
          setStarting(false);
          return;
        }
        const reason =
          status === 501
            ? tRef.current('RecordedHlsPlayer.notSupported')
            : tRef.current('RecordedHlsPlayer.startFailed');
        setFailed(reason);
        setStarting(false);
        onUnavailableRef.current?.(reason);
      }
    })();

    return () => {
      cancelled = true;
      if (heartbeat) clearInterval(heartbeat);
      const sid = sessionRef.current;
      sessionRef.current = null;
      if (sid) hlsStreamApi.stop(sid).catch(() => {});
    };
  }, [cameraId, startTime, quality, durationS]);

  if (failed) {
    return (
      <div className={cn('relative flex items-center justify-center bg-black', className)}>
        <p className="px-4 text-center text-sm text-white/60">{failed}</p>
      </div>
    );
  }

  if (starting || !src) {
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
      src={src}
      className={className}
      autoPlay
      muted={muted}
      paused={paused}
      live={false}
      onError={(e) => onUnavailableRef.current?.(e)}
      onProgress={(sec) => onPlayheadTimeRef.current?.(startMs + sec * 1000)}
    />
  );
}

export default RecordedHlsPlayer;
