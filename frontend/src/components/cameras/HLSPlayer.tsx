// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import Hls from 'hls.js';

interface HLSPlayerProps {
  src: string;
  className?: string;
  autoPlay?: boolean;
  muted?: boolean;
  /** When true, the underlying <video> is paused (and resumed when false). */
  paused?: boolean;
  /**
   * Live stream (default) vs recorded VOD playback. Recorded playback uses an
   * EVENT-type playlist that grows at ~real-time; chasing a "live edge" there
   * makes the player stall on every jitter, so we disable lowLatencyMode and let
   * it build a buffer and play straight through.
   */
  live?: boolean;
  onError?: (error: string) => void;
  onPlaying?: () => void;
  /** Fires on each video timeupdate with the current play position (seconds). */
  onProgress?: (currentTimeSec: number) => void;
}

export function HLSPlayer({
  src,
  className,
  autoPlay = true,
  muted = true,
  paused = false,
  live = true,
  onError,
  onPlaying,
  onProgress,
}: HLSPlayerProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const hlsRef = useRef<Hls | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Keep the latest t in a ref so error strings localize without adding t to
  // the HLS-setup effect's deps (which would needlessly re-init the player).
  const { t } = useTranslation('cameras');
  const tRef = useRef(t);
  tRef.current = t;

  // Use refs for callbacks to avoid re-creating HLS instance on every parent render
  const onErrorRef = useRef(onError);
  const onPlayingRef = useRef(onPlaying);
  const onProgressRef = useRef(onProgress);
  onProgressRef.current = onProgress;

  useEffect(() => {
    onErrorRef.current = onError;
  }, [onError]);

  useEffect(() => {
    onPlayingRef.current = onPlaying;
  }, [onPlaying]);

  const recoveryAttemptsRef = useRef(0);
  const MAX_RECOVERY_ATTEMPTS = 3;

  useEffect(() => {
    const video = videoRef.current;
    if (!video || !src) return;

    setLoading(true);
    setError(null);

    // Clean up any previous instance
    if (hlsRef.current) {
      hlsRef.current.destroy();
      hlsRef.current = null;
    }

    const handlePlaying = () => {
      setLoading(false);
      setError(null);
      recoveryAttemptsRef.current = 0;
      onPlayingRef.current?.();
    };

    const handleWaiting = () => {
      setLoading(true);
    };

    const handleTimeUpdate = () => onProgressRef.current?.(video.currentTime);

    video.addEventListener('playing', handlePlaying);
    video.addEventListener('waiting', handleWaiting);
    video.addEventListener('timeupdate', handleTimeUpdate);

    if (Hls.isSupported()) {
      const hls = new Hls({
        enableWorker: true,
        // Live HLS rides the edge for low latency; recorded VOD must NOT, it
        // builds a buffer and plays through, which is what stops the choppy,
        // stall-on-every-jitter behaviour on a ~real-time 4K-HEVC transcode.
        lowLatencyMode: live,
        // For recorded playback, buffer generously ahead so a transcode that only
        // sustains ~1x is absorbed (the player isn't starved the instant a
        // fragment lands a beat late).
        ...(live
          ? {}
          : { maxBufferLength: 30, maxMaxBufferLength: 120, backBufferLength: 30 }),
        // Send the httpOnly auth cookie with playlist/segment requests so the
        // org-scoped /cameras/streams/hls/* endpoints authenticate (matters if
        // the API is served from a different origin than the SPA).
        xhrSetup: (xhr) => {
          xhr.withCredentials = true;
        },
        // Tolerate transient gaps while the server transcodes the recording in
        // real time (a fragment can momentarily lag behind the playlist).
        manifestLoadingMaxRetry: 6,
        manifestLoadingRetryDelay: 1000,
        levelLoadingMaxRetry: 6,
        levelLoadingRetryDelay: 1000,
        fragLoadingMaxRetry: 8,
        fragLoadingRetryDelay: 1000,
      });

      hls.loadSource(src);
      hls.attachMedia(video);

      hls.on(Hls.Events.MANIFEST_PARSED, () => {
        if (autoPlay) {
          video.play().catch(() => {
            // Autoplay blocked by browser policy · not a fatal error
          });
        }
      });

      hls.on(Hls.Events.ERROR, (_event, data) => {
        if (data.fatal) {
          let message: string;
          switch (data.type) {
            case Hls.ErrorTypes.NETWORK_ERROR:
              message = tRef.current('HLSPlayer.errors.networkError');
              if (recoveryAttemptsRef.current >= MAX_RECOVERY_ATTEMPTS) {
                setError(tRef.current('HLSPlayer.errors.streamFailed'));
                onErrorRef.current?.('Stream failed after multiple recovery attempts');
                return;
              }
              recoveryAttemptsRef.current++;
              // Try to recover from network errors
              hls.startLoad();
              break;
            case Hls.ErrorTypes.MEDIA_ERROR:
              message = tRef.current('HLSPlayer.errors.mediaError');
              if (recoveryAttemptsRef.current >= MAX_RECOVERY_ATTEMPTS) {
                setError(tRef.current('HLSPlayer.errors.streamFailed'));
                onErrorRef.current?.('Stream failed after multiple recovery attempts');
                return;
              }
              recoveryAttemptsRef.current++;
              // Try to recover from media errors
              hls.recoverMediaError();
              break;
            default:
              message = tRef.current('HLSPlayer.errors.streamError', { details: data.details || 'unknown' });
              hls.destroy();
              hlsRef.current = null;
              break;
          }
          setError(message);
          setLoading(false);
          onErrorRef.current?.(message);
        }
      });

      hlsRef.current = hls;
    } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
      // Native HLS support (Safari)
      video.src = src;
      if (autoPlay) {
        video.play().catch(() => {
          // Autoplay blocked by browser policy
        });
      }

      const handleNativeError = () => {
        const message = tRef.current('HLSPlayer.errors.playbackError');
        setError(message);
        setLoading(false);
        onErrorRef.current?.(message);
      };

      video.addEventListener('error', handleNativeError);

      return () => {
        video.pause();
        video.removeAttribute('src');
        video.load(); // Release the media resource
        video.removeEventListener('playing', handlePlaying);
        video.removeEventListener('waiting', handleWaiting);
        video.removeEventListener('timeupdate', handleTimeUpdate);
        video.removeEventListener('error', handleNativeError);
      };
    } else {
      const message = tRef.current('HLSPlayer.errors.notSupported');
      setError(message);
      setLoading(false);
      onErrorRef.current?.(message);
    }

    return () => {
      video.pause();
      video.removeEventListener('playing', handlePlaying);
      video.removeEventListener('waiting', handleWaiting);
      video.removeEventListener('timeupdate', handleTimeUpdate);
      if (hlsRef.current) {
        hlsRef.current.destroy();
        hlsRef.current = null;
      }
    };
  }, [src, autoPlay, live]);

  // Honour an external pause/resume without re-initialising the player: a paused
  // parent (e.g. the multi-playback scrubber) must actually freeze the <video>,
  // otherwise it keeps advancing while the timestamp overlay is frozen (desync).
  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;
    if (paused) {
      video.pause();
    } else if (video.paused) {
      video.play().catch(() => {/* autoplay policy, muted should allow it */});
    }
  }, [paused, src]);

  return (
    <div className={`relative bg-black ${className ?? ''}`}>
      <video
        ref={videoRef}
        muted={muted}
        playsInline
        className="h-full w-full"
      />

      {loading && !error && (
        <div className="absolute inset-0 flex items-center justify-center bg-black/50">
          <svg
            className="h-8 w-8 animate-spin text-white"
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
            />
          </svg>
        </div>
      )}

      {error && (
        <div className="absolute inset-0 flex items-center justify-center bg-black/70">
          <div className="px-4 text-center">
            <p className="text-sm text-red-400">{error}</p>
          </div>
        </div>
      )}
    </div>
  );
}
