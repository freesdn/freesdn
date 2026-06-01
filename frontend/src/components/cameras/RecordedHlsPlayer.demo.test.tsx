// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Regression test: demo-mode network isolation for recorded HLS playback.
 *
 * The demo build serves a STATIC, network-isolated bundle: every backend call
 * must go through the demo axios adapter (installed in lib/api/client.ts when
 * `isDemoMode`). The recorded-playback UI used to bypass that adapter, it
 * started an HLS session and then polled the playlist via a direct `fetch()`
 * and fed `${API_URL}${playlist_url}` straight to hls.js, both of which emit
 * real same-origin /api requests from the static demo bundle.
 *
 * These tests pin the behavioral contract that closes that bypass:
 *   - DEMO build:  RecordedHlsPlayer never starts a real session and fires
 *                  onUnavailable so the parent degrades to the demo-mocked
 *                  per-frame snapshot path. No direct /api request escapes.
 *   - NON-demo:    the guard is a no-op, the real start-session path runs
 *                  exactly as before (the pattern-completion / no-op case).
 */
import { render, waitFor, cleanup } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// --- controllable demo flag ------------------------------------------------
// isDemoMode is a module-level const derived from import.meta.env at import
// time; mock the module so each test can flip the flag. The state object is
// created via vi.hoisted so it exists before the (hoisted) vi.mock factory
// runs at module load.
const demoState = vi.hoisted(() => ({ isDemoMode: false }));
vi.mock('@/demo/mode', () => ({
  get isDemoMode() {
    return demoState.isDemoMode;
  },
  demoWriteMessage: 'Demo mode: changes are disabled',
}));

// Keep the unit pure: stub the heavy hls.js player and the API surface.
vi.mock('./HLSPlayer', () => ({
  HLSPlayer: () => null,
}));

const hlsMocks = vi.hoisted(() => ({
  startPlayback: vi.fn(),
  stop: vi.fn(() => Promise.resolve()),
  heartbeat: vi.fn(() => Promise.resolve()),
}));
const { startPlayback, stop, heartbeat } = hlsMocks;
vi.mock('@/lib/api/cameras', () => ({
  hlsStreamApi: hlsMocks,
}));

// Import AFTER the mocks are registered.
import { RecordedHlsPlayer } from './RecordedHlsPlayer';

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('RecordedHlsPlayer, demo-mode network isolation', () => {
  beforeEach(() => {
    // A real start would resolve with a session_id + playlist_url; the demo
    // guard must short-circuit BEFORE we ever call this.
    startPlayback.mockResolvedValue({
      data: { session_id: 'sess-1', playlist_url: '/api/v1/cameras/cam-1/playback/hls/sess-1.m3u8' },
    });
  });

  it('demo build: never starts a real HLS session and reports unavailable', async () => {
    demoState.isDemoMode = true;
    const onUnavailable = vi.fn();

    render(
      <RecordedHlsPlayer
        cameraId="cam-1"
        startTime="2026-06-07T14:30:00Z"
        onUnavailable={onUnavailable}
      />,
    );

    await waitFor(() => expect(onUnavailable).toHaveBeenCalledTimes(1));
    // The bypass is closed: no session POST, so no direct fetch()/hls.js URL
    // build can follow, and no /api request escapes the static demo bundle.
    expect(startPlayback).not.toHaveBeenCalled();
    expect(stop).not.toHaveBeenCalled();
    expect(heartbeat).not.toHaveBeenCalled();
  });

  it('non-demo build: guard is a no-op, the real start-session path runs', async () => {
    demoState.isDemoMode = false;

    render(
      <RecordedHlsPlayer cameraId="cam-1" startTime="2026-06-07T14:30:00Z" />,
    );

    await waitFor(() => expect(startPlayback).toHaveBeenCalledTimes(1));
    expect(startPlayback).toHaveBeenCalledWith(
      'cam-1',
      expect.objectContaining({ start_time: '2026-06-07T14:30:00Z' }),
    );
  });
});
