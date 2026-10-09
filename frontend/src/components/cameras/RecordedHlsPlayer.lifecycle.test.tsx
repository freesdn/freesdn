// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Actual component effects and timers with explicit API/media transport doubles. */
import { act, cleanup, render } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const fixture = vi.hoisted(() => ({
  startPlayback: vi.fn(), stop: vi.fn(), heartbeat: vi.fn(),
  player: null as null | { src: string; onError: (reason: string) => void },
}));
vi.mock('@/demo/mode', () => ({ isDemoMode: false }));
vi.mock('@/lib/api/cameras', () => ({ hlsStreamApi: fixture }));
vi.mock('@/lib/api/client', () => ({ API_URL: '' }));
vi.mock('./HLSPlayer', () => ({
  HLSPlayer: (props: { src: string; onError: (reason: string) => void }) => {
    fixture.player = props;
    return null;
  },
}));
import { RecordedHlsPlayer } from './RecordedHlsPlayer';

const props = { cameraId: 'owned-camera', startTime: '2026-09-24T10:00:00Z' };
const response = (id = 'owned-session') => ({
  data: { session_id: id, playlist_url: `/api/v1/cameras/streams/hls/${id}/stream.m3u8` },
});
const fetchMock = vi.fn();
const settle = () => act(async () => { await Promise.resolve(); await Promise.resolve(); });
const advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });

beforeEach(() => {
  vi.useFakeTimers();
  fixture.startPlayback.mockReset().mockResolvedValue(response());
  fixture.stop.mockReset().mockResolvedValue({});
  fixture.heartbeat.mockReset().mockResolvedValue({});
  fixture.player = null;
  fetchMock.mockReset().mockResolvedValue({ ok: true, text: async () => '#EXTM3U\n00000.ts\n' });
  vi.stubGlobal('fetch', fetchMock);
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.unstubAllGlobals(); });

describe('recorded HLS ownership and terminal failure', () => {
  it('stops and stops heartbeating after a manifest deadline while still mounted', async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 404 });
    const unavailable = vi.fn();
    const view = render(<RecordedHlsPlayer {...props} onUnavailable={unavailable} />);
    await settle(); await advance(32_000);
    expect(unavailable).toHaveBeenCalledTimes(1);
    expect(fixture.stop).toHaveBeenCalledExactlyOnceWith('owned-session');
    const beats = fixture.heartbeat.mock.calls.length;
    await advance(45_000);
    expect(fixture.heartbeat).toHaveBeenCalledTimes(beats);
    view.unmount();
    expect(fixture.stop).toHaveBeenCalledTimes(1);
  });

  it('bounds a hanging manifest request and aborts its fetch', async () => {
    fetchMock.mockImplementation((_url: string, options?: RequestInit) => new Promise((_resolve, reject) => {
      options?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
    }));
    const unavailable = vi.fn();
    render(<RecordedHlsPlayer {...props} onUnavailable={unavailable} />);
    await settle(); await advance(31_000);
    expect(unavailable).toHaveBeenCalledTimes(1);
    expect(fixture.stop).toHaveBeenCalledExactlyOnceWith('owned-session');
    expect(fetchMock.mock.calls[0][1]?.signal?.aborted).toBe(true);
  });

  it('aborts an in-flight manifest on unmount', async () => {
    fetchMock.mockImplementation((_url: string, options?: RequestInit) => new Promise((_resolve, reject) => {
      options?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
    }));
    const view = render(<RecordedHlsPlayer {...props} />);
    await settle(); view.unmount(); await settle();
    expect(fetchMock.mock.calls[0][1]?.signal?.aborted).toBe(true);
    expect(fixture.stop).toHaveBeenCalledExactlyOnceWith('owned-session');
  });

  it('releases once on fatal decode error without relying on parent unmount', async () => {
    const unavailable = vi.fn();
    const view = render(<RecordedHlsPlayer {...props} onUnavailable={unavailable} />);
    await settle();
    const error = fixture.player!.onError;
    await act(async () => { error('Owned synthetic decode failure'); error('Owned synthetic decode failure'); });
    expect(fixture.stop).toHaveBeenCalledExactlyOnceWith('owned-session');
    expect(unavailable).toHaveBeenCalledTimes(1);
    const beats = fixture.heartbeat.mock.calls.length;
    await advance(45_000);
    expect(fixture.heartbeat).toHaveBeenCalledTimes(beats);
    view.unmount(); expect(fixture.stop).toHaveBeenCalledTimes(1);
  });

  it.each([401, 403, 404])('releases after a definitive heartbeat refusal %i', async (status) => {
    fixture.heartbeat.mockRejectedValue({ response: { status } });
    const unavailable = vi.fn();
    render(<RecordedHlsPlayer {...props} onUnavailable={unavailable} />);
    await settle(); await advance(16_000);
    expect(fixture.stop).toHaveBeenCalledExactlyOnceWith('owned-session');
    const beats = fixture.heartbeat.mock.calls.length;
    await advance(45_000);
    expect(fixture.heartbeat).toHaveBeenCalledTimes(beats);
    expect(unavailable).toHaveBeenCalledTimes(status === 404 ? 1 : 0);
  });

  it.each([401, 403])('does not keep polling or fall back after manifest authority refusal %i', async (status) => {
    fetchMock.mockResolvedValue({ ok: false, status });
    const unavailable = vi.fn();
    render(<RecordedHlsPlayer {...props} onUnavailable={unavailable} />);
    await settle();
    expect(fixture.stop).toHaveBeenCalledExactlyOnceWith('owned-session');
    await advance(45_000);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fixture.heartbeat).not.toHaveBeenCalled();
    expect(unavailable).not.toHaveBeenCalled();
  });

  it('keeps successful paused playback alive until its owner unmounts', async () => {
    const view = render(<RecordedHlsPlayer {...props} paused />);
    await settle(); await advance(31_000);
    expect(fixture.player?.src).toContain('owned-session');
    expect(fixture.heartbeat).toHaveBeenCalledTimes(2);
    expect(fixture.stop).not.toHaveBeenCalled();
    view.unmount(); expect(fixture.stop).toHaveBeenCalledExactlyOnceWith('owned-session');
  });

  it('does not terminate healthy media on a transient heartbeat 503', async () => {
    fixture.heartbeat.mockRejectedValue({ response: { status: 503 } });
    const unavailable = vi.fn();
    render(<RecordedHlsPlayer {...props} onUnavailable={unavailable} />);
    await settle(); await advance(31_000);
    expect(fixture.stop).not.toHaveBeenCalled();
    expect(unavailable).not.toHaveBeenCalled();
    expect(fixture.player?.src).toContain('owned-session');
  });

  it('releases a start that resolves after unmount without beginning polling', async () => {
    let resolve!: (value: ReturnType<typeof response>) => void;
    fixture.startPlayback.mockReturnValue(new Promise((done) => { resolve = done; }));
    const view = render(<RecordedHlsPlayer {...props} />);
    view.unmount();
    await act(async () => { resolve(response('late-session')); });
    expect(fixture.stop).toHaveBeenCalledExactlyOnceWith('late-session');
    expect(fetchMock).not.toHaveBeenCalled();
    expect(fixture.heartbeat).not.toHaveBeenCalled();
  });

  it('does not let an old start or error release a replacement session', async () => {
    const unavailable = vi.fn();
    const view = render(<RecordedHlsPlayer {...props} onUnavailable={unavailable} />);
    await settle(); const oldError = fixture.player!.onError;
    fixture.startPlayback.mockResolvedValue(response('replacement'));
    view.rerender(<RecordedHlsPlayer {...props} startTime="2026-09-24T11:00:00Z" onUnavailable={unavailable} />);
    await settle();
    await act(async () => { oldError('Stale error'); });
    expect(unavailable).not.toHaveBeenCalled();
    expect(fixture.stop).toHaveBeenCalledExactlyOnceWith('owned-session');
    await advance(16_000);
    expect(fixture.heartbeat).toHaveBeenLastCalledWith('replacement');
    view.unmount();
    expect(fixture.stop.mock.calls.map(([sid]) => sid)).toEqual(['owned-session', 'replacement']);
  });

  it('bounds a stalled response body as well as initial fetch', async () => {
    fetchMock.mockResolvedValue({ ok: true, text: () => new Promise(() => {}) });
    const unavailable = vi.fn();
    render(<RecordedHlsPlayer {...props} onUnavailable={unavailable} />);
    await settle(); await advance(31_000);
    expect(fixture.stop).toHaveBeenCalledExactlyOnceWith('owned-session');
    expect(unavailable).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][1]?.signal?.aborted).toBe(true);
  });

  it('does not adopt a manifest that resolves after its deadline', async () => {
    let resolve!: (value: { ok: boolean; text: () => Promise<string> }) => void;
    fetchMock.mockReturnValue(new Promise((done) => { resolve = done; }));
    const unavailable = vi.fn();
    render(<RecordedHlsPlayer {...props} onUnavailable={unavailable} />);
    await settle(); await advance(31_000);
    await act(async () => { resolve({ ok: true, text: async () => '#EXTM3U\n00000.ts' }); });
    expect(fixture.player).toBeNull();
    expect(fixture.stop).toHaveBeenCalledExactlyOnceWith('owned-session');
    expect(unavailable).toHaveBeenCalledTimes(1);
  });

  it.each([401, 403])('does not fall back after start authority refusal %i', async (status) => {
    fixture.startPlayback.mockRejectedValue({ response: { status } });
    const unavailable = vi.fn();
    render(<RecordedHlsPlayer {...props} onUnavailable={unavailable} />);
    await settle();
    expect(unavailable).not.toHaveBeenCalled();
    expect(fixture.stop).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([422, 501])('preserves recorded-source refusal semantics %i', async (status) => {
    fixture.startPlayback.mockRejectedValue({ response: { status } });
    const unavailable = vi.fn();
    render(<RecordedHlsPlayer {...props} onUnavailable={unavailable} />);
    await settle();
    expect(unavailable).toHaveBeenCalledTimes(status === 501 ? 1 : 0);
    expect(fixture.stop).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(fixture.heartbeat).not.toHaveBeenCalled();
  });
});
