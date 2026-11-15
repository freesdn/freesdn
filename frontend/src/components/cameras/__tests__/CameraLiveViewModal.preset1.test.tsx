// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The live view's centre PTZ button says what it does. It was labelled
 * "Return to home position" with a house icon but sent "go to preset 1",
 * which on most cameras is whatever view someone saved first. The backend
 * has no home-position command (the PTZ route accepts directions, zoom, stop
 * and preset), so the button is "Go to preset 1", names that preset when the
 * camera has it, is disabled with the reason when the camera's presets do not
 * include 1, and a refused move is shown instead of only logged.
 */
import type { ReactNode } from 'react';
import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { AxiosError } from 'axios';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { api } from '@/lib/api/client';
import { useAuthStore, type User } from '@/stores/authStore';
import { CameraLiveViewModal } from '../CameraLiveViewModal';

const CAMERA_ID = '0f6c1a52-6d1e-4a4b-9b55-1d2f3c4b5a69';
const camera = { id: CAMERA_ID, name: 'Dock', status: 'online' as const, vendor: 'hikvision', has_ptz: true, has_audio: false };
type Handler = (config: InternalAxiosRequestConfig) => [number, unknown];
let routes: Record<string, Handler> = {};
const posts: string[] = [];
const oldAdapter = api.defaults.adapter;

function renderWithClient(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

beforeEach(() => {
  posts.length = 0;
  routes = {};
  useAuthStore.setState({
    user: { id: 'u', username: 'u', organization_id: 'o', role: 'operator', is_active: true, permissions: ['cameras.view', 'cameras.ptz'], roles: ['operator'] } as unknown as User,
    isAuthenticated: true,
  });
  api.defaults.adapter = async (config) => {
    const key = `${config.method?.toUpperCase()} ${config.url}`;
    if (config.method === 'post') posts.push(`${key}?${new URLSearchParams(config.params as Record<string, string>).toString()}`);
    const handler = routes[key];
    const [status, data] = handler ? handler(config) : [200, {}];
    const response = { config, data, status, statusText: String(status), headers: {} } as AxiosResponse;
    if (status >= 400) throw new AxiosError(`Request failed with status code ${status}`, 'ERR_BAD_RESPONSE', config, null, response);
    return response;
  };
});

afterEach(() => {
  cleanup();
  api.defaults.adapter = oldAdapter;
});

describe('Live view centre PTZ button', () => {
  it('names preset 1 and goes to it', async () => {
    routes[`GET /cameras/${CAMERA_ID}/ptz/presets`] = () => [200, { items: [{ id: 1, name: 'Gate' }, { id: 2, name: 'Yard' }] }];
    renderWithClient(<CameraLiveViewModal camera={camera} open onOpenChange={() => {}} />);
    const button = await screen.findByRole('button', { name: 'Go to preset 1 (Gate)' });
    expect(screen.queryByRole('button', { name: /home position/i })).toBeNull();
    fireEvent.click(button);
    await waitFor(() => expect(posts).toContain(`POST /cameras/${CAMERA_ID}/ptz?action=preset&speed=50&preset=1`));
  });

  it('is disabled, with the reason, when the camera has presets but no preset 1', async () => {
    routes[`GET /cameras/${CAMERA_ID}/ptz/presets`] = () => [200, { items: [{ id: 3, name: 'Loading dock' }] }];
    renderWithClient(<CameraLiveViewModal camera={camera} open onOpenChange={() => {}} />);
    await screen.findByRole('button', { name: 'Loading dock' });
    const button = screen.getByRole('button', { name: /has no preset 1/ });
    expect(button).toBeDisabled();
    expect(button.parentElement).toHaveAttribute('tabindex', '0');
  });

  it('says so when the camera refuses to move', async () => {
    routes[`GET /cameras/${CAMERA_ID}/ptz/presets`] = () => [200, { items: [] }];
    routes[`POST /cameras/${CAMERA_ID}/ptz`] = () => [502, { error: { code: 502, message: 'The camera refused the PTZ command; it did not move.' } }];
    renderWithClient(<CameraLiveViewModal camera={camera} open onOpenChange={() => {}} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Go to preset 1' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('The camera did not move: The camera refused the PTZ command; it did not move.');
  });
});
