// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Camera controls follow the permissions the backend enforces.
 *
 * moved saving, overwriting and deleting presets and tours,
 * auto-tracking and two-way audio to `cameras.manage_ptz`; moving, going to a
 * preset and running or stopping a tour stay on `cameras.ptz`. The UI still
 * offered every control to every role, so an operator's tour edit or delete
 * (and a viewer's move) ended in a 403. These tests render the controls for
 * each role over the real Axios client and check which are usable, that a
 * disabled one says why, and that the live view lists the camera's own presets
 * instead of four invented names.
 */
import type { ReactNode } from 'react';
import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { api } from '@/lib/api/client';
import { useAuthStore, type User } from '@/stores/authStore';
import PTZToursPanel from '../PTZToursPanel';
import { CameraLiveViewModal } from '../CameraLiveViewModal';

const CAMERA_ID = '0f6c1a52-6d1e-4a4b-9b55-1d2f3c4b5a69';

// The permission lists the backend's DEFAULT_ROLE_PERMISSIONS gives each role,
// reduced to the camera entries that matter here.
const ROLE_PERMISSIONS: Record<string, string[]> = {
  viewer: ['cameras.view', 'cameras.playback'],
  operator: ['cameras.view', 'cameras.playback', 'cameras.ptz', 'cameras.access'],
  site_admin: ['cameras.*'],
};

function user(role: string): User {
  return {
    id: '11111111-1111-4111-8111-111111111111',
    username: 'u',
    email: 'u@example.invalid',
    first_name: 'U',
    last_name: 'U',
    full_name: 'U U',
    organization_id: '22222222-2222-4222-8222-222222222222',
    role,
    is_active: true,
    is_superuser: false,
    is_org_admin: false,
    mfa_enabled: false,
    permissions: ROLE_PERMISSIONS[role],
    roles: [role],
  } as User;
}

type Handler = (config: InternalAxiosRequestConfig) => [number, unknown];
let routes: Record<string, Handler> = {};
const requests: string[] = [];
const oldAdapter = api.defaults.adapter;

const tour = {
  id: 1,
  name: 'Perimeter',
  enabled: true,
  actions: [{ id: 1, preset_id: 2, dwell: 10, speed: 50 }],
};

function renderWithClient(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

beforeEach(() => {
  requests.length = 0;
  routes = {
    [`GET /cameras/${CAMERA_ID}/ptz/tours`]: () => [200, [tour]],
    [`DELETE /cameras/${CAMERA_ID}/ptz/tours/1`]: () => [200, { status: 'ok', deleted: 1 }],
    [`GET /cameras/${CAMERA_ID}/ptz/presets`]: () => [200, { items: [{ id: 3, name: 'Loading dock' }] }],
  };
  document.cookie = 'freesdn_csrf=synthetic-csrf; path=/';
  api.defaults.adapter = async (config) => {
    const key = `${config.method?.toUpperCase()} ${config.url}`;
    requests.push(key);
    const handler = routes[key];
    const [status, data] = handler ? handler(config) : [200, {}];
    const response = { config, data, status, statusText: String(status), headers: {} } as AxiosResponse;
    if (status >= 400) {
      throw Object.assign(new Error('Request failed'), { isAxiosError: true, response, config });
    }
    return response;
  };
});

afterEach(() => {
  cleanup();
  api.defaults.adapter = oldAdapter;
});

async function tourCard() {
  await screen.findByText('Perimeter');
  return {
    start: screen.getByRole('button', { name: /Start/ }),
    stop: screen.getByRole('button', { name: /Stop/ }),
    edit: screen.getByRole('button', { name: 'Edit tour' }),
    remove: screen.getByRole('button', { name: 'Delete tour' }),
  };
}

describe('PTZ tours panel', () => {
  it('lets an operator run a tour but not edit or delete it, and says why', async () => {
    useAuthStore.setState({ user: user('operator'), isAuthenticated: true });
    renderWithClient(<PTZToursPanel cameraId={CAMERA_ID} isOnline />);
    const { start, stop, edit, remove } = await tourCard();
    expect(start).toBeEnabled();
    expect(stop).toBeEnabled();
    expect(edit).toBeDisabled();
    expect(remove).toBeDisabled();

    // The disabled button sits in a focusable wrapper that carries the reason.
    await act(async () => {
      fireEvent.focus(edit.parentElement as HTMLElement);
    });
    expect(
      (await screen.findAllByText(/needs the cameras\.manage_ptz permission, which site admins and above have/))
        .length,
    ).toBeGreaterThan(0);
  });

  it('gives a viewer neither, with the cameras.ptz reason on run and stop', async () => {
    useAuthStore.setState({ user: user('viewer'), isAuthenticated: true });
    renderWithClient(<PTZToursPanel cameraId={CAMERA_ID} isOnline />);
    const { start, stop, edit, remove } = await tourCard();
    expect(start).toBeDisabled();
    expect(stop).toBeDisabled();
    expect(edit).toBeDisabled();
    expect(remove).toBeDisabled();
    await act(async () => {
      fireEvent.focus(start.parentElement as HTMLElement);
    });
    expect((await screen.findAllByText(/Running and stopping patrol tours needs the cameras\.ptz/)).length).toBeGreaterThan(0);
  });

  it('lets a site admin delete a tour after an in-app confirmation', async () => {
    useAuthStore.setState({ user: user('site_admin'), isAuthenticated: true });
    renderWithClient(<PTZToursPanel cameraId={CAMERA_ID} isOnline />);
    const { edit, remove } = await tourCard();
    expect(edit).toBeEnabled();
    expect(remove).toBeEnabled();

    fireEvent.click(remove);
    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText(/"Perimeter" is removed from the camera/)).toBeTruthy();
    expect(requests).not.toContain(`DELETE /cameras/${CAMERA_ID}/ptz/tours/1`);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete tour' }));
    await waitFor(() => expect(requests).toContain(`DELETE /cameras/${CAMERA_ID}/ptz/tours/1`));
  });
});

describe('Live view PTZ side panel', () => {
  const camera = {
    id: CAMERA_ID,
    name: 'Dock',
    status: 'online' as const,
    vendor: 'hikvision',
    has_ptz: true,
    has_audio: false,
  };

  it("lists the camera's own presets for an operator", async () => {
    useAuthStore.setState({ user: user('operator'), isAuthenticated: true });
    renderWithClient(<CameraLiveViewModal camera={camera} open onOpenChange={() => {}} />);
    expect(await screen.findByRole('button', { name: 'Loading dock' })).toBeEnabled();
    expect(screen.queryByText('Entrance')).toBeNull();
    expect(screen.queryByText('Parking')).toBeNull();
    expect(screen.getByRole('button', { name: 'Pan up' })).toBeEnabled();
  });

  it('disables movement for a viewer, says why, and does not ask for presets', async () => {
    useAuthStore.setState({ user: user('viewer'), isAuthenticated: true });
    renderWithClient(<CameraLiveViewModal camera={camera} open onOpenChange={() => {}} />);
    expect(await screen.findByText(/need the cameras\.ptz permission, which operators and above have/)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Pan up' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Zoom in' })).toBeDisabled();
    expect(requests).not.toContain(`GET /cameras/${CAMERA_ID}/ptz/presets`);
  });
});
