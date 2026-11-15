// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The camera detail PTZ tab offers movement only to users who may move the
 * camera (`cameras.ptz`), and lays its direction pad out as a 3 x 3 compass at
 * every width. The pad used `grid-cols-1 sm:grid-cols-2 md:grid-cols-3`, so
 * on a phone the nine cells stacked into one column and between 640 and
 * 768 px they formed two scrambled columns.
 */
import type { AxiosResponse } from 'axios';
import { cleanup, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { api } from '@/lib/api/client';
import { useAuthStore, type User } from '@/stores/authStore';
import { renderWithProviders } from '@/test-utils';
import CameraDetailPage from '../CameraDetailPage';

const CAMERA_ID = '0f6c1a52-6d1e-4a4b-9b55-1d2f3c4b5a69';
const oldAdapter = api.defaults.adapter;

function user(role: string, permissions: string[]): User {
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
    permissions,
    roles: [role],
  } as User;
}

const camera = {
  id: CAMERA_ID,
  name: 'Dock',
  status: 'online',
  vendor: 'hikvision',
  model: 'DS-2DE',
  ip_address: '198.51.100.20',
  has_ptz: true,
  has_audio: false,
  has_two_way_audio: false,
  is_recording: false,
};

beforeEach(() => {
  api.defaults.adapter = async (config) => {
    let data: unknown = {};
    if (config.url === `/cameras/${CAMERA_ID}`) data = camera;
    if (config.url === `/cameras/${CAMERA_ID}/ptz/presets`) data = { items: [{ id: 2, name: 'Gate' }] };
    if (config.url === `/cameras/${CAMERA_ID}/ptz/tours`) data = [];
    return { config, data, status: 200, statusText: '200', headers: {} } as AxiosResponse;
  };
});

afterEach(() => {
  cleanup();
  api.defaults.adapter = oldAdapter;
});

function renderPtzTab() {
  return renderWithProviders(<CameraDetailPage />, {
    initialPath: `/cameras/${CAMERA_ID}/ptz`,
    routePath: '/cameras/:id/:tab',
  });
}

describe('Camera detail PTZ tab', () => {
  it('gives an operator a working 3 x 3 direction pad and preset buttons', async () => {
    useAuthStore.setState({
      user: user('operator', ['cameras.view', 'cameras.ptz']),
      isAuthenticated: true,
    });
    renderPtzTab();
    const pad = await screen.findByRole('group', { name: 'PTZ Control' });
    expect(pad.className).toMatch(/(^|\s)grid-cols-3(\s|$)/);
    expect(pad.className).not.toMatch(/grid-cols-1|grid-cols-2/);
    expect(screen.getByRole('button', { name: 'Pan up' })).toBeEnabled();
    expect(await screen.findByRole('button', { name: /Gate/ })).toBeEnabled();
    expect(screen.queryByText(/need the cameras\.ptz permission/)).toBeNull();
  });

  it('shows a viewer the pad disabled with the reason', async () => {
    useAuthStore.setState({ user: user('viewer', ['cameras.view']), isAuthenticated: true });
    renderPtzTab();
    expect(await screen.findByText(/need the cameras\.ptz permission, which operators and above have/)).toBeTruthy();
    for (const name of ['Pan up', 'Pan left', 'Pan right', 'Pan down', 'Zoom in', 'Zoom out', 'Stop']) {
      expect(screen.getByRole('button', { name })).toBeDisabled();
    }
  });
});
