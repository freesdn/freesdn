// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The camera detail Access tab grants and revokes per-camera permissions,
 * which the API allows only with `cameras.access` (site admins and above).
 * Operators no longer hold it, so the tab is not offered to them, and a link
 * straight to it opens the overview instead of a panel that can only fail.
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
const requested: string[] = [];

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
  model: 'DS-2CD',
  ip_address: '198.51.100.20',
  has_ptz: false,
  has_audio: false,
  has_two_way_audio: false,
  is_recording: false,
};

beforeEach(() => {
  requested.length = 0;
  api.defaults.adapter = async (config) => {
    requested.push(config.url ?? '');
    let data: unknown = {};
    if (config.url === `/cameras/${CAMERA_ID}`) data = camera;
    if (config.url === '/cameras/access/grants') data = { items: [], total: 0 };
    return { config, data, status: 200, statusText: '200', headers: {} } as AxiosResponse;
  };
});

afterEach(() => {
  cleanup();
  api.defaults.adapter = oldAdapter;
});

function renderAccessTab() {
  return renderWithProviders(<CameraDetailPage />, {
    initialPath: `/cameras/${CAMERA_ID}/access`,
    routePath: '/cameras/:id/:tab',
  });
}

describe('Camera detail Access tab', () => {
  it('is not offered to an operator, and a direct link opens the overview', async () => {
    useAuthStore.setState({
      user: user('operator', ['cameras.view', 'cameras.playback', 'cameras.ptz']),
      isAuthenticated: true,
    });
    renderAccessTab();
    expect(await screen.findByRole('tab', { name: /Overview/ })).toHaveAttribute('aria-selected', 'true');
    expect(screen.queryByRole('tab', { name: /^Access$/ })).toBeNull();
    expect(requested).not.toContain('/cameras/access/grants');
  });

  it('is offered to a site admin', async () => {
    useAuthStore.setState({ user: user('site_admin', ['cameras.*']), isAuthenticated: true });
    renderAccessTab();
    expect(await screen.findByRole('tab', { name: /^Access$/ })).toHaveAttribute('aria-selected', 'true');
  });
});
