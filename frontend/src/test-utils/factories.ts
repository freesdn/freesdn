// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Test-data factories.
 *
 * Each factory returns a fully-populated object with sensible defaults
 * and a partial override hook so individual tests can vary one field
 * without restating the boilerplate. Mirrors the backend DTOs but
 * exists purely for tests · do NOT import from app code.
 */
import type { User } from '@/stores/authStore';

let _idCounter = 0;
function nextId(prefix: string): string {
  _idCounter += 1;
  return `${prefix}-${_idCounter}`;
}

/** Resets the auto-incrementing id counter. Useful for snapshot stability. */
export function resetFactoryIds(): void {
  _idCounter = 0;
}

export function makeUser(overrides: Partial<User> = {}): User {
  return {
    id: nextId('user'),
    email: 'test@example.com',
    first_name: 'Test',
    last_name: 'User',
    username: 'testuser',
    full_name: 'Test User',
    role: 'org_admin',
    organization_id: 'org-1',
    is_active: true,
    is_superuser: false,
    is_org_admin: true,
    mfa_enabled: false,
    permissions: ['*'],
    roles: ['org_admin'],
    ...overrides,
  };
}

export interface OrgFactory {
  id: string;
  name: string;
  slug: string;
  timezone: string;
  locale: string;
  is_active: boolean;
}

export function makeOrg(overrides: Partial<OrgFactory> = {}): OrgFactory {
  return {
    id: nextId('org'),
    name: 'Acme Corp',
    slug: 'acme-corp',
    timezone: 'UTC',
    locale: 'en-US',
    is_active: true,
    ...overrides,
  };
}

export interface SiteFactory {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  organization_id: string;
  timezone: string;
  time_format: string;
  date_format: string;
  is_active: boolean;
  controller_count: number;
  device_count: number;
  online_device_count: number;
  created_at: string;
  updated_at: string;
}

export function makeSite(overrides: Partial<SiteFactory> = {}): SiteFactory {
  const id = overrides.id ?? nextId('site');
  return {
    id,
    name: 'HQ',
    slug: 'hq',
    description: null,
    organization_id: 'org-1',
    timezone: 'UTC',
    time_format: '24h',
    date_format: 'YYYY-MM-DD',
    is_active: true,
    controller_count: 0,
    device_count: 0,
    online_device_count: 0,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

export interface DeviceFactory {
  id: string;
  name: string;
  hostname: string | null;
  device_type: string;
  vendor: string | null;
  model: string | null;
  serial_number: string | null;
  mac_address: string | null;
  ip_address: string | null;
  firmware_version: string | null;
  status: string;
  is_online: boolean;
  is_active: boolean;
  site_id: string | null;
  organization_id: string;
  controller_id: string | null;
  last_seen: string | null;
  created_at: string;
  updated_at: string;
}

export function makeDevice(overrides: Partial<DeviceFactory> = {}): DeviceFactory {
  return {
    id: nextId('device'),
    name: 'switch-01',
    hostname: 'switch-01.local',
    device_type: 'switch',
    vendor: 'unifi',
    model: 'USW-24',
    serial_number: 'SN12345',
    mac_address: 'aa:bb:cc:dd:ee:ff',
    ip_address: '10.0.0.10',
    firmware_version: '6.5.0',
    status: 'online',
    is_online: true,
    is_active: true,
    site_id: 'site-1',
    organization_id: 'org-1',
    controller_id: 'ctrl-1',
    last_seen: '2026-05-20T00:00:00Z',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-05-20T00:00:00Z',
    ...overrides,
  };
}
