// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
// Small synchronous identity used before the full demo dataset is requested.
export const demoIds = {
  org: '11111111-1111-4111-8111-111111111111',
  hq: '22222222-2222-4222-8222-222222222222',
  branch: '33333333-3333-4333-8333-333333333333',
  dc: '44444444-4444-4444-8444-444444444444',
  omada: '55555555-5555-4555-8555-555555555555',
  opnsense: '66666666-6666-4666-8666-666666666666',
  proxmox: '77777777-7777-4777-8777-777777777777',
  hikvision: '88888888-8888-4888-8888-888888888888',
  freepbx: '99999999-9999-4999-8999-999999999999',
  truenas: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  unifi: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
};

export const demoUser = {
  id: '10000000-0000-4000-8000-000000000001',
  email: 'demo@freesdn.local',
  username: 'demo-admin',
  first_name: 'Demo',
  last_name: 'Admin',
  full_name: 'Demo Admin',
  role: 'super_admin',
  organization_id: demoIds.org,
  is_active: true,
  is_superuser: true,
  is_org_admin: true,
  mfa_enabled: false,
  permissions: ['*'],
  roles: ['super_admin'],
};

