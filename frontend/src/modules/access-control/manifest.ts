// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Access Control Module - Frontend Manifest
 */
import { lazy } from 'react';
import { DoorClosed } from 'lucide-react';
import type { FrontendModuleManifest } from '../types';

export const accessControlModule: FrontendModuleManifest = {
  id: 'access_control',
  name: 'Access Control',
  description: 'Doors, cardholders, credentials, schedules, and access events',
  icon: DoorClosed,
  color: '#f59e0b',
  routes: [
    {
      path: '/access',
      component: lazy(() => import('@/pages/access/AccessControlPage')),
      title: 'Access Control',
    },
  ],
  navItems: [
    { name: 'Access Control', path: '/access', icon: DoorClosed, section: 'network', order: 13 },
  ],
};
