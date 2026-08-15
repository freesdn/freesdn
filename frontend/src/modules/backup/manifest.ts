// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Backup Module - Frontend Manifest
 */
import { lazy } from 'react';
import { Archive } from 'lucide-react';
import type { FrontendModuleManifest } from '../types';

export const backupModule: FrontendModuleManifest = {
  id: 'backup',
  name: 'Backup',
  description: 'Scheduled device backups, restore, and storage location management',
  icon: Archive,
  color: '#06b6d4',
  routes: [
    {
      path: '/backups',
      component: lazy(() => import('@/pages/backups/BackupsPage')),
      title: 'Backups',
    },
    {
      path: '/backups/storage-locations',
      component: lazy(() => import('@/pages/storage-locations/StorageLocationsPage')),
      title: 'Storage Locations',
    },
    {
      path: '/backups/:tab',
      component: lazy(() => import('@/pages/backups/BackupsPage')),
      title: 'Backups',
    },
  ],
  navItems: [
    { name: 'Backups', path: '/backups', icon: Archive, section: 'configuration', order: 0 },
  ],
};
