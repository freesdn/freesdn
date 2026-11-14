// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Backup Module - Frontend Manifest
 */
import { lazy } from 'react';
import { Archive } from 'lucide-react';
import type { FrontendModuleManifest } from '../types';

// One lazy component shared by /backups and /backups/:tab. Two separate
// `lazy()` wrappers are two component types, so moving between the first tab
// and any other remounted the whole page.
const BackupsPage = lazy(() => import('@/pages/backups/BackupsPage'));

export const backupModule: FrontendModuleManifest = {
  id: 'backup',
  name: 'Backup',
  description: 'Scheduled device backups, restore, and storage location management',
  icon: Archive,
  color: '#06b6d4',
  routes: [
    {
      path: '/backups',
      component: BackupsPage,
      title: 'Backups',
    },
    {
      path: '/backups/storage-locations',
      component: lazy(() => import('@/pages/storage-locations/StorageLocationsPage')),
      title: 'Storage Locations',
    },
    {
      path: '/backups/:tab',
      component: BackupsPage,
      title: 'Backups',
    },
  ],
  navItems: [
    { name: 'Backups', path: '/backups', icon: Archive, section: 'configuration', order: 0 },
  ],
};
