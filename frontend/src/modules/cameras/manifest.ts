// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Cameras Module - Frontend Manifest
 */
import { lazy } from 'react';
import { Camera, Server, Layers, LayoutGrid, Monitor, BellRing, FileBarChart } from 'lucide-react';
import type { FrontendModuleManifest } from '../types';

export const camerasModule: FrontendModuleManifest = {
  id: 'cameras',
  name: 'Cameras',
  description: 'IP camera management, live view, recording, NVR, and AI events',
  icon: Camera,
  color: '#8b5cf6',
  routes: [
    {
      path: '/cameras',
      component: lazy(() => import('@/pages/cameras/CamerasPage')),
      title: 'Cameras',
    },
    {
      path: '/cameras/list',
      component: lazy(() => import('@/pages/cameras/CamerasPage')),
      title: 'Cameras · List',
    },
    {
      path: '/cameras/wall',
      component: lazy(() => import('@/pages/cameras/CameraWallPage')),
      title: 'Camera Wall',
    },
    {
      path: '/cameras/playback',
      component: lazy(() => import('@/pages/cameras/MultiPlaybackPage')),
      title: 'Multi-Camera Playback',
    },
    {
      path: '/cameras/events',
      component: lazy(() => import('@/pages/cameras/CameraEventsPage')),
      title: 'Camera Events',
    },
    {
      // MUST be registered before the '/cameras/:id' catch-all below so the
      // literal 'reports' segment isn't matched as a camera id.
      path: '/cameras/reports',
      component: lazy(() => import('@/pages/cameras/CameraReportsPage')),
      title: 'Camera Reports',
    },
    {
      path: '/cameras/nvrs',
      component: lazy(() => import('@/pages/cameras/NVRListPage')),
      title: 'NVRs',
    },
    {
      path: '/cameras/nvrs/:id',
      component: lazy(() => import('@/pages/cameras/NVRDetailPage')),
      title: 'NVR Detail',
    },
    {
      path: '/cameras/nvrs/:id/:tab',
      component: lazy(() => import('@/pages/cameras/NVRDetailPage')),
      title: 'NVR Detail',
    },
    {
      path: '/cameras/:id',
      component: lazy(() => import('@/pages/cameras/CameraDetailPage')),
      title: 'Camera Detail',
    },
    {
      path: '/cameras/:id/:tab',
      component: lazy(() => import('@/pages/cameras/CameraDetailPage')),
      title: 'Camera Detail',
    },
  ],
  navItems: [
    { name: 'Cameras', path: '/cameras', icon: Camera, section: 'network', order: 10 },
    { name: 'Camera Wall', path: '/cameras/wall', icon: LayoutGrid, section: 'network', order: 11 },
    { name: 'Display Wall', path: '/cameras/display', icon: Monitor, section: 'network', order: 12 },
    { name: 'Multi-Playback', path: '/cameras/playback', icon: Layers, section: 'network', order: 13 },
    { name: 'Review', path: '/cameras/events', icon: BellRing, section: 'network', order: 14 },
    { name: 'Reports', path: '/cameras/reports', icon: FileBarChart, section: 'network', order: 15 },
    { name: 'NVRs', path: '/cameras/nvrs', icon: Server, section: 'network', order: 16 },
  ],
};
