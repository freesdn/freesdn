// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * VoIP Module - Frontend Manifest
 *
 * Multi-page architecture:
 *  - Fleet Dashboard (overview)
 *  - Phones (list + detail)
 *  - Discovery (network scanning)
 *  - Config Templates
 *  - Firmware Management
 *  - PBX Systems
 *  - Extensions & Ring Groups
 *  - Call History / CDR
 *  - Voicemail Inbox
 */
import { lazy } from 'react';
import {
  Phone, LayoutDashboard, Radar,
  Server, Hash, PhoneCall, Voicemail,
} from 'lucide-react';
import type { FrontendModuleManifest } from '../types';

export const voipModule: FrontendModuleManifest = {
  id: 'voip',
  name: 'VoIP',
  description: 'GDMS-style phone fleet management, PBX, extensions, call history, voicemail',
  icon: Phone,
  color: '#10b981',
  routes: [
    // Fleet dashboard (default landing page)
    {
      path: '/voip',
      component: lazy(() => import('@/pages/voip/FleetDashboardPage')),
      title: 'VoIP · Fleet Dashboard',
    },
    // Phone fleet management
    {
      path: '/voip/phones',
      component: lazy(() => import('@/pages/voip/PhonesListPage')),
      title: 'VoIP · Phones',
    },
    {
      path: '/voip/phones/:id',
      component: lazy(() => import('@/pages/voip/PhoneDetailPage')),
      title: 'VoIP · Phone Detail',
    },
    {
      path: '/voip/phones/:id/:tab',
      component: lazy(() => import('@/pages/voip/PhoneDetailPage')),
      title: 'VoIP · Phone Detail',
    },
    // Network discovery
    {
      path: '/voip/discovery',
      component: lazy(() => import('@/pages/voip/DiscoveryPage')),
      title: 'VoIP · Discovery',
    },
    // Config templates
    {
      path: '/voip/templates',
      component: lazy(() => import('@/pages/voip/TemplatesPage')),
      title: 'VoIP · Config Templates',
    },
    // Firmware management
    {
      path: '/voip/firmware',
      component: lazy(() => import('@/pages/voip/FirmwarePage')),
      title: 'VoIP · Firmware',
    },
    // PBX systems
    {
      path: '/voip/pbx/:id/:tab',
      component: lazy(() => import('@/pages/voip/PBXDetailPage')),
      title: 'VoIP · PBX Detail',
    },
    {
      path: '/voip/pbx/:id',
      component: lazy(() => import('@/pages/voip/PBXDetailPage')),
      title: 'VoIP · PBX Detail',
    },
    {
      path: '/voip/pbx',
      component: lazy(() => import('@/pages/voip/PBXPage')),
      title: 'VoIP · PBX Systems',
    },
    // Extensions & Ring Groups
    {
      path: '/voip/extensions',
      component: lazy(() => import('@/pages/voip/ExtensionsPage')),
      title: 'VoIP · Extensions',
    },
    {
      path: '/voip/extensions/:tab',
      component: lazy(() => import('@/pages/voip/ExtensionsPage')),
      title: 'VoIP · Extensions',
    },
    // Call Logs / CDR
    {
      path: '/voip/calls',
      component: lazy(() => import('@/pages/voip/CallLogsPage')),
      title: 'VoIP · Call History',
    },
    // Voicemail
    {
      path: '/voip/voicemail',
      component: lazy(() => import('@/pages/voip/VoicemailPage')),
      title: 'VoIP · Voicemail',
    },
    // Legacy monolith fallback (catches /voip/*)
    {
      path: '/voip/*',
      component: lazy(() => import('@/pages/voip/VoIPPage')),
      title: 'VoIP',
    },
  ],
  navItems: [
    { name: 'VoIP',        path: '/voip',            icon: LayoutDashboard, section: 'network', order: 12 },
    { name: 'Phones',      path: '/voip/phones',     icon: Phone,           section: 'network', order: 13 },
    { name: 'Discovery',   path: '/voip/discovery',  icon: Radar,           section: 'network', order: 14 },
    { name: 'PBX Systems', path: '/voip/pbx',        icon: Server,          section: 'network', order: 15 },
    { name: 'Extensions',  path: '/voip/extensions', icon: Hash,            section: 'network', order: 16 },
    { name: 'Call History', path: '/voip/calls',      icon: PhoneCall,       section: 'network', order: 17 },
    { name: 'Voicemail',   path: '/voip/voicemail',  icon: Voicemail,       section: 'network', order: 18 },
  ],
};
