// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
// DEPRECATED: Gateway navigation is handled by the firewall module. This manifest is not registered.

/**
 * Gateway Orchestration Module · Frontend Manifest
 *
 * Brain/Limb VLAN distribution, drift detection, import wizard,
 * canonical resource management, and diagnostics.
 */
import { lazy } from 'react';
import { Router } from 'lucide-react';
import type { FrontendModuleManifest } from '../types';

export const gatewayModule: FrontendModuleManifest = {
  id: 'gateway',
  name: 'Gateway',
  description: 'VLAN orchestration, distribution engine, drift detection, and gateway diagnostics',
  icon: Router,
  color: '#8b5cf6',
  routes: [
    {
      path: '/gateway/import/:sessionId?',
      component: lazy(() => import('@/pages/gateway/ImportWizardPage')),
      title: 'Import Wizard',
    },
    {
      path: '/gateway/:tab?',
      component: lazy(() => import('@/pages/gateway/GatewayPage')),
      title: 'Gateway Orchestration',
    },
  ],
  navItems: [
    {
      name: 'Gateway',
      path: '/gateway',
      icon: Router,
      section: 'network',
      order: 12,
    },
  ],
};
