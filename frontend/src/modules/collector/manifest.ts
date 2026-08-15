// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Observability Module Frontend Manifest
 *
 * SNMP trap, Syslog, and NetFlow collection with log aggregation
 * and traffic analytics.
 */

import { lazy } from 'react';
import { Radio, ScrollText } from 'lucide-react';
import type { FrontendModuleManifest } from '../types';

export const collectorModule: FrontendModuleManifest = {
  id: 'collector',
  name: 'Observability',
  description: 'SNMP traps, Syslog, and NetFlow collection with log aggregation and traffic analytics',
  icon: Radio,
  color: '#F59E0B',
  routes: [
    {
      path: '/collector',
      component: lazy(() => import('@/pages/collector/CollectorPage')),
      title: 'Observability',
    },
    {
      path: '/collector/logs',
      component: lazy(() => import('@/pages/collector/LogExplorerPage')),
      title: 'Log Explorer',
    },
  ],
  navItems: [
    {
      name: 'Observability',
      path: '/collector',
      icon: Radio,
      section: 'monitoring',
      order: 85,
    },
    {
      name: 'Log Explorer',
      path: '/collector/logs',
      icon: ScrollText,
      section: 'monitoring',
      order: 86,
    },
  ],
};
