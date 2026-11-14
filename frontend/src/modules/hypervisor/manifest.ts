// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Hypervisor Module - Frontend Manifest
 *
 * Proxmox VE hypervisor management · cluster, nodes, VMs, containers, storage.
 */
import { lazy } from 'react';
import { Server } from 'lucide-react';
import type { FrontendModuleManifest } from '../types';

// One lazy component shared by /hypervisor and /hypervisor/:tab. Two separate
// `lazy()` wrappers are two component types, so moving between the first tab
// and any other remounted the whole page.
const HypervisorPage = lazy(() => import('@/pages/hypervisor/HypervisorPage'));

export const hypervisorModule: FrontendModuleManifest = {
  id: 'hypervisor',
  name: 'Hypervisor',
  description: 'Proxmox VE cluster, node, VM, and container management',
  icon: Server,
  color: '#7c3aed',
  routes: [
    {
      path: '/hypervisor',
      component: HypervisorPage,
      title: 'Hypervisor',
    },
    {
      path: '/hypervisor/:tab',
      component: HypervisorPage,
      title: 'Hypervisor',
    },
  ],
  navItems: [
    { name: 'Hypervisor', path: '/hypervisor', icon: Server, section: 'network', order: 12 },
  ],
};
