// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Firewall Module - Frontend Manifest
 *
 * Unified firewall + gateway orchestration module.
 * Includes: rules, NAT, VPN, IDS/IPS, gateway integrations,
 * VLAN orchestration, drift detection, and brownfield import.
 */
import { lazy } from 'react';
import { Shield } from 'lucide-react';
import type { FrontendModuleManifest } from '../types';

export const firewallModule: FrontendModuleManifest = {
  id: 'firewall',
  name: 'Firewall',
  description:
    'Firewall rules, NAT, VPN, IDS/IPS, gateway integrations, and cross-gateway orchestration',
  icon: Shield,
  color: '#ef4444',
  routes: [
    // Firewall core routes
    {
      path: '/firewall/gateways/add',
      component: lazy(() => import('@/pages/firewall/AddGatewayPage')),
      title: 'Add Gateway',
    },
    {
      path: '/firewall/gateways/:id/:tab?',
      component: lazy(() => import('@/pages/firewall/GatewayDetailPage')),
      title: 'Gateway Details',
    },
    // UniFi controllers don't live in firewall.gateway_connections,
    // they're Controllers in core.controllers. Route them through a
    // dedicated page that mounts the Pending Changes badge + drawer
    // and the per-domain UniFi tabs.
    {
      path: '/firewall/unifi/:id',
      component: lazy(() => import('@/pages/firewall/UniFiControllerPage')),
      title: 'UniFi Controller',
    },
    // Gateway orchestration routes (merged from gateway module)
    {
      path: '/firewall/orchestration/import/:sessionId?',
      component: lazy(() => import('@/pages/gateway/ImportWizardPage')),
      title: 'Import Wizard',
    },
    {
      path: '/firewall/orchestration/:tab?',
      component: lazy(() => import('@/pages/gateway/GatewayPage')),
      title: 'Orchestration',
    },
    // Catch-all for firewall tabs
    {
      path: '/firewall/*',
      component: lazy(() => import('@/pages/firewall/FirewallPage')),
      title: 'Firewall',
    },
  ],
  navItems: [
    { name: 'Firewall', path: '/firewall', icon: Shield, section: 'network', order: 11 },
  ],
};
