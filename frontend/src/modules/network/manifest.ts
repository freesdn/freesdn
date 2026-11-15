// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Network Module - Frontend Manifest
 */
import { lazy } from 'react';
import { Network, Layers, Wifi, Plug, Globe, Server, Radio } from 'lucide-react';
import type { FrontendModuleManifest } from '../types';

// One lazy component per page, shared by every route that renders it. A
// separate `lazy()` per route gave sibling routes (/switches/:id and
// /switches/:id/:tab) different component types, so React remounted the whole
// page, and showed the full-page "Loading module" fallback, on every tab click.
const VlansPage = lazy(() => import('@/pages/network/VlansPage'));
const WifiNetworksPage = lazy(() => import('@/pages/network/WifiNetworksPage'));
const SwitchesPage = lazy(() => import('@/pages/switches/SwitchesPage'));
const AccessPointsPage = lazy(() => import('@/pages/access-points/AccessPointsPage'));
const PoEPage = lazy(() => import('@/pages/poe/PoEPage'));
const VPNPage = lazy(() => import('@/pages/vpn/VPNPage'));

export const networkModule: FrontendModuleManifest = {
  id: 'network',
  name: 'Network',
  description: 'VLANs, WiFi, switches, PoE, topology, and VPN management',
  icon: Network,
  color: '#3b82f6',
  routes: [
    {
      path: '/network',
      component: lazy(() => import('@/pages/network/NetworkDashboardPage')),
      title: 'Network Dashboard',
    },
    {
      path: '/vlans',
      component: VlansPage,
      title: 'VLANs',
    },
    {
      path: '/vlans/:tab',
      component: VlansPage,
      title: 'VLANs',
    },
    {
      path: '/network/vlans',
      component: VlansPage,
      title: 'VLANs',
    },
    {
      path: '/network/vlans/:tab',
      component: VlansPage,
      title: 'VLANs',
    },
    {
      path: '/wifi',
      component: WifiNetworksPage,
      title: 'WiFi Networks',
    },
    {
      path: '/network/wifi',
      component: WifiNetworksPage,
      title: 'WiFi Networks',
    },
    {
      path: '/network/clients',
      component: lazy(() => import('@/pages/network/NetworkClientsPage')),
      title: 'Network Clients',
    },
    {
      path: '/topology',
      component: lazy(() => import('@/pages/enterprise/topology/TopologyPage')),
      title: 'Topology',
    },
    {
      path: '/switches',
      component: SwitchesPage,
      title: 'Switches',
    },
    {
      path: '/switches/:deviceId',
      component: SwitchesPage,
      title: 'Switches',
    },
    {
      path: '/switches/:deviceId/:tab',
      component: SwitchesPage,
      title: 'Switches',
    },
    {
      path: '/access-points',
      component: AccessPointsPage,
      title: 'Access Points',
    },
    {
      path: '/access-points/:deviceId',
      component: AccessPointsPage,
      title: 'Access Points',
    },
    {
      path: '/access-points/:deviceId/:tab',
      component: AccessPointsPage,
      title: 'Access Points',
    },
    {
      path: '/poe',
      component: PoEPage,
      title: 'PoE',
    },
    {
      path: '/poe/:tab',
      component: PoEPage,
      title: 'PoE',
    },
    {
      path: '/vpn',
      component: VPNPage,
      title: 'VPN',
    },
    {
      path: '/vpn/:tab',
      component: VPNPage,
      title: 'VPN',
    },
  ],
  navItems: [
    { name: 'Network', path: '/network', icon: Network, section: 'network', order: 0 },
    { name: 'Topology', path: '/topology', icon: Network, section: 'network', order: 1 },
    { name: 'Switches', path: '/switches', icon: Server, section: 'network', order: 2 },
    { name: 'Access Points', path: '/access-points', icon: Radio, section: 'network', order: 3 },
    { name: 'VLANs', path: '/vlans', icon: Layers, section: 'network', order: 4 },
    { name: 'WiFi Networks', path: '/wifi', icon: Wifi, section: 'network', order: 5 },
    { name: 'PoE', path: '/poe', icon: Plug, section: 'network', order: 6 },
    { name: 'VPN', path: '/vpn', icon: Globe, section: 'network', order: 7 },
  ],
};
