// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Network Module - Frontend Manifest
 */
import { lazy } from 'react';
import { Network, Layers, Wifi, Plug, Globe, Server, Radio } from 'lucide-react';
import type { FrontendModuleManifest } from '../types';

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
      component: lazy(() => import('@/pages/network/VlansPage')),
      title: 'VLANs',
    },
    {
      path: '/vlans/:tab',
      component: lazy(() => import('@/pages/network/VlansPage')),
      title: 'VLANs',
    },
    {
      path: '/network/vlans',
      component: lazy(() => import('@/pages/network/VlansPage')),
      title: 'VLANs',
    },
    {
      path: '/network/vlans/:tab',
      component: lazy(() => import('@/pages/network/VlansPage')),
      title: 'VLANs',
    },
    {
      path: '/wifi',
      component: lazy(() => import('@/pages/network/WifiNetworksPage')),
      title: 'WiFi Networks',
    },
    {
      path: '/network/wifi',
      component: lazy(() => import('@/pages/network/WifiNetworksPage')),
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
      component: lazy(() => import('@/pages/switches/SwitchesPage')),
      title: 'Switches',
    },
    {
      path: '/switches/:deviceId',
      component: lazy(() => import('@/pages/switches/SwitchesPage')),
      title: 'Switches',
    },
    {
      path: '/switches/:deviceId/:tab',
      component: lazy(() => import('@/pages/switches/SwitchesPage')),
      title: 'Switches',
    },
    {
      path: '/access-points',
      component: lazy(() => import('@/pages/access-points/AccessPointsPage')),
      title: 'Access Points',
    },
    {
      path: '/access-points/:deviceId',
      component: lazy(() => import('@/pages/access-points/AccessPointsPage')),
      title: 'Access Points',
    },
    {
      path: '/access-points/:deviceId/:tab',
      component: lazy(() => import('@/pages/access-points/AccessPointsPage')),
      title: 'Access Points',
    },
    {
      path: '/poe',
      component: lazy(() => import('@/pages/poe/PoEPage')),
      title: 'PoE',
    },
    {
      path: '/poe/:tab',
      component: lazy(() => import('@/pages/poe/PoEPage')),
      title: 'PoE',
    },
    {
      path: '/vpn',
      component: lazy(() => import('@/pages/vpn/VPNPage')),
      title: 'VPN',
    },
    {
      path: '/vpn/:tab',
      component: lazy(() => import('@/pages/vpn/VPNPage')),
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
