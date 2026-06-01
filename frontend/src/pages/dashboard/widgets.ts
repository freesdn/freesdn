// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Dashboard widget registry
 * ============================
 *
 * Single source of truth for the customisable home-page widgets:
 *  - id           · stable key used by the layout store (NEVER rename · would orphan user state)
 *  - label        · shown in the "Add widget" picker AND as the card title
 *  - description  · short hint for the picker
 *  - icon         · lucide icon (matches the card header)
 *  - category     · groups widgets in the picker (Overview, Performance, Security, Network, System)
 *  - colSpan      · 1-3 columns on the lg+ grid; widgets reflow when added/removed
 *  - defaultEnabled · seed for first-time users (empty store)
 *
 * Renderers live inline in DashboardPage so each has access to its data hooks.
 */

import {
  Activity,
  AlertTriangle,
  BarChart3,
  Building2,
  Camera,
  Cpu,
  Cable,
  Eye,
  MemoryStick,
  Package,
  Server,
  Shield,
  Signal,
  Wifi,
  Zap,
  type LucideIcon,
} from 'lucide-react';

export type WidgetColSpan = 1 | 2 | 3;
export type WidgetCategory = 'Overview' | 'Performance' | 'Security' | 'Network' | 'System';

export interface DashboardWidgetMeta {
  id: string;
  label: string;
  description: string;
  icon: LucideIcon;
  category: WidgetCategory;
  colSpan: WidgetColSpan;
  defaultEnabled: boolean;
}

export const DASHBOARD_WIDGETS: DashboardWidgetMeta[] = [
  // ── Overview ──────────────────────────────────────────────────────
  {
    id: 'traffic',
    label: 'Network Traffic',
    description: 'Aggregate upload / download over the last 24h',
    icon: BarChart3,
    category: 'Overview',
    colSpan: 2,
    defaultEnabled: true,
  },
  {
    id: 'alerts',
    label: 'Active Alerts',
    description: 'Open alerts across all configured rules',
    icon: Shield,
    category: 'Overview',
    colSpan: 1,
    defaultEnabled: true,
  },
  {
    id: 'device-status',
    label: 'Device Status',
    description: 'Online / offline / warning device counts',
    icon: Wifi,
    category: 'Overview',
    colSpan: 1,
    defaultEnabled: true,
  },
  {
    id: 'site-health',
    label: 'Site Health Map',
    description: 'Per-site device counts and reachability',
    icon: Building2,
    category: 'Overview',
    colSpan: 2,
    defaultEnabled: false,
  },
  {
    id: 'incidents',
    label: 'Incident Overview',
    description: 'Open / investigating / resolved breakdown',
    icon: AlertTriangle,
    category: 'Overview',
    colSpan: 1,
    defaultEnabled: false,
  },

  // ── Performance ────────────────────────────────────────────────────
  {
    id: 'network-health',
    label: 'Network Health',
    description: 'Latency, throughput, packet loss and uptime',
    icon: Activity,
    category: 'Performance',
    colSpan: 1,
    defaultEnabled: true,
  },
  {
    id: 'top-cpu',
    label: 'Top CPU Consumers',
    description: 'Devices burning the most CPU right now',
    icon: Cpu,
    category: 'Performance',
    colSpan: 1,
    defaultEnabled: false,
  },
  {
    id: 'top-memory',
    label: 'Top Memory Consumers',
    description: 'Devices with highest memory pressure',
    icon: MemoryStick,
    category: 'Performance',
    colSpan: 1,
    defaultEnabled: false,
  },
  {
    id: 'port-status',
    label: 'Port Status',
    description: 'Total ports up / down / errors across the fleet',
    icon: Cable,
    category: 'Performance',
    colSpan: 1,
    defaultEnabled: false,
  },

  // ── Security ───────────────────────────────────────────────────────
  {
    id: 'security-posture',
    label: 'Security Posture',
    description: 'Failed logins, IP blocks, anomalies, security events',
    icon: Shield,
    category: 'Security',
    colSpan: 2,
    defaultEnabled: false,
  },
  {
    id: 'audit-activity',
    label: 'Audit Activity',
    description: 'Recent audit events grouped by severity level',
    icon: Eye,
    category: 'Security',
    colSpan: 1,
    defaultEnabled: false,
  },

  // ── Network ────────────────────────────────────────────────────────
  {
    id: 'wifi-bands',
    label: 'Wi-Fi Band Mix',
    description: '2.4 / 5 / 6 GHz client distribution',
    icon: Signal,
    category: 'Network',
    colSpan: 1,
    defaultEnabled: false,
  },
  {
    id: 'top-ssids',
    label: 'Top SSIDs',
    description: 'Most populated wireless networks',
    icon: Wifi,
    category: 'Network',
    colSpan: 1,
    defaultEnabled: false,
  },
  {
    id: 'manufacturer-mix',
    label: 'Manufacturer Mix',
    description: 'Fleet vendor breakdown',
    icon: Package,
    category: 'Network',
    colSpan: 1,
    defaultEnabled: false,
  },
  {
    id: 'poe-budget',
    label: 'PoE Power Budget',
    description: 'Total PoE wattage delivered across switches',
    icon: Zap,
    category: 'Network',
    colSpan: 1,
    defaultEnabled: false,
  },

  // ── System ─────────────────────────────────────────────────────────
  {
    id: 'quick-actions',
    label: 'Quick Actions',
    description: 'Shortcuts for discovery, backups, and provisioning',
    icon: Zap,
    category: 'System',
    colSpan: 1,
    defaultEnabled: true,
  },
  {
    id: 'camera-preview',
    label: 'Camera Overview',
    description: 'Live thumbnails of your most recent cameras',
    icon: Camera,
    category: 'System',
    colSpan: 2,
    defaultEnabled: true,
  },
  {
    id: 'activity',
    label: 'Recent Activity',
    description: 'Stream of recent alerts and notable events',
    icon: Activity,
    category: 'System',
    colSpan: 1,
    defaultEnabled: true,
  },
  {
    id: 'system-status',
    label: 'System Status',
    description: 'Backend service health and resource usage',
    icon: Server,
    category: 'System',
    colSpan: 1,
    defaultEnabled: false,
  },
];

export const DASHBOARD_DEFAULT_ENABLED: string[] = DASHBOARD_WIDGETS.filter(
  (w) => w.defaultEnabled,
).map((w) => w.id);

/** Group hidden widgets by category for a tidier "Add widget" picker. */
export function groupWidgetsByCategory(widgets: DashboardWidgetMeta[]): Record<WidgetCategory, DashboardWidgetMeta[]> {
  const out: Record<WidgetCategory, DashboardWidgetMeta[]> = {
    Overview: [],
    Performance: [],
    Security: [],
    Network: [],
    System: [],
  };
  for (const w of widgets) out[w.category].push(w);
  return out;
}
