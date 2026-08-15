// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Shared Navigation Data
 *
 * Single source of truth for sidebar sections + command palette navigation.
 * Both Sidebar.tsx and CommandPalette.tsx import from here so the two stay
 * in sync · every page in the sidebar is searchable in the command palette.
 *
 * Adding a new page? Add it here ONCE.
 */

import type { LucideIcon } from 'lucide-react';
import {
  // Page-item icons
  LayoutDashboard,
  Building2,
  HeartPulse,
  Network,
  MonitorSmartphone,
  Server,
  Radio,
  Layers,
  Wifi,
  Users,
  Plug,
  Globe,
  Shield,
  Radar,
  Camera,
  Video,
  PlayCircle,
  Phone,
  PhoneCall,
  Voicemail,
  FileCode2,
  HardDrive,
  Cpu,
  Archive,
  DoorClosed,
  Bell,
  AlertTriangle,
  ScrollText,
  BarChart3,
  Gauge,
  Workflow,
  GitCompareArrows,
  Download,
  Zap,
  Webhook,
  FolderTree,
  Brain,
  Bot,
  Key,
  ShieldAlert,
  UserCog,
  Package,
  Store,
  Activity,
  TrendingUp,
  Route,
  Clock,
  // Section icons
  Home,
  Sparkles,
  Lock,
} from 'lucide-react';

import type { SectionId } from '@/stores/sidebarStore';

export interface NavItem {
  /** Display name */
  name: string;
  /** Route path */
  href: string;
  /** Lucide icon */
  icon: LucideIcon;
  /** Badge count (computed at runtime in Sidebar) */
  badge?: number;
  /** Show badge settings dropdown on right-click / long-press */
  badgeSettings?: boolean;
  /** Site-context visibility */
  siteVisibility?: 'global' | 'site';
  /** Module gate · item hidden if this module is disabled */
  moduleId?: string;
  /** Search keywords (synonyms, alternative names) for command palette fuzzy match */
  keywords?: string[];
  /** Section the item belongs to (set by buildSections, used by command palette grouping) */
  sectionId?: SectionId;
  /** Section title for command palette display */
  sectionTitle?: string;
}

export interface NavSection {
  id: SectionId;
  title: string;
  icon: LucideIcon;
  items: NavItem[];
}

// ────────────────────────────────────────────────────────────────
// Section definitions
// ────────────────────────────────────────────────────────────────

export function buildSections(
  alertCount = 0,
  t?: (k: string, o?: any) => string,
): NavSection[] {
  // Fallback strips the "items."/"sections." prefix so a missing t (or a
  // missing key) yields the clean English name (e.g. "Firewall"), never a
  // raw key like "items.Firewall", which would otherwise leak into the
  // sidebar Recent rail (recorded via trackVisit when buildSections runs
  // without t).
  const L = (s: string) => {
    const fallback = s.replace(/^(items|sections)\./, '');
    return t ? t(`nav.${s}`, { defaultValue: fallback }) : fallback;
  };
  return [
    // ── 1. OVERVIEW ──
    {
      id: 'overview',
      title: L('sections.Overview'),
      icon: Home,
      items: [
        { name: L('items.Dashboard'), href: '/', icon: LayoutDashboard, keywords: ['home', 'main'] },
        { name: L('items.Sites'), href: '/sites', icon: Building2, siteVisibility: 'global', keywords: ['locations', 'buildings'] },
        { name: L('items.Health'), href: '/health', icon: HeartPulse, keywords: ['status', 'fleet health'] },
        { name: L('items.Topology'), href: '/topology', icon: Network, siteVisibility: 'site', keywords: ['map', 'graph'] },
      ],
    },

    // ── 2. NETWORK ──
    {
      id: 'network',
      title: L('sections.Network'),
      icon: Network,
      items: [
        { name: L('items.Network Overview'), href: '/network', icon: Network, moduleId: 'network' },
        { name: L('items.Devices'), href: '/devices', icon: MonitorSmartphone, keywords: ['inventory', 'all devices'] },
        { name: L('items.Switches'), href: '/switches', icon: Server, moduleId: 'network', keywords: ['ports', 'lan'] },
        { name: L('items.Access Points'), href: '/access-points', icon: Radio, moduleId: 'network', keywords: ['ap', 'wireless'] },
        { name: L('items.VLANs'), href: '/vlans', icon: Layers, moduleId: 'network', keywords: ['segmentation'] },
        { name: L('items.WiFi Networks'), href: '/wifi', icon: Wifi, moduleId: 'network', keywords: ['ssid', 'wireless'] },
        { name: L('items.Clients'), href: '/network/clients', icon: Users, moduleId: 'network', keywords: ['connected'] },
        { name: L('items.PoE'), href: '/poe', icon: Plug, moduleId: 'network', keywords: ['power over ethernet'] },
        { name: L('items.VPN'), href: '/vpn', icon: Globe, moduleId: 'network', keywords: ['tailscale', 'wireguard'] },
        { name: L('items.Firewall'), href: '/firewall', icon: Shield, moduleId: 'firewall', keywords: ['rules', 'rules', 'opnsense', 'pfsense'] },
        { name: L('items.Discovery'), href: '/discovery', icon: Radar, siteVisibility: 'site', keywords: ['scan', 'find devices'] },
      ],
    },

    // ── 3. CAMERAS ──
    {
      id: 'cameras',
      title: L('sections.Cameras'),
      icon: Camera,
      items: [
        { name: L('items.Cameras'), href: '/cameras', icon: Camera, moduleId: 'cameras', keywords: ['cctv', 'surveillance', 'video'] },
        { name: L('items.Camera Wall'), href: '/cameras/wall', icon: Video, moduleId: 'cameras', keywords: ['live grid', 'multi'] },
        { name: L('items.NVRs'), href: '/cameras/nvrs', icon: Server, moduleId: 'cameras', keywords: ['recorder', 'hikvision'] },
        { name: L('items.Multi-Playback'), href: '/cameras/playback', icon: PlayCircle, moduleId: 'cameras', keywords: ['recording', 'history', 'investigate'] },
      ],
    },

    // ── 4. VOIP ──
    {
      id: 'voip',
      title: L('sections.VoIP'),
      icon: Phone,
      items: [
        { name: L('items.Fleet Overview'), href: '/voip', icon: Phone, moduleId: 'voip', keywords: ['phones'] },
        { name: L('items.PBX Systems'), href: '/voip/pbx', icon: Server, moduleId: 'voip', keywords: ['freepbx', 'asterisk'] },
        { name: L('items.Phones'), href: '/voip/phones', icon: Phone, moduleId: 'voip', keywords: ['handsets', 'sip'] },
        { name: L('items.Extensions'), href: '/voip/extensions', icon: Users, moduleId: 'voip', keywords: ['users', 'sip ext'] },
        { name: L('items.Call History'), href: '/voip/calls', icon: PhoneCall, moduleId: 'voip', keywords: ['cdr', 'log'] },
        { name: L('items.Voicemail'), href: '/voip/voicemail', icon: Voicemail, moduleId: 'voip', keywords: ['vm', 'inbox'] },
        { name: L('items.Phone Templates'), href: '/voip/templates', icon: FileCode2, moduleId: 'voip', keywords: ['provisioning'] },
        { name: L('items.Phone Discovery'), href: '/voip/discovery', icon: Radar, moduleId: 'voip', keywords: ['scan'] },
      ],
    },

    // ── 5. INFRASTRUCTURE ──
    {
      id: 'infrastructure',
      title: L('sections.Infrastructure'),
      icon: HardDrive,
      items: [
        { name: L('items.Hypervisor'), href: '/hypervisor', icon: Cpu, moduleId: 'hypervisor', keywords: ['proxmox', 'vm', 'compute'] },
        { name: L('items.Storage'), href: '/storage', icon: HardDrive, keywords: ['truenas', 'nas', 'zfs', 'pools', 'disks', 'storage', 'ixsystems'] },
        { name: L('items.Backups'), href: '/backups', icon: Archive, moduleId: 'backup', keywords: ['restore', 'snapshot'] },
        { name: L('items.Access Control'), href: '/access', icon: DoorClosed, moduleId: 'access_control', keywords: ['doors', 'badges', 'rfid'] },
      ],
    },

    // ── 6. OPERATIONS ──
    {
      id: 'operations',
      title: L('sections.Operations'),
      icon: Activity,
      items: [
        {
          name: L('items.Alerts'),
          href: '/alerts',
          icon: Bell,
          badge: alertCount > 0 ? alertCount : undefined,
          badgeSettings: true,
          keywords: ['notifications', 'warnings'],
        },
        { name: L('items.Incidents'), href: '/incidents', icon: AlertTriangle, keywords: ['outage', 'issue'] },
        { name: L('items.Observability'), href: '/collector', icon: Activity, keywords: ['snmp', 'syslog', 'netflow'] },
        { name: L('items.Log Explorer'), href: '/collector/logs', icon: ScrollText, keywords: ['search logs'] },
        { name: L('items.System Logs'), href: '/logs', icon: ScrollText, keywords: ['platform logs'] },
        { name: L('items.Analytics'), href: '/analytics', icon: BarChart3, keywords: ['metrics', 'charts', 'reports'] },
        { name: L('items.SLA'), href: '/sla', icon: Gauge, keywords: ['service level', 'uptime'] },
        { name: L('items.Bulk Operations'), href: '/bulk-operations', icon: PlayCircle, keywords: ['mass action', 'fleet'] },
        { name: L('items.Device Lifecycle'), href: '/lifecycle', icon: Workflow, keywords: ['adopting', 'provisioning'] },
        { name: L('items.Reconciliation'), href: '/reconciliation', icon: GitCompareArrows, keywords: ['drift', 'sync'] },
        { name: L('items.Firmware'), href: '/firmware', icon: Download, keywords: ['updates', 'upgrade'] },
        // ── Gateway / controller-side feature routes (staged writes) ──
        { name: L('items.Gateway VPN'), href: '/gateway/vpn', icon: Globe, moduleId: 'firewall', keywords: ['ipsec', 'openvpn', 'wireguard', 'controller vpn'] },
        { name: L('items.Gateway Firmware'), href: '/gateway/firmware', icon: HardDrive, moduleId: 'firewall', keywords: ['controller firmware', 'omada firmware'] },
        { name: L('items.Gateway Bulk Ops'), href: '/gateway/bulk', icon: Layers, moduleId: 'firewall', keywords: ['site clone', 'templates', 'bulk adopt', 'bulk reboot'] },
        { name: L('items.Gateway System'), href: '/gateway/system', icon: Server, moduleId: 'firewall', keywords: ['controller system', 'smtp', 'ssl', 'admins', 'backup'] },
        { name: L('items.Gateway Routing'), href: '/gateway/routing', icon: Route, moduleId: 'firewall', keywords: ['vrrp', 'bgp', 'ipv6', 'static routes'] },
        { name: L('items.Gateway Firewall'), href: '/gateway/firewall', icon: Shield, moduleId: 'firewall', keywords: ['dmz', 'upnp', 'attack defense', 'alg', 'ids ips'] },
        { name: L('items.Gateway Hotspot'), href: '/gateway/hotspot', icon: Wifi, moduleId: 'firewall', keywords: ['captive portal', 'operators', 'sms gateway', 'free auth'] },
        { name: L('items.Gateway Profiles'), href: '/gateway/profiles', icon: FileCode2, moduleId: 'firewall', keywords: ['mac groups', 'domain groups', 'time ranges', 'rate limit', 'radius', 'ldap', 'ppsk'] },
        { name: L('items.Gateway Switch Advanced'), href: '/gateway/switch-advanced', icon: Network, moduleId: 'firewall', keywords: ['sflow', 'mirror', 'mstp', 'lldp med', 'qinq'] },
        { name: L('items.Gateway Diagnostics'), href: '/gateway/diagnostics', icon: Gauge, moduleId: 'firewall', keywords: ['speed test', 'session stats', 'active sessions', 'wan'] },
        { name: L('items.Gateway Insights'), href: '/gateway/insights', icon: TrendingUp, moduleId: 'firewall', keywords: ['top talkers', 'anomalies', 'ai suggestions', 'mesh topology'] },
        { name: L('items.Pending Changes'), href: '/gateway/pending', icon: Clock, moduleId: 'firewall', keywords: ['staged', 'apply', 'discard', 'omada changes'] },
      ],
    },

    // ── 7. AUTOMATION ──
    {
      id: 'automation',
      title: L('sections.Automation'),
      icon: Sparkles,
      items: [
        { name: L('items.Fabric'), href: '/fabric', icon: Workflow, keywords: ['interconnect', 'connections', 'wire apps', 'integration', 'bridge'] },
        { name: L('items.Automation Rules'), href: '/automation', icon: Zap, keywords: ['workflows', 'triggers'] },
        { name: L('items.Alert Rules'), href: '/alert-rules', icon: ShieldAlert, keywords: ['conditions'] },
        { name: L('items.Notification Providers'), href: '/notification-providers', icon: Bell, siteVisibility: 'global', keywords: ['email', 'slack', 'sms', 'webhook channels'] },
        { name: L('items.Webhooks'), href: '/webhooks', icon: Webhook, keywords: ['callbacks', 'http'] },
        { name: L('items.Integrations'), href: '/integrations', icon: Plug, keywords: ['third-party', 'api'] },
        { name: L('items.Config Templates'), href: '/templates', icon: FileCode2, keywords: ['provisioning'] },
        { name: L('items.Site Groups'), href: '/groups', icon: FolderTree, keywords: ['hierarchy', 'organization'] },
        { name: L('items.AI Assistant'), href: '/ai', icon: Brain, moduleId: 'ai', keywords: ['chat', 'llm', 'gpt'] },
      ],
    },

    // ── 8. ADMINISTRATION ──
    {
      id: 'administration',
      title: L('sections.Administration'),
      icon: Lock,
      items: [
        { name: L('items.Controllers'), href: '/controllers', icon: Server, keywords: ['omada', 'unifi', 'sdn', 'meraki'] },
        { name: L('items.Credentials'), href: '/credentials', icon: Key, keywords: ['secrets', 'vault', 'passwords'] },
        { name: L('items.Agents'), href: '/agents', icon: Bot, keywords: ['remote agent', 'site agent'] },
        { name: L('items.Agent Downloads'), href: '/agents/downloads', icon: Download, keywords: ['installer', 'binary'] },
        { name: L('items.Agent Releases'), href: '/agents/releases', icon: Package, keywords: ['release', 'binary', 'upload', 'version'] },
        { name: L('items.Users'), href: '/users', icon: Users, siteVisibility: 'global', keywords: ['accounts'] },
        { name: L('items.Roles'), href: '/roles', icon: UserCog, siteVisibility: 'global', keywords: ['permissions', 'rbac'] },
        { name: L('items.Organizations'), href: '/organizations', icon: Building2, siteVisibility: 'global', keywords: ['tenants', 'orgs'] },
        { name: L('items.Security Audit'), href: '/security', icon: Shield, keywords: ['audit log', 'events', 'logins'] },
        { name: L('items.Plugins'), href: '/plugins', icon: Package, keywords: ['extensions', 'addons'] },
        { name: L('items.Marketplace'), href: '/marketplace', icon: Store, keywords: ['plugin store', 'extensions'] },
        { name: L('items.Drivers'), href: '/drivers', icon: HardDrive, siteVisibility: 'global', keywords: ['adapters', 'vendor'] },
      ],
    },
  ];
}

/** Flatten all sections to a single array of items, with sectionId/sectionTitle attached. */
export function flattenItems(sections: NavSection[]): NavItem[] {
  return sections.flatMap((section) =>
    section.items.map((item) => ({
      ...item,
      sectionId: section.id,
      sectionTitle: section.title,
    })),
  );
}
