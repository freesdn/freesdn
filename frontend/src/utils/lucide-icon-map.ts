// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, Lucide Icon Map
 *
 * Maps lowercase / kebab-case icon name strings (sent by the backend module
 * manifests) to actual Lucide React icon components.
 *
 * Usage:
 *   import { resolveIcon } from '@/utils/lucide-icon-map';
 *   const Icon = resolveIcon('archive');       // → Archive
 *   const Icon = resolveIcon('phone-call');    // → PhoneCall
 *   const Icon = resolveIcon(undefined);       // → Puzzle (fallback)
 */

import type { LucideIcon } from 'lucide-react';
import {
  Archive,
  AlertTriangle,
  ArrowRightLeft,
  Bell,
  Box,
  Boxes,
  Calendar,
  Camera,
  Clock,
  Cloud,
  CloudCog,
  Cpu,
  CreditCard,
  DoorClosed,
  DoorOpen,
  ExternalLink,
  Eye,
  Film,
  FileText,
  FolderSync,
  GitBranch,
  Globe,
  HardDrive,
  Hash,
  History,
  Key,
  Layers,
  LayoutDashboard,
  List,
  Lock,
  Mail,
  Monitor,
  Network,
  Package,
  Phone,
  PhoneCall,
  Play,
  Plug,
  Puzzle,
  Radio,
  RefreshCw,
  Server,
  Settings,
  Shield,
  Smartphone,
  Users,
  Video,
  Wifi,
  Zap,
} from 'lucide-react';

/**
 * Comprehensive mapping of icon name strings to Lucide icon components.
 * Keys are normalised to lowercase (kebab-case variants are also handled).
 */
const ICON_MAP: Record<string, LucideIcon> = {
  // ── Module-level icons ──────────────────────────────────
  archive: Archive,
  phone: Phone,
  network: Network,
  shield: Shield,
  video: Video,
  'door-open': DoorOpen,
  package: Package,

  // ── Navigation / sub-page icons ─────────────────────────
  history: History,
  calendar: Calendar,
  settings: Settings,
  smartphone: Smartphone,
  hash: Hash,
  users: Users,
  'phone-call': PhoneCall,
  server: Server,
  layers: Layers,
  wifi: Wifi,
  plug: Plug,
  'git-branch': GitBranch,
  list: List,
  'arrow-right-left': ArrowRightLeft,
  lock: Lock,
  'alert-triangle': AlertTriangle,
  'file-text': FileText,
  play: Play,
  film: Film,
  bell: Bell,
  'hard-drive': HardDrive,
  'door-closed': DoorClosed,
  'credit-card': CreditCard,
  clock: Clock,
  cpu: Cpu,

  // ── Storage / infrastructure icons ──────────────────────
  harddrive: HardDrive,
  cloud: Cloud,
  cloudcog: CloudCog,
  foldersync: FolderSync,
  box: Box,
  globe: Globe,

  // ── Extra common icons ──────────────────────────────────
  boxes: Boxes,
  camera: Camera,
  dashboard: LayoutDashboard,
  'external-link': ExternalLink,
  eye: Eye,
  key: Key,
  mail: Mail,
  monitor: Monitor,
  puzzle: Puzzle,
  radio: Radio,
  refresh: RefreshCw,
  zap: Zap,
};

/**
 * Resolve an icon name string to its Lucide component.
 *
 * @param name  Icon name (case-insensitive, supports kebab-case)
 * @param fallback  Fallback icon if name is not found (defaults to Puzzle)
 * @returns The Lucide icon component
 */
export function resolveIcon(name?: string | null, fallback: LucideIcon = Puzzle): LucideIcon {
  if (!name) return fallback;
  return ICON_MAP[name.toLowerCase()] ?? fallback;
}

export { ICON_MAP };
