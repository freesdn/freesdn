// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Design System - Type Badge
 *
 * Centralized vendor / device-type / protocol indicator.
 * Replaces page-local TypeBadge implementations that hardcoded vendor colors.
 *
 * Vendor brand colors are an intentional exception to the strict color-token
 * rule (decorative tints). They live in ONE map here so the UI is consistent
 * and rebrandable.
 *
 * Usage:
 *   <TypeBadge type="omada" />
 *   <TypeBadge type="opnsense">OPNsense</TypeBadge>
 *   <TypeBadge type="custom" label="ACME" icon={Server} />
 */

import { Server, type LucideIcon } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { cn } from '../../lib/utils';

type TypeKey =
  // SDN controllers
  | 'omada'
  | 'unifi'
  | 'meraki'
  | 'aruba'
  | 'mist'
  // Firewalls / gateways
  | 'opnsense'
  | 'pfsense'
  | 'mikrotik'
  | 'fortinet'
  | 'sophos'
  // Cameras / NVR
  | 'hikvision'
  | 'axis'
  | 'dahua'
  | 'generic_onvif'
  // Hypervisors
  | 'proxmox'
  | 'vmware'
  | 'xcpng'
  // Storage
  | 'truenas'
  | 'synology'
  | 'qnap'
  // PBX / VoIP
  | 'freepbx'
  | 'grandstream'
  | 'asterisk'
  // Generic
  | 'openwrt'
  | 'generic_snmp'
  | 'generic_ssh'
  | 'unknown';

interface TypeMeta {
  label: string;
  /** tone class · using `bg-{color}/10 text-{color}` pattern */
  tone: string;
}

const TYPE_REGISTRY: Record<TypeKey, TypeMeta> = {
  // SDN controllers
  omada:         { label: 'TP-Link Omada', tone: 'bg-blue-500/10 text-blue-600 dark:text-blue-400' },
  unifi:         { label: 'Ubiquiti UniFi', tone: 'bg-sky-500/10 text-sky-600 dark:text-sky-400' },
  meraki:        { label: 'Cisco Meraki', tone: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' },
  aruba:         { label: 'Aruba', tone: 'bg-orange-500/10 text-orange-600 dark:text-orange-400' },
  mist:          { label: 'Juniper Mist', tone: 'bg-teal-500/10 text-teal-600 dark:text-teal-400' },

  // Firewalls
  opnsense:      { label: 'OPNsense', tone: 'bg-orange-500/10 text-orange-600 dark:text-orange-400' },
  pfsense:       { label: 'pfSense', tone: 'bg-red-500/10 text-red-600 dark:text-red-400' },
  mikrotik:      { label: 'MikroTik', tone: 'bg-blue-500/10 text-blue-600 dark:text-blue-400' },
  fortinet:      { label: 'Fortinet', tone: 'bg-red-500/10 text-red-600 dark:text-red-400' },
  sophos:        { label: 'Sophos', tone: 'bg-indigo-500/10 text-indigo-600 dark:text-indigo-400' },

  // Cameras
  hikvision:     { label: 'Hikvision', tone: 'bg-red-500/10 text-red-600 dark:text-red-400' },
  axis:          { label: 'Axis', tone: 'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400' },
  dahua:         { label: 'Dahua', tone: 'bg-amber-500/10 text-amber-600 dark:text-amber-400' },
  generic_onvif: { label: 'ONVIF', tone: 'bg-purple-500/10 text-purple-600 dark:text-purple-400' },

  // Hypervisors
  proxmox:       { label: 'Proxmox', tone: 'bg-orange-500/10 text-orange-600 dark:text-orange-400' },
  vmware:        { label: 'VMware', tone: 'bg-blue-500/10 text-blue-600 dark:text-blue-400' },
  xcpng:         { label: 'XCP-ng', tone: 'bg-purple-500/10 text-purple-600 dark:text-purple-400' },

  // Storage
  truenas:       { label: 'TrueNAS', tone: 'bg-red-500/10 text-red-600 dark:text-red-400' },
  synology:      { label: 'Synology', tone: 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400' },
  qnap:          { label: 'QNAP', tone: 'bg-violet-500/10 text-violet-600 dark:text-violet-400' },

  // PBX
  freepbx:       { label: 'FreePBX', tone: 'bg-green-500/10 text-green-600 dark:text-green-400' },
  grandstream:   { label: 'Grandstream', tone: 'bg-blue-500/10 text-blue-600 dark:text-blue-400' },
  asterisk:      { label: 'Asterisk', tone: 'bg-red-500/10 text-red-600 dark:text-red-400' },

  // Generic
  openwrt:       { label: 'OpenWrt', tone: 'bg-blue-500/10 text-blue-600 dark:text-blue-400' },
  generic_snmp:  { label: 'SNMP', tone: 'bg-slate-500/10 text-slate-600 dark:text-slate-400' },
  generic_ssh:   { label: 'SSH', tone: 'bg-slate-500/10 text-slate-600 dark:text-slate-400' },
  unknown:       { label: 'Unknown', tone: 'bg-muted text-muted-foreground' },
};

interface TypeBadgeProps {
  /** Type key · looks up label + tone from the registry */
  type: string;
  /** Override the label (default: from registry, falls back to titlecased type) */
  label?: string;
  /** Override children (default: label) */
  children?: React.ReactNode;
  /** Override the icon (default: Server) */
  icon?: LucideIcon;
  /** Hide the icon */
  hideIcon?: boolean;
  /** Compact size variant */
  size?: 'sm' | 'md';
  className?: string;
}

function titlecase(s: string): string {
  return s
    .replace(/[_-]/g, ' ')
    .replace(/\b\w/g, (m) => m.toUpperCase());
}

export function TypeBadge({
  type,
  label,
  children,
  icon: Icon = Server,
  hideIcon = false,
  size = 'md',
  className,
}: TypeBadgeProps) {
  const { t } = useTranslation('common');
  const meta = TYPE_REGISTRY[type as TypeKey] ?? {
    label: titlecase(type),
    tone: 'bg-muted text-muted-foreground',
  };
  const registryLabel =
    type === 'unknown' ? t('TypeBadge.unknown') : meta.label;
  const labelText = children ?? label ?? registryLabel;

  const sizeClasses =
    size === 'sm'
      ? 'px-1.5 py-0.5 text-[10px] gap-1'
      : 'px-2 py-0.5 text-xs gap-1.5';

  const iconSize = size === 'sm' ? 'h-3 w-3' : 'h-3 w-3';

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md font-medium whitespace-nowrap',
        meta.tone,
        sizeClasses,
        className,
      )}
    >
      {!hideIcon && <Icon className={cn(iconSize, 'flex-shrink-0')} />}
      {labelText && <span>{labelText}</span>}
    </span>
  );
}

export type { TypeKey };
