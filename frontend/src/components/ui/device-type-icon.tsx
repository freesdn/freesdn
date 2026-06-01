// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Design System · DeviceTypeIcon
 *
 * Single source of truth for device-type icons + their tinted containers.
 * Replaces every page-local DEVICE_TYPE_META map and inline icon container
 * (e.g., `<div className="bg-emerald-500/10"><HardDrive className="text-blue-500"/></div>`).
 *
 * Status-aware tinting:
 *   - online    → success token tint
 *   - offline   → destructive token tint
 *   - degraded  → warning token tint
 *   - default   → neutral muted tint
 *
 * Usage:
 *   <DeviceTypeIcon type="switch" />                    // default neutral
 *   <DeviceTypeIcon type="camera" status="online" />    // success-tinted container
 *   <DeviceTypeIcon type="firewall" status="offline" size="lg" />
 *   <DeviceTypeIcon type="custom" icon={Cog} label="Custom" />
 */

import {
  HardDrive,
  Wifi,
  Router,
  Globe,
  Shield,
  Camera,
  Video,
  DoorOpen,
  Radio,
  Phone,
  Cpu,
  Zap,
  Activity,
  Server,
  type LucideIcon,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { cn } from '../../lib/utils';

// ============================================================================
// Device-type registry · single source of truth
// ============================================================================

export type DeviceTypeKey =
  | 'switch'
  | 'access_point'
  | 'router'
  | 'gateway'
  | 'firewall'
  | 'camera'
  | 'nvr'
  | 'dvr'
  | 'access_control'
  | 'intercom'
  | 'voip_phone'
  | 'pbx'
  | 'server'
  | 'hypervisor'
  | 'iot'
  | 'sensor'
  | 'controller'
  | 'other';

interface DeviceTypeMeta {
  icon: LucideIcon;
  /** English fallback label. Used when no translator is available. */
  label: string;
  /** Semantic i18n key suffix · translated at the use site as `DeviceTypeIcon.types.<labelKey>`. */
  labelKey: string;
}

const DEVICE_TYPE_REGISTRY: Record<DeviceTypeKey, DeviceTypeMeta> = {
  switch:         { icon: HardDrive, label: 'Switch',         labelKey: 'switch' },
  access_point:   { icon: Wifi,      label: 'Access Point',   labelKey: 'access_point' },
  router:         { icon: Router,    label: 'Router',         labelKey: 'router' },
  gateway:        { icon: Globe,     label: 'Gateway',        labelKey: 'gateway' },
  firewall:       { icon: Shield,    label: 'Firewall',       labelKey: 'firewall' },
  camera:         { icon: Camera,    label: 'Camera',         labelKey: 'camera' },
  nvr:            { icon: Video,     label: 'NVR',            labelKey: 'nvr' },
  dvr:            { icon: Video,     label: 'DVR',            labelKey: 'dvr' },
  access_control: { icon: DoorOpen,  label: 'Access Control', labelKey: 'access_control' },
  intercom:       { icon: Radio,     label: 'Intercom',       labelKey: 'intercom' },
  voip_phone:     { icon: Phone,     label: 'VoIP Phone',     labelKey: 'voip_phone' },
  pbx:            { icon: Phone,     label: 'PBX',            labelKey: 'pbx' },
  server:         { icon: Cpu,       label: 'Server',         labelKey: 'server' },
  hypervisor:     { icon: Cpu,       label: 'Hypervisor',     labelKey: 'hypervisor' },
  iot:            { icon: Zap,       label: 'IoT',            labelKey: 'iot' },
  sensor:         { icon: Activity,  label: 'Sensor',         labelKey: 'sensor' },
  controller:     { icon: Server,    label: 'Controller',     labelKey: 'controller' },
  other:          { icon: Server,    label: 'Other',          labelKey: 'other' },
};

// ============================================================================
// Status → tint mapping (semantic tokens only)
// ============================================================================

type Status = 'online' | 'offline' | 'degraded' | 'pending' | 'unknown' | 'neutral';

const statusTint: Record<Status, { container: string; icon: string }> = {
  online:   { container: 'bg-success/10',     icon: 'text-success' },
  offline:  { container: 'bg-destructive/10', icon: 'text-destructive' },
  degraded: { container: 'bg-warning/10',     icon: 'text-warning' },
  pending:  { container: 'bg-info/10',        icon: 'text-info' },
  unknown:  { container: 'bg-muted',          icon: 'text-muted-foreground' },
  neutral:  { container: 'bg-muted',          icon: 'text-muted-foreground' },
};

// ============================================================================
// Sizes
// ============================================================================

type Size = 'sm' | 'md' | 'lg';

const sizeClass: Record<Size, { container: string; icon: string }> = {
  sm: { container: 'h-7 w-7 rounded-md',   icon: 'h-3.5 w-3.5' },
  md: { container: 'h-9 w-9 rounded-lg',   icon: 'h-4 w-4' },
  lg: { container: 'h-12 w-12 rounded-xl', icon: 'h-6 w-6' },
};

// ============================================================================
// Component
// ============================================================================

interface DeviceTypeIconProps {
  /** Type key · looked up in registry. Unknown types fall back to "other". */
  type: string;
  /** Status · drives container tint. Default 'neutral' (muted gray). */
  status?: Status;
  /** Size variant */
  size?: Size;
  /** Override the icon (default: from registry) */
  icon?: LucideIcon;
  /** Render the icon WITHOUT a tinted container */
  bare?: boolean;
  /** Override the label for accessibility */
  label?: string;
  className?: string;
}

export function DeviceTypeIcon({
  type,
  status = 'neutral',
  size = 'md',
  icon,
  bare = false,
  label,
  className,
}: DeviceTypeIconProps) {
  const { t } = useTranslation('common');
  const meta = DEVICE_TYPE_REGISTRY[type as DeviceTypeKey] ?? DEVICE_TYPE_REGISTRY.other;
  const Icon = icon ?? meta.icon;
  const tint = statusTint[status];
  const sizes = sizeClass[size];

  const labelText = label ?? t(`DeviceTypeIcon.types.${meta.labelKey}`, { defaultValue: meta.label });

  if (bare) {
    return <Icon className={cn(sizes.icon, tint.icon, className)} aria-label={labelText} />;
  }

  return (
    <span
      className={cn(
        'inline-flex items-center justify-center flex-shrink-0',
        sizes.container,
        tint.container,
        className,
      )}
      aria-label={labelText}
    >
      <Icon className={cn(sizes.icon, tint.icon)} />
    </span>
  );
}

// Helper to look up the label for a type · useful in tables, filters etc.
// Pass a `t` translator (from useTranslation('common')) to get a localized
// label; omit it to fall back to the English label (backward compatible).
export function getDeviceTypeLabel(type: string, t?: TFunction): string {
  const meta = DEVICE_TYPE_REGISTRY[type as DeviceTypeKey] ?? DEVICE_TYPE_REGISTRY.other;
  return t ? t(`DeviceTypeIcon.types.${meta.labelKey}`, { defaultValue: meta.label }) : meta.label;
}

// Helper to get all registered types · useful for filter dropdowns.
// Pass a `t` translator to localize the labels; omit it for English fallbacks.
export function getAllDeviceTypes(
  t?: TFunction,
): Array<{ key: DeviceTypeKey; label: string; icon: LucideIcon }> {
  return Object.entries(DEVICE_TYPE_REGISTRY).map(([key, meta]) => ({
    key: key as DeviceTypeKey,
    label: t ? t(`DeviceTypeIcon.types.${meta.labelKey}`, { defaultValue: meta.label }) : meta.label,
    icon: meta.icon,
  }));
}
