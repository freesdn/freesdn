// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · VoIP Shared Components
 *
 * Status badges, formatters, and small UI pieces reused across VoIP pages.
 */

import {
  CheckCircle, XCircle, AlertCircle, PhoneCall, PhoneIncoming,
  PhoneOutgoing, PhoneOff, Phone, Wifi, WifiOff,
  CircleDot, Wrench, Upload, Download,
  Radar,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import type { PhoneStatus, LifecycleState, ProvisionStatus, ScanStatus } from './types';

// =============================================================================
// Phone Status Badge
// =============================================================================

const STATUS_CONFIG: Record<string, { icon: typeof CheckCircle; labelKey: string; className: string }> = {
  online: { icon: CheckCircle, labelKey: 'phoneStatus.online', className: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' },
  offline: { icon: XCircle, labelKey: 'phoneStatus.offline', className: 'bg-red-500/10 text-red-500 border-red-500/20' },
  in_call: { icon: PhoneCall, labelKey: 'phoneStatus.inCall', className: 'bg-amber-500/10 text-amber-500 border-amber-500/20' },
  ringing: { icon: PhoneIncoming, labelKey: 'phoneStatus.ringing', className: 'bg-blue-500/10 text-blue-500 border-blue-500/20 animate-pulse' },
  dnd: { icon: PhoneOff, labelKey: 'phoneStatus.dnd', className: 'bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20' },
  warning: { icon: AlertCircle, labelKey: 'phoneStatus.warning', className: 'bg-amber-500/10 text-amber-500 border-amber-500/20' },
  unknown: { icon: AlertCircle, labelKey: 'phoneStatus.unknown', className: 'bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20' },
};

export function PhoneStatusBadge({ status }: { status: PhoneStatus }) {
  const { t } = useTranslation('voip');
  const { icon: Icon, labelKey, className } = STATUS_CONFIG[status] || STATUS_CONFIG.unknown;
  return (
    <Badge variant="outline" className={cn('gap-1', className)}>
      <Icon className="h-3 w-3" />
      {t(`components.${labelKey}`)}
    </Badge>
  );
}

// =============================================================================
// Lifecycle State Badge
// =============================================================================

const LIFECYCLE_CONFIG: Record<string, { icon: typeof CircleDot; labelKey: string; className: string }> = {
  discovered: { icon: Radar, labelKey: 'lifecycle.discovered', className: 'bg-blue-500/10 text-blue-500 border-blue-500/20' },
  onboarding: { icon: Upload, labelKey: 'lifecycle.onboarding', className: 'bg-cyan-500/10 text-cyan-500 border-cyan-500/20' },
  managed: { icon: CheckCircle, labelKey: 'lifecycle.managed', className: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' },
  maintenance: { icon: Wrench, labelKey: 'lifecycle.maintenance', className: 'bg-amber-500/10 text-amber-500 border-amber-500/20' },
  firmware_updating: { icon: Download, labelKey: 'lifecycle.firmwareUpdating', className: 'bg-purple-500/10 text-purple-500 border-purple-500/20 animate-pulse' },
  decommissioned: { icon: XCircle, labelKey: 'lifecycle.decommissioned', className: 'bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20' },
};

export function LifecycleBadge({ state }: { state?: LifecycleState }) {
  const { t } = useTranslation('voip');
  if (!state) return null;
  const { icon: Icon, labelKey, className } = LIFECYCLE_CONFIG[state] || LIFECYCLE_CONFIG.discovered;
  return (
    <Badge variant="outline" className={cn('gap-1', className)}>
      <Icon className="h-3 w-3" />
      {t(`components.${labelKey}`)}
    </Badge>
  );
}

// =============================================================================
// Provision Status Badge
// =============================================================================

const PROVISION_CONFIG: Record<string, { labelKey: string; className: string }> = {
  pending: { labelKey: 'provision.pending', className: 'bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20' },
  generated: { labelKey: 'provision.generated', className: 'bg-blue-500/10 text-blue-500 border-blue-500/20' },
  pushed: { labelKey: 'provision.pushed', className: 'bg-cyan-500/10 text-cyan-500 border-cyan-500/20' },
  applied: { labelKey: 'provision.applied', className: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' },
  failed: { labelKey: 'provision.failed', className: 'bg-red-500/10 text-red-500 border-red-500/20' },
  stale: { labelKey: 'provision.stale', className: 'bg-amber-500/10 text-amber-500 border-amber-500/20' },
};

export function ProvisionBadge({ status }: { status?: ProvisionStatus }) {
  const { t } = useTranslation('voip');
  if (!status) return null;
  const { labelKey, className } = PROVISION_CONFIG[status] || PROVISION_CONFIG.pending;
  return <Badge variant="outline" className={cn('gap-1', className)}>{t(`components.${labelKey}`)}</Badge>;
}

// =============================================================================
// Scan Status Badge
// =============================================================================

const SCAN_CONFIG: Record<string, { labelKey: string; className: string }> = {
  pending: { labelKey: 'scan.pending', className: 'bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20' },
  running: { labelKey: 'scan.running', className: 'bg-blue-500/10 text-blue-500 border-blue-500/20 animate-pulse' },
  completed: { labelKey: 'scan.completed', className: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' },
  failed: { labelKey: 'scan.failed', className: 'bg-red-500/10 text-red-500 border-red-500/20' },
  cancelled: { labelKey: 'scan.cancelled', className: 'bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20' },
};

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  const { t } = useTranslation('voip');
  const { labelKey, className } = SCAN_CONFIG[status] || SCAN_CONFIG.pending;
  return <Badge variant="outline" className={cn('gap-1', className)}>{t(`components.${labelKey}`)}</Badge>;
}

// =============================================================================
// Call Direction Badge
// =============================================================================

export function CallDirectionBadge({ direction }: { direction: 'inbound' | 'outbound' | 'internal' }) {
  const { t } = useTranslation('voip');
  const config = {
    inbound: { icon: PhoneIncoming, label: t('components.callDirection.inbound'), className: 'text-blue-500' },
    outbound: { icon: PhoneOutgoing, label: t('components.callDirection.outbound'), className: 'text-emerald-500' },
    internal: { icon: Phone, label: t('components.callDirection.internal'), className: 'text-muted-foreground' },
  };
  const { icon: Icon, label, className } = config[direction] || config.internal;
  return (
    <div className={cn('flex items-center gap-1', className)}>
      <Icon className="h-4 w-4" />
      <span className="text-xs font-medium">{label}</span>
    </div>
  );
}

// =============================================================================
// Call Status Badge
// =============================================================================

export function CallStatusBadge({ status }: { status: string }) {
  const { t } = useTranslation('voip');
  const cfg: Record<string, { label: string; className: string }> = {
    answered: { label: t('components.callStatus.answered'), className: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' },
    // FreePBX CDR dispositions emit 'completed' for an answered call, treat it as answered.
    completed: { label: t('components.callStatus.completed'), className: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' },
    missed: { label: t('components.callStatus.missed'), className: 'bg-red-500/10 text-red-500 border-red-500/20' },
    no_answer: { label: t('components.callStatus.noAnswer'), className: 'bg-amber-500/10 text-amber-500 border-amber-500/20' },
    busy: { label: t('components.callStatus.busy'), className: 'bg-yellow-500/10 text-yellow-600 border-yellow-500/20' },
    voicemail: { label: t('components.callStatus.voicemail'), className: 'bg-purple-500/10 text-purple-500 border-purple-500/20' },
    failed: { label: t('components.callStatus.failed'), className: 'bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20' },
  };
  const { label, className } = cfg[status] || cfg.failed;
  return <Badge variant="outline" className={cn('gap-1', className)}>{label}</Badge>;
}

// =============================================================================
// PBX Type Badge
// =============================================================================

export function PBXTypeBadge({ type }: { type: string }) {
  const { t } = useTranslation('voip');
  const cfg: Record<string, { label: string; className: string }> = {
    freepbx: { label: 'FreePBX', className: 'bg-blue-500/10 text-blue-500 border-blue-500/20' },
    asterisk: { label: 'Asterisk', className: 'bg-orange-500/10 text-orange-500 border-orange-500/20' },
    '3cx': { label: '3CX', className: 'bg-green-500/10 text-green-500 border-green-500/20' },
    freeswitch: { label: 'FreeSWITCH', className: 'bg-purple-500/10 text-purple-500 border-purple-500/20' },
    other: { label: t('components.pbxType.other'), className: 'bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20' },
  };
  const { label, className } = cfg[type] || cfg.other;
  return <Badge variant="outline" className={cn('gap-1', className)}>{label}</Badge>;
}

// =============================================================================
// SIP Registration Indicator
// =============================================================================

export function SIPIndicator({ registered }: { registered?: boolean }) {
  if (registered === undefined || registered === null) return null;
  return registered ? (
    <div className="flex items-center gap-1 text-emerald-500">
      <Wifi className="h-3.5 w-3.5" />
      <span className="text-xs">SIP</span>
    </div>
  ) : (
    <div className="flex items-center gap-1 text-red-500">
      <WifiOff className="h-3.5 w-3.5" />
      <span className="text-xs">SIP</span>
    </div>
  );
}

// =============================================================================
// Vendor Icon
// =============================================================================

export function VendorLabel({ vendor }: { vendor?: string }) {
  if (!vendor) return <span className="text-muted-foreground">-</span>;
  const colors: Record<string, string> = {
    grandstream: 'text-blue-500',
    yealink: 'text-green-500',
    polycom: 'text-orange-500',
    poly: 'text-orange-500',
    cisco: 'text-cyan-500',
    fanvil: 'text-purple-500',
    snom: 'text-red-500',
  };
  const color = colors[vendor.toLowerCase()] || 'text-foreground';
  return <span className={cn('font-medium capitalize', color)}>{vendor}</span>;
}

// =============================================================================
// Duration Formatter
// =============================================================================

export function formatDuration(seconds: number): string {
  if (!seconds || seconds < 0) return '0s';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function formatUptime(seconds: number | undefined): string {
  if (!seconds) return '-';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  if (d > 0) return `${d}d ${h}h`;
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

export function formatTimeAgo(dateStr: string | undefined): string {
  if (!dateStr) return '-';
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}
