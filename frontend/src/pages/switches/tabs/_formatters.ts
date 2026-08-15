// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Shared formatters used across SwitchesPage tabs.
 *
 * Lives next to the tab files so the tabs can be extracted into siblings
 * without depending on the parent SwitchesPage file. The leading underscore
 * keeps it sorted at the top of the directory listing and signals "internal".
 */

export const formatUptime = (seconds?: number) => {
  if (seconds == null) return '-';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
};

export const formatBytes = (bytes: number) => {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
};

export const formatSpeed = (speed?: number) => {
  if (!speed) return '-';
  if (speed >= 10000) return '10 Gbps';
  if (speed >= 2500) return '2.5 Gbps';
  if (speed >= 1000) return '1 Gbps';
  return `${speed} Mbps`;
};

export const formatActivity = (bytesPerSec?: number) => {
  if (bytesPerSec == null) return '-';
  if (bytesPerSec < 1024) return `${bytesPerSec.toFixed(0)} B/s`;
  if (bytesPerSec < 1024 * 1024) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  return `${(bytesPerSec / (1024 * 1024)).toFixed(1)} MB/s`;
};

export const formatTimeAgo = (iso?: string) => {
  if (!iso) return '-';
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 0) return 'just now';
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
};

export const getUtilizationColor = (pct: number): string => {
  if (!Number.isFinite(pct) || pct <= 0) return 'bg-emerald-500';
  if (pct > 80) return 'bg-red-500';
  if (pct > 60) return 'bg-orange-500';
  if (pct > 40) return 'bg-yellow-500';
  if (pct > 20) return 'bg-emerald-400';
  return 'bg-emerald-500';
};

export const getPoeClassLabel = (poeClass?: number): string | null => {
  if (poeClass == null) return null;
  if (poeClass <= 3) return '802.3af';
  if (poeClass <= 4) return '802.3at';
  if (poeClass <= 8) return '802.3bt';
  return `Class ${poeClass}`;
};

export const getStatusColor = (status: string) => {
  switch (status) {
    case 'up':
    case 'online':
    case 'forwarding':
    case 'delivering':
      return 'bg-success';
    case 'down':
    case 'searching':
      return 'bg-warning';
    case 'disabled':
    case 'blocking':
      return 'bg-muted-foreground';
    case 'fault':
    case 'offline':
      return 'bg-destructive';
    default:
      return 'bg-muted-foreground';
  }
};
