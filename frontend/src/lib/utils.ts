// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatRelativeTime(dateStr: string | null | undefined): string {
  if (!dateStr) return 'Never';
  const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
  if (Number.isNaN(seconds)) return 'Unknown';
  if (seconds < 0) return 'just now';
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;
  return new Date(dateStr).toLocaleDateString();
}

export function formatUptime(seconds: number | null | undefined): string {
  if (seconds == null) return 'N/A';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  if (days > 0) return `${days}d ${hours}h`;
  const mins = Math.floor((seconds % 3600) / 60);
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

export function formatWatts(watts: number | null | undefined): string {
  if (watts == null) return 'N/A';
  return `${watts.toFixed(1)}W`;
}

/**
 * SECURITY: Validate a URL for safe use in `<a href>` / `window.open()`.
 * Blocks `javascript:`, `data:`, `vbscript:`, `file:`, etc. injected via API
 * responses or user input. Allows only http(s) and relative-path URLs.
 *
 * Returns the original URL if safe, or `null` if not. Callers should treat
 * `null` as "do not navigate".
 */
export function safeExternalUrl(url: string | null | undefined): string | null {
  if (!url) return null;
  const trimmed = String(url).trim();
  if (!trimmed) return null;
  // Allow same-origin / relative URLs (no scheme)
  if (trimmed.startsWith('/') || trimmed.startsWith('#') || trimmed.startsWith('?')) {
    return trimmed;
  }
  try {
    const parsed = new URL(trimmed, window.location.origin);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return trimmed;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * SECURITY: Open a URL in a new tab with `noopener,noreferrer` and only if
 * the URL passes `safeExternalUrl()`. Use this instead of `window.open(url, '_blank')`
 * whenever the URL comes from user input or API data.
 */
export function safeOpen(url: string | null | undefined, features = 'noopener,noreferrer'): void {
  const safe = safeExternalUrl(url);
  if (safe) {
    window.open(safe, '_blank', features);
  }
}
