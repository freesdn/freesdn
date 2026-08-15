// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Alert Badge Preferences Store
 *
 * Zustand store persisted in localStorage that controls how the sidebar
 * alert badge count is computed.  Users can:
 *   - Toggle which alert sources contribute (rules / incidents / security)
 *   - Set a minimum severity threshold
 *   - "Clear" the badge by recording `lastReviewedAt` (only items newer
 *     than that timestamp are counted)
 */
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

// ── Types ───────────────────────────────────────────────────────────────

export type AlertSource = 'rules' | 'incidents' | 'security';

/** Minimum severity level that should count toward the badge. */
export type BadgeSeverityThreshold = 'all' | 'info' | 'warning' | 'critical';

export interface AlertBadgeState {
  /** Which sources contribute to the badge count. */
  sources: Record<AlertSource, boolean>;
  /** Minimum severity to include. */
  minSeverity: BadgeSeverityThreshold;
  /** ISO timestamp · only items after this are counted. null = count all. */
  lastReviewedAt: string | null;

  // ── Actions ──
  toggleSource: (source: AlertSource) => void;
  setMinSeverity: (s: BadgeSeverityThreshold) => void;
  /** Mark all current alerts as "reviewed" · clears the badge. */
  markAllReviewed: () => void;
  /** Reset preferences to defaults. */
  resetPreferences: () => void;
}

// ── Severity ordering (lower = more severe) ─────────────────────────────

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  warning: 2,
  medium: 2,
  low: 3,
  info: 4,
};

const THRESHOLD_RANK: Record<BadgeSeverityThreshold, number> = {
  critical: 0,
  warning: 2,
  info: 4,
  all: 99,
};

/**
 * Check whether a given severity passes the minimum-severity threshold.
 *
 * Usage:
 *   `passesThreshold('warning', 'critical')` → false
 *   `passesThreshold('critical', 'critical')` → true
 *   `passesThreshold('info', 'all')` → true
 */
export function passesThreshold(
  severity: string,
  threshold: BadgeSeverityThreshold,
): boolean {
  if (threshold === 'all') return true;
  const rank = SEVERITY_RANK[severity] ?? 5;
  return rank <= THRESHOLD_RANK[threshold];
}

// ── Store ───────────────────────────────────────────────────────────────

const DEFAULT_STATE = {
  sources: { rules: true, incidents: true, security: true } as Record<AlertSource, boolean>,
  minSeverity: 'all' as BadgeSeverityThreshold,
  lastReviewedAt: null as string | null,
};

export const useAlertBadgeStore = create<AlertBadgeState>()(
  persist(
    (set) => ({
      ...DEFAULT_STATE,

      toggleSource: (source) =>
        set((state) => ({
          sources: { ...state.sources, [source]: !state.sources[source] },
        })),

      setMinSeverity: (s) => set({ minSeverity: s }),

      markAllReviewed: () => set({ lastReviewedAt: new Date().toISOString() }),

      resetPreferences: () => set({ ...DEFAULT_STATE }),
    }),
    {
      name: 'freesdn-alert-badge',
    },
  ),
);
