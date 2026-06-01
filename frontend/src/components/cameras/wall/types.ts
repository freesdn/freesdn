// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Camera Wall · Type definitions
 *
 * Enterprise-grade multi-channel surveillance wall supporting up to 64
 * simultaneous camera feeds with adaptive refresh rates.
 */

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

/** Grid layout presets matching industry standards */
export type WallLayout =
  | '1x1'   //  1 cell  · single focus
  | '1+5'   //  6 cells · 1 large + 5 small (UniFi-style)
  | '2x2'   //  4 cells
  | '3x3'   //  9 cells
  | '4x4'   // 16 cells
  | '5x5'   // 25 cells
  | '6x6'   // 36 cells
  | '8x8';  // 64 cells · max

/** Number of cells each layout provides */
export const LAYOUT_CELL_COUNT: Record<WallLayout, number> = {
  '1x1': 1,
  '1+5': 6,
  '2x2': 4,
  '3x3': 9,
  '4x4': 16,
  '5x5': 25,
  '6x6': 36,
  '8x8': 64,
};

/** Display label for layouts */
export const LAYOUT_LABELS: Record<WallLayout, string> = {
  '1x1': '1×1',
  '1+5': '1+5',
  '2x2': '2×2',
  '3x3': '3×3',
  '4x4': '4×4',
  '5x5': '5×5',
  '6x6': '6×6',
  '8x8': '8×8',
};

// ---------------------------------------------------------------------------
// Stream quality tiers · adaptive based on cell count
// ---------------------------------------------------------------------------

export interface RefreshTier {
  /** Max number of cells for this tier */
  maxCells: number;
  /** Snapshot refresh interval in milliseconds */
  intervalMs: number;
  /** Label for user display */
  label: string;
}

/**
 * Adaptive refresh tiers (inspired by Blue Iris / Hikvision):
 * Fewer cameras → faster refresh → smoother experience.
 * More cameras → slower refresh → less bandwidth/CPU.
 */
export const REFRESH_TIERS: RefreshTier[] = [
  { maxCells: 1,  intervalMs: 1_500,  label: '~1.5s' },
  { maxCells: 4,  intervalMs: 3_000,  label: '~3s'   },
  { maxCells: 9,  intervalMs: 4_000,  label: '~4s'   },
  { maxCells: 16, intervalMs: 5_000,  label: '~5s'   },
  { maxCells: 25, intervalMs: 8_000,  label: '~8s'   },
  { maxCells: 36, intervalMs: 10_000, label: '~10s'  },
  { maxCells: 64, intervalMs: 12_000, label: '~12s'  },
];

/** Resolve refresh interval for a given cell count */
export function getRefreshInterval(cellCount: number): number {
  for (const tier of REFRESH_TIERS) {
    if (cellCount <= tier.maxCells) return tier.intervalMs;
  }
  return 15_000;
}

/** Resolve refresh tier label */
export function getRefreshLabel(cellCount: number): string {
  for (const tier of REFRESH_TIERS) {
    if (cellCount <= tier.maxCells) return tier.label;
  }
  return '~15s';
}

// ---------------------------------------------------------------------------
// Camera data (minimal projection used by the wall)
// ---------------------------------------------------------------------------

export interface WallCamera {
  id: string;
  name: string;
  status: 'online' | 'offline' | 'recording' | 'error' | 'unknown';
  ip_address?: string;
  location?: string;
  has_ptz?: boolean;
  has_audio?: boolean;
  is_recording?: boolean;
  vendor?: string;
  model?: string;
  nvr_id?: string;
  nvr_channel?: number;
  nvr?: { id: string; name: string } | null;
}

// ---------------------------------------------------------------------------
// Wall state
// ---------------------------------------------------------------------------

export interface WallState {
  /** Currently active layout */
  layout: WallLayout;
  /** Ordered camera IDs assigned to wall cells (sparse · null = empty cell) */
  cameraIds: (string | null)[];
  /** Current page when paginating through cameras */
  page: number;
  /** ID of the camera currently in "focus" (enlarged) mode, or null */
  focusedCameraId: string | null;
  /** Whether auto-cycle is enabled */
  autoCycle: boolean;
  /** Auto-cycle interval in seconds */
  autoCycleInterval: number;
  /** Whether the wall is in fullscreen mode */
  isFullscreen: boolean;
  /** Stream quality preference */
  streamQuality: 'sub' | 'main';
  /** Whether to show camera labels on cells */
  showLabels: boolean;
  /** Whether to show status indicators */
  showStatus: boolean;
  /** Stream mode: 'snapshot' polls JPEGs, 'live' renders MJPEG for all cells */
  streamMode: 'snapshot' | 'live';
  /** Whether the camera sidebar drawer is visible (for drag-drop placement) */
  showSidebar: boolean;
  /** Whether alert sounds are enabled for event highlights */
  alertSoundEnabled: boolean;
}

export const DEFAULT_WALL_STATE: WallState = {
  layout: '4x4',
  cameraIds: [],
  page: 0,
  focusedCameraId: null,
  autoCycle: false,
  autoCycleInterval: 10,
  isFullscreen: false,
  streamQuality: 'sub',
  showLabels: true,
  showStatus: true,
  streamMode: 'snapshot',
  showSidebar: false,
  alertSoundEnabled: typeof window !== 'undefined'
    ? localStorage.getItem('freesdn-wall-alert-sound') !== 'false'
    : true,
};

// ---------------------------------------------------------------------------
// Bandwidth warning thresholds for live MJPEG mode
// ---------------------------------------------------------------------------

export type BandwidthLevel = 'ok' | 'moderate' | 'high' | 'very-high';

export function getBandwidthWarning(activeCells: number): { level: BandwidthLevel; message: string } | null {
  if (activeCells <= 9) return null;
  if (activeCells <= 16) return { level: 'moderate', message: 'Moderate bandwidth usage' };
  if (activeCells <= 36) return { level: 'high', message: 'High bandwidth · sub quality recommended' };
  return { level: 'very-high', message: 'Very high bandwidth · snapshots recommended for best performance' };
}

// ---------------------------------------------------------------------------
// Event highlight state (for event-triggered cell highlighting)
// ---------------------------------------------------------------------------

export interface CellHighlight {
  type: string;
  timestamp: number;
}

// ---------------------------------------------------------------------------
// Replay state (for instant replay)
// ---------------------------------------------------------------------------

export interface CellReplay {
  startTime: string;
  endTime: string;
  videoUrl?: string;
  loading?: boolean;
}
