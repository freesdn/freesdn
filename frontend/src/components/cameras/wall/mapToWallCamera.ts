// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * mapToWallCamera · Shared utility to convert raw API camera data to WallCamera type.
 *
 * Used by CameraWallPopout, MultiPlaybackPage, and any page that needs
 * to transform API responses into the WallCamera shape.
 */

import type { WallCamera } from './types';

export function mapToWallCameras(items: unknown): WallCamera[] {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const list = (items as any)?.items || items || [];
  if (!Array.isArray(list)) return [];
  return list.map((c: Record<string, unknown>) => ({
    id: String(c.id || ''),
    name: String(c.name || 'Unknown'),
    status: (c.status as WallCamera['status']) || 'unknown',
    ip_address: c.ip_address as string | undefined,
    location: c.location as string | undefined,
    has_ptz: Boolean(c.has_ptz),
    has_audio: Boolean(c.has_audio),
    is_recording: Boolean(c.is_recording),
    vendor: c.vendor as string | undefined,
    model: c.model as string | undefined,
    nvr_id: c.nvr_id as string | undefined,
    nvr_channel: c.nvr_channel as number | undefined,
  }));
}
