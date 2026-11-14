// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { demoCameraId } from './identity';

// Demo cameras are served with UUIDs derived from their readable fixture keys
// (see demoCameraId); accept either form.
const WAREHOUSE = new Set(['cam-warehouse', demoCameraId('cam-warehouse')]);
const BRANCH_LOBBY = new Set(['cam-branch-lobby', demoCameraId('cam-branch-lobby')]);

export function getDemoCameraSnapshotPath(cameraId: string | undefined) {
  if (cameraId && WAREHOUSE.has(cameraId)) return '/demo/camera-warehouse.jpg';
  if (cameraId && BRANCH_LOBBY.has(cameraId)) return '/demo/camera-branch-lobby.jpg';
  return '/demo/camera-front-door.jpg';
}
