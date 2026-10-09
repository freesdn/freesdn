// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
export function getDemoCameraSnapshotPath(cameraId: string | undefined) {
  if (cameraId === 'cam-warehouse') return '/demo/camera-warehouse.jpg';
  if (cameraId === 'cam-branch-lobby') return '/demo/camera-branch-lobby.jpg';
  return '/demo/camera-front-door.jpg';
}
