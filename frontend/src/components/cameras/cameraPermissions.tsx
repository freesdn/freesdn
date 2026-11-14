// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Camera control permissions, as the backend enforces them.
 *
 * `cameras.ptz` (operators and up) moves a camera, goes to a preset and runs
 * or stops a patrol tour. `cameras.manage_ptz` (site admins and up, through
 * `cameras.*`) changes what every later viewer gets: saving, overwriting and
 * deleting presets and tours, auto-tracking, and two-way audio. A control the
 * user cannot use is shown disabled with the reason, rather than left to fail
 * with a 403 (the shared DisabledReason wrapper carries the reason).
 */
import { useAuthStore } from '@/stores/authStore';

export function useCameraControlPermissions() {
  const canPtz = useAuthStore((s) => s.hasPermission('cameras.ptz'));
  const canManagePtz = useAuthStore((s) => s.hasPermission('cameras.manage_ptz'));
  return { canPtz, canManagePtz };
}
