// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Camera vendor support tiers.
 *
 * First public release: **Hikvision is the only NATIVELY supported camera
 * vendor** (full ISAPI adapter, live, recordings, playback, zones/masks,
 * events). Every other vendor connects through the generic ONVIF adapter, which
 * provides live view but not recorded search/playback or smart-detection zones
 * yet. Native adapters for Dahua/Reolink/Ubiquiti/Avigilon are on the roadmap;
 * the UI labels the tier honestly so expectations are set up front.
 */
export const NATIVELY_SUPPORTED_VENDORS = ['hikvision'] as const;

/** True when the vendor has a full native adapter (currently Hikvision only). */
export function isNativeVendor(vendor?: string | null): boolean {
  const v = (vendor ?? '').toLowerCase().trim();
  return NATIVELY_SUPPORTED_VENDORS.some((n) => v.includes(n));
}
