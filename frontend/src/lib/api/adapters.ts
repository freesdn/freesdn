// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Adapter catalog API — honest maturity for the UI vendor pickers.
 *
 * Backed by the project's single source of truth (`app/adapters/maturity.py`).
 * VERIFIED is granted only there; anything absent is EXPERIMENTAL.
 */

import { api } from './client';

export type AdapterMaturityLevel = 'verified' | 'experimental' | 'planned';

/**
 * Write surface is graded SEPARATELY from reads — most adapters' writes are
 * gated + mock-tested but not yet proven on real hardware, so a single
 * "Verified" badge oversold them. The UI shows a "Writes: …" sub-badge.
 */
export type AdapterWriteMaturity =
  | 'live_validated'
  | 'partial'
  | 'mock_tested'
  | 'disabled'
  | 'not_implemented'
  | 'experimental';

export interface AdapterMaturityInfo {
  maturity: AdapterMaturityLevel;
  notes: string;
  /** Honest write-surface grade (defaults to mock_tested server-side). */
  write_maturity?: AdapterWriteMaturity;
  write_note?: string;
}

/** Adapter id (e.g. `omada`, `opnsense`, `onvif`) → honest maturity. */
export type AdapterMaturityMap = Record<string, AdapterMaturityInfo>;

export const adaptersApi = {
  /** GET /adapters/maturity — the honest live-validation record. */
  async getMaturity(): Promise<AdapterMaturityMap> {
    const { data } = await api.get<AdapterMaturityMap>('/adapters/maturity');
    return data;
  },
};
