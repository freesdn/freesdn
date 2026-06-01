// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Capability maturity API — honest Stable / Beta / Experimental for FEATURES.
 *
 * Backed by the project's single source of truth (`app/core/capability_maturity.py`).
 * STABLE is earned (verified end-to-end); anything absent is EXPERIMENTAL. This is
 * the capability-level sibling of the adapter maturity record.
 */

import { api } from './client';

export type CapabilityMaturityLevel = 'stable' | 'beta' | 'experimental';

export interface CapabilityMaturityInfo {
  maturity: CapabilityMaturityLevel;
  title: string;
  notes: string;
}

/** Capability id (e.g. `sso`, `automation`, `collector`) → honest maturity. */
export type CapabilityMaturityMap = Record<string, CapabilityMaturityInfo>;

export const capabilitiesApi = {
  /** GET /capabilities/maturity — the honest feature-readiness record. */
  async getMaturity(): Promise<CapabilityMaturityMap> {
    const { data } = await api.get<CapabilityMaturityMap>('/capabilities/maturity');
    return data;
  },
};
