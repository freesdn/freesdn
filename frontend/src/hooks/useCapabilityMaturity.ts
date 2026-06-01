// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * React hook for capability maturity — drives the honest Stable / Beta /
 * Experimental badges on feature pages (SSO, automation, collector, …).
 *
 * Backend: `GET /api/v1/capabilities/maturity` (single source of truth =
 * `app/core/capability_maturity.py`). STABLE is earned; anything the record
 * doesn't know is EXPERIMENTAL — we never assume a feature is production-ready.
 *
 * Usage:
 *   const { maturityFor } = useCapabilityMaturity();
 *   <CapabilityMaturityBadge info={maturityFor('sso')} />
 */

import { useQuery } from '@tanstack/react-query';

import {
  capabilitiesApi,
  type CapabilityMaturityInfo,
  type CapabilityMaturityMap,
} from '@/lib/api/capabilities';

/** Honest default for anything the record hasn't explicitly promoted. */
const EXPERIMENTAL: CapabilityMaturityInfo = { maturity: 'experimental', title: '', notes: '' };

export interface UseCapabilityMaturityResult {
  /** Raw id → maturity map (undefined while loading). */
  map: CapabilityMaturityMap | undefined;
  isLoading: boolean;
  /**
   * Honest maturity for a capability id. Unknown ids (and the loading window)
   * resolve to EXPERIMENTAL so the UI errs toward the cautious label rather than
   * a false "Stable".
   */
  maturityFor: (capabilityId: string) => CapabilityMaturityInfo;
}

export function useCapabilityMaturity(): UseCapabilityMaturityResult {
  const { data, isLoading } = useQuery({
    queryKey: ['capability-maturity'],
    queryFn: () => capabilitiesApi.getMaturity(),
    staleTime: 60 * 60 * 1000, // changes rarely; cache an hour
  });

  return {
    map: data,
    isLoading,
    maturityFor: (capabilityId: string) => data?.[capabilityId] ?? EXPERIMENTAL,
  };
}
