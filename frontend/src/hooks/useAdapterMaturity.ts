// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * React hook for adapter maturity — drives the honest Verified / Experimental
 * badges on the vendor pickers (controllers, cameras, PBX).
 *
 * Backend: ``GET /api/v1/adapters/maturity`` (single source of truth =
 * ``app/adapters/maturity.py``). VERIFIED is granted only there; anything the
 * record doesn't know is EXPERIMENTAL — we never assume an integration works.
 *
 * Usage::
 *
 *     const { maturityFor } = useAdapterMaturity();
 *     const info = maturityFor('opnsense');   // { maturity, notes }
 *     <MaturityBadge info={info} />
 */

import { useQuery } from '@tanstack/react-query';

import {
  adaptersApi,
  type AdapterMaturityInfo,
  type AdapterMaturityMap,
} from '@/lib/api/adapters';

/** Honest default for anything the record hasn't explicitly verified. */
const EXPERIMENTAL: AdapterMaturityInfo = { maturity: 'experimental', notes: '' };

export interface UseAdapterMaturityResult {
  /** Raw id → maturity map (undefined while loading). */
  map: AdapterMaturityMap | undefined;
  isLoading: boolean;
  /**
   * Honest maturity for an adapter id. Unknown ids resolve to EXPERIMENTAL —
   * never assume verified. While loading we also default to EXPERIMENTAL so the
   * UI errs toward the cautious label rather than a false "Verified".
   */
  maturityFor: (adapterId: string) => AdapterMaturityInfo;
}

export function useAdapterMaturity(): UseAdapterMaturityResult {
  const { data, isLoading } = useQuery({
    queryKey: ['adapter-maturity'],
    queryFn: () => adaptersApi.getMaturity(),
    staleTime: 60 * 60 * 1000, // changes rarely; cache an hour
  });

  return {
    map: data,
    isLoading,
    maturityFor: (adapterId: string) => data?.[adapterId] ?? EXPERIMENTAL,
  };
}
