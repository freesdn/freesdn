// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * CapabilityMaturityBadge — the honest Stable / Beta / Experimental marker for
 * FEATURES (SSO, automation, collector, …). Driven by `useCapabilityMaturity` →
 * the backend single source of truth (`app/core/capability_maturity.py`).
 *
 * The whole point is to NOT oversell: a capability reads "Experimental" until it
 * has been proven end-to-end against real infrastructure — mirroring the adapter
 * Verified/Experimental badge. (Labels are English for now; i18n is a follow-up —
 * the honesty does not depend on translation.)
 *
 * Pass `capabilityId` (it resolves itself via the hook) or a pre-fetched `info`:
 *   <CapabilityMaturityBadge capabilityId="sso" />
 */

import { AlertTriangle, Info, ShieldCheck } from 'lucide-react';

import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { useCapabilityMaturity } from '@/hooks/useCapabilityMaturity';
import type { CapabilityMaturityInfo } from '@/lib/api/capabilities';
import { cn } from '@/lib/utils';

const EXPERIMENTAL_DEFAULT =
  'Built but not yet verified end-to-end against real infrastructure — treat as experimental.';

const EXPERIMENTAL_INFO: CapabilityMaturityInfo = {
  maturity: 'experimental',
  title: '',
  notes: '',
};

export function CapabilityMaturityBadge({
  capabilityId,
  info,
  className,
}: {
  /** Resolve maturity for this capability id via the record (preferred). */
  capabilityId?: string;
  /** Or pass a pre-fetched info object directly. */
  info?: CapabilityMaturityInfo;
  className?: string;
}) {
  const { maturityFor } = useCapabilityMaturity();
  const resolved: CapabilityMaturityInfo = capabilityId
    ? maturityFor(capabilityId)
    : (info ?? EXPERIMENTAL_INFO);

  const base =
    'inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium leading-none';

  // STABLE — earned (audited E2E). May still carry a caveat note.
  if (resolved.maturity === 'stable') {
    const badge = (
      <span
        className={cn(
          base,
          'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300',
          className,
        )}
      >
        <ShieldCheck className="h-3 w-3" />
        Stable
      </span>
    );
    if (!resolved.notes) return badge;
    return (
      <TooltipProvider delayDuration={150}>
        <Tooltip>
          <TooltipTrigger asChild>{badge}</TooltipTrigger>
          <TooltipContent className="max-w-xs text-xs">{resolved.notes}</TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }

  // BETA (works, partial) vs EXPERIMENTAL (unverified E2E) — both carry an honest
  // tooltip so the operator knows exactly what they're relying on.
  const isBeta = resolved.maturity === 'beta';
  const Icon = isBeta ? Info : AlertTriangle;
  const label = isBeta ? 'Beta' : 'Experimental';
  const color = isBeta
    ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300'
    : 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300';

  return (
    <TooltipProvider delayDuration={150}>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className={cn(base, 'cursor-help', color, className)}>
            <Icon className="h-3 w-3" />
            {label}
          </span>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs text-xs">
          {resolved.notes || EXPERIMENTAL_DEFAULT}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
