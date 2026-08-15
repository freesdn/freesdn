// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MaturityBadge — the honest Verified / Experimental marker for vendor pickers
 * (controllers, cameras, PBX). Driven by `useAdapterMaturity` → the backend
 * single source of truth (`app/adapters/maturity.py`).
 *
 * The whole point of this badge is to NOT oversell: an integration is only ever
 * labelled "Verified" when the project has proven it on real hardware; anything
 * else reads "Experimental" with an honest tooltip. (Labels are English for now;
 * i18n strings are a follow-up — the honesty does not depend on translation.)
 */

import { Info, PencilLine, ShieldCheck } from 'lucide-react';

import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import type {
  AdapterMaturityInfo,
  AdapterWriteMaturity,
} from '@/lib/api/adapters';
import { cn } from '@/lib/utils';

const EXPERIMENTAL_DEFAULT =
  'Implemented but not yet verified on real hardware — please report results.';

const BADGE =
  'inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium leading-none';

// Honest write-surface sub-badge. Reads being Verified does NOT mean writes are
// — most adapters' writes are gated + mock-tested but unproven on hardware. This
// surfaces that instead of letting the single "Verified" badge oversell writes.
const WRITE_STYLE: Record<
  AdapterWriteMaturity,
  { label: string; cls: string; defaultNote: string }
> = {
  live_validated: {
    label: 'Writes: Live',
    cls: 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300',
    defaultNote: 'Write paths proven on real hardware with persisted evidence.',
  },
  partial: {
    label: 'Writes: Partial',
    cls: 'bg-sky-100 text-sky-700 dark:bg-sky-900/40 dark:text-sky-300',
    defaultNote:
      'Some write paths proven live; others unit-tested against mocks only.',
  },
  mock_tested: {
    label: 'Writes: Mock-tested',
    cls: 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300',
    defaultNote:
      'Write code is gated + unit-tested, but not yet proven on real hardware.',
  },
  disabled: {
    label: 'Writes: Off by design',
    cls: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300',
    defaultNote: 'Writes are intentionally disabled — run read-only.',
  },
  not_implemented: {
    label: 'Writes: Not implemented',
    cls: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300',
    defaultNote: 'Write transport is not built yet.',
  },
  experimental: {
    label: 'Writes: Experimental',
    cls: 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300',
    defaultNote: 'Experimental adapter — writes not verified.',
  },
};

function WriteBadge({ info }: { info: AdapterMaturityInfo }) {
  const wm = info.write_maturity;
  if (!wm) return null;
  const s = WRITE_STYLE[wm];
  return (
    <TooltipProvider delayDuration={150}>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className={cn(BADGE, 'cursor-help', s.cls)}>
            <PencilLine className="h-3 w-3" />
            {s.label}
          </span>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs text-xs">
          {info.write_note || s.defaultNote}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

export function MaturityBadge({
  info,
  className,
}: {
  info: AdapterMaturityInfo;
  className?: string;
}) {
  if (info.maturity === 'verified') {
    const readBadge = (
      <span
        className={cn(
          BADGE,
          'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300',
          className,
        )}
      >
        <ShieldCheck className="h-3 w-3" />
        Reads: Verified
      </span>
    );
    // Verified reads + an honest, separate write-surface sub-badge.
    return (
      <span className="inline-flex flex-wrap items-center gap-1">
        {info.notes ? (
          <TooltipProvider delayDuration={150}>
            <Tooltip>
              <TooltipTrigger asChild>{readBadge}</TooltipTrigger>
              <TooltipContent className="max-w-xs text-xs">
                {info.notes}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        ) : (
          readBadge
        )}
        <WriteBadge info={info} />
      </span>
    );
  }

  // experimental (and any non-verified) — always carries an honest tooltip
  return (
    <TooltipProvider delayDuration={150}>
      <Tooltip>
        <TooltipTrigger asChild>
          <span
            className={cn(
              BADGE,
              'cursor-help bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300',
              className,
            )}
          >
            <Info className="h-3 w-3" />
            Experimental
          </span>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs text-xs">
          {info.notes || EXPERIMENTAL_DEFAULT}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
