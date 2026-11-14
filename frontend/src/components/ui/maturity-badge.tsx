// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MaturityBadge — the honest Verified / Experimental marker for vendor pickers
 * (controllers, cameras, PBX). Driven by `useAdapterMaturity` → the backend
 * single source of truth (`app/adapters/maturity.py`).
 *
 * The whole point of this badge is to NOT oversell: an integration is only ever
 * labelled "Verified" when the project has proven it on real hardware; anything
 * else reads "Experimental" with an honest tooltip. Labels and fallback notes
 * are translated (common:MaturityBadge); notes that come from the backend
 * record are shown as sent.
 */

import { Info, PencilLine, ShieldCheck } from 'lucide-react';
import { useTranslation } from 'react-i18next';

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


const BADGE =
  'inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium leading-none';

// Honest write-surface sub-badge. Reads being Verified does NOT mean writes are
// — most adapters' writes are gated + mock-tested but unproven on hardware. This
// surfaces that instead of letting the single "Verified" badge oversell writes.
// Label and fallback note come from common:MaturityBadge.write.<grade>.
const WRITE_STYLE: Record<AdapterWriteMaturity, { cls: string }> = {
  live_validated: {
    cls: 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300',
  },
  partial: {
    cls: 'bg-sky-100 text-sky-700 dark:bg-sky-900/40 dark:text-sky-300',
  },
  mock_tested: {
    cls: 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300',
  },
  disabled: {
    cls: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300',
  },
  not_implemented: {
    cls: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300',
  },
  experimental: {
    cls: 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300',
  },
};

function WriteBadge({ info }: { info: AdapterMaturityInfo }) {
  const { t } = useTranslation('common');
  const wm = info.write_maturity;
  if (!wm) return null;
  const s = WRITE_STYLE[wm];
  return (
    <TooltipProvider delayDuration={150}>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className={cn(BADGE, 'cursor-help', s.cls)}>
            <PencilLine className="h-3 w-3" aria-hidden="true" />
            {t(`MaturityBadge.write.${wm}.label`)}
          </span>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs text-xs">
          {info.write_note || t(`MaturityBadge.write.${wm}.note`)}
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
  const { t } = useTranslation('common');
  if (info.maturity === 'verified') {
    const readBadge = (
      <span
        className={cn(
          BADGE,
          'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300',
          className,
        )}
      >
        <ShieldCheck className="h-3 w-3" aria-hidden="true" />
        {t('MaturityBadge.readsVerified')}
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
            <Info className="h-3 w-3" aria-hidden="true" />
            {t('MaturityBadge.experimental')}
          </span>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs text-xs">
          {info.notes || t('MaturityBadge.experimentalNote')}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
