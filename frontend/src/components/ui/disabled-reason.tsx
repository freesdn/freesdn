// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Design System · DisabledReason
 *
 * A control the user cannot use is shown disabled WITH the reason ("Needs the
 * firewall.manage_rules permission"), not left to fail with a 403. A disabled
 * button gets no pointer or focus events, so the tooltip cannot hang off the
 * button itself: this wraps it in a focusable span that carries the tooltip,
 * reachable by keyboard and by hover. With no ``reason`` the child renders
 * unchanged.
 *
 *   <DisabledReason reason={canManage ? undefined : t('needsManage')}>
 *     <Button disabled={!canManage}>Save preset</Button>
 *   </DisabledReason>
 */
import type { ReactElement } from 'react';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from './tooltip';

export interface DisabledReasonProps {
  /** Why the control is disabled. Omit (or pass undefined) when it is usable. */
  reason?: string;
  /** The (disabled) control. */
  children: ReactElement;
}

export function DisabledReason({ reason, children }: DisabledReasonProps) {
  if (!reason) return children;
  return (
    <TooltipProvider delayDuration={150}>
      <Tooltip>
        <TooltipTrigger asChild>
          <span
            tabIndex={0}
            className="inline-flex rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            {children}
          </span>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs">{reason}</TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
