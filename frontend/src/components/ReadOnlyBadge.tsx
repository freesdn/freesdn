// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { Link } from 'react-router-dom';
import { Eye } from 'lucide-react';
import { useUIStore } from '@/stores';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

/**
 * Subtle read-only indicator, rendered under the sidebar logo.
 *
 * Replaces the old full-width top banner: read-only is a posture, not an
 * emergency, so we surface it as a small, persistent pill that links to the
 * Settings toggle. Driven by live server state (``readOnlyMode`` in the UI
 * store, seeded on app mount from GET /system/settings/adapter-read-only).
 *
 * Returns null (no layout footprint) when the platform is in read-write mode.
 * Must render inside the sidebar's TooltipProvider.
 */
export function ReadOnlyBadge({ collapsed }: { collapsed: boolean }) {
  const readOnlyMode = useUIStore((state) => state.readOnlyMode);
  if (!readOnlyMode) return null;

  if (collapsed) {
    return (
      <div className="flex justify-center pt-2">
        <Tooltip>
          <TooltipTrigger asChild>
            <Link
              to="/settings/access"
              aria-label="Read-only mode — device writes are disabled"
              className="flex h-6 w-6 items-center justify-center rounded-md bg-warning/15 text-warning transition-colors hover:bg-warning/25"
            >
              <Eye className="h-3.5 w-3.5" aria-hidden="true" />
            </Link>
          </TooltipTrigger>
          <TooltipContent side="right" sideOffset={10}>
            Read-only — device writes disabled
          </TooltipContent>
        </Tooltip>
      </div>
    );
  }

  return (
    <div className="px-3 pt-2">
      <Link
        to="/settings/access"
        title="Read-only mode — device writes are disabled. Click to change."
        className="flex w-fit items-center gap-1.5 rounded-md bg-warning/10 px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-warning transition-colors hover:bg-warning/20"
      >
        <Eye className="h-3 w-3 shrink-0" aria-hidden="true" />
        Read only
      </Link>
    </div>
  );
}
