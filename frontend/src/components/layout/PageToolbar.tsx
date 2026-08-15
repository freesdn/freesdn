// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Page Toolbar
 *
 * Consistent toolbar placed between PageHeader and page content.
 * Supports: search bar, filter dropdowns, action buttons.
 *
 * Usage:
 *   <PageToolbar>
 *     <SearchBar value={q} onChange={setQ} placeholder="Search devices…" />
 *     <Select … />
 *     <Button variant="outline" onClick={refresh}>Refresh</Button>
 *   </PageToolbar>
 */

import { cn } from '@/lib/utils';

export interface PageToolbarProps {
  children: React.ReactNode;
  className?: string;
}

export function PageToolbar({ children, className }: PageToolbarProps) {
  return (
    <div
      className={cn(
        // gap-y so wrapped rows breathe; gap-x stays modest on phones
        'flex flex-wrap items-center gap-x-2 gap-y-2 sm:gap-3',
        // Children that contain SearchBar (`flex-1`) tend to push siblings off
        // screen at 360px · `min-w-0` lets them shrink instead of overflowing.
        '[&>*]:min-w-0',
        className,
      )}
    >
      {children}
    </div>
  );
}

export default PageToolbar;
