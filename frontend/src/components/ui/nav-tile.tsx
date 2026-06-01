// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Design System · NavTile + NavTileGrid + SectionHeading
 *
 * Big-icon navigation tiles for dashboard / overview pages.
 * Replaces every page-local "Quick Access" / "Quick Actions" card grid.
 *
 *   <SectionHeading>Quick Access</SectionHeading>
 *   <NavTileGrid>
 *     <NavTile icon={Network}  title="VLANs"        description="Manage segmentation" count={6} href="/vlans" />
 *     <NavTile icon={Wifi}     title="WiFi Networks" description="Configure SSIDs"   count={4} href="/wifi" />
 *     <NavTile icon={Users}    title="Clients"       description="View connected"    count={34} href="/clients" />
 *   </NavTileGrid>
 */

import { Link } from 'react-router-dom';
import { ArrowRight, type LucideIcon } from 'lucide-react';
import { cn } from '../../lib/utils';
import { Card, CardContent } from './card';

type Tone = 'primary' | 'success' | 'warning' | 'destructive' | 'info' | 'neutral';

const toneClass: Record<Tone, { container: string; icon: string }> = {
  primary:     { container: 'bg-primary/10',     icon: 'text-primary' },
  success:     { container: 'bg-success/10',     icon: 'text-success' },
  warning:     { container: 'bg-warning/10',     icon: 'text-warning' },
  destructive: { container: 'bg-destructive/10', icon: 'text-destructive' },
  info:        { container: 'bg-info/10',        icon: 'text-info' },
  neutral:     { container: 'bg-muted',          icon: 'text-muted-foreground' },
};

interface NavTileProps {
  /** Lucide icon component */
  icon: LucideIcon;
  /** Tile title */
  title: string;
  /** Optional secondary description text */
  description?: string;
  /** Optional count badge (top-right) */
  count?: number | string;
  /** Optional link target. If omitted, renders as button. */
  href?: string;
  /** Click handler (used when href omitted) */
  onClick?: () => void;
  /** Icon container tone */
  tone?: Tone;
  /** Hide the trailing arrow */
  hideArrow?: boolean;
  className?: string;
}

export function NavTile({
  icon: Icon,
  title,
  description,
  count,
  href,
  onClick,
  tone = 'primary',
  hideArrow = false,
  className,
}: NavTileProps) {
  const content = (
    <Card
      className={cn(
        'group transition-all hover:border-primary/30 hover:shadow-md cursor-pointer h-full',
        className,
      )}
    >
      <CardContent noOffset className="p-4 sm:p-5 flex flex-col h-full">
        <div className="flex items-start justify-between gap-2 mb-4">
          <div
            className={cn(
              'flex h-11 w-11 items-center justify-center rounded-xl flex-shrink-0',
              toneClass[tone].container,
            )}
          >
            <Icon className={cn('h-5 w-5', toneClass[tone].icon)} />
          </div>
          {count !== undefined && (
            <span className="text-2xl font-bold tabular-nums text-foreground">{count}</span>
          )}
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="text-base font-semibold text-foreground flex items-center gap-1">
            {title}
            {!hideArrow && (
              <ArrowRight className="h-4 w-4 text-muted-foreground opacity-0 -translate-x-1 group-hover:opacity-100 group-hover:translate-x-0 transition-all" />
            )}
          </h3>
          {description && (
            <p className="text-sm text-muted-foreground mt-1">{description}</p>
          )}
        </div>
      </CardContent>
    </Card>
  );

  if (href) {
    return (
      <Link to={href} className="block h-full">
        {content}
      </Link>
    );
  }

  if (onClick) {
    return (
      <button onClick={onClick} type="button" className="block w-full text-left h-full">
        {content}
      </button>
    );
  }

  return content;
}

// ============================================================================
// NavTileGrid · responsive grid wrapper
// ============================================================================

interface NavTileGridProps {
  children: React.ReactNode;
  /** Number of columns at lg+ breakpoint. Default 4. */
  columns?: 2 | 3 | 4;
  className?: string;
}

const gridCols: Record<2 | 3 | 4, string> = {
  2: 'grid-cols-1 sm:grid-cols-2',
  3: 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3',
  4: 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-4',
};

export function NavTileGrid({ children, columns = 4, className }: NavTileGridProps) {
  return (
    <div className={cn('grid gap-4', gridCols[columns], className)}>
      {children}
    </div>
  );
}

// ============================================================================
// SectionHeading · consistent label for sub-sections inside dashboard pages
// ============================================================================

interface SectionHeadingProps {
  children: React.ReactNode;
  /** Optional icon before the heading */
  icon?: LucideIcon;
  /** Optional action element (right-aligned) · link, button, etc. */
  action?: React.ReactNode;
  /** Optional description below the heading */
  description?: string;
  /** Heading level (semantic only · visual style is consistent) */
  as?: 'h2' | 'h3';
  className?: string;
}

export function SectionHeading({
  children,
  icon: Icon,
  action,
  description,
  as = 'h2',
  className,
}: SectionHeadingProps) {
  const HeadingTag = as;
  return (
    <div className={cn('flex flex-col sm:flex-row sm:items-end sm:justify-between gap-2 sm:gap-4', className)}>
      <div className="min-w-0">
        <HeadingTag className="text-lg font-semibold tracking-tight text-foreground flex items-center gap-2">
          {Icon && <Icon className="h-5 w-5 text-muted-foreground flex-shrink-0" />}
          <span className="truncate">{children}</span>
        </HeadingTag>
        {description && (
          <p className="text-sm text-muted-foreground mt-0.5">{description}</p>
        )}
      </div>
      {action && <div className="flex-shrink-0">{action}</div>}
    </div>
  );
}
