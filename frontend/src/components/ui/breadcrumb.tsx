// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Breadcrumb Component
 *
 * Navigation breadcrumbs for deep page hierarchies
 */

import * as React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ChevronRight, Home } from 'lucide-react';
import { cn } from '@/lib/utils';

interface BreadcrumbItem {
  label: string;
  href?: string;
  icon?: React.ElementType;
}

interface BreadcrumbProps {
  items?: BreadcrumbItem[];
  separator?: React.ReactNode;
  showHome?: boolean;
  className?: string;
}

// Auto-generate breadcrumbs from current path.
// Maps a path segment to a translation key suffix under Breadcrumb.paths.*
const pathLabelKeys: Record<string, string> = {
  dashboard: 'dashboard',
  devices: 'devices',
  controllers: 'controllers',
  sites: 'sites',
  cameras: 'cameras',
  voip: 'voip',
  access: 'access',
  firewall: 'firewall',
  users: 'users',
  settings: 'settings',
  discovery: 'discovery',
  organizations: 'organizations',
  network: 'network',
};

export function Breadcrumb({
  items,
  separator = <ChevronRight className="h-4 w-4 text-muted-foreground" />,
  showHome = true,
  className,
}: BreadcrumbProps) {
  const { t } = useTranslation('common');
  const location = useLocation();

  // Auto-generate items from path if not provided
  const breadcrumbItems = React.useMemo(() => {
    if (items) return items;

    const pathParts = location.pathname.split('/').filter(Boolean);
    return pathParts.map((part, index) => {
      const href = '/' + pathParts.slice(0, index + 1).join('/');
      const labelKey = pathLabelKeys[part];
      const label = labelKey
        ? t(`Breadcrumb.paths.${labelKey}`)
        : part.charAt(0).toUpperCase() + part.slice(1);
      return { label, href };
    });
  }, [items, location.pathname, t]);

  if (breadcrumbItems.length === 0) return null;

  return (
    <nav
      aria-label={t('Breadcrumb.ariaLabel')}
      className={cn('flex items-center text-sm', className)}
    >
      <ol className="flex items-center gap-1.5">
        {showHome && (
          <>
            <li>
              <Link
                to="/"
                className="flex items-center text-muted-foreground hover:text-foreground transition-colors"
              >
                <Home className="h-4 w-4" />
              </Link>
            </li>
            {breadcrumbItems.length > 0 && (
              <li className="flex items-center">{separator}</li>
            )}
          </>
        )}
        {breadcrumbItems.map((item, index) => {
          const isLast = index === breadcrumbItems.length - 1;
          const Icon = 'icon' in item ? item.icon : undefined;

          return (
            <React.Fragment key={index}>
              <li>
                {isLast || !item.href ? (
                  <span className={cn(
                    'flex items-center gap-1.5',
                    isLast ? 'font-medium text-foreground' : 'text-muted-foreground'
                  )}>
                    {Icon && <Icon className="h-4 w-4" />}
                    {item.label}
                  </span>
                ) : (
                  <Link
                    to={item.href}
                    className="flex items-center gap-1.5 text-muted-foreground hover:text-foreground transition-colors"
                  >
                    {Icon && <Icon className="h-4 w-4" />}
                    {item.label}
                  </Link>
                )}
              </li>
              {!isLast && (
                <li className="flex items-center">{separator}</li>
              )}
            </React.Fragment>
          );
        })}
      </ol>
    </nav>
  );
}

// Compact breadcrumb variant
export function BreadcrumbCompact({ className }: { className?: string }) {
  const { t } = useTranslation('common');
  const location = useLocation();
  const pathParts = location.pathname.split('/').filter(Boolean);

  if (pathParts.length <= 1) return null;

  const currentPage = pathParts[pathParts.length - 1];
  const parentPage = pathParts[pathParts.length - 2];
  const parentHref = '/' + pathParts.slice(0, -1).join('/');
  const parentLabelKey = pathLabelKeys[parentPage];
  const parentLabel = parentLabelKey
    ? t(`Breadcrumb.paths.${parentLabelKey}`)
    : parentPage.charAt(0).toUpperCase() + parentPage.slice(1);
  const currentLabelKey = pathLabelKeys[currentPage];
  const currentLabel = currentLabelKey
    ? t(`Breadcrumb.paths.${currentLabelKey}`)
    : currentPage.charAt(0).toUpperCase() + currentPage.slice(1);

  return (
    <nav
      aria-label={t('Breadcrumb.ariaLabel')}
      className={cn('flex items-center gap-1.5 text-sm', className)}
    >
      <Link
        to={parentHref}
        className="text-muted-foreground hover:text-foreground transition-colors"
      >
        {parentLabel}
      </Link>
      <ChevronRight className="h-4 w-4 text-muted-foreground" />
      <span className="font-medium">{currentLabel}</span>
    </nav>
  );
}
