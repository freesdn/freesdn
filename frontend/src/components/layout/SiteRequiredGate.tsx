// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Site-required gate
 *
 * Discovery and Topology work on one site at a time (SITE_ONLY_PATHS). In the
 * "All Sites" view MainLayout used to bounce them to the dashboard without a
 * word, so a sidebar click, a bookmark, the command palette, `g y`, and the
 * "Add device" redirect (/devices/new -> /discovery) all silently landed on
 * the dashboard. The restriction stays; this explains it and lets the user
 * pick a site in place.
 */
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Building2, ChevronRight, MapPin } from 'lucide-react';
import { useSiteStore } from '@/stores/siteStore';
import { Card, CardContent } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { sitesApiV2 } from '@/lib/api/sites';

export function SiteRequiredGate() {
  const { t } = useTranslation('common');
  const sites = useSiteStore((s) => s.sites);
  const selectSite = useSiteStore((s) => s.selectSite);
  // Same query as the TopBar SiteSelector (shared cache): the store's list is
  // empty until it lands, which must read as loading, not as "no sites".
  const { isPending } = useQuery({
    queryKey: ['sites-selector'],
    queryFn: async () => (await sitesApiV2.list({ page_size: 100 })).data,
    staleTime: 30_000,
  });

  return (
    <div className="mx-auto max-w-xl py-10 sm:py-16" role="region" aria-labelledby="site-required-title">
      <div className="flex flex-col items-center text-center">
        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
          <MapPin className="h-6 w-6 text-primary" aria-hidden />
        </div>
        <h1 id="site-required-title" className="mt-4 text-xl font-semibold tracking-tight">
          {t('SiteRequiredGate.title')}
        </h1>
        <p className="mt-2 text-sm text-muted-foreground">{t('SiteRequiredGate.description')}</p>
      </div>

      <Card className="mt-6">
        <CardContent noOffset className="p-2">
          {sites.length === 0 && isPending ? (
            <div className="space-y-2 p-2" aria-busy="true">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : sites.length === 0 ? (
            <div className="p-4 text-center text-sm text-muted-foreground">
              {t('SiteRequiredGate.noSites')}{' '}
              <Link to="/sites" className="font-medium text-primary hover:underline">
                {t('SiteRequiredGate.manageSites')}
              </Link>
            </div>
          ) : (
            <ul className="divide-y divide-border" aria-label={t('SiteRequiredGate.listLabel')}>
              {sites.map((site) => (
                <li key={site.id}>
                  <button
                    type="button"
                    onClick={() => selectSite(site.id)}
                    className="flex w-full items-center gap-3 rounded-md px-3 py-2.5 text-left text-sm transition-colors hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  >
                    <Building2 className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
                    <span className="min-w-0 flex-1 truncate font-medium">{site.name}</span>
                    <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
