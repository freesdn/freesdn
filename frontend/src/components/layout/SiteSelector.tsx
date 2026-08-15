// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Global Site Selector
 *
 * Dropdown in the TopBar that lets users switch between "All Sites" (global)
 * and a specific site. Persists selection via siteStore (localStorage).
 * All pages react to site changes via useSiteFilteredQuery.
 */
import { useState, useMemo, useEffect, useRef, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import {
  ChevronDown,
  Search,
  Plus,
  Globe,
  Check,
} from 'lucide-react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from '../ui/dropdown-menu';
import { cn } from '../../lib/utils';
import { useSiteStore } from '../../stores/siteStore';
import { sitesApiV2 } from '../../lib/api/sites';
import { useAuthStore } from '../../stores/authStore';
import { useNavigate } from 'react-router-dom';
import type { Site } from '../../lib/api/types';

/** Map API health status to dot color class */
function healthDotColor(
  totalDevices: number,
  onlineDevices: number,
  criticalAlerts: number
): string {
  if (totalDevices === 0) return 'bg-muted-foreground'; // gray
  if (criticalAlerts > 0 || onlineDevices < totalDevices * 0.5)
    return 'bg-red-500'; // red
  if (onlineDevices < totalDevices) return 'bg-yellow-500'; // yellow
  return 'bg-green-500'; // green
}

export function SiteSelector() {
  const { t } = useTranslation('common');
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const searchRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const { isAuthenticated } = useAuthStore();

  const { selectedSiteId, selectSite, setSites } = useSiteStore();

  // Fetch sites list
  const { data: sitesData } = useQuery({
    queryKey: ['sites-selector'],
    queryFn: async () => {
      const res = await sitesApiV2.list({ page_size: 100 });
      return res.data;
    },
    enabled: isAuthenticated,
    staleTime: 30_000,
    refetchInterval: 60_000,
  });

  // Sync API response into siteStore
  useEffect(() => {
    const items: Site[] = sitesData?.items ?? [];
    if (items.length > 0 || sitesData) {
      setSites(
        items.map((s) => ({
          id: s.id,
          name: s.name,
          site_type: s.site_type,
          is_active: true,
        }))
      );
    }
  }, [sitesData, setSites]);

  const apiSites: Site[] = useMemo(() => sitesData?.items ?? [], [sitesData]);

  // Filter sites by search
  const filteredSites = useMemo(() => {
    if (!search.trim()) return apiSites;
    const q = search.toLowerCase();
    return apiSites.filter(
      (s) =>
        s.name.toLowerCase().includes(q) ||
        s.city?.toLowerCase().includes(q) ||
        s.country?.toLowerCase().includes(q)
    );
  }, [apiSites, search]);

  // Current site from API data (richer than siteStore's SiteInfo)
  const currentSite = apiSites.find((s) => s.id === selectedSiteId);

  // Auto-focus search when dropdown opens
  useEffect(() => {
    if (open) {
      setSearch('');
      setTimeout(() => searchRef.current?.focus(), 50);
    }
  }, [open]);

  const handleSelect = useCallback(
    (siteId: string | null) => {
      selectSite(siteId);
      setOpen(false);
    },
    [selectSite]
  );

  // Keyboard shortcut: Ctrl+Shift+S
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'S') {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  return (
    <DropdownMenu open={open} onOpenChange={setOpen}>
      <DropdownMenuTrigger asChild>
        <button
          className={cn(
            'flex items-center gap-2 px-2 sm:px-3 py-1.5 rounded-lg border transition-colors',
            'bg-secondary/50 border-border hover:bg-secondary hover:border-border/80',
            'focus:outline-none focus:ring-2 focus:ring-primary/30',
            // Tighter cap on phones so the TopBar gutter has room for icons
            'max-w-[160px] sm:max-w-[240px]'
          )}
          aria-label={t('SiteSelector.ariaLabel.selector')}
        >
          {selectedSiteId && currentSite ? (
            <>
              <span
                className={cn(
                  'w-2 h-2 rounded-full flex-shrink-0',
                  healthDotColor(
                    currentSite.device_count,
                    currentSite.online_device_count,
                    0
                  )
                )}
              />
              <span className="text-sm font-medium truncate">
                {currentSite.name}
              </span>
            </>
          ) : (
            <>
              <Globe className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />
              <span className="text-sm font-medium">{t('SiteSelector.allSites')}</span>
            </>
          )}
          <ChevronDown className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />
        </button>
      </DropdownMenuTrigger>

      <DropdownMenuContent align="start" className="w-[min(92vw,18rem)] p-0">
        {/* Search */}
        <div className="p-2 border-b border-border">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <input
              ref={searchRef}
              type="text"
              placeholder={t('SiteSelector.searchPlaceholder')}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full h-8 pl-8 pr-3 rounded-md bg-background border border-border text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary/30"
              aria-label={t('SiteSelector.ariaLabel.search')}
            />
          </div>
        </div>

        {/* All Sites option */}
        <button
          onClick={() => handleSelect(null)}
          className={cn(
            'w-full flex items-center gap-3 px-3 py-2.5 text-left transition-colors',
            'hover:bg-muted/50',
            selectedSiteId === null && 'bg-primary/5'
          )}
        >
          <Globe className="h-4 w-4 text-muted-foreground flex-shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="text-sm font-medium">{t('SiteSelector.allSites')}</div>
            <div className="text-[11px] text-muted-foreground">
              {t(
                apiSites.length !== 1
                  ? 'SiteSelector.allSitesSummary'
                  : 'SiteSelector.allSitesSummary_one',
                {
                  count: apiSites.length,
                  devices: apiSites.reduce(
                    (sum, s) => sum + s.device_count,
                    0
                  ),
                }
              )}
            </div>
          </div>
          {selectedSiteId === null && (
            <Check className="h-4 w-4 text-primary flex-shrink-0" />
          )}
        </button>

        <div className="border-t border-border" />

        {/* Sites list */}
        <div className="max-h-64 overflow-y-auto">
          {filteredSites.length === 0 ? (
            <div className="py-6 text-center text-sm text-muted-foreground">
              {search
                ? t('SiteSelector.empty.noMatch')
                : t('SiteSelector.empty.none')}
            </div>
          ) : (
            filteredSites.map((site) => (
              <button
                key={site.id}
                onClick={() => handleSelect(site.id)}
                className={cn(
                  'w-full flex items-center gap-3 px-3 py-2.5 text-left transition-colors',
                  'hover:bg-muted/50',
                  selectedSiteId === site.id && 'bg-primary/5'
                )}
              >
                <span
                  className={cn(
                    'w-2 h-2 rounded-full flex-shrink-0',
                    healthDotColor(
                      site.device_count,
                      site.online_device_count,
                      0
                    )
                  )}
                />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium truncate">
                    {site.name}
                  </div>
                  <div className="text-[11px] text-muted-foreground">
                    {t(
                      site.device_count !== 1
                        ? 'SiteSelector.deviceCount'
                        : 'SiteSelector.deviceCount_one',
                      { count: site.device_count }
                    )}
                    {site.online_device_count < site.device_count && (
                      <span className="text-yellow-600 dark:text-yellow-400">
                        {' '}
                        &middot;{' '}
                        {t('SiteSelector.offline', {
                          count:
                            site.device_count - site.online_device_count,
                        })}
                      </span>
                    )}
                  </div>
                </div>
                {selectedSiteId === site.id && (
                  <Check className="h-4 w-4 text-primary flex-shrink-0" />
                )}
              </button>
            ))
          )}
        </div>

        {/* Add Site footer */}
        <div className="border-t border-border">
          <button
            onClick={() => {
              setOpen(false);
              navigate('/sites');
            }}
            className="w-full flex items-center gap-2 px-3 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors"
          >
            <Plus className="h-3.5 w-3.5" />
            {t('SiteSelector.manageSites')}
          </button>
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
