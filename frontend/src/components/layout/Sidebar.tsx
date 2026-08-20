// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useState, useMemo, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { NavLink, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { useQuery } from '@tanstack/react-query';
import {
  Network,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  Settings,
  Shield,
  ShieldAlert,
  AlertTriangle,
  SlidersHorizontal,
  RotateCcw,
  BellOff,
  Clock,
  LayoutDashboard,
} from 'lucide-react';
import { cn } from '../../lib/utils';
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
  TooltipProvider,
} from '../ui/tooltip';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
  DropdownMenuCheckboxItem,
  DropdownMenuRadioItem,
  DropdownMenuRadioGroup,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuItem,
} from '../ui/dropdown-menu';
import { api } from '../../lib/api';
import { useAuthStore } from '../../stores/authStore';
import { useModuleStore } from '../../stores/moduleStore';
import {
  useAlertBadgeStore,
  passesThreshold,
  type BadgeSeverityThreshold,
} from '../../stores/alertBadgeStore';
import { useSiteStore } from '../../stores/siteStore';
import {
  useSidebarStore,
  useRecentRoutes,
  RECENT_VISIBILITY_THRESHOLD,
  type SectionId,
} from '../../stores/sidebarStore';
import {
  buildSections,
  type NavItem,
  type NavSection,
} from '../../lib/nav-data';
import { ReadOnlyBadge } from '../ReadOnlyBadge';

// Lightweight types for badge computation (avoids depending on full API types)
interface SecurityEvent {
  success: boolean;
  timestamp: string;
  risk_score: number;
}

interface AlertInstance {
  status: string;
  severity?: string;
  fired_at?: string;
  created_at?: string;
}

interface IncidentItem {
  status: string;
  severity?: string;
  opened_at?: string;
  created_at?: string;
}

interface SidebarProps {
  collapsed: boolean;
  onCollapsedChange: (collapsed: boolean) => void;
  /** Mobile drawer open state (sub-lg breakpoint). */
  mobileOpen?: boolean;
  /** Called when the mobile drawer wants to open or close (backdrop click, navigation, etc.) */
  onMobileOpenChange?: (open: boolean) => void;
}

export function Sidebar({
  collapsed,
  onCollapsedChange,
  mobileOpen = false,
  onMobileOpenChange,
}: SidebarProps) {
  const { t } = useTranslation('common');
  const [searchQuery, setSearchQuery] = useState('');
  const location = useLocation();
  const { isAuthenticated } = useAuthStore();
  // Subscribe to the enabledModules ARRAY (not the stable isModuleEnabled
  // function): selecting the function never changes reference, so the sidebar
  // would not re-render when a module is enabled/disabled — leaving the nav
  // stale until a hard refresh. Selecting the array re-renders + recomputes the
  // nav the moment enablement changes.
  const enabledModules = useModuleStore((s) => s.enabledModules);
  const badgePrefs = useAlertBadgeStore();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const isInSite = selectedSiteId !== null;
  const sectionsState = useSidebarStore((s) => s.sections);
  const toggleSection = useSidebarStore((s) => s.toggleSection);
  const expandSection = useSidebarStore((s) => s.expandSection);
  const recentRoutes = useRecentRoutes();

  // ── Data queries (shared keys with AlertsPage for cache reuse) ──

  const { data: alertsData } = useQuery({
    queryKey: ['security-events'],
    queryFn: async () => {
      // ``per_page``, not ``limit``. GET /audit/security paginates on
      // page/per_page (default 50, max 200); ``limit`` is not a parameter it
      // accepts, so it was silently ignored and every request came back with
      // 50 rows. The alert badge counts UNSUCCESSFUL events out of that page,
      // so it could never reflect more than the first 50 -- undercounting
      // exactly when there is a burst worth noticing.
      const response = await api.get('/audit/security', { params: { per_page: 200 } });
      return response.data;
    },
    enabled: isAuthenticated,
    staleTime: 30_000,
    refetchInterval: 60_000,
  });

  const { data: ruleStatsData } = useQuery({
    queryKey: ['alert-rules-stats'],
    queryFn: async () => {
      const response = await api.get('/alert-rules/stats');
      return response.data;
    },
    enabled: isAuthenticated,
    staleTime: 30_000,
    refetchInterval: 60_000,
  });

  const { data: correlationStatsData } = useQuery({
    queryKey: ['correlation-stats'],
    queryFn: async () => {
      const response = await api.get('/correlation/stats');
      return response.data;
    },
    enabled: isAuthenticated,
    staleTime: 30_000,
    refetchInterval: 60_000,
  });

  // Fetch individual alert instances when severity filtering is active
  // so we can filter per-item (stats only give aggregate counts).
  const needsItemLevel = badgePrefs.minSeverity !== 'all' || badgePrefs.lastReviewedAt !== null;

  const { data: alertInstancesData } = useQuery({
    queryKey: ['sidebar-alert-instances'],
    queryFn: async () => {
      const response = await api.get('/alert-rules/alerts', { params: { limit: 200, status: 'firing' } });
      return response.data;
    },
    enabled: isAuthenticated && needsItemLevel && badgePrefs.sources.rules,
    staleTime: 30_000,
    refetchInterval: 60_000,
  });

  const { data: incidentsData } = useQuery({
    queryKey: ['sidebar-incidents'],
    queryFn: async () => {
      const response = await api.get('/correlation/incidents', { params: { limit: 200, status: 'open' } });
      return response.data;
    },
    enabled: isAuthenticated && needsItemLevel && badgePrefs.sources.incidents,
    staleTime: 30_000,
    refetchInterval: 60_000,
  });

  // ── Badge count computation (respects preferences) ──

  const totalAlertCount = useMemo(() => {
    const { sources, minSeverity, lastReviewedAt } = badgePrefs;
    const cutoff = lastReviewedAt ? new Date(lastReviewedAt).getTime() : 0;

    let count = 0;

    // Security events
    if (sources.security) {
      const events: SecurityEvent[] = Array.isArray(alertsData) ? alertsData : alertsData?.items || [];
      count += events.filter((e: SecurityEvent) => {
        if (e.success) return false;
        if (cutoff && new Date(e.timestamp).getTime() <= cutoff) return false;
        if (minSeverity !== 'all') {
          const sev = e.risk_score >= 80 ? 'critical' : e.risk_score >= 60 ? 'high' : e.risk_score >= 30 ? 'warning' : 'info';
          if (!passesThreshold(sev, minSeverity)) return false;
        }
        return true;
      }).length;
    }

    // Rule alerts
    if (sources.rules) {
      if (needsItemLevel) {
        const alerts: AlertInstance[] = alertInstancesData?.data?.alerts || alertInstancesData?.alerts || [];
        count += alerts.filter((a: AlertInstance) => {
          if (a.status !== 'firing') return false;
          if (cutoff && new Date(a.fired_at || a.created_at || '').getTime() <= cutoff) return false;
          if (minSeverity !== 'all' && !passesThreshold(a.severity || 'info', minSeverity)) return false;
          return true;
        }).length;
      } else {
        count += ruleStatsData?.firing_alerts || 0;
      }
    }

    // Incidents
    if (sources.incidents) {
      if (needsItemLevel) {
        const incidents: IncidentItem[] = incidentsData?.data?.incidents || incidentsData?.incidents || [];
        count += incidents.filter((i: IncidentItem) => {
          if (!['open', 'investigating', 'mitigating'].includes(i.status)) return false;
          if (cutoff && new Date(i.opened_at || i.created_at || '').getTime() <= cutoff) return false;
          if (minSeverity !== 'all' && !passesThreshold(i.severity || 'info', minSeverity)) return false;
          return true;
        }).length;
      } else {
        count += correlationStatsData?.open_incidents || 0;
      }
    }

    return count;
  }, [badgePrefs, alertsData, ruleStatsData, correlationStatsData, alertInstancesData, incidentsData, needsItemLevel]);

  // ── Build sections from shared nav data, then apply gating ──

  const filterBySiteContext = (items: NavItem[]): NavItem[] =>
    items.filter((item) => {
      if (!item.siteVisibility) return true;
      if (item.siteVisibility === 'global') return !isInSite;
      if (item.siteVisibility === 'site') return isInSite;
      return true;
    });

  const filterByModule = (items: NavItem[]): NavItem[] =>
    items.filter((item) => !item.moduleId || enabledModules.includes(item.moduleId));

  const allSections: NavSection[] = useMemo(() => {
    const built = buildSections(totalAlertCount, t);
    return built
      .map((section) => ({
        ...section,
        // Dashboard is rendered as a top-level pinned item below · don't duplicate inside Overview
        items: filterBySiteContext(
          filterByModule(section.items.filter((i) => i.href !== '/')),
        ),
      }))
      .filter((section) => section.items.length > 0);
    // `t` MUST stay in the deps: react-i18next hands out a new `t` when the
    // language changes, and rebuilding here is what re-translates the sidebar
    // labels live. Omitting it froze the sidebar in the boot language until a
    // full page refresh.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [totalAlertCount, isInSite, enabledModules, t]);

  // Dashboard is the home page · pinned at the top of the sidebar, always visible.
  const isDashboardActive =
    location.pathname === '/' || location.pathname === '/dashboard';

  // ── Filter by sidebar search input ──

  const trimmedQuery = searchQuery.trim().toLowerCase();
  const filteredSections: NavSection[] = useMemo(() => {
    if (!trimmedQuery) return allSections;
    return allSections
      .map((section) => ({
        ...section,
        items: section.items.filter((item) => {
          const haystack = [item.name, ...(item.keywords ?? [])].join(' ').toLowerCase();
          return haystack.includes(trimmedQuery);
        }),
      }))
      .filter((section) => section.items.length > 0);
  }, [allSections, trimmedQuery]);

  // ── Compute active item + active section ──

  const allItems = useMemo(
    () => allSections.flatMap((s) => s.items.map((i) => ({ ...i, _sectionId: s.id }))),
    [allSections],
  );

  const activeItem = useMemo(() => {
    return allItems
      .filter(
        (item) =>
          location.pathname === item.href ||
          (item.href !== '/' && location.pathname.startsWith(item.href + '/')),
      )
      .sort((a, b) => b.href.length - a.href.length)[0] ?? null;
  }, [allItems, location.pathname]);

  const activeSectionId = activeItem?._sectionId ?? null;

  // ── Auto-expand the active section so users always see their location ──
  useEffect(() => {
    if (activeSectionId && !sectionsState[activeSectionId]) {
      expandSection(activeSectionId);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeSectionId]);

  // ── Auto-expand all sections that match the current search ──
  useEffect(() => {
    if (!trimmedQuery) return;
    filteredSections.forEach((s) => {
      if (!sectionsState[s.id]) expandSection(s.id);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [trimmedQuery, filteredSections.length]);

  // ── Recent routes (excluding current path) ──
  const recentItems = useMemo(() => {
    return recentRoutes
      .filter((r) => r.path !== location.pathname)
      .slice(0, 3);
  }, [recentRoutes, location.pathname]);

  const closeMobile = () => onMobileOpenChange?.(false);

  return (
    <TooltipProvider delayDuration={0}>
      {/* Mobile backdrop */}
      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="lg:hidden fixed inset-0 z-40 bg-black/50 backdrop-blur-sm"
            onClick={closeMobile}
            aria-hidden="true"
          />
        )}
      </AnimatePresence>

      <motion.aside
        initial={false}
        animate={{ width: collapsed ? 72 : 256 }}
        transition={{ duration: 0.2, ease: 'easeInOut' }}
        className={cn(
          'flex flex-col h-screen fixed left-0 top-0 z-50 bg-sidebar border-r border-border overflow-hidden',
          'transition-transform duration-200 ease-in-out lg:translate-x-0',
          mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0',
        )}
      >
        {/* Logo */}
        <div className="flex h-16 items-center px-4 border-b border-border">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-xl bg-gradient-to-br from-primary to-primary/80 flex items-center justify-center shadow-lg shadow-primary/20">
              <Network className="h-5 w-5 text-primary-foreground" />
            </div>
            <AnimatePresence mode="wait">
              {!collapsed && (
                <motion.span
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -10 }}
                  className="text-lg font-semibold text-foreground"
                >
                  FreeSDN
                </motion.span>
              )}
            </AnimatePresence>
          </div>
        </div>

        {/* Read-only posture · subtle indicator under the logo (null when read-write) */}
        <ReadOnlyBadge collapsed={collapsed} />

        {/* Search (when expanded) */}
        {!collapsed && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="px-3 py-3"
          >
            <form className="relative" autoComplete="off" onSubmit={(e) => e.preventDefault()}>
              <input
                type="search"
                placeholder={t('Sidebar.search.placeholder')}
                aria-label={t('Sidebar.search.ariaLabel')}
                id="freesdn-nav-search"
                name="freesdn-nav-filter"
                autoComplete="new-password"
                data-1p-ignore
                data-lpignore="true"
                data-form-type="other"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full h-9 pl-9 pr-3 rounded-lg bg-secondary border border-border text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary/30 transition-all"
              />
              <svg className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </form>
          </motion.div>
        )}

        {/* Navigation */}
        <nav
          aria-label="Main navigation"
          className="flex-1 overflow-y-auto px-3 py-2 scrollbar-thin scrollbar-thumb-border scrollbar-track-transparent"
        >
          {/* ── Dashboard · pinned home item, always visible at the top ── */}
          {!trimmedQuery && (
            <div className={cn('mb-2', !collapsed && 'pb-2 border-b border-border/50')}>
              <NavLink
                to="/"
                onClick={closeMobile}
                className={cn(
                  'relative flex items-center gap-3 h-9 rounded-lg px-3 text-[13px] font-medium transition-all',
                  isDashboardActive
                    ? 'bg-primary/15 text-primary'
                    : 'text-foreground hover:bg-secondary',
                  collapsed && 'justify-center px-0',
                )}
              >
                {isDashboardActive && (
                  <motion.div
                    layoutId="activeIndicator"
                    className="absolute -left-3 inset-y-0 my-auto w-[3px] h-5 bg-primary rounded-r-full"
                    transition={{ type: 'spring', stiffness: 500, damping: 30 }}
                  />
                )}
                <LayoutDashboard className={cn('h-4 w-4 flex-shrink-0', collapsed && 'h-5 w-5')} />
                {!collapsed && <span className="truncate">{t('Sidebar.dashboard')}</span>}
              </NavLink>
            </div>
          )}

          {/* ── Recent section (only after user has visited 5+ distinct nav routes) ── */}
          {!collapsed &&
            !trimmedQuery &&
            recentRoutes.length >= RECENT_VISIBILITY_THRESHOLD &&
            recentItems.length > 0 && (
            <div className="mb-2">
              <div className="flex items-center gap-1.5 text-[10px] font-semibold text-muted-foreground uppercase tracking-wider px-3 mb-1.5 mt-1">
                <Clock className="h-3 w-3" />
                {t('Sidebar.recent')}
              </div>
              <div className="space-y-0.5">
                {recentItems.map((r) => (
                  <NavLink
                    key={r.path}
                    to={r.path}
                    onClick={closeMobile}
                    className="flex items-center gap-3 h-8 rounded-lg px-3 text-[13px] text-muted-foreground hover:bg-secondary hover:text-foreground transition-all"
                  >
                    <Clock className="h-3.5 w-3.5 flex-shrink-0 opacity-60" />
                    <span className="truncate">{r.label}</span>
                  </NavLink>
                ))}
              </div>
              <div className="my-2 mx-3 border-t border-border/50" />
            </div>
          )}

          {filteredSections.map((section, index) => {
            const expanded = sectionsState[section.id] ?? true;
            const sectionBadge = section.items.reduce(
              (sum, i) => sum + (i.badge ?? 0),
              0,
            );
            const isActiveSection = activeSectionId === section.id;
            const SectionIcon = section.icon;

            return (
              <div key={section.id}>
                {/* Section header · collapsible */}
                {!collapsed ? (
                  <button
                    type="button"
                    onClick={() => toggleSection(section.id)}
                    className={cn(
                      'w-full flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider px-3 py-1.5 mt-1 rounded transition-colors',
                      isActiveSection
                        ? 'text-foreground'
                        : 'text-muted-foreground hover:text-foreground',
                    )}
                    aria-expanded={expanded}
                    aria-controls={`sidebar-section-${section.id}`}
                  >
                    <SectionIcon className="h-3 w-3 opacity-70" />
                    <span className="flex-1 text-left">{section.title}</span>
                    {sectionBadge > 0 && (
                      <span className="flex h-4 min-w-4 items-center justify-center rounded-full bg-destructive px-1 text-[9px] font-semibold text-destructive-foreground">
                        {sectionBadge > 99 ? '99+' : sectionBadge}
                      </span>
                    )}
                    <ChevronDown
                      className={cn(
                        'h-3 w-3 transition-transform',
                        expanded ? 'rotate-0' : '-rotate-90',
                      )}
                    />
                  </button>
                ) : (
                  // Collapsed sidebar: tiny divider with section icon (decorative)
                  <div className="flex justify-center py-1.5 mt-1">
                    <SectionIcon className="h-3 w-3 text-muted-foreground/50" />
                  </div>
                )}

                {/* Section items */}
                <AnimatePresence initial={false}>
                  {(collapsed || expanded) && (
                    <motion.div
                      id={`sidebar-section-${section.id}`}
                      initial={collapsed ? false : { height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.15 }}
                      className="space-y-0.5 overflow-hidden"
                    >
                      {section.items.map((item) => (
                        <SidebarItem
                          key={item.href}
                          item={item}
                          collapsed={collapsed}
                          isActive={item.href === activeItem?.href}
                          onNavigate={closeMobile}
                        />
                      ))}
                    </motion.div>
                  )}
                </AnimatePresence>

                {index < filteredSections.length - 1 && (
                  <div className="my-2 mx-3 border-t border-border/50" />
                )}
              </div>
            );
          })}
        </nav>

        {/* Footer */}
        <div className="border-t border-border p-3 space-y-1">
          <SidebarItem
            item={{ name: t('Sidebar.settings'), href: '/settings', icon: Settings }}
            collapsed={collapsed}
            isActive={location.pathname === '/settings' || location.pathname.startsWith('/settings/')}
            onNavigate={closeMobile}
          />

          <button
            onClick={() => onCollapsedChange(!collapsed)}
            aria-label={collapsed ? t('Sidebar.expand') : t('Sidebar.collapse')}
            className="w-full flex items-center justify-center h-9 rounded-lg text-muted-foreground hover:text-foreground hover:bg-secondary transition-all"
          >
            {collapsed ? (
              <ChevronRight className="h-4 w-4" />
            ) : (
              <ChevronLeft className="h-4 w-4" />
            )}
          </button>
        </div>
      </motion.aside>
    </TooltipProvider>
  );
}

interface SidebarItemProps {
  item: NavItem | { name: string; href: string; icon: NavItem['icon'] };
  collapsed: boolean;
  isActive: boolean;
  onNavigate?: () => void;
}

function SidebarItem({ item, collapsed, isActive, onNavigate }: SidebarItemProps) {
  const { t } = useTranslation('common');
  const badgePrefs = useAlertBadgeStore();
  const navItem = item as NavItem;
  const hasBadgeSettings = navItem.badgeSettings === true;

  // ── Badge element (with optional dropdown) ──

  const badgePill = navItem.badge ? (
    <span className="flex h-5 min-w-5 items-center justify-center rounded-full bg-destructive px-1.5 text-[10px] font-semibold text-destructive-foreground">
      {navItem.badge > 99 ? '99+' : navItem.badge}
    </span>
  ) : null;

  /** Badge + settings dropdown (only for items with badgeSettings flag) */
  const badgeWithSettings =
    !collapsed && hasBadgeSettings ? (
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button
            className="ml-auto flex items-center gap-1 group/badge focus:outline-none"
            onClick={(e) => e.preventDefault()}
            title={t('Sidebar.badge.settings')}
            aria-label={t('Sidebar.badge.settings')}
          >
            {badgePill || (
              <span className="flex h-5 min-w-5 items-center justify-center rounded-full bg-muted px-1.5 text-[10px] font-medium text-muted-foreground opacity-0 group-hover/badge:opacity-100 transition-opacity">
                <SlidersHorizontal className="h-3 w-3" />
              </span>
            )}
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent side="right" align="start" className="w-56">
          <DropdownMenuLabel className="flex items-center gap-2 text-xs">
            <SlidersHorizontal className="h-3.5 w-3.5" />
            {t('Sidebar.badge.settings')}
          </DropdownMenuLabel>
          <DropdownMenuSeparator />

          {/* Source toggles */}
          <DropdownMenuLabel className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">
            {t('Sidebar.badge.sources')}
          </DropdownMenuLabel>
          <DropdownMenuCheckboxItem
            checked={badgePrefs.sources.rules}
            onCheckedChange={() => badgePrefs.toggleSource('rules')}
            onSelect={(e) => e.preventDefault()}
          >
            <ShieldAlert className="h-3.5 w-3.5 mr-2" />
            {t('Sidebar.badge.alertRules')}
          </DropdownMenuCheckboxItem>
          <DropdownMenuCheckboxItem
            checked={badgePrefs.sources.incidents}
            onCheckedChange={() => badgePrefs.toggleSource('incidents')}
            onSelect={(e) => e.preventDefault()}
          >
            <AlertTriangle className="h-3.5 w-3.5 mr-2" />
            {t('Sidebar.badge.incidents')}
          </DropdownMenuCheckboxItem>
          <DropdownMenuCheckboxItem
            checked={badgePrefs.sources.security}
            onCheckedChange={() => badgePrefs.toggleSource('security')}
            onSelect={(e) => e.preventDefault()}
          >
            <Shield className="h-3.5 w-3.5 mr-2" />
            {t('Sidebar.badge.securityEvents')}
          </DropdownMenuCheckboxItem>
          <DropdownMenuSeparator />

          {/* Severity threshold */}
          <DropdownMenuLabel className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">
            {t('Sidebar.badge.minimumSeverity')}
          </DropdownMenuLabel>
          <DropdownMenuRadioGroup
            value={badgePrefs.minSeverity}
            onValueChange={(v) => badgePrefs.setMinSeverity(v as BadgeSeverityThreshold)}
          >
            <DropdownMenuRadioItem value="all" onSelect={(e) => e.preventDefault()}>
              {t('Sidebar.severity.all')}
            </DropdownMenuRadioItem>
            <DropdownMenuRadioItem value="info" onSelect={(e) => e.preventDefault()}>
              {t('Sidebar.severity.info')}
            </DropdownMenuRadioItem>
            <DropdownMenuRadioItem value="warning" onSelect={(e) => e.preventDefault()}>
              {t('Sidebar.severity.warning')}
            </DropdownMenuRadioItem>
            <DropdownMenuRadioItem value="critical" onSelect={(e) => e.preventDefault()}>
              {t('Sidebar.severity.critical')}
            </DropdownMenuRadioItem>
          </DropdownMenuRadioGroup>
          <DropdownMenuSeparator />

          {/* Actions */}
          <DropdownMenuItem
            className="text-primary"
            onSelect={() => badgePrefs.markAllReviewed()}
          >
            <BellOff className="h-3.5 w-3.5 mr-2" />
            {t('Sidebar.badge.clear')}
          </DropdownMenuItem>
          <DropdownMenuItem
            className="text-muted-foreground"
            onSelect={() => badgePrefs.resetPreferences()}
          >
            <RotateCcw className="h-3.5 w-3.5 mr-2" />
            {t('Sidebar.badge.reset')}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    ) : !collapsed && badgePill ? (
      <span className="ml-auto">{badgePill}</span>
    ) : null;

  const Icon = item.icon;

  const content = (
    <NavLink
      to={item.href}
      onClick={() => onNavigate?.()}
      className={cn(
        'relative flex items-center gap-3 h-9 rounded-lg px-3 text-sm font-medium transition-all duration-200',
        isActive
          ? 'bg-primary/15 text-primary'
          : 'text-muted-foreground hover:bg-secondary hover:text-foreground',
        collapsed && 'justify-center px-0',
      )}
    >
      {isActive && (
        <motion.div
          layoutId="activeIndicator"
          className="absolute -left-3 inset-y-0 my-auto w-[3px] h-5 bg-primary rounded-r-full"
          transition={{ type: 'spring', stiffness: 500, damping: 30 }}
        />
      )}
      <Icon className={cn('h-4 w-4 flex-shrink-0', collapsed && 'h-5 w-5')} />
      {/*
        Plain conditional label · NOT a framer-motion `width: 'auto'` span.
        `useLocation()` re-renders the Sidebar on every navigation, and an
        `animate={{ width: 'auto' }}` span forces a layout re-measure on each
        re-render that momentarily reads 0 · so all ~30 labels collapsed to
        width:0/opacity:0 and animated back on every page change (the "sidebar
        text takes a few seconds to load" flicker). The parent <motion.aside>
        already animates its width with `overflow-hidden`, so the labels clip
        smoothly on collapse/expand without any per-item animation. Matches the
        pinned Dashboard + Recent labels, which were already plain spans.
      */}
      {!collapsed && (
        <span className="whitespace-nowrap text-[13px]">{item.name}</span>
      )}
      {badgeWithSettings}
    </NavLink>
  );

  if (collapsed) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>{content}</TooltipTrigger>
        <TooltipContent side="right" sideOffset={10} className="flex items-center gap-2">
          {item.name}
          {badgePill}
        </TooltipContent>
      </Tooltip>
    );
  }

  return content;
}

// Re-export type for ergonomic imports elsewhere
export type { SectionId };
