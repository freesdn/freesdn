// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { ReactNode, Suspense, useEffect, useMemo, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { motion, AnimatePresence } from 'framer-motion';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { ErrorBoundary } from '../ErrorBoundary';
import { useUIStore, useWebSocketStore } from '../../stores';
import { useSidebarStore } from '../../stores/sidebarStore';
import { EventToastContainer } from '../cameras/CameraEventAlerts';
import { useSiteContextRedirect } from '../../hooks/useSiteContextRedirect';
import { buildSections, flattenItems } from '../../lib/nav-data';

interface MainLayoutProps {
  children: ReactNode;
}

/**
 * Match against the stable list of top-level nav routes so we don't track
 * dynamic detail pages (e.g. `/devices/<uuid>`). Only routes that exist in the
 * nav-data are tracked.
 */
function findMatchingNavItem(pathname: string, t?: (k: string, o?: any) => string) {
  const items = flattenItems(buildSections(0, t));
  // Prefer the longest exact-or-prefix match so /cameras/wall beats /cameras
  return items
    .filter(
      (item) =>
        pathname === item.href ||
        (item.href !== '/' && pathname === item.href),
    )
    .sort((a, b) => b.href.length - a.href.length)[0];
}

export function MainLayout({ children }: MainLayoutProps) {
  const { t } = useTranslation('common');
  const location = useLocation();
  const connectionStatus = useWebSocketStore((s) => s.connectionStatus);
  const animationsEnabled = useUIStore((s) => s.animationsEnabled);
  const sidebarMobileOpen = useUIStore((s) => s.sidebarMobileOpen);
  const setSidebarMobileOpen = useUIStore((s) => s.setSidebarMobileOpen);
  const trackVisit = useSidebarStore((s) => s.trackVisit);

  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  // Track whether we're at the lg breakpoint (>=1024px) so we know whether
  // to apply sidebar margin or let the sidebar float as a drawer.
  const [isLg, setIsLg] = useState<boolean>(() =>
    typeof window !== 'undefined'
      ? window.matchMedia('(min-width: 1024px)').matches
      : true,
  );

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const mq = window.matchMedia('(min-width: 1024px)');
    const handler = (e: MediaQueryListEvent) => {
      setIsLg(e.matches);
      // Auto-close mobile drawer when crossing into lg
      if (e.matches) setSidebarMobileOpen(false);
    };
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, [setSidebarMobileOpen]);

  // Redirect away from site-only pages when switching to global view
  useSiteContextRedirect();

  // ── Auto-track route visits (top-level nav items only) ──
  useEffect(() => {
    const match = findMatchingNavItem(location.pathname, t);
    if (match) {
      trackVisit(match.href, match.name);
    }
  }, [location.pathname, trackVisit, t]);

  // ── Compute main content margin based on breakpoint + sidebar state ──
  const marginLeft = useMemo(() => {
    if (!isLg) return 0; // sidebar floats above content on mobile
    return sidebarCollapsed ? 72 : 256;
  }, [isLg, sidebarCollapsed]);

  return (
    <div className="min-h-screen bg-background">
      {/*
        A11Y: skip-to-content link.

        WCAG 2.4.1 (Bypass Blocks) requires keyboard users to be able to
        jump past the ~30 sidebar tab-stops on every page navigation.
        The link is visually hidden by default (``sr-only``) and revealed
        on focus (``focus:not-sr-only``) so it's first in the tab order.
        Activating it moves focus to ``#main-content`` (the ``<main>``
        element, made focusable below via ``tabIndex={-1}``).
      */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[10000] focus:rounded focus:bg-background focus:px-4 focus:py-2 focus:text-foreground focus:shadow-lg focus:outline-none focus:ring-2 focus:ring-ring"
      >
        {t('MainLayout.skipToMainContent')}
      </a>

      {/* Sidebar */}
      <Sidebar
        collapsed={sidebarCollapsed}
        onCollapsedChange={setSidebarCollapsed}
        mobileOpen={sidebarMobileOpen}
        onMobileOpenChange={setSidebarMobileOpen}
      />

      {/* Main content area */}
      <div
        className="min-w-0 transition-all duration-200"
        style={{ marginLeft: `${marginLeft}px` }}
      >
        {/* Top bar */}
        <TopBar connectionStatus={connectionStatus} />

        {/* Page content with route transitions.
            Route-level ErrorBoundary keeps sidebar+topbar visible if a page
            crashes, and auto-resets when the user navigates away.

            ``id="main-content"`` + ``tabIndex={-1}`` make this the
            programmatic-focus target for the skip-to-content link
            above. tabIndex=-1 keeps it out of the normal tab order
            (it would otherwise be a stray tab stop) while still
            allowing ``element.focus()`` from the anchor. */}
        <main
          id="main-content"
          tabIndex={-1}
          className="p-3 sm:p-6 min-h-[calc(100vh-64px)] overflow-x-hidden focus:outline-none"
        >
          <ErrorBoundary level="route" resetKeys={[location.pathname]}>
            {/* Per-content Suspense boundary.

                CRITICAL: this MUST live inside MainLayout so that a lazy page
                (or its on-demand i18n namespace) suspending only swaps the
                content area for a spinner · the sidebar and top bar stay
                mounted and visible. Without it, the page suspension bubbles to
                the single app-level <Suspense> ABOVE MainLayout (App.tsx),
                which React resolves by setting the whole route subtree to
                ``display:none`` and showing a fullscreen spinner · that
                briefly collapsed the fixed sidebar to rect-width 0 on every
                navigation (the "icons appear, then labels load seconds later"
                flash users reported). Keep this boundary here. */}
            <Suspense
              fallback={
                <div className="flex items-center justify-center min-h-[calc(100vh-128px)]">
                  <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
                </div>
              }
            >
              {animationsEnabled ? (
                <AnimatePresence mode="wait">
                  <motion.div
                    key={location.pathname}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -4 }}
                    transition={{ duration: 0.2, ease: 'easeOut' }}
                  >
                    {children}
                  </motion.div>
                </AnimatePresence>
              ) : (
                children
              )}
            </Suspense>
          </ErrorBoundary>
        </main>
      </div>

      {/* Global camera event toast notifications */}
      <EventToastContainer />
    </div>
  );
}
