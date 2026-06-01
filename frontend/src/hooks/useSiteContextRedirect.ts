// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Site Context Redirect Hook
 *
 * Watches the global site context and auto-redirects to Dashboard
 * when the user switches to "All Sites" while on a site-only page
 * (e.g. Topology, Discovery).
 *
 * Should be mounted once in MainLayout.
 */
import { useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useSiteStore, SITE_ONLY_PATHS } from '@/stores/siteStore';

export function useSiteContextRedirect() {
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (
      selectedSiteId === null &&
      SITE_ONLY_PATHS.some((p) => location.pathname.startsWith(p))
    ) {
      navigate('/', { replace: true });
    }
  }, [selectedSiteId, location.pathname, navigate]);
}
