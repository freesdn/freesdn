// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * CameraWallPage · Dedicated deep-linkable camera wall page
 *
 * Full-page camera wall with URL-synced state for bookmarkable layouts:
 *   /cameras/wall?layout=4x4&cameras=id1,id2&quality=sub&mode=snapshot
 *
 * Supports all wall features: live/snapshot mode, layout presets, drag-and-drop,
 * auto-cycle, fullscreen, saved views, event highlighting.
 */

import { useMemo, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, LayoutGrid, AlertCircle, Monitor } from 'lucide-react';
import { camerasApi } from '@/lib/api';
import { useSiteStore } from '@/stores/siteStore';
import { CameraWall } from '@/components/cameras/wall/CameraWall';
import type { WallLayout } from '@/components/cameras/wall/types';
import { mapToWallCameras } from '@/components/cameras/wall/mapToWallCamera';
import { PageHeader } from '@/components/layout';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';

const VALID_LAYOUTS = new Set(['1x1', '1+5', '2x2', '3x3', '4x4', '5x5', '6x6', '8x8']);

export default function CameraWallPage() {
  const { t } = useTranslation('cameras');
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // Parse URL params
  const layout = useMemo((): WallLayout => {
    const l = searchParams.get('layout') || '4x4';
    return VALID_LAYOUTS.has(l) ? (l as WallLayout) : '4x4';
  }, [searchParams]);

  const initialCameraIds = useMemo(() => {
    const c = searchParams.get('cameras');
    return c ? c.split(',').filter(Boolean) : [];
  }, [searchParams]);

  const streamMode = useMemo(() => {
    const m = searchParams.get('mode');
    return m === 'live' ? 'live' : 'snapshot';
  }, [searchParams]);

  // Sync layout/cameras back to URL for bookmarking
  const handleLayoutChange = useCallback((newLayout: WallLayout) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (newLayout === '4x4') next.delete('layout'); else next.set('layout', newLayout);
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  const handleCameraIdsChange = useCallback((ids: string[]) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (ids.length === 0) next.delete('cameras'); else next.set('cameras', ids.join(','));
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  // Fetch cameras
  const { data: camerasData, isLoading, isError } = useQuery({
    queryKey: ['cameras', 'wall-page', selectedSiteId],
    queryFn: async () => {
      const { data } = await camerasApi.getAll({
        site_id: selectedSiteId || undefined,
        limit: 100,
      });
      return data;
    },
    refetchInterval: 30_000,
  });

  const cameras = useMemo(() => mapToWallCameras(camerasData), [camerasData]);

  return (
    <div className="space-y-3 p-4">
      <PageHeader
        icon={LayoutGrid}
        title={t('CameraWallPage.title')}
        description={t('CameraWallPage.description', { count: cameras.length })}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => navigate('/cameras/display?fill=true&mode=live')}>
              <Monitor className="h-4 w-4 mr-1.5" />
              {t('CameraWallPage.actions.displayMode')}
            </Button>
            <Button variant="outline" size="sm" onClick={() => navigate('/cameras')}>
              <ArrowLeft className="h-4 w-4 mr-1.5" />
              {t('CameraWallPage.actions.backToCameras')}
            </Button>
          </div>
        }
      />

      {isLoading && (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="aspect-video rounded-md" />
          ))}
        </div>
      )}

      {isError && (
        <div className="rounded-md bg-destructive/10 border border-destructive/20 px-4 py-3 flex items-center gap-2">
          <AlertCircle className="h-4 w-4 text-destructive" />
          <span className="text-sm text-destructive">{t('CameraWallPage.errors.loadFailed')}</span>
        </div>
      )}

      {!isLoading && !isError && (
        <CameraWall
          cameras={cameras}
          initialLayout={layout}
          initialCameraIds={initialCameraIds}
          initialStreamMode={streamMode}
          onOpenDetail={(id) => navigate(`/cameras/${id}`)}
          onOpenLiveView={(id) => navigate(`/cameras/${id}/stream`)}
          onLayoutChange={handleLayoutChange}
          onCameraIdsChange={handleCameraIdsChange}
          height="calc(100vh - 160px)"
        />
      )}
    </div>
  );
}
