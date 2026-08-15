// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * CameraWallPopout · Standalone camera wall page for pop-out windows
 *
 * Opens in a new browser window via the "Pop Out" button on the main wall.
 * No sidebar, no PageHeader · pure wall view for security monitors.
 *
 * Reads configuration from URL search params:
 *   ?layout=4x4&cameras=id1,id2,...&quality=sub&mode=live
 */

import { useMemo, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { camerasApi } from '@/lib/api';
import { useSiteStore } from '@/stores/siteStore';
import { CameraWall } from '@/components/cameras/wall/CameraWall';
import type { WallLayout } from '@/components/cameras/wall/types';
import { mapToWallCameras } from '@/components/cameras/wall/mapToWallCamera';
import { TooltipProvider } from '@/components/ui/tooltip';

const VALID_LAYOUTS = new Set(['1x1', '1+5', '2x2', '3x3', '4x4', '5x5', '6x6', '8x8']);

export default function CameraWallPopout() {
  const { t } = useTranslation('cameras');
  const [searchParams] = useSearchParams();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // Parse URL params
  const layout = useMemo(() => {
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

  // Set window title
  useEffect(() => {
    document.title = `FreeSDN · ${t('CameraWallPopout.documentTitle')}`;
  }, [t]);

  // Fetch cameras
  const { data: camerasData, isLoading, isError } = useQuery({
    queryKey: ['cameras', 'popout-wall', selectedSiteId],
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

  if (isLoading) {
    return (
      <div className="h-screen w-screen bg-black flex items-center justify-center">
        <div className="text-white/40 text-sm">{t('CameraWallPopout.loading')}</div>
      </div>
    );
  }

  if (isError) {
    return (
      <div className="h-screen w-screen bg-black flex items-center justify-center">
        <div className="text-red-400 text-sm">{t('CameraWallPopout.error')}</div>
      </div>
    );
  }

  return (
    <TooltipProvider>
      <div className="h-screen w-screen bg-black p-2 flex flex-col">
        <CameraWall
          cameras={cameras}
          initialLayout={layout}
          initialCameraIds={initialCameraIds}
          initialStreamMode={streamMode}
          onOpenDetail={(id) => {
            window.open(`/cameras/${id}`, '_blank', 'noopener,noreferrer');
          }}
          height="calc(100vh - 60px)"
          className="flex-1"
        />
      </div>
    </TooltipProvider>
  );
}
