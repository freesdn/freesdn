// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * WallCameraSidebar · Draggable camera list for wall placement
 *
 * Collapsible sidebar that displays all available cameras as draggable items.
 * Cameras can be dragged from here into wall cells for placement.
 *
 * Features:
 *  - Search by camera name, IP, or location
 *  - Filter by status (online/offline/recording)
 *  - Visual indicator for cameras already on the wall
 *  - Compact thumbnails with status dots
 */

import { memo, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Search,
  X,
  Circle,
  Camera,
} from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { ScrollArea } from '@/components/ui/scroll-area';
import { cn } from '@/lib/utils';
import type { WallCamera } from './types';

interface WallCameraSidebarProps {
  cameras: WallCamera[];
  /** Camera IDs currently assigned to wall cells */
  assignedCameraIds: string[];
  onClose: () => void;
}

type StatusFilter = 'all' | 'online' | 'offline' | 'recording';

export const WallCameraSidebar = memo(function WallCameraSidebar({
  cameras,
  assignedCameraIds,
  onClose,
}: WallCameraSidebarProps) {
  const { t } = useTranslation('common');
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');

  const assignedSet = useMemo(() => new Set(assignedCameraIds), [assignedCameraIds]);

  const filteredCameras = useMemo(() => {
    let filtered = cameras;

    // Status filter
    if (statusFilter === 'online') {
      filtered = filtered.filter((c) => c.status === 'online' || c.status === 'recording');
    } else if (statusFilter === 'offline') {
      filtered = filtered.filter((c) => c.status === 'offline' || c.status === 'error');
    } else if (statusFilter === 'recording') {
      filtered = filtered.filter((c) => c.status === 'recording');
    }

    // Search filter
    if (search.trim()) {
      const q = search.toLowerCase();
      filtered = filtered.filter((c) =>
        c.name.toLowerCase().includes(q) ||
        c.ip_address?.toLowerCase().includes(q) ||
        c.location?.toLowerCase().includes(q) ||
        c.model?.toLowerCase().includes(q)
      );
    }

    return filtered;
  }, [cameras, statusFilter, search]);

  const onlineCount = useMemo(
    () => cameras.filter((c) => c.status === 'online' || c.status === 'recording').length,
    [cameras],
  );

  const handleDragStart = (e: React.DragEvent, camera: WallCamera) => {
    e.dataTransfer.setData('text/plain', camera.id);
    e.dataTransfer.effectAllowed = 'move';
  };

  return (
    <div className="w-60 flex-shrink-0 bg-card border rounded-md flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 border-b">
        <div className="flex items-center gap-1.5">
          <Camera className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-xs font-medium">{t('WallCameraSidebar.header.title')}</span>
          <span className="text-[10px] text-muted-foreground">
            ({onlineCount}/{cameras.length})
          </span>
        </div>
        <Button variant="ghost" size="icon" className="h-6 w-6" onClick={onClose}>
          <X className="h-3.5 w-3.5" />
        </Button>
      </div>

      {/* Search + Filter */}
      <div className="px-2 py-2 space-y-1.5 border-b">
        <div className="relative">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('WallCameraSidebar.search.placeholder')}
            className="h-7 pl-7 text-xs"
          />
          {search && (
            <button
              className="absolute right-1.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              onClick={() => setSearch('')}
            >
              <X className="h-3 w-3" />
            </button>
          )}
        </div>
        <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v as StatusFilter)}>
          <SelectTrigger className="h-7 text-xs">
            <SelectValue placeholder={t('WallCameraSidebar.status.placeholder')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('WallCameraSidebar.status.all')}</SelectItem>
            <SelectItem value="online">{t('WallCameraSidebar.status.online')}</SelectItem>
            <SelectItem value="offline">{t('WallCameraSidebar.status.offline')}</SelectItem>
            <SelectItem value="recording">{t('WallCameraSidebar.status.recording')}</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Camera list */}
      <ScrollArea className="flex-1">
        <div className="p-1 space-y-0.5">
          {filteredCameras.length === 0 ? (
            <div className="text-center py-6 text-xs text-muted-foreground">
              {t('WallCameraSidebar.empty.noMatch')}
            </div>
          ) : (
            filteredCameras.map((camera) => {
              const isAssigned = assignedSet.has(camera.id);
              const isOnline = camera.status === 'online' || camera.status === 'recording';

              return (
                <div
                  key={camera.id}
                  draggable
                  onDragStart={(e) => handleDragStart(e, camera)}
                  className={cn(
                    'flex items-center gap-2 px-2 py-1.5 rounded cursor-grab active:cursor-grabbing hover:bg-accent/50 transition-colors',
                    isAssigned && 'opacity-50',
                  )}
                >
                  {/* Status dot */}
                  <Circle
                    className={cn(
                      'h-2 w-2 flex-shrink-0',
                      isOnline ? 'fill-emerald-500 text-emerald-500' : 'fill-red-500 text-red-500',
                    )}
                  />

                  {/* Camera info */}
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-medium truncate">{camera.name}</div>
                    <div className="text-[10px] text-muted-foreground truncate">
                      {camera.ip_address || camera.location || camera.model || t('WallCameraSidebar.camera.noDetails')}
                    </div>
                  </div>

                  {/* Indicators */}
                  <div className="flex items-center gap-1 flex-shrink-0">
                    {camera.is_recording && (
                      <div className="h-1.5 w-1.5 rounded-full bg-red-500 animate-pulse" />
                    )}
                    {isAssigned && (
                      <span className="text-[9px] text-muted-foreground bg-muted px-1 rounded">
                        {t('WallCameraSidebar.camera.onWall')}
                      </span>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </ScrollArea>

      {/* Footer hint */}
      <div className="px-3 py-1.5 border-t text-[10px] text-muted-foreground text-center">
        {t('WallCameraSidebar.footer.dragHint')}
      </div>
    </div>
  );
});
