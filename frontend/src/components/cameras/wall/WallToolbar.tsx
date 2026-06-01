// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * WallToolbar · Camera wall control bar
 *
 * Layout selector, stream mode toggle, auto-cycle, fullscreen,
 * page indicators, quality, display toggles, sidebar toggle,
 * pop-out, alert sound, and refresh info.
 */

import { memo } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Maximize2,
  Minimize2,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  LayoutGrid,
  Eye,
  Tag,
  Zap,
  MonitorPlay,
  Video,
  ImageIcon,
  PanelLeft,
  ExternalLink,
  Bell,
  BellOff,
  Server,
} from 'lucide-react';
import type { StreamStats } from '@/lib/api/cameras';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuCheckboxItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Badge } from '@/components/ui/badge';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import {
  type WallLayout,
  type WallState,
  LAYOUT_LABELS,
  LAYOUT_CELL_COUNT,
  getRefreshLabel,
  getBandwidthWarning,
} from './types';

interface WallToolbarProps {
  state: WallState;
  totalCameras: number;
  onlineCameras: number;
  pageCount: number;
  activeCellCount: number;
  /** NVR stream stats for load indicator (polled every 10s in live mode) */
  nvrLoadStats?: StreamStats | null;
  onLayoutChange: (layout: WallLayout) => void;
  onPageChange: (page: number) => void;
  onToggleAutoCycle: () => void;
  onAutoCycleIntervalChange: (seconds: number) => void;
  onToggleFullscreen: () => void;
  onForceRefresh: () => void;
  onStreamQualityChange: (quality: 'sub' | 'main') => void;
  onToggleLabels: () => void;
  onToggleStatus: () => void;
  onFillWall: () => void;
  onStreamModeChange: (mode: 'snapshot' | 'live') => void;
  onToggleSidebar: () => void;
  onToggleAlertSound: () => void;
  onPopOut: () => void;
}

export const WallToolbar = memo(function WallToolbar({
  state,
  totalCameras,
  onlineCameras,
  pageCount,
  activeCellCount,
  nvrLoadStats,
  onLayoutChange,
  onPageChange,
  onToggleAutoCycle,
  onAutoCycleIntervalChange,
  onToggleFullscreen,
  onForceRefresh,
  onStreamQualityChange,
  onToggleLabels,
  onToggleStatus,
  onFillWall,
  onStreamModeChange,
  onToggleSidebar,
  onToggleAlertSound,
  onPopOut,
}: WallToolbarProps) {
  const { t } = useTranslation('common');
  const cellCount = LAYOUT_CELL_COUNT[state.layout];
  const refreshLabel = getRefreshLabel(activeCellCount);
  const bandwidthWarning = state.streamMode === 'live' ? getBandwidthWarning(activeCellCount) : null;

  return (
    <TooltipProvider delayDuration={300}>
    <div className="flex items-center gap-2 flex-wrap">
      {/* Sidebar toggle */}
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant={state.showSidebar ? 'default' : 'outline'}
            size="icon"
            className="h-8 w-8"
            onClick={onToggleSidebar}
          >
            <PanelLeft className="h-3.5 w-3.5" />
          </Button>
        </TooltipTrigger>
        <TooltipContent>{t('WallToolbar.tooltips.sidebar')}</TooltipContent>
      </Tooltip>

      {/* Layout selector */}
      <Select value={state.layout} onValueChange={(v) => onLayoutChange(v as WallLayout)}>
        <SelectTrigger className="w-[85px] h-8 text-xs">
          <LayoutGrid className="h-3.5 w-3.5 mr-1.5" />
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {(Object.entries(LAYOUT_LABELS) as [WallLayout, string][]).map(([key, label]) => (
            <SelectItem key={key} value={key}>
              <span className="flex items-center justify-between w-full gap-3">
                <span>{label}</span>
                <span className="text-muted-foreground text-[10px]">{LAYOUT_CELL_COUNT[key]}</span>
              </span>
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      {/* Fill wall button */}
      <Button variant="outline" size="sm" className="h-8 gap-1.5 text-xs" onClick={onFillWall}>
        <MonitorPlay className="h-3.5 w-3.5" />
        {t('WallToolbar.actions.fill', { count: cellCount })}
      </Button>

      {/* Stream mode toggle: Snapshots / Live */}
      <div className="flex items-center rounded-md border border-input">
        <button
          className={cn(
            'px-2.5 py-1 text-xs flex items-center gap-1 rounded-l-md transition-colors',
            state.streamMode === 'snapshot' ? 'bg-primary text-primary-foreground' : 'hover:bg-accent',
          )}
          onClick={() => onStreamModeChange('snapshot')}
        >
          <ImageIcon className="h-3 w-3" />
          {t('WallToolbar.streamMode.snapshots')}
        </button>
        <button
          className={cn(
            'px-2.5 py-1 text-xs flex items-center gap-1 rounded-r-md transition-colors',
            state.streamMode === 'live' ? 'bg-primary text-primary-foreground' : 'hover:bg-accent',
          )}
          onClick={() => onStreamModeChange('live')}
        >
          <Video className="h-3 w-3" />
          {t('WallToolbar.streamMode.live')}
        </button>
      </div>

      {/* Bandwidth warning for live mode */}
      {bandwidthWarning && (
        <Badge
          variant="outline"
          className={cn(
            'text-[10px] px-1.5',
            bandwidthWarning.level === 'moderate' && 'border-yellow-500 text-yellow-600',
            bandwidthWarning.level === 'high' && 'border-orange-500 text-orange-600',
            bandwidthWarning.level === 'very-high' && 'border-red-500 text-red-600',
          )}
        >
          {bandwidthWarning.message}
        </Badge>
      )}

      {/* NVR load indicator (live mode only) */}
      {nvrLoadStats && state.streamMode === 'live' && (
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge
              variant="outline"
              className={cn(
                'text-[10px] px-1.5 gap-1 cursor-default',
                nvrLoadStats.overloaded_nvrs.length > 0
                  ? 'border-red-500 text-red-600'
                  : 'border-emerald-500 text-emerald-600',
              )}
            >
              <Server className="h-2.5 w-2.5" />
              {nvrLoadStats.active_streams === 1
                ? t('WallToolbar.nvrLoad.streamCount_one', { count: nvrLoadStats.active_streams })
                : t('WallToolbar.nvrLoad.streamCount_other', { count: nvrLoadStats.active_streams })}
              {nvrLoadStats.overloaded_nvrs.length > 0 && (
                <span className="text-red-600 font-bold ml-0.5">
                  {nvrLoadStats.overloaded_nvrs.length === 1
                    ? t('WallToolbar.nvrLoad.overloaded_one', { count: nvrLoadStats.overloaded_nvrs.length })
                    : t('WallToolbar.nvrLoad.overloaded_other', { count: nvrLoadStats.overloaded_nvrs.length })}
                </span>
              )}
            </Badge>
          </TooltipTrigger>
          <TooltipContent className="max-w-xs">
            <div className="text-xs space-y-1">
              <div className="font-medium">{t('WallToolbar.nvrLoad.title')}</div>
              {Object.entries(nvrLoadStats.per_nvr).map(([nvr, stats]) => (
                <div key={nvr} className="flex justify-between gap-3">
                  <span className="truncate">{nvr}</span>
                  <span className={cn(
                    'font-mono',
                    stats.available === 0 ? 'text-red-500' : stats.available <= 2 ? 'text-amber-500' : 'text-emerald-500',
                  )}>
                    {stats.active}/{stats.max}
                  </span>
                </div>
              ))}
              {Object.keys(nvrLoadStats.per_nvr).length === 0 && (
                <div className="text-muted-foreground">{t('WallToolbar.nvrLoad.empty')}</div>
              )}
            </div>
          </TooltipContent>
        </Tooltip>
      )}

      {/* Page navigation */}
      {pageCount > 1 && (
        <div className="flex items-center gap-1">
          <Button
            variant="outline"
            size="icon"
            className="h-7 w-7"
            onClick={() => onPageChange(Math.max(0, state.page - 1))}
            disabled={state.page === 0}
            aria-label={t('WallToolbar.pagination.previous')}
          >
            <ChevronLeft className="h-3.5 w-3.5" />
          </Button>
          <span className="text-xs text-muted-foreground min-w-[48px] text-center">
            {state.page + 1} / {pageCount}
          </span>
          <Button
            variant="outline"
            size="icon"
            className="h-7 w-7"
            onClick={() => onPageChange(Math.min(pageCount - 1, state.page + 1))}
            disabled={state.page >= pageCount - 1}
            aria-label={t('WallToolbar.pagination.next')}
          >
            <ChevronRight className="h-3.5 w-3.5" />
          </Button>
        </div>
      )}

      {/* Page dots (when auto-cycling) */}
      {state.autoCycle && pageCount > 1 && (
        <div className="flex items-center gap-0.5">
          {Array.from({ length: Math.min(pageCount, 20) }, (_, i) => (
            <div
              key={i}
              className={cn(
                'rounded-full transition-all',
                i === state.page
                  ? 'w-3 h-1.5 bg-primary'
                  : 'w-1.5 h-1.5 bg-muted-foreground/25',
              )}
            />
          ))}
        </div>
      )}

      <div className="flex-1" />

      {/* Status summary */}
      <div className="hidden sm:flex items-center gap-2 text-xs text-muted-foreground">
        <Badge variant="secondary" className="text-[10px] gap-1 px-1.5">
          <Zap className="h-2.5 w-2.5" />
          {state.streamMode === 'live' ? t('WallToolbar.status.live') : refreshLabel}
        </Badge>
        <span>{t('WallToolbar.status.summary', { active: activeCellCount, online: onlineCameras, total: totalCameras })}</span>
      </div>

      {/* Auto-cycle toggle */}
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant={state.autoCycle ? 'default' : 'outline'}
            size="sm"
            className="h-8 gap-1.5 text-xs"
          >
            <RefreshCw className={cn('h-3.5 w-3.5', state.autoCycle && 'animate-spin')} />
            {state.autoCycle ? `${state.autoCycleInterval}s` : t('WallToolbar.autoCycle.button')}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-40">
          <DropdownMenuLabel className="text-xs">{t('WallToolbar.autoCycle.title')}</DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuCheckboxItem
            checked={state.autoCycle}
            onCheckedChange={onToggleAutoCycle}
          >
            {state.autoCycle ? t('WallToolbar.autoCycle.enabled') : t('WallToolbar.autoCycle.disabled')}
          </DropdownMenuCheckboxItem>
          <DropdownMenuSeparator />
          <DropdownMenuLabel className="text-xs">{t('WallToolbar.autoCycle.interval')}</DropdownMenuLabel>
          {[5, 10, 15, 30, 60].map((s) => (
            <DropdownMenuCheckboxItem
              key={s}
              checked={state.autoCycleInterval === s}
              onCheckedChange={() => onAutoCycleIntervalChange(s)}
            >
              {t('WallToolbar.autoCycle.seconds', { count: s })}
            </DropdownMenuCheckboxItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>

      {/* Display options */}
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm" className="h-8 gap-1.5 text-xs">
            <Eye className="h-3.5 w-3.5" />
            {t('WallToolbar.display.button')}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-44">
          <DropdownMenuCheckboxItem
            checked={state.showLabels}
            onCheckedChange={onToggleLabels}
          >
            <Tag className="h-3.5 w-3.5 mr-2" />
            {t('WallToolbar.display.labels')}
          </DropdownMenuCheckboxItem>
          <DropdownMenuCheckboxItem
            checked={state.showStatus}
            onCheckedChange={onToggleStatus}
          >
            <Zap className="h-3.5 w-3.5 mr-2" />
            {t('WallToolbar.display.statusIndicators')}
          </DropdownMenuCheckboxItem>
          <DropdownMenuSeparator />
          <DropdownMenuLabel className="text-xs">{t('WallToolbar.display.streamQuality')}</DropdownMenuLabel>
          <DropdownMenuCheckboxItem
            checked={state.streamQuality === 'sub'}
            onCheckedChange={() => onStreamQualityChange('sub')}
          >
            {t('WallToolbar.display.subStream')}
          </DropdownMenuCheckboxItem>
          <DropdownMenuCheckboxItem
            checked={state.streamQuality === 'main'}
            onCheckedChange={() => onStreamQualityChange('main')}
          >
            {t('WallToolbar.display.mainStream')}
          </DropdownMenuCheckboxItem>
        </DropdownMenuContent>
      </DropdownMenu>

      {/* Alert sound toggle */}
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="outline"
            size="icon"
            className="h-8 w-8"
            onClick={onToggleAlertSound}
          >
            {state.alertSoundEnabled ? (
              <Bell className="h-3.5 w-3.5" />
            ) : (
              <BellOff className="h-3.5 w-3.5 text-muted-foreground" />
            )}
          </Button>
        </TooltipTrigger>
        <TooltipContent>{state.alertSoundEnabled ? t('WallToolbar.alertSound.mute') : t('WallToolbar.alertSound.enable')}</TooltipContent>
      </Tooltip>

      {/* Refresh now (only in snapshot mode) */}
      {state.streamMode === 'snapshot' && (
        <Button variant="outline" size="icon" className="h-8 w-8" onClick={onForceRefresh} title={t('WallToolbar.refresh.title')} aria-label={t('WallToolbar.refresh.ariaLabel')}>
          <RefreshCw className="h-3.5 w-3.5" />
        </Button>
      )}

      {/* Pop-out wall */}
      <Tooltip>
        <TooltipTrigger asChild>
          <Button variant="outline" size="icon" className="h-8 w-8" onClick={onPopOut} title={t('WallToolbar.popOut.title')}>
            <ExternalLink className="h-3.5 w-3.5" />
          </Button>
        </TooltipTrigger>
        <TooltipContent>{t('WallToolbar.popOut.tooltip')}</TooltipContent>
      </Tooltip>

      {/* Fullscreen */}
      <Button variant="outline" size="icon" className="h-8 w-8" onClick={onToggleFullscreen} title={t('WallToolbar.fullscreen.title')} aria-label={state.isFullscreen ? t('WallToolbar.fullscreen.exit') : t('WallToolbar.fullscreen.enter')}>
        {state.isFullscreen ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
      </Button>
    </div>
    </TooltipProvider>
  );
});
