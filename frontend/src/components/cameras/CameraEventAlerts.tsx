// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, Camera Event Alert Components
 *
 *  - EventBadge:     Unacknowledged count badge for nav bar
 *  - EventFeedPanel: Sidebar / panel listing recent events with acknowledge
 *  - EventToast:     Toast notifications for real-time camera alerts
 */

import { useState, useCallback, useEffect, useRef } from 'react';
import { isValid } from 'date-fns';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { camerasApi } from '@/lib/api';
import { cn } from '@/lib/utils';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import {
  AlertTriangle,
  Bell,
  BellOff,
  Check,
  CheckCheck,
  Eye,
  X,
} from 'lucide-react';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface CameraEventItem {
  id: string;
  camera_id: string;
  event_type: string;
  timestamp: string;
  description: string | null;
  snapshot_path: string | null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  metadata_json: Record<string, any>;
  is_acknowledged: boolean;
  acknowledged_by: string | null;
  acknowledged_at: string | null;
  camera?: { name: string };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Maps raw event-type codes to translation key suffixes under
// CameraEventAlerts.eventTypes.*  (translated at the use site).
const EVENT_TYPE_KEYS: Record<string, string> = {
  VMD: 'motionDetected',
  linedetection: 'lineCrossing',
  fielddetection: 'intrusion',
  shelteralarm: 'tampering',
  videoloss: 'videoLoss',
  diskerror: 'diskError',
  diskfull: 'diskFull',
  illaccess: 'illegalAccess',
  IO: 'alarmInput',
};

function eventLabel(t: TFunction, type: string): string {
  const keySuffix = EVENT_TYPE_KEYS[type];
  if (keySuffix) return t(`CameraEventAlerts.eventTypes.${keySuffix}`);
  return type.replace(/([A-Z])/g, ' $1').trim();
}

function relativeTime(t: TFunction, iso: string): string {
  const parsed = new Date(iso);
  if (!iso || !isValid(parsed)) return '—';
  const diff = Date.now() - parsed.getTime();
  const secs = Math.floor(diff / 1000);
  if (secs < 60) return t('CameraEventAlerts.time.justNow');
  const mins = Math.floor(secs / 60);
  if (mins < 60) return t('CameraEventAlerts.time.minutesAgo', { n: mins });
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return t('CameraEventAlerts.time.hoursAgo', { n: hrs });
  const days = Math.floor(hrs / 24);
  return t('CameraEventAlerts.time.daysAgo', { n: days });
}

// ---------------------------------------------------------------------------
// EventBadge · shows unacknowledged count, for use in nav bar
// ---------------------------------------------------------------------------

interface EventBadgeProps {
  onClick?: () => void;
  className?: string;
}

export function EventBadge({ onClick, className }: EventBadgeProps) {
  const { t } = useTranslation('common');
  const { data } = useQuery({
    queryKey: ['camera-event-count'],
    queryFn: () => camerasApi.getUnacknowledgedCount().then((r) => r.data),
    // No poll: camera.alert.* WS events invalidate ['camera-event-count'],
    // and the ack mutation invalidates it locally (useWebSocket.ts).
    staleTime: 10_000,
  });

  const count = data?.count ?? 0;

  return (
    <Button
      variant="ghost"
      size="icon"
      className={cn('relative h-9 w-9', className)}
      onClick={onClick}
      title={
        count > 0
          ? t('CameraEventAlerts.badge.unacknowledgedTooltip', { n: count })
          : t('CameraEventAlerts.badge.cameraEvents')
      }
      aria-label={
        count > 0
          ? t('CameraEventAlerts.badge.unacknowledgedAria', { n: count })
          : t('CameraEventAlerts.badge.cameraEvents')
      }
    >
      <Bell className="h-4.5 w-4.5" />
      {count > 0 && (
        <span className="absolute -top-0.5 -right-0.5 flex h-4 min-w-[1rem] items-center justify-center rounded-full bg-destructive px-1 text-[10px] font-bold text-destructive-foreground">
          {count > 99 ? '99+' : count}
        </span>
      )}
    </Button>
  );
}

// ---------------------------------------------------------------------------
// EventFeedPanel · list of recent camera events
// ---------------------------------------------------------------------------

interface EventFeedPanelProps {
  /** Optional camera_id filter */
  cameraId?: string;
  /** Maximum events to show */
  limit?: number;
  className?: string;
}

export function EventFeedPanel({ cameraId, limit = 50, className }: EventFeedPanelProps) {
  const { t } = useTranslation('common');
  const queryClient = useQueryClient();
  const [showAcknowledged, setShowAcknowledged] = useState(false);

  const { data, isLoading, isError } = useQuery({
    queryKey: ['camera-events', cameraId, showAcknowledged, limit],
    queryFn: () =>
      camerasApi
        .getEvents({
          camera_id: cameraId,
          acknowledged: showAcknowledged ? undefined : false,
          limit,
        })
        .then((r) => r.data),
    // No poll: camera.alert.* WS events invalidate ['camera-events'], and
    // the ack mutation invalidates it locally (useWebSocket.ts).
    staleTime: 5_000,
  });

  const ackMutation = useMutation({
    mutationFn: (eventId: string) => camerasApi.acknowledgeEvent(eventId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['camera-events'] });
      queryClient.invalidateQueries({ queryKey: ['camera-event-count'] });
    },
  });

  const bulkAckMutation = useMutation({
    mutationFn: (ids: string[]) => camerasApi.bulkAcknowledgeEvents(ids),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['camera-events'] });
      queryClient.invalidateQueries({ queryKey: ['camera-event-count'] });
    },
  });

  const events: CameraEventItem[] = data?.items || [];
  const unackIds = events.filter((e) => !e.is_acknowledged).map((e) => e.id);

  return (
    <Card className={cn('flex flex-col', className)}>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            <Bell className="h-4 w-4" />
            {t('CameraEventAlerts.feed.title')}
            {events.length > 0 && (
              <Badge variant="secondary" className="text-xs ml-1">
                {data?.total ?? events.length}
              </Badge>
            )}
          </CardTitle>
          <div className="flex items-center gap-1">
            {unackIds.length > 0 && (
              <Button
                variant="outline"
                size="sm"
                className="gap-1 text-xs h-7"
                onClick={() => bulkAckMutation.mutate(unackIds)}
                disabled={bulkAckMutation.isPending}
              >
                <CheckCheck className="h-3 w-3" />
                {t('CameraEventAlerts.feed.ackAll')}
              </Button>
            )}
            <Button
              variant="ghost"
              size="sm"
              className="gap-1 text-xs h-7"
              onClick={() => setShowAcknowledged(!showAcknowledged)}
              title={
                showAcknowledged
                  ? t('CameraEventAlerts.feed.hideAcknowledged')
                  : t('CameraEventAlerts.feed.showAllEvents')
              }
              aria-label={
                showAcknowledged
                  ? t('CameraEventAlerts.feed.hideAcknowledgedAria')
                  : t('CameraEventAlerts.feed.showAllEvents')
              }
            >
              {showAcknowledged ? <BellOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="flex-1 overflow-y-auto max-h-[500px] space-y-1.5 pt-0">
        {isLoading ? (
          <div className="space-y-2 pt-2">
            {[0, 1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-14 w-full" />
            ))}
          </div>
        ) : isError ? (
          <div className="text-center py-8 text-destructive">
            <AlertTriangle className="h-8 w-8 mx-auto mb-2 opacity-60" />
            <p className="text-sm">{t('CameraEventAlerts.feed.loadError')}</p>
          </div>
        ) : events.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground">
            <Bell className="h-8 w-8 mx-auto mb-2 opacity-30" />
            <p className="text-sm">
              {showAcknowledged
                ? t('CameraEventAlerts.feed.noEvents')
                : t('CameraEventAlerts.feed.noUnacknowledged')}
            </p>
          </div>
        ) : (
          events.map((event) => (
            <div
              key={event.id}
              className={cn(
                'flex items-start gap-3 rounded-lg border px-3 py-2 text-sm transition-colors',
                !event.is_acknowledged
                  ? 'border-amber-500/30 bg-amber-50/50 dark:bg-amber-950/20'
                  : 'border-transparent bg-muted/30',
              )}
            >
              {/* Event icon */}
              <div
                className={cn(
                  'mt-0.5 flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-full',
                  !event.is_acknowledged
                    ? 'bg-warning/10 text-warning'
                    : 'bg-muted text-muted-foreground',
                )}
              >
                <AlertTriangle className="h-3.5 w-3.5" />
              </div>

              {/* Event details */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-medium truncate">{eventLabel(t, event.event_type)}</span>
                  <span className="text-xs text-muted-foreground flex-shrink-0">
                    {relativeTime(t, event.timestamp)}
                  </span>
                </div>
                {event.description && (
                  <p className="text-xs text-muted-foreground truncate mt-0.5">
                    {event.description}
                  </p>
                )}
                <p className="text-[11px] text-muted-foreground mt-0.5">
                  {t('CameraEventAlerts.feed.channel', {
                    channel: String(event.metadata_json?.channel_id ?? '-'),
                  })}
                </p>
              </div>

              {/* Acknowledge button */}
              {!event.is_acknowledged && (
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-6 w-6 flex-shrink-0"
                  onClick={() => ackMutation.mutate(event.id)}
                  disabled={ackMutation.isPending}
                  title={t('CameraEventAlerts.feed.acknowledge')}
                  aria-label={t('CameraEventAlerts.feed.acknowledgeAria')}
                >
                  <Check className="h-3.5 w-3.5" />
                </Button>
              )}
            </div>
          ))
        )}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// EventToastContainer · subscribes to WS and shows toasts for new events
// ---------------------------------------------------------------------------

interface EventToast {
  id: string;
  eventType: string;
  description: string;
  timestamp: string;
  cameraName?: string;
}

interface EventToastContainerProps {
  /** Max visible toasts */
  maxToasts?: number;
}

export function EventToastContainer({ maxToasts = 5 }: EventToastContainerProps) {
  const { t } = useTranslation('common');
  const [toasts, setToasts] = useState<EventToast[]>([]);
  const toastTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  // Listen for WS camera_event messages via a custom event on window
  useEffect(() => {
    const timers = toastTimersRef.current;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const handler = (e: CustomEvent<any>) => {
      const data = e.detail;
      if (!data) return;
      const toast: EventToast = {
        id: data.id || `${Date.now()}-${Math.random()}`,
        eventType: data.event_type || 'unknown',
        description: data.description || '',
        timestamp: data.timestamp || new Date().toISOString(),
        cameraName: data.camera_name,
      };
      setToasts((prev) => [toast, ...prev].slice(0, maxToasts));

      // Auto-dismiss after 8 seconds (tracked for cleanup)
      const timer = setTimeout(() => {
        timers.delete(toast.id);
        setToasts((prev) => prev.filter((t) => t.id !== toast.id));
      }, 8000);
      timers.set(toast.id, timer);
    };

    window.addEventListener('freesdn:camera-event', handler as EventListener);
    return () => {
      window.removeEventListener('freesdn:camera-event', handler as EventListener);
      // Clear all pending dismiss timers on unmount
      timers.forEach((t) => clearTimeout(t));
      timers.clear();
    };
  }, [maxToasts]);

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 w-80">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className="flex items-start gap-3 rounded-lg border border-amber-500/40 bg-background/95 backdrop-blur-sm p-3 shadow-lg animate-in slide-in-from-bottom-5 fade-in duration-300"
        >
          <AlertTriangle className="h-4 w-4 text-amber-500 mt-0.5 flex-shrink-0" />
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium">{eventLabel(t, toast.eventType)}</p>
            {toast.cameraName && (
              <p className="text-xs text-muted-foreground">{toast.cameraName}</p>
            )}
            {toast.description && (
              <p className="text-xs text-muted-foreground truncate">{toast.description}</p>
            )}
            <p className="text-[10px] text-muted-foreground mt-0.5">
              {relativeTime(t, toast.timestamp)}
            </p>
          </div>
          <Button
            variant="ghost"
            size="icon"
            className="h-5 w-5 flex-shrink-0"
            onClick={() => dismiss(toast.id)}
            aria-label={t('CameraEventAlerts.toast.dismissAria')}
          >
            <X className="h-3 w-3" />
          </Button>
        </div>
      ))}
    </div>
  );
}
