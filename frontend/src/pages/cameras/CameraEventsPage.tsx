// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * CameraEventsPage, Review feed of NVR/camera events (motion, smart detections,
 * tamper, video-loss…). Events are ingested from the NVRs' alert stream into
 * camera_events; this page lists/filters them and lets operators acknowledge
 * ("review") them. Events appear here as the NVRs detect activity.
 */
import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { BellRing, BellOff, Bell, Check, CheckCheck, ShieldAlert, Activity, Loader2, PlayCircle, Search } from 'lucide-react';
import { camerasApi } from '@/lib/api';
import { Input } from '@/components/ui/input';
import { enablePush, disablePush, getPushStatus, type PushStatus } from '@/lib/push';
import { useSiteStore } from '@/stores/siteStore';
import { useToast } from '@/hooks/use-toast';
import { PageHeader } from '@/components/layout';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import { cn } from '@/lib/utils';

interface CameraEvent {
  id: string;
  camera_id: string;
  event_type: string;
  timestamp: string;
  description?: string | null;
  snapshot_url?: string | null;
  is_acknowledged: boolean;
  metadata_json?: Record<string, unknown> | null;
}

// Detection categories (the timeline/tab filter). person/vehicle are derived from
// the NVR's object classification (metadata_json.target_type) when it sends one,
// they stay empty on NVRs that don't classify, rather than being faked.
const CATEGORIES = [
  'all', 'person', 'vehicle', 'motion', 'line', 'intrusion', 'face', 'tamper', 'audio',
] as const;
type EventCategory = (typeof CATEGORIES)[number];

function eventCategory(ev: CameraEvent): Exclude<EventCategory, 'all'> | 'other' | 'lpr' {
  const target = String((ev.metadata_json?.target_type as string) ?? '').toLowerCase();
  if (/human|person|pedestrian/.test(target)) return 'person';
  if (/vehicle|car|truck|motor|bike/.test(target)) return 'vehicle';
  const et = (ev.event_type || '').toLowerCase();
  if (et.includes('line')) return 'line';
  if (et.includes('field') || et.includes('intrusion')) return 'intrusion';
  if (et.includes('face')) return 'face';
  if (et.includes('tamper') || et.includes('shelter')) return 'tamper';
  if (et.includes('audio')) return 'audio';
  if (et.includes('motion') || et === 'vmd') return 'motion';
  if (et.includes('plate') || et.includes('anpr')) return 'lpr';
  return 'other';
}

const EVENT_TYPE_KEYS: Record<string, string> = {
  motion: 'motion',
  line_cross: 'lineCross',
  linecrossing: 'lineCross',
  linedetection: 'lineCross',
  intrusion: 'intrusion',
  fielddetection: 'intrusion',
  face: 'face',
  facedetection: 'face',
  tamper: 'tamper',
  shelteralarm: 'tamper',
  video_loss: 'videoLoss',
  videoloss: 'videoLoss',
};

const ALERT_TYPES = new Set(['line_cross', 'linecrossing', 'linedetection', 'intrusion', 'fielddetection', 'face', 'facedetection', 'tamper', 'shelteralarm']);

function rangeStart(hours: number): string {
  return new Date(Date.now() - hours * 3600_000).toISOString();
}

// Hard ceiling on the events query, must equal the backend service clamp
// (CameraEventService._MAX_LIST_LIMIT) and the endpoint's Query le bound.
// "Load More" grows `limit` toward this max and then stops, so it never
// silently requests rows the backend won't return.
const MAX_EVENT_LIMIT = 500;

export default function CameraEventsPage() {
  const { t } = useTranslation('cameras');
  const navigate = useNavigate();
  const { toast } = useToast();
  const qc = useQueryClient();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  const [cameraId, setCameraId] = useState<string>('all');
  const [category, setCategory] = useState<EventCategory>('all');
  const [search, setSearch] = useState<string>('');
  const [ackFilter, setAckFilter] = useState<'all' | 'unack' | 'ack'>('unack');
  const [hours, setHours] = useState<number>(24);
  const [limit, setLimit] = useState<number>(100);

  const { data: camerasRes } = useQuery({
    // Backend caps the /cameras list `limit` at 100; 500 → 422 → empty dropdown +
    // "Unknown Camera" rows. Stay at the cap (site-scoped narrows it further).
    queryKey: ['cameras', 'all-for-events', selectedSiteId],
    queryFn: () => camerasApi.getAll({ limit: 100, site_id: selectedSiteId || undefined }),
  });
  const cameras = useMemo(() => camerasRes?.data?.items ?? camerasRes?.data ?? [], [camerasRes]);
  const cameraName = useMemo(() => {
    const m = new Map<string, string>();
    // Normalize keys to lowercase so a casing/whitespace difference between the
    // camera list and an event's camera_id can't fall through to "Unknown Camera".
    for (const c of cameras as Array<{ id: string; name: string }>) m.set(String(c.id).trim().toLowerCase(), c.name);
    return m;
  }, [cameras]);

  // Category + free-text are applied client-side over the fetched page (so the
  // tabs/search react instantly); camera/ack/time/limit stay server-side.
  // Key on the STABLE filter inputs only and compute the concrete start_time
  // inside queryFn, embedding rangeStart() (ms-precision, new on every render)
  // in the key made every render a brand-new query that refetched + thrashed the
  // cache, and defeated staleTime.
  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ['camera-events', { cameraId, ackFilter, hours, limit }],
    queryFn: () =>
      camerasApi
        .getEvents({
          camera_id: cameraId !== 'all' ? cameraId : undefined,
          acknowledged: ackFilter === 'all' ? undefined : ackFilter === 'ack',
          start_time: rangeStart(hours),
          limit,
        })
        .then((r) => r.data),
    refetchInterval: 30_000,
  });
  const events: CameraEvent[] = useMemo(() => data?.items ?? [], [data]);
  const total: number = data?.total ?? events.length;

  const { data: unackData } = useQuery({
    queryKey: ['camera-events-unack-count'],
    queryFn: () => camerasApi.getUnacknowledgedCount().then((r) => r.data),
    refetchInterval: 30_000,
  });

  const ackMut = useMutation({
    mutationFn: (id: string) => camerasApi.acknowledgeEvent(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['camera-events'] });
      qc.invalidateQueries({ queryKey: ['camera-events-unack-count'] });
    },
    onError: (err: unknown) =>
      toast({ title: t('CameraEventsPage.toasts.ackFailed'), description: String((err as Error)?.message ?? ''), variant: 'destructive' }),
  });

  const bulkAckMut = useMutation({
    mutationFn: (ids: string[]) => camerasApi.bulkAcknowledgeEvents(ids),
    onSuccess: (_res, ids) => {
      qc.invalidateQueries({ queryKey: ['camera-events'] });
      qc.invalidateQueries({ queryKey: ['camera-events-unack-count'] });
      toast({ title: t('CameraEventsPage.toasts.bulkAcked', { count: ids.length }) });
    },
    onError: (err: unknown) =>
      toast({ title: t('CameraEventsPage.toasts.ackFailed'), description: String((err as Error)?.message ?? ''), variant: 'destructive' }),
  });

  // Client-side category + free-text filter over the fetched page.
  const filteredEvents = useMemo(() => {
    const q = search.trim().toLowerCase();
    return events.filter((ev) => {
      if (category !== 'all' && eventCategory(ev) !== category) return false;
      if (q) {
        const name = cameraName.get(String(ev.camera_id).trim().toLowerCase()) ?? '';
        const hay = `${ev.event_type} ${ev.description ?? ''} ${name}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [events, category, search, cameraName]);

  const categoryCounts = useMemo(() => {
    const m: Record<string, number> = { all: events.length };
    for (const ev of events) {
      const c = eventCategory(ev);
      m[c] = (m[c] ?? 0) + 1;
    }
    return m;
  }, [events]);

  const unackIds = filteredEvents.filter((e) => !e.is_acknowledged).map((e) => e.id);

  // ── Browser push notifications (PWA) ──
  const [pushStatus, setPushStatus] = useState<PushStatus>('unsupported');
  const [pushBusy, setPushBusy] = useState(false);
  useEffect(() => {
    let active = true;
    getPushStatus().then((s) => active && setPushStatus(s));
    return () => { active = false; };
  }, []);

  const togglePush = async () => {
    setPushBusy(true);
    try {
      if (pushStatus === 'subscribed') {
        await disablePush();
        toast({ title: t('CameraEventsPage.push.disabledToast') });
      } else {
        await enablePush();
        toast({ title: t('CameraEventsPage.push.enabledToast') });
      }
      setPushStatus(await getPushStatus());
    } catch (err) {
      toast({
        title: t('CameraEventsPage.push.failed'),
        description: String((err as Error)?.message ?? ''),
        variant: 'destructive',
      });
    } finally {
      setPushBusy(false);
    }
  };

  // Only offer the toggle when push is actually usable (SW present + browser
  // support). 'unsupported'/'unconfigured' → hide; 'denied' → show disabled.
  const showPushToggle = pushStatus !== 'unsupported' && pushStatus !== 'unconfigured';

  return (
    <div className="space-y-4">
      <PageHeader
        title={t('CameraEventsPage.title')}
        description={t('CameraEventsPage.description')}
        actions={
          <div className="flex items-center gap-2">
            {(unackData?.count ?? 0) > 0 && (
              <Badge variant="destructive" className="gap-1">
                <BellRing className="h-3 w-3" />
                {t('CameraEventsPage.unreviewed', { count: unackData?.count ?? 0 })}
              </Badge>
            )}
            {showPushToggle && (
              <Button
                variant={pushStatus === 'subscribed' ? 'default' : 'outline'}
                size="sm"
                disabled={pushBusy || pushStatus === 'denied'}
                onClick={togglePush}
                title={pushStatus === 'denied' ? t('CameraEventsPage.push.denied') : undefined}
              >
                {pushBusy ? (
                  <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                ) : pushStatus === 'subscribed' ? (
                  <Bell className="h-4 w-4 mr-1" />
                ) : (
                  <BellOff className="h-4 w-4 mr-1" />
                )}
                {pushStatus === 'subscribed'
                  ? t('CameraEventsPage.push.enabled')
                  : t('CameraEventsPage.push.enable')}
              </Button>
            )}
            <Button
              variant="outline"
              size="sm"
              disabled={unackIds.length === 0 || bulkAckMut.isPending}
              onClick={() => bulkAckMut.mutate(unackIds)}
            >
              <CheckCheck className="h-4 w-4 mr-1" />
              {t('CameraEventsPage.reviewAllShown')}
            </Button>
          </div>
        }
      />

      {/* Free-text search + camera / status / range filters */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-60">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('CameraEventsPage.searchPlaceholder')}
            className="h-9 pl-8"
          />
        </div>
        <Select value={cameraId} onValueChange={setCameraId}>
          <SelectTrigger className="w-48 h-9"><SelectValue placeholder={t('CameraEventsPage.filters.camera')} /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('CameraEventsPage.filters.allCameras')}</SelectItem>
            {(cameras as Array<{ id: string; name: string }>).map((c) => (
              <SelectItem key={String(c.id)} value={String(c.id)}>{c.name}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={ackFilter} onValueChange={(v) => setAckFilter(v as typeof ackFilter)}>
          <SelectTrigger className="w-40 h-9"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="unack">{t('CameraEventsPage.filters.unreviewed')}</SelectItem>
            <SelectItem value="ack">{t('CameraEventsPage.filters.reviewed')}</SelectItem>
            <SelectItem value="all">{t('CameraEventsPage.filters.allStatus')}</SelectItem>
          </SelectContent>
        </Select>
        <Select value={String(hours)} onValueChange={(v) => setHours(Number(v))}>
          <SelectTrigger className="w-36 h-9"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="1">{t('CameraEventsPage.range.h1')}</SelectItem>
            <SelectItem value="24">{t('CameraEventsPage.range.h24')}</SelectItem>
            <SelectItem value="168">{t('CameraEventsPage.range.d7')}</SelectItem>
            <SelectItem value="720">{t('CameraEventsPage.range.d30')}</SelectItem>
          </SelectContent>
        </Select>
        {isFetching && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
      </div>

      {/* Detection category tabs (All / Person / Vehicle / Motion / …) */}
      <div className="flex flex-wrap items-center gap-1">
        {CATEGORIES.map((c) => {
          const count = categoryCounts[c] ?? 0;
          const active = category === c;
          return (
            <button
              key={c}
              type="button"
              onClick={() => setCategory(c)}
              className={cn(
                'rounded-full px-3 py-1 text-xs transition-colors',
                active ? 'bg-primary text-primary-foreground' : 'bg-muted/60 text-muted-foreground hover:bg-muted',
              )}
            >
              {t(`CameraEventsPage.categories.${c}`)}
              {c !== 'all' && count > 0 && <span className="ml-1 opacity-70">{count}</span>}
            </button>
          );
        })}
      </div>

      {/* Content */}
      {isError ? (
        <ErrorState message={t('CameraEventsPage.error')} onRetry={() => refetch()} />
      ) : isLoading ? (
        <div className="flex items-center justify-center py-16 text-muted-foreground">
          <Loader2 className="h-5 w-5 animate-spin mr-2" /> {t('CameraEventsPage.loading')}
        </div>
      ) : filteredEvents.length === 0 ? (
        <Card>
          <EmptyState
            icon={Activity}
            title={t('CameraEventsPage.empty.title')}
            description={t('CameraEventsPage.empty.description')}
          />
        </Card>
      ) : (
        <div className="space-y-2">
          {filteredEvents.map((ev) => {
            const et = (ev.event_type || '').toLowerCase();
            const isAlert = ALERT_TYPES.has(et);
            const typeKey = EVENT_TYPE_KEYS[et];
            const typeLabel = typeKey ? t(`CameraEventsPage.types.${typeKey}`) : ev.event_type;
            return (
              <Card key={ev.id} className={cn(!ev.is_acknowledged && 'border-l-2 border-l-primary')}>
                <CardContent className="flex items-center gap-3 py-3">
                  <div className={cn(
                    'flex h-10 w-10 shrink-0 items-center justify-center rounded-md',
                    isAlert ? 'bg-red-500/10 text-red-500' : 'bg-primary/10 text-primary',
                  )}>
                    {isAlert ? <ShieldAlert className="h-5 w-5" /> : <Activity className="h-5 w-5" />}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <Badge variant={isAlert ? 'destructive' : 'secondary'} className="text-xs">{typeLabel}</Badge>
                      <span className="text-sm font-medium truncate">
                        {cameraName.get(String(ev.camera_id).trim().toLowerCase()) ?? t('CameraEventsPage.unknownCamera')}
                      </span>
                      {!ev.is_acknowledged && (
                        <Badge variant="outline" className="text-[10px] h-5 px-1.5">{t('CameraEventsPage.new')}</Badge>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground truncate">
                      {new Date(ev.timestamp).toLocaleString()}
                      {ev.description ? ` · ${ev.description}` : ''}
                    </p>
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    {/* Jump to the recorded playback at this event's instant. */}
                    <Button
                      size="sm"
                      variant="ghost"
                      title={t('CameraEventsPage.playAtTime')}
                      onClick={() =>
                        navigate(
                          `/cameras/playback?cameras=${encodeURIComponent(ev.camera_id)}&time=${encodeURIComponent(ev.timestamp)}`,
                        )
                      }
                    >
                      <PlayCircle className="h-4 w-4 mr-1" /> {t('CameraEventsPage.play')}
                    </Button>
                    {ev.is_acknowledged ? (
                      <span className="flex items-center gap-1 text-xs text-emerald-600">
                        <Check className="h-3.5 w-3.5" /> {t('CameraEventsPage.reviewed')}
                      </span>
                    ) : (
                      <Button size="sm" variant="ghost" disabled={ackMut.isPending} onClick={() => ackMut.mutate(ev.id)}>
                        <Check className="h-4 w-4 mr-1" /> {t('CameraEventsPage.review')}
                      </Button>
                    )}
                  </div>
                </CardContent>
              </Card>
            );
          })}
          {events.length >= limit && total > events.length && limit < MAX_EVENT_LIMIT && (
            <div className="flex justify-center pt-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setLimit((l) => Math.min(l + 100, MAX_EVENT_LIMIT))}
              >
                {t('CameraEventsPage.loadMore')}
              </Button>
            </div>
          )}
          {total > events.length && limit >= MAX_EVENT_LIMIT && (
            <p className="text-center text-xs text-muted-foreground pt-2">
              {t('CameraEventsPage.maxEventsReached', { max: MAX_EVENT_LIMIT })}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
