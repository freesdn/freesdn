// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * OverlayDiscoveryTab — the "Discovered" inbox for the connected overlay mesh.
 *
 * The tailnet/netbird is an inventory: GET /vpn/discovery enumerates peers and
 * classifies each into an adoptable candidate (tags > hostname > OS) on the
 * backend. This tab renders them as cards and reuses the existing
 * DiscoveredDeviceCard + AdoptDeviceDialog (the agent-scan adopt flow) by mapping
 * an overlay device into the shared DiscoveredDevice shape. See
 * docs.freesdn.org.
 */
import { useMemo, useState } from 'react';

import { useQuery } from '@tanstack/react-query';
import { RefreshCw, Radar } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import AdoptDeviceDialog from '@/components/discovery/AdoptDeviceDialog';
import DiscoveredDeviceCard, {
  type DiscoveredDevice,
} from '@/components/discovery/DiscoveredDeviceCard';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { Skeleton } from '@/components/ui/skeleton';
import { useToast } from '@/hooks/use-toast';
import { vpnApi, type OverlayDiscoveredDevice } from '@/lib/api';
import { useSiteStore } from '@/stores/siteStore';

const CONFIDENCE_SCORE: Record<string, number> = { high: 90, medium: 65, low: 30 };

/** Map an overlay peer into the shared DiscoveredDevice shape the card + adopt
 *  dialog already understand (ip = the overlay address; vendor = the provider). */
function toDiscoveredDevice(d: OverlayDiscoveredDevice): DiscoveredDevice {
  return {
    ip: d.address,
    hostname: d.hostname || d.magic_dns || undefined,
    device_type:
      d.suggested_type && d.suggested_type !== 'unknown' ? d.suggested_type : undefined,
    vendor: d.online ? d.source : `${d.source} (offline)`,
    confidence: CONFIDENCE_SCORE[d.confidence] ?? 40,
    is_adopted: d.already_adopted ?? false,
    adopted_device_id: d.adopted_device_id ?? undefined,
    status: d.already_adopted ? 'adopted' : 'new',
  };
}

interface OverlayDiscoveryTabProps {
  active: boolean;
}

export default function OverlayDiscoveryTab({ active }: OverlayDiscoveryTabProps) {
  const { t } = useTranslation('vpn');
  const { toast } = useToast();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  const [ignored, setIgnored] = useState<Set<string>>(new Set());
  const [adoptDevice, setAdoptDevice] = useState<DiscoveredDevice | null>(null);
  const [adoptOpen, setAdoptOpen] = useState(false);

  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ['vpnOverlayDiscovery'],
    queryFn: async () => (await vpnApi.getDiscovery()).data,
    refetchInterval: 30000,
    refetchIntervalInBackground: false,
    enabled: active,
  });

  const mode = data?.mode ?? 'off';
  const devices = useMemo(
    () => (data?.devices ?? []).filter((d) => !ignored.has(d.address)),
    [data, ignored],
  );

  const handleAdopt = (device: DiscoveredDevice) => {
    if (!selectedSiteId) {
      toast({
        title: t('VPNPage.overlayDiscovery.noSiteTitle'),
        description: t('VPNPage.overlayDiscovery.noSiteBody'),
        variant: 'destructive',
      });
      return;
    }
    setAdoptDevice(device);
    setAdoptOpen(true);
  };

  const handleIgnore = (device: DiscoveredDevice) => {
    setIgnored((prev) => new Set(prev).add(device.ip));
    toast({
      title: t('VPNPage.overlayDiscovery.ignoredTitle'),
      description: device.hostname || device.ip,
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="flex items-center gap-2 text-lg font-semibold">
            <Radar className="h-5 w-5 text-primary" />
            {t('VPNPage.overlayDiscovery.heading')}
            {devices.length > 0 && <Badge variant="secondary">{devices.length}</Badge>}
          </h3>
          <p className="text-sm text-muted-foreground">
            {t('VPNPage.overlayDiscovery.subtitle')}
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
          <RefreshCw className={`mr-1 h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />
          {t('VPNPage.overlayDiscovery.refresh')}
        </Button>
      </div>

      {isError ? (
        <Card className="border-destructive">
          <CardContent className="p-4 text-sm text-destructive">
            {t('VPNPage.overlayDiscovery.loadError')}
          </CardContent>
        </Card>
      ) : isLoading ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} className="h-40 w-full" />
          ))}
        </div>
      ) : devices.length === 0 ? (
        <EmptyState
          icon={Radar}
          title={t('VPNPage.overlayDiscovery.emptyTitle')}
          description={
            mode === 'off'
              ? t('VPNPage.overlayDiscovery.emptyOffBody')
              : t('VPNPage.overlayDiscovery.emptyOnBody')
          }
        />
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {devices.map((d) => (
            <DiscoveredDeviceCard
              key={`${d.source}:${d.address}`}
              device={toDiscoveredDevice(d)}
              onAdopt={handleAdopt}
              onIgnore={handleIgnore}
            />
          ))}
        </div>
      )}

      <AdoptDeviceDialog
        device={adoptDevice}
        open={adoptOpen}
        onOpenChange={setAdoptOpen}
        siteId={selectedSiteId ?? ''}
        onAdopted={() => {
          setAdoptOpen(false);
          if (adoptDevice) {
            setIgnored((prev) => new Set(prev).add(adoptDevice.ip));
          }
          refetch();
        }}
      />
    </div>
  );
}
