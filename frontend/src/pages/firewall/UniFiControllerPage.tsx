// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, UniFi Controller detail page (firewall/unifi/:id)
 *
 * Mounts the Pending Changes badge + drawer for UniFi controllers and
 * renders the per-domain UniFi tabs. Mirrors GatewayDetailPage but
 * targets ``core.controllers`` rows (the polymorphic resolver accepts
 * either id shape on the backend stage/apply path).
 *
 * The MikroTik UI lives at /firewall/gateways/:id because MikroTik
 * routers can be Gateways (limb side) OR Controllers (brain side).
 * UniFi is controller-only, so it gets its own page here and routes
 * are kept clean for future per-vendor pages.
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, Loader2, Server } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { PageHeader } from '@/components/layout';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { PendingChangesBadge } from '@/components/gateways/PendingChangesBadge';
import { PendingChangesDrawer } from '@/components/gateways/PendingChangesDrawer';
import { UniFiClientsTab } from './unifi-tabs/UniFiClientsTab';
import { UniFiDevicesTab } from './unifi-tabs/UniFiDevicesTab';
import { UniFiNetworksTab } from './unifi-tabs/UniFiNetworksTab';
import { UniFiWlansTab } from './unifi-tabs/UniFiWlansTab';
import { UniFiFirewallTab } from './unifi-tabs/UniFiFirewallTab';
import { UniFiTrafficTab } from './unifi-tabs/UniFiTrafficTab';
import { UniFiDnsTab } from './unifi-tabs/UniFiDnsTab';
import { UniFiRoutingTab } from './unifi-tabs/UniFiRoutingTab';
import { UniFiVpnTab } from './unifi-tabs/UniFiVpnTab';
import { UniFiSwitchTab } from './unifi-tabs/UniFiSwitchTab';
import { UniFiPortProfilesTab } from './unifi-tabs/UniFiPortProfilesTab';
import { UniFiRadiosTab } from './unifi-tabs/UniFiRadiosTab';
import { UniFiWlanGroupsTab } from './unifi-tabs/UniFiWlanGroupsTab';
import { UniFiRadiusTab } from './unifi-tabs/UniFiRadiusTab';
import { UniFiHotspotTab } from './unifi-tabs/UniFiHotspotTab';
import { api } from '@/lib/api/client';

interface ControllerSummary {
  id: string;
  name: string;
  host: string;
  port: number;
  controller_type: string;
  site_id: string | null;
  config?: Record<string, unknown>;
}

export function UniFiControllerPage() {
  const { t } = useTranslation('firewall');
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('clients');
  const [pendingDrawerOpen, setPendingDrawerOpen] = useState(false);

  const controllerQuery = useQuery({
    queryKey: ['controller', id],
    queryFn: () =>
      api.get<ControllerSummary>(`/controllers/${encodeURIComponent(id!)}`),
    enabled: !!id,
  });

  if (!id) {
    return (
      <div className="p-8 text-destructive">
        {t('UniFiControllerPage.errors.missingId')}
      </div>
    );
  }
  if (controllerQuery.isLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }
  if (controllerQuery.isError || !controllerQuery.data) {
    return (
      <div className="p-8 text-destructive">
        {t('UniFiControllerPage.errors.loadFailed')}{' '}
        {(controllerQuery.error as Error)?.message ||
          t('UniFiControllerPage.errors.unknown')}
      </div>
    );
  }

  const ctrl = controllerQuery.data.data;
  if (ctrl.controller_type !== 'unifi') {
    return (
      <div className="p-8 text-destructive">
        {t('UniFiControllerPage.errors.notUnifi.before')}{' '}
        <code className="font-mono">{id}</code>{' '}
        {t('UniFiControllerPage.errors.notUnifi.middle')}
        <code className="font-mono">{ctrl.controller_type}</code>
        {t('UniFiControllerPage.errors.notUnifi.after')}
      </div>
    );
  }

  // UniFi sites are controller-scoped strings (not FreeSDN sub-sites).
  // ``default`` is the universal first site name and what fresh UOS
  // controllers ship with. Override via ``config.site`` if the operator
  // points at a non-default site.
  const site =
    ((ctrl.config as { site?: string } | undefined)?.site as string) ||
    'default';

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Server}
        title={ctrl.name}
        subtitle={t('UniFiControllerPage.subtitle', {
          host: ctrl.host,
          port: ctrl.port,
          site,
        })}
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate('/controllers')}
            >
              <ArrowLeft className="h-4 w-4 mr-2" />{' '}
              {t('UniFiControllerPage.actions.back')}
            </Button>
            <PendingChangesBadge
              vendor="unifi"
              gatewayId={id}
              open={pendingDrawerOpen}
              onOpenChange={setPendingDrawerOpen}
            />
          </div>
        }
      />

      <PendingChangesDrawer
        open={pendingDrawerOpen}
        onOpenChange={setPendingDrawerOpen}
        vendor="unifi"
        gatewayId={id}
        gatewayName={ctrl.name}
      />

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="clients" data-testid="tab-clients">
            {t('UniFiControllerPage.tabs.clients')}
          </TabsTrigger>
          <TabsTrigger value="devices" data-testid="tab-devices">
            {t('UniFiControllerPage.tabs.devices')}
          </TabsTrigger>
          <TabsTrigger value="wlans" data-testid="tab-wlans">
            {t('UniFiControllerPage.tabs.wlans')}
          </TabsTrigger>
          <TabsTrigger value="networks" data-testid="tab-networks">
            {t('UniFiControllerPage.tabs.networks')}
          </TabsTrigger>
          <TabsTrigger value="firewall" data-testid="tab-firewall">
            {t('UniFiControllerPage.tabs.firewall')}
          </TabsTrigger>
          <TabsTrigger value="traffic" data-testid="tab-traffic">
            {t('UniFiControllerPage.tabs.traffic')}
          </TabsTrigger>
          <TabsTrigger value="dns" data-testid="tab-dns">
            {t('UniFiControllerPage.tabs.dns')}
          </TabsTrigger>
          <TabsTrigger value="routing" data-testid="tab-routing">
            {t('UniFiControllerPage.tabs.routing')}
          </TabsTrigger>
          <TabsTrigger value="vpn" data-testid="tab-vpn">
            {t('UniFiControllerPage.tabs.vpn')}
          </TabsTrigger>
          <TabsTrigger value="switch" data-testid="tab-switch">
            {t('UniFiControllerPage.tabs.switch')}
          </TabsTrigger>
          <TabsTrigger value="port-profiles" data-testid="tab-port-profiles">
            {t('UniFiControllerPage.tabs.portProfiles')}
          </TabsTrigger>
          <TabsTrigger value="radios" data-testid="tab-radios">
            {t('UniFiControllerPage.tabs.radios')}
          </TabsTrigger>
          <TabsTrigger value="wlan-groups" data-testid="tab-wlan-groups">
            {t('UniFiControllerPage.tabs.wlanGroups')}
          </TabsTrigger>
          <TabsTrigger value="radius" data-testid="tab-radius">
            {t('UniFiControllerPage.tabs.radius')}
          </TabsTrigger>
          <TabsTrigger value="hotspot" data-testid="tab-hotspot">
            {t('UniFiControllerPage.tabs.hotspot')}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="clients" className="mt-4">
          <UniFiClientsTab
            controllerId={id}
            site={site}
            isActive={activeTab === 'clients'}
          />
        </TabsContent>
        <TabsContent value="devices" className="mt-4">
          <UniFiDevicesTab
            controllerId={id}
            site={site}
            isActive={activeTab === 'devices'}
          />
        </TabsContent>
        <TabsContent value="wlans" className="mt-4">
          <UniFiWlansTab
            controllerId={id}
            site={site}
            isActive={activeTab === 'wlans'}
          />
        </TabsContent>
        <TabsContent value="networks" className="mt-4">
          <UniFiNetworksTab
            controllerId={id}
            site={site}
            isActive={activeTab === 'networks'}
          />
        </TabsContent>
        <TabsContent value="firewall" className="mt-4">
          <UniFiFirewallTab
            controllerId={id}
            site={site}
            isActive={activeTab === 'firewall'}
          />
        </TabsContent>
        <TabsContent value="traffic" className="mt-4">
          <UniFiTrafficTab
            controllerId={id}
            site={site}
            isActive={activeTab === 'traffic'}
          />
        </TabsContent>
        <TabsContent value="dns" className="mt-4">
          <UniFiDnsTab
            controllerId={id}
            site={site}
            isActive={activeTab === 'dns'}
          />
        </TabsContent>
        <TabsContent value="routing" className="mt-4">
          <UniFiRoutingTab
            controllerId={id}
            site={site}
            isActive={activeTab === 'routing'}
          />
        </TabsContent>
        <TabsContent value="vpn" className="mt-4">
          <UniFiVpnTab
            controllerId={id}
            site={site}
            isActive={activeTab === 'vpn'}
          />
        </TabsContent>
        <TabsContent value="switch" className="mt-4">
          <UniFiSwitchTab
            controllerId={id}
            site={site}
            isActive={activeTab === 'switch'}
          />
        </TabsContent>
        <TabsContent value="port-profiles" className="mt-4">
          <UniFiPortProfilesTab
            controllerId={id}
            site={site}
            isActive={activeTab === 'port-profiles'}
          />
        </TabsContent>
        <TabsContent value="radios" className="mt-4">
          <UniFiRadiosTab
            controllerId={id}
            site={site}
            isActive={activeTab === 'radios'}
          />
        </TabsContent>
        <TabsContent value="wlan-groups" className="mt-4">
          <UniFiWlanGroupsTab
            controllerId={id}
            site={site}
            isActive={activeTab === 'wlan-groups'}
          />
        </TabsContent>
        <TabsContent value="radius" className="mt-4">
          <UniFiRadiusTab
            controllerId={id}
            site={site}
            isActive={activeTab === 'radius'}
          />
        </TabsContent>
        <TabsContent value="hotspot" className="mt-4">
          <UniFiHotspotTab
            controllerId={id}
            site={site}
            isActive={activeTab === 'hotspot'}
          />
        </TabsContent>
      </Tabs>
    </div>
  );
}

export default UniFiControllerPage;
