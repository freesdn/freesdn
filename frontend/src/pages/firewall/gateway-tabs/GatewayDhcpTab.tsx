// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * GatewayDhcpTab · DHCP leases, static mappings, Kea subnets/leases, DHCP relay.
 *
 * Extracted from GatewayDetailPage as part of the monolith breakup. Owns the
 * dhcpColumns and dhcpStaticColumns definitions (only used here) and receives
 * all data, loading flags, and add/edit/delete callbacks via props.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useTranslation } from 'react-i18next';
import { Activity, Globe, Pencil, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { Skeleton } from '@/components/ui/skeleton';

export interface GatewayDhcpTabProps {
  dhcpLeases: any[];
  dhcpLoading: boolean;
  dhcpStatic: any[];
  dhcpStaticLoading: boolean;
  keaSubnetsData: any;
  keaSubnetsLoading: boolean;
  keaLeasesData: any;
  keaLeasesLoading: boolean;
  dhcpRelayData: any;
  dhcpRelayLoading: boolean;
  onAddStatic: () => void;
  onEditStatic: (item: any) => void;
  onDeleteStatic: (item: any, vid: string) => void;
}

export function GatewayDhcpTab({
  dhcpLeases,
  dhcpLoading,
  dhcpStatic,
  dhcpStaticLoading,
  keaSubnetsData,
  keaSubnetsLoading,
  keaLeasesData,
  keaLeasesLoading,
  dhcpRelayData,
  dhcpRelayLoading,
  onAddStatic,
  onEditStatic,
  onDeleteStatic,
}: GatewayDhcpTabProps) {
  const { t } = useTranslation('firewall');

  const dhcpColumns: DataTableColumn<any>[] = [
    { id: 'ip', header: t('GatewayDhcpTab.leases.columns.ipAddress'), accessorFn: (r: any) => r.ip_address || r.address || '-', sortable: true },
    { id: 'mac', header: t('GatewayDhcpTab.leases.columns.mac'), accessorFn: (r: any) => r.mac_address || r.mac || '-' },
    { id: 'hostname', header: t('GatewayDhcpTab.leases.columns.hostname'), accessorFn: (r: any) => r.hostname || r.host_name || '-' },
    { id: 'interface', header: t('GatewayDhcpTab.leases.columns.interface'), accessorFn: (r: any) => r.interface_name || r.interface || '-' },
    { id: 'status', header: t('GatewayDhcpTab.leases.columns.status'), cell: (r: any) => {
      const active = r.status === 'active' || r.binding_state === 'active';
      return <Badge variant={active ? 'default' : 'secondary'}>{r.status || r.binding_state || t('GatewayDhcpTab.leases.unknownStatus')}</Badge>;
    }},
    { id: 'ends', header: t('GatewayDhcpTab.leases.columns.expires'), accessorFn: (r: any) => r.ends || r.expires || '-' },
  ];

  const dhcpStaticColumns: DataTableColumn<any>[] = [
    { id: 'mac', header: t('GatewayDhcpTab.static.columns.mac'), accessorFn: (r: any) => r.mac_address || r.mac || '-', sortable: true },
    { id: 'ip', header: t('GatewayDhcpTab.static.columns.ip'), accessorFn: (r: any) => r.ip_address || r.ipaddr || r.ip || '-' },
    { id: 'hostname', header: t('GatewayDhcpTab.static.columns.hostname'), accessorFn: (r: any) => r.hostname || '-' },
    { id: 'description', header: t('GatewayDhcpTab.static.columns.description'), accessorFn: (r: any) => r.description || '-' },
    { id: 'interface', header: t('GatewayDhcpTab.static.columns.interface'), accessorFn: (r: any) => r.interface_name || r.interface || '-' },
    { id: 'actions', header: '', cell: (r: any) => {
      const vid = r.uuid || r.id;
      return (
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="sm" onClick={() => onEditStatic(r)}><Pencil className="h-3.5 w-3.5" /></Button>
          {vid && <Button variant="ghost" size="sm" onClick={() => onDeleteStatic(r, vid)}><Trash2 className="h-3.5 w-3.5 text-destructive" /></Button>}
        </div>
      );
    }},
  ];

  return (
    <>
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle>{t('GatewayDhcpTab.leases.title')}</CardTitle>
          <CardDescription>{t('GatewayDhcpTab.leases.description')}</CardDescription>
        </CardHeader>
        <DataTable data={dhcpLeases} columns={dhcpColumns} isLoading={dhcpLoading} searchable searchPlaceholder={t('GatewayDhcpTab.leases.searchPlaceholder')} embedded />
      </Card>
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t('GatewayDhcpTab.static.title')}</CardTitle>
              <CardDescription>{t('GatewayDhcpTab.static.description')}</CardDescription>
            </div>
            <Button size="sm" onClick={onAddStatic}>
              <Plus className="h-4 w-4 mr-1" /> {t('GatewayDhcpTab.static.addMapping')}
            </Button>
          </div>
        </CardHeader>
        <DataTable data={dhcpStatic} columns={dhcpStaticColumns} isLoading={dhcpStaticLoading} searchable searchPlaceholder={t('GatewayDhcpTab.static.searchPlaceholder')} embedded />
      </Card>

      {/* Kea DHCPv4 Subnets */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2"><Globe className="h-4 w-4" /> {t('GatewayDhcpTab.keaSubnets.title')}</CardTitle>
          <CardDescription>{t('GatewayDhcpTab.keaSubnets.description')}</CardDescription>
        </CardHeader>
        {keaSubnetsLoading ? (
          <CardContent><Skeleton className="h-20" /></CardContent>
        ) : (() => {
          const subnets = keaSubnetsData?.data?.kea_dhcpv4_subnets || [];
          return (
            <CardContent>
              {subnets.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead><tr className="border-b text-left text-muted-foreground">
                      <th className="px-3 py-2 font-medium">{t('GatewayDhcpTab.keaSubnets.columns.subnet')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayDhcpTab.keaSubnets.columns.description')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayDhcpTab.keaSubnets.columns.pools')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayDhcpTab.keaSubnets.columns.interface')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayDhcpTab.keaSubnets.columns.gateway')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayDhcpTab.keaSubnets.columns.dnsServers')}</th>
                    </tr></thead>
                    <tbody>
                      {subnets.map((s: any, i: number) => (
                        <tr key={i} className="border-b last:border-0">
                          <td className="px-3 py-2 font-mono text-xs">{s.subnet || '-'}</td>
                          <td className="px-3 py-2">{s.description || '-'}</td>
                          <td className="px-3 py-2 font-mono text-xs">{s.pools || '-'}</td>
                          <td className="px-3 py-2">{s.interface || '-'}</td>
                          <td className="px-3 py-2 font-mono text-xs">{s.gateway || s.option_routers || '-'}</td>
                          <td className="px-3 py-2 font-mono text-xs">{s.dns_servers || s.option_domain_name_servers || '-'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-sm text-muted-foreground text-center py-4">{t('GatewayDhcpTab.keaSubnets.empty')}</p>
              )}
            </CardContent>
          );
        })()}
      </Card>

      {/* Kea DHCP Leases */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2"><Activity className="h-4 w-4" /> {t('GatewayDhcpTab.keaLeases.title')}</CardTitle>
          <CardDescription>{t('GatewayDhcpTab.keaLeases.description')}</CardDescription>
        </CardHeader>
        {keaLeasesLoading ? (
          <CardContent><Skeleton className="h-20" /></CardContent>
        ) : (() => {
          const leases = keaLeasesData?.data?.kea_leases || [];
          return (
            <CardContent>
              {leases.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead><tr className="border-b text-left text-muted-foreground">
                      <th className="px-3 py-2 font-medium">{t('GatewayDhcpTab.keaLeases.columns.ipAddress')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayDhcpTab.keaLeases.columns.macAddress')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayDhcpTab.keaLeases.columns.hostname')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayDhcpTab.keaLeases.columns.state')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayDhcpTab.keaLeases.columns.expires')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayDhcpTab.keaLeases.columns.subnetId')}</th>
                    </tr></thead>
                    <tbody>
                      {leases.map((l: any, i: number) => (
                        <tr key={i} className="border-b last:border-0">
                          <td className="px-3 py-2 font-mono text-xs">{l.address || l.ip_address || '-'}</td>
                          <td className="px-3 py-2 font-mono text-xs">{l.hw_address || l.mac || '-'}</td>
                          <td className="px-3 py-2">{l.hostname || '-'}</td>
                          <td className="px-3 py-2"><Badge variant={l.state === 'default' || l.state === 0 ? 'default' : 'secondary'}>{l.state || '-'}</Badge></td>
                          <td className="px-3 py-2 text-xs">{l.expire || l.valid_lifetime || '-'}</td>
                          <td className="px-3 py-2">{l.subnet_id || '-'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-sm text-muted-foreground text-center py-4">{t('GatewayDhcpTab.keaLeases.empty')}</p>
              )}
            </CardContent>
          );
        })()}
      </Card>

      {/* ─── DHCP Relay ─────────────────────────────────────── */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle>{t('GatewayDhcpTab.relay.title')}</CardTitle>
          <CardDescription>{t('GatewayDhcpTab.relay.description')}</CardDescription>
        </CardHeader>
        {dhcpRelayLoading ? (
          <CardContent><div className="flex items-center gap-2 text-muted-foreground"><RefreshCw className="h-4 w-4 animate-spin" /> {t('GatewayDhcpTab.relay.loading')}</div></CardContent>
        ) : (() => {
          const relay = dhcpRelayData?.data?.dhcp_relay || {};
          const relayEnabled = relay.enabled === '1' || relay.enabled === true;
          const destinations = Array.isArray(relay.destinations) ? relay.destinations : [];
          return (
            <CardContent>
              <dl className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <dt className="text-muted-foreground">{t('GatewayDhcpTab.relay.status')}</dt>
                  <dd><Badge variant={relayEnabled ? 'default' : 'secondary'}>{relayEnabled ? t('GatewayDhcpTab.relay.enabled') : t('GatewayDhcpTab.relay.disabled')}</Badge></dd>
                </div>
                {destinations.length > 0 && (
                  <>
                    <div>
                      <dt className="text-muted-foreground">{t('GatewayDhcpTab.relay.relayServers')}</dt>
                      <dd className="font-mono text-xs">{destinations.map((d: any) => d.server || d.address || d.destination || d).filter(Boolean).join(', ') || '-'}</dd>
                    </div>
                    <div>
                      <dt className="text-muted-foreground">{t('GatewayDhcpTab.relay.interface')}</dt>
                      <dd className="font-mono text-xs">{destinations.map((d: any) => d.interface).filter(Boolean).join(', ') || '-'}</dd>
                    </div>
                  </>
                )}
              </dl>
            </CardContent>
          );
        })()}
      </Card>
    </>
  );
}
