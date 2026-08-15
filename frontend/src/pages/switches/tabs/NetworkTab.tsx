// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * NetworkTab · LLDP neighbors, static routes, DHCP config, and MAC table
 * for the switch detail view.
 *
 * Extracted from SwitchesPage as part of the monolith breakup. Purely
 * presentational; receives all data via props from the parent's queries.
 */
import { Globe, Monitor, Network, Router } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Badge } from '@/components/ui/badge';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import type {
  LLDPNeighbor,
  MACTableEntry,
  StaticRoute,
} from '@/lib/api';

export interface NetworkTabProps {
  lldpNeighbors: LLDPNeighbor[] | undefined;
  staticRoutes: StaticRoute[] | undefined;
  dhcpConfig: unknown;
  macTable: MACTableEntry[] | undefined;
}

export function NetworkTab({ lldpNeighbors, staticRoutes, dhcpConfig, macTable }: NetworkTabProps) {
  const { t } = useTranslation('switches');
  return (
    <>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* LLDP Neighbors */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Router className="h-4 w-4" />
              {t('NetworkTab.lldp.title')}
            </CardTitle>
            <CardDescription>{t('NetworkTab.lldp.discovered', { count: lldpNeighbors?.length || 0 })}</CardDescription>
          </CardHeader>
          <CardContent>
            {lldpNeighbors?.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('NetworkTab.lldp.columns.port')}</TableHead>
                    <TableHead>{t('NetworkTab.lldp.columns.neighborDevice')}</TableHead>
                    <TableHead>{t('NetworkTab.lldp.columns.neighborPort')}</TableHead>
                    <TableHead>{t('NetworkTab.lldp.columns.ip')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {lldpNeighbors.map((n, i) => (
                    <TableRow key={i}>
                      <TableCell className="font-medium">{n.port_name || t('NetworkTab.lldp.portFallback', { index: n.port_index })}</TableCell>
                      <TableCell>{n.system_name || n.neighbor_device || '-'}</TableCell>
                      <TableCell>{n.neighbor_port || '-'}</TableCell>
                      <TableCell className="font-mono text-xs">{n.neighbor_ip || '-'}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p className="text-sm text-muted-foreground py-4 text-center">{t('NetworkTab.lldp.empty')}</p>
            )}
          </CardContent>
        </Card>

        {/* Static Routes */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Globe className="h-4 w-4" />
              {t('NetworkTab.routes.title')}
            </CardTitle>
            <CardDescription>{t('NetworkTab.routes.configured', { count: staticRoutes?.length || 0 })}</CardDescription>
          </CardHeader>
          <CardContent>
            {staticRoutes?.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('NetworkTab.routes.columns.destination')}</TableHead>
                    <TableHead>{t('NetworkTab.routes.columns.mask')}</TableHead>
                    <TableHead>{t('NetworkTab.routes.columns.gateway')}</TableHead>
                    <TableHead>{t('NetworkTab.routes.columns.metric')}</TableHead>
                    <TableHead>{t('NetworkTab.routes.columns.status')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {staticRoutes.map((route, i) => (
                    <TableRow key={route.id || i}>
                      <TableCell className="font-mono text-xs">{route.destination || '-'}</TableCell>
                      <TableCell className="font-mono text-xs">{route.subnet_mask || '-'}</TableCell>
                      <TableCell className="font-mono text-xs">{route.gateway || '-'}</TableCell>
                      <TableCell>{route.metric ?? '-'}</TableCell>
                      <TableCell>
                        <Badge variant={route.enabled ? 'default' : 'secondary'}>
                          {route.enabled ? t('NetworkTab.routes.status.active') : t('NetworkTab.routes.status.disabled')}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p className="text-sm text-muted-foreground py-4 text-center">{t('NetworkTab.routes.empty')}</p>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* DHCP Info */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Network className="h-4 w-4" />
              {t('NetworkTab.dhcp.title')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {dhcpConfig ? (
              <div className="space-y-2 text-sm">
                {Object.entries(dhcpConfig as Record<string, unknown>).slice(0, 10).map(([key, val]) => (
                  <div key={key} className="flex justify-between">
                    <span className="text-muted-foreground capitalize">{key.replace(/_/g, ' ')}</span>
                    <span className="font-medium">{String(val)}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground py-4 text-center">{t('NetworkTab.dhcp.empty')}</p>
            )}
          </CardContent>
        </Card>

        {/* MAC Address Table */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Monitor className="h-4 w-4" />
              {t('NetworkTab.mac.title')}
            </CardTitle>
            <CardDescription>{t('NetworkTab.mac.entries', { count: macTable?.length || 0 })}</CardDescription>
          </CardHeader>
          <CardContent>
            {macTable?.length ? (
              <div className="max-h-[300px] overflow-y-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{t('NetworkTab.mac.columns.macAddress')}</TableHead>
                      <TableHead>{t('NetworkTab.mac.columns.vlan')}</TableHead>
                      <TableHead>{t('NetworkTab.mac.columns.port')}</TableHead>
                      <TableHead>{t('NetworkTab.mac.columns.type')}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {macTable.map((entry, i) => (
                      <TableRow key={i}>
                        <TableCell className="font-mono text-xs">{entry.mac_address}</TableCell>
                        <TableCell>{entry.vlan_id ?? '-'}</TableCell>
                        <TableCell>{entry.port ?? '-'}</TableCell>
                        <TableCell>
                          <Badge variant={entry.type === 'static' ? 'default' : 'secondary'} className="text-xs">
                            {entry.type || 'dynamic'}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            ) : (
              <p className="text-sm text-muted-foreground py-4 text-center">{t('NetworkTab.mac.empty')}</p>
            )}
          </CardContent>
        </Card>
      </div>
    </>
  );
}
