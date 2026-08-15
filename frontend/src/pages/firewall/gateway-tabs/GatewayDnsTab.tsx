// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * GatewayDnsTab · DNS resolver status, host/domain overrides, dynamic DNS.
 *
 * Extracted from GatewayDetailPage as part of the monolith breakup. Owns the
 * dnsOverrideColumns and dnsDomainColumns definitions (only used here) and
 * receives all data, loading flags, and add/edit/delete callbacks via props.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { CheckCircle, Globe, Pencil, Plus, Trash2, XCircle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { Skeleton } from '@/components/ui/skeleton';

export interface GatewayDnsTabProps {
  unboundStatusData: any;
  dnsOverrides: any[];
  dnsOvLoading: boolean;
  dnsDomainOverrides: any[];
  dnsDomLoading: boolean;
  dyndnsData: any;
  dyndnsLoading: boolean;
  onAddOverride: () => void;
  onEditOverride: (item: any) => void;
  onDeleteOverride: (item: any, vid: string) => void;
  onAddDomain: () => void;
  onEditDomain: (item: any) => void;
  onDeleteDomain: (item: any, vid: string) => void;
}

export function GatewayDnsTab({
  unboundStatusData,
  dnsOverrides,
  dnsOvLoading,
  dnsDomainOverrides,
  dnsDomLoading,
  dyndnsData,
  dyndnsLoading,
  onAddOverride,
  onEditOverride,
  onDeleteOverride,
  onAddDomain,
  onEditDomain,
  onDeleteDomain,
}: GatewayDnsTabProps) {
  const { t } = useTranslation('firewall');

  const dnsOverrideColumns: DataTableColumn<any>[] = [
    { id: 'host', header: t('GatewayDnsTab.overrideColumns.host'), accessorFn: (r: any) => r.hostname || r.host || '-', sortable: true },
    { id: 'domain', header: t('GatewayDnsTab.overrideColumns.domain'), accessorFn: (r: any) => r.domain || '-' },
    { id: 'type', header: t('GatewayDnsTab.overrideColumns.type'), accessorFn: (r: any) => r.record_type || 'A' },
    { id: 'ip', header: t('GatewayDnsTab.overrideColumns.serverIp'), accessorFn: (r: any) => r.server || r.ip || '-' },
    { id: 'fqdn', header: t('GatewayDnsTab.overrideColumns.fqdn'), accessorFn: (r: any) => r.fqdn || `${r.hostname || ''}${r.domain ? '.' + r.domain : ''}` || '-' },
    { id: 'description', header: t('GatewayDnsTab.overrideColumns.description'), accessorFn: (r: any) => r.description || '-' },
    { id: 'enabled', header: t('GatewayDnsTab.overrideColumns.enabled'), cell: (r: any) => {
      const enabled = r.enabled === true || r.enabled === 'True' || r.enabled === '1';
      return enabled ? <CheckCircle className="h-4 w-4 text-green-600" /> : <XCircle className="h-4 w-4 text-muted-foreground" />;
    }},
    { id: 'actions', header: '', cell: (r: any) => {
      const vid = r.uuid || r.id;
      return (
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="sm" onClick={() => onEditOverride(r)}><Pencil className="h-3.5 w-3.5" /></Button>
          {vid && <Button variant="ghost" size="sm" onClick={() => onDeleteOverride(r, vid)}><Trash2 className="h-3.5 w-3.5 text-destructive" /></Button>}
        </div>
      );
    }},
  ];

  const dnsDomainColumns: DataTableColumn<any>[] = [
    { id: 'domain', header: t('GatewayDnsTab.domainColumns.domain'), accessorFn: (r: any) => r.domain || '-', sortable: true },
    { id: 'server', header: t('GatewayDnsTab.domainColumns.server'), accessorFn: (r: any) => r.server || r.ip || '-' },
    { id: 'port', header: t('GatewayDnsTab.domainColumns.port'), accessorFn: (r: any) => r.port || '53' },
    { id: 'description', header: t('GatewayDnsTab.domainColumns.description'), accessorFn: (r: any) => r.description || '-' },
    { id: 'actions', header: '', cell: (r: any) => {
      const vid = r.uuid || r.id;
      return (
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="sm" onClick={() => onEditDomain(r)}><Pencil className="h-3.5 w-3.5" /></Button>
          {vid && <Button variant="ghost" size="sm" onClick={() => onDeleteDomain(r, vid)}><Trash2 className="h-3.5 w-3.5 text-destructive" /></Button>}
        </div>
      );
    }},
  ];

  return (
    <>
      {/* Unbound DNS Resolver Status */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2"><Globe className="h-4 w-4" /> {t('GatewayDnsTab.resolverStatus.title')}</CardTitle>
          <CardDescription>{t('GatewayDnsTab.resolverStatus.description')}</CardDescription>
        </CardHeader>
        <CardContent>
          {unboundStatusData?.data?.status ? (
            <dl className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              {Object.entries(unboundStatusData.data.status)
                .filter(([, val]) => val !== null && typeof val !== 'object')
                .map(([key, val]) => (
                <div key={key}>
                  <dt className="text-muted-foreground capitalize">{key.replace(/_/g, ' ')}</dt>
                  <dd className="font-medium">{typeof val === 'boolean' ? (val ? t('GatewayDnsTab.common.yes') : t('GatewayDnsTab.common.no')) : String(val ?? '-')}</dd>
                </div>
              ))}
            </dl>
          ) : (
            <p className="text-sm text-muted-foreground text-center py-4">{t('GatewayDnsTab.resolverStatus.unavailable')}</p>
          )}
        </CardContent>
      </Card>

      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t('GatewayDnsTab.hostOverrides.title')}</CardTitle>
              <CardDescription>{t('GatewayDnsTab.hostOverrides.description')}</CardDescription>
            </div>
            <Button size="sm" onClick={onAddOverride}>
              <Plus className="h-4 w-4 mr-1" /> {t('GatewayDnsTab.hostOverrides.add')}
            </Button>
          </div>
        </CardHeader>
        <DataTable data={dnsOverrides} columns={dnsOverrideColumns} isLoading={dnsOvLoading} searchable searchPlaceholder={t('GatewayDnsTab.hostOverrides.searchPlaceholder')} embedded />
      </Card>
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t('GatewayDnsTab.domainOverrides.title')}</CardTitle>
              <CardDescription>{t('GatewayDnsTab.domainOverrides.description')}</CardDescription>
            </div>
            <Button size="sm" onClick={onAddDomain}>
              <Plus className="h-4 w-4 mr-1" /> {t('GatewayDnsTab.domainOverrides.add')}
            </Button>
          </div>
        </CardHeader>
        <DataTable data={dnsDomainOverrides} columns={dnsDomainColumns} isLoading={dnsDomLoading} searchable embedded />
      </Card>

      {/* Dynamic DNS Accounts */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2"><Globe className="h-4 w-4" /> {t('GatewayDnsTab.dynamicDns.title')}</CardTitle>
          <CardDescription>{t('GatewayDnsTab.dynamicDns.description')}</CardDescription>
        </CardHeader>
        {dyndnsLoading ? (
          <CardContent><Skeleton className="h-16" /></CardContent>
        ) : (() => {
          const accounts = dyndnsData?.data?.dyndns_accounts || [];
          return (
            <CardContent>
              {accounts.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead><tr className="border-b text-left text-muted-foreground">
                      <th className="px-3 py-2 font-medium">{t('GatewayDnsTab.dynamicDns.columns.description')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayDnsTab.dynamicDns.columns.service')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayDnsTab.dynamicDns.columns.hostname')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayDnsTab.dynamicDns.columns.username')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayDnsTab.dynamicDns.columns.interface')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayDnsTab.dynamicDns.columns.currentIp')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayDnsTab.dynamicDns.columns.status')}</th>
                    </tr></thead>
                    <tbody>
                      {accounts.map((a: any, i: number) => (
                        <tr key={i} className="border-b last:border-0">
                          <td className="px-3 py-2 font-medium">{a.description || t('GatewayDnsTab.dynamicDns.accountFallback', { n: i + 1 })}</td>
                          <td className="px-3 py-2">{a.service || '-'}</td>
                          <td className="px-3 py-2 font-mono text-xs">{a.hostname || '-'}</td>
                          <td className="px-3 py-2">{a.username || '-'}</td>
                          <td className="px-3 py-2">{a.interface || '-'}</td>
                          <td className="px-3 py-2 font-mono text-xs">{a.current_ip || '-'}</td>
                          <td className="px-3 py-2"><Badge variant={a.enabled ? 'default' : 'secondary'}>{a.enabled ? t('GatewayDnsTab.dynamicDns.enabled') : t('GatewayDnsTab.dynamicDns.disabled')}</Badge></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-sm text-muted-foreground text-center py-4">{t('GatewayDnsTab.dynamicDns.empty')}</p>
              )}
            </CardContent>
          );
        })()}
      </Card>
    </>
  );
}
