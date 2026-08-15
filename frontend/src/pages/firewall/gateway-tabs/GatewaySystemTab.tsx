// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * GatewaySystemTab · installed packages/plugins, cron jobs, trust store
 * (certs/CAs/CRLs), ACME / Let's Encrypt, syslog destinations, HA / config sync,
 * certificate lifecycle warnings, plus three top-of-tab actions
 * (Check Updates · Download Config · Halt).
 *
 * Extracted from GatewayDetailPage as part of the monolith breakup. Receives
 * all data via props and exposes three write callbacks (the parent owns the
 * shared writeOp helper that handles toast + queryClient invalidation).
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useTranslation } from 'react-i18next';
import { Activity, Archive, Lock, Power, RefreshCw, ScrollText, Search, Shield } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { Skeleton } from '@/components/ui/skeleton';

export interface GatewaySystemTabProps {
  packagesData: any;
  packagesLoading: boolean;
  pluginsData: any;
  cronData: any;
  cronLoading: boolean;
  trustData: any;
  trustLoading: boolean;
  acmeData: any;
  acmeLoading: boolean;
  syslogData: any;
  syslogLoading: boolean;
  haStatusData: any;
  haStatusLoading: boolean;
  certExpiryData: any;
  certExpiryLoading: boolean;
  onCheckUpdates: () => void;
  onDownloadConfig: () => void;
  onHaltGateway: () => void;
}

export function GatewaySystemTab({
  packagesData,
  packagesLoading,
  pluginsData,
  cronData,
  cronLoading,
  trustData,
  trustLoading,
  acmeData,
  acmeLoading,
  syslogData,
  syslogLoading,
  haStatusData,
  haStatusLoading,
  certExpiryData,
  certExpiryLoading,
  onCheckUpdates,
  onDownloadConfig,
  onHaltGateway,
}: GatewaySystemTabProps) {
  const { t } = useTranslation('firewall');
  return (
    <>
      <div className="flex items-center gap-2">
        <Button variant="outline" size="sm" onClick={onCheckUpdates}>
          <Search className="h-4 w-4 mr-1" /> {t('GatewaySystemTab.actions.checkUpdates')}
        </Button>
        <Button variant="outline" size="sm" onClick={onDownloadConfig}>
          <Archive className="h-4 w-4 mr-1" /> {t('GatewaySystemTab.actions.downloadConfig')}
        </Button>
        <Button variant="destructive" size="sm" onClick={() => {
          if (window.confirm(t('GatewaySystemTab.actions.haltConfirm')))
            onHaltGateway();
        }}>
          <Power className="h-4 w-4 mr-1" /> {t('GatewaySystemTab.actions.halt')}
        </Button>
      </div>

      <Card className="border-border/50">
        <CardHeader className="pb-4"><CardTitle>{t('GatewaySystemTab.packages.title')}</CardTitle></CardHeader>
        <CardContent>
          {packagesLoading ? <Skeleton className="h-20" /> : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
              {(packagesData?.data?.packages || []).map((pkg: any, i: number) => (
                <div key={i} className="flex justify-between text-sm p-2 border rounded">
                  <span className="font-medium">{pkg.name || pkg}</span>
                  <span className="text-muted-foreground">{pkg.version || ''}</span>
                </div>
              ))}
              {(!packagesData?.data?.packages || packagesData.data.packages.length === 0) && (
                <p className="text-sm text-muted-foreground col-span-full">{t('GatewaySystemTab.packages.empty')}</p>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="border-border/50">
        <CardHeader className="pb-4"><CardTitle>{t('GatewaySystemTab.plugins.title')}</CardTitle></CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
            {(pluginsData?.data?.plugins || []).map((p: any, i: number) => (
              <div key={i} className="flex justify-between text-sm p-2 border rounded">
                <span className="font-medium">{p.name || p}</span>
                <span className="text-muted-foreground">{p.version || ''}</span>
              </div>
            ))}
            {(!pluginsData?.data?.plugins || pluginsData.data.plugins.length === 0) && (
              <p className="text-sm text-muted-foreground col-span-full">{t('GatewaySystemTab.plugins.empty')}</p>
            )}
          </div>
        </CardContent>
      </Card>

      <Card className="border-border/50">
        <CardHeader className="pb-4"><CardTitle>{t('GatewaySystemTab.cron.title')}</CardTitle></CardHeader>
        <DataTable
          data={cronData?.data?.cron_jobs || []}
          isLoading={cronLoading}
          columns={[
            { id: 'description', header: t('GatewaySystemTab.cron.columns.description'), accessorKey: 'description' },
            { id: 'schedule', header: t('GatewaySystemTab.cron.columns.schedule'), accessorFn: (r: any) => r.schedule || `${r.minutes || '*'} ${r.hours || '*'} ${r.days || '*'} ${r.months || '*'} ${r.weekdays || '*'}`, cell: (r: any) => <code>{r.schedule || `${r.minutes || '*'} ${r.hours || '*'} ${r.days || '*'} ${r.months || '*'} ${r.weekdays || '*'}`}</code> },
            { id: 'command', header: t('GatewaySystemTab.cron.columns.command'), accessorKey: 'command' },
            { id: 'enabled', header: t('GatewaySystemTab.cron.columns.enabled'), cell: (r: any) => <Badge variant={r.enabled !== false ? 'default' : 'secondary'}>{r.enabled !== false ? t('GatewaySystemTab.common.yes') : t('GatewaySystemTab.common.no')}</Badge> },
          ] as DataTableColumn<any>[]}
          embedded
        />
      </Card>

      {/* Certificate Management (Trust Store) */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2"><Lock className="h-4 w-4" /> {t('GatewaySystemTab.trust.title')}</CardTitle>
          <CardDescription>{t('GatewaySystemTab.trust.description')}</CardDescription>
        </CardHeader>
        {trustLoading ? (
          <CardContent><Skeleton className="h-24" /></CardContent>
        ) : (() => {
          const trust = trustData?.data?.trust;
          const certs = trust?.certificates || [];
          const cas = trust?.certificate_authorities || [];
          const crls = trust?.certificate_revocation_lists || [];
          return (
            <CardContent noOffset className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
                <div className="text-center p-3 rounded-lg border">
                  <p className="text-2xl font-bold">{certs.length}</p>
                  <p className="text-xs text-muted-foreground">{t('GatewaySystemTab.trust.certificates')}</p>
                </div>
                <div className="text-center p-3 rounded-lg border">
                  <p className="text-2xl font-bold">{cas.length}</p>
                  <p className="text-xs text-muted-foreground">{t('GatewaySystemTab.trust.certificateAuthorities')}</p>
                </div>
                <div className="text-center p-3 rounded-lg border">
                  <p className="text-2xl font-bold">{crls.length}</p>
                  <p className="text-xs text-muted-foreground">{t('GatewaySystemTab.trust.revocationLists')}</p>
                </div>
              </div>

              {cas.length > 0 && (
                <div>
                  <p className="text-sm font-medium mb-2">{t('GatewaySystemTab.trust.certificateAuthorities')}</p>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead><tr className="border-b text-left text-muted-foreground">
                        <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.trust.columns.name')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.trust.columns.dn')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.trust.columns.keyLength')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.trust.columns.inUse')}</th>
                      </tr></thead>
                      <tbody>
                        {cas.map((ca: any, i: number) => (
                          <tr key={i} className="border-b last:border-0">
                            <td className="px-3 py-2 font-medium">{ca.descr || ca.name}</td>
                            <td className="px-3 py-2 text-xs font-mono truncate max-w-[250px]">{ca.dn || ca.distinguished_name || '-'}</td>
                            <td className="px-3 py-2">{ca.key_length || '-'}</td>
                            <td className="px-3 py-2"><Badge variant={ca.in_use ? 'default' : 'secondary'}>{ca.in_use ? t('GatewaySystemTab.common.yes') : t('GatewaySystemTab.common.no')}</Badge></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {certs.length > 0 && (
                <div>
                  <p className="text-sm font-medium mb-2">{t('GatewaySystemTab.trust.certificates')}</p>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead><tr className="border-b text-left text-muted-foreground">
                        <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.trust.columns.name')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.trust.columns.ca')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.trust.columns.keyLength')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.trust.columns.type')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.trust.columns.inUse')}</th>
                      </tr></thead>
                      <tbody>
                        {certs.map((c: any, i: number) => (
                          <tr key={i} className="border-b last:border-0">
                            <td className="px-3 py-2 font-medium">{c.descr || c.name}</td>
                            <td className="px-3 py-2">{c.ca || c.caref || '-'}</td>
                            <td className="px-3 py-2">{c.key_length || '-'}</td>
                            <td className="px-3 py-2">{c.type || '-'}</td>
                            <td className="px-3 py-2"><Badge variant={c.in_use ? 'default' : 'secondary'}>{c.in_use ? t('GatewaySystemTab.common.yes') : t('GatewaySystemTab.common.no')}</Badge></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {certs.length === 0 && cas.length === 0 && crls.length === 0 && (
                <p className="text-sm text-muted-foreground text-center py-4">{t('GatewaySystemTab.trust.empty')}</p>
              )}
            </CardContent>
          );
        })()}
      </Card>

      {/* ACME / Let's Encrypt */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2"><Shield className="h-4 w-4" /> {t('GatewaySystemTab.acme.title')}</CardTitle>
          <CardDescription>{t('GatewaySystemTab.acme.description')}</CardDescription>
        </CardHeader>
        {acmeLoading ? (
          <CardContent><Skeleton className="h-24" /></CardContent>
        ) : (() => {
          const acme = acmeData?.data?.acme;
          const acmeCerts = acme?.certificates || [];
          const accounts = acme?.accounts || [];
          const validations = acme?.validations || [];
          const actions = acme?.actions || [];
          return (
            <CardContent noOffset className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="text-center p-3 rounded-lg border">
                  <p className="text-2xl font-bold">{acmeCerts.length}</p>
                  <p className="text-xs text-muted-foreground">{t('GatewaySystemTab.acme.certificates')}</p>
                </div>
                <div className="text-center p-3 rounded-lg border">
                  <p className="text-2xl font-bold">{accounts.length}</p>
                  <p className="text-xs text-muted-foreground">{t('GatewaySystemTab.acme.accounts')}</p>
                </div>
                <div className="text-center p-3 rounded-lg border">
                  <p className="text-2xl font-bold">{validations.length}</p>
                  <p className="text-xs text-muted-foreground">{t('GatewaySystemTab.acme.validations')}</p>
                </div>
                <div className="text-center p-3 rounded-lg border">
                  <p className="text-2xl font-bold">{actions.length}</p>
                  <p className="text-xs text-muted-foreground">{t('GatewaySystemTab.acme.actions')}</p>
                </div>
              </div>

              {acmeCerts.length > 0 && (
                <div>
                  <p className="text-sm font-medium mb-2">{t('GatewaySystemTab.acme.certificatesHeading')}</p>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead><tr className="border-b text-left text-muted-foreground">
                        <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.acme.columns.name')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.acme.columns.domains')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.acme.columns.account')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.acme.columns.lastUpdate')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.acme.columns.status')}</th>
                      </tr></thead>
                      <tbody>
                        {acmeCerts.map((c: any, i: number) => (
                          <tr key={i} className="border-b last:border-0">
                            <td className="px-3 py-2 font-medium">{c.name || c.description}</td>
                            <td className="px-3 py-2 font-mono text-xs">{c.altNames || c.domain || '-'}</td>
                            <td className="px-3 py-2">{c.account || '-'}</td>
                            <td className="px-3 py-2 text-xs">{c.lastUpdate || '-'}</td>
                            <td className="px-3 py-2"><Badge variant={c.enabled ? 'default' : 'secondary'}>{c.enabled ? t('GatewaySystemTab.common.active') : t('GatewaySystemTab.common.disabled')}</Badge></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {accounts.length > 0 && (
                <div>
                  <p className="text-sm font-medium mb-2">{t('GatewaySystemTab.acme.accountsHeading')}</p>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead><tr className="border-b text-left text-muted-foreground">
                        <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.acme.columns.name')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.acme.columns.email')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.acme.columns.ca')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.acme.columns.status')}</th>
                      </tr></thead>
                      <tbody>
                        {accounts.map((a: any, i: number) => (
                          <tr key={i} className="border-b last:border-0">
                            <td className="px-3 py-2 font-medium">{a.name || a.description}</td>
                            <td className="px-3 py-2">{a.email || '-'}</td>
                            <td className="px-3 py-2">{a.ca || a.certificateAuthority || '-'}</td>
                            <td className="px-3 py-2"><Badge variant={a.enabled ? 'default' : 'secondary'}>{a.enabled ? t('GatewaySystemTab.common.active') : t('GatewaySystemTab.common.disabled')}</Badge></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {acmeCerts.length === 0 && accounts.length === 0 && (
                <p className="text-sm text-muted-foreground text-center py-4">{t('GatewaySystemTab.acme.empty')}</p>
              )}
            </CardContent>
          );
        })()}
      </Card>

      {/* Syslog Destinations */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2"><ScrollText className="h-4 w-4" /> {t('GatewaySystemTab.syslog.title')}</CardTitle>
          <CardDescription>{t('GatewaySystemTab.syslog.description')}</CardDescription>
        </CardHeader>
        {syslogLoading ? (
          <CardContent><Skeleton className="h-16" /></CardContent>
        ) : (() => {
          const dests = syslogData?.data?.syslog_destinations || [];
          return (
            <CardContent>
              {dests.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead><tr className="border-b text-left text-muted-foreground">
                      <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.syslog.columns.description')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.syslog.columns.transport')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.syslog.columns.hostname')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.syslog.columns.port')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.syslog.columns.level')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewaySystemTab.syslog.columns.status')}</th>
                    </tr></thead>
                    <tbody>
                      {dests.map((d: any, i: number) => (
                        <tr key={i} className="border-b last:border-0">
                          <td className="px-3 py-2 font-medium">{d.description || t('GatewaySystemTab.syslog.defaultDestination', { n: i + 1 })}</td>
                          <td className="px-3 py-2">{d.transport || '-'}</td>
                          <td className="px-3 py-2 font-mono text-xs">{d.hostname || '-'}</td>
                          <td className="px-3 py-2">{d.port || '-'}</td>
                          <td className="px-3 py-2">{d.level || '-'}</td>
                          <td className="px-3 py-2"><Badge variant={d.enabled ? 'default' : 'secondary'}>{d.enabled ? t('GatewaySystemTab.common.enabled') : t('GatewaySystemTab.common.disabled')}</Badge></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-sm text-muted-foreground text-center py-4">{t('GatewaySystemTab.syslog.empty')}</p>
              )}
            </CardContent>
          );
        })()}
      </Card>

      {/* HA / Config Sync Status */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2"><Activity className="h-4 w-4" /> {t('GatewaySystemTab.ha.title')}</CardTitle>
          <CardDescription>{t('GatewaySystemTab.ha.description')}</CardDescription>
        </CardHeader>
        {haStatusLoading ? (
          <CardContent><Skeleton className="h-16" /></CardContent>
        ) : (() => {
          const ha = haStatusData?.data?.ha_status;
          if (!ha) return (
            <CardContent>
              <p className="text-sm text-muted-foreground text-center py-4">{t('GatewaySystemTab.ha.empty')}</p>
            </CardContent>
          );
          return (
            <CardContent noOffset>
              <dl className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                {Object.entries(ha)
                  .filter(([, val]) => val !== null && val !== undefined && typeof val !== 'object')
                  .map(([key, val]) => (
                  <div key={key}>
                    <dt className="text-muted-foreground capitalize">{key.replace(/_/g, ' ')}</dt>
                    <dd className="font-medium">{typeof val === 'boolean' ? (val ? t('GatewaySystemTab.common.yes') : t('GatewaySystemTab.common.no')) : String(val ?? '-')}</dd>
                  </div>
                ))}
              </dl>
            </CardContent>
          );
        })()}
      </Card>

      {/* ─── Certificate Expiry ───────────────────────────────── */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2"><Lock className="h-4 w-4" /> {t('GatewaySystemTab.lifecycle.title')}</CardTitle>
          <CardDescription>{t('GatewaySystemTab.lifecycle.description')}</CardDescription>
        </CardHeader>
        {certExpiryLoading ? (
          <CardContent><div className="flex items-center gap-2 text-muted-foreground"><RefreshCw className="h-4 w-4 animate-spin" /> {t('GatewaySystemTab.lifecycle.checking')}</div></CardContent>
        ) : (() => {
          const ce = certExpiryData?.data || {};
          const expired = ce.expired || [];
          const expiring = ce.expiring_soon || [];
          return (
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div className="text-center p-3 rounded-lg border">
                  <p className="text-2xl font-bold">{ce.total_certificates || 0}</p>
                  <p className="text-xs text-muted-foreground">{t('GatewaySystemTab.lifecycle.totalCertificates')}</p>
                </div>
                <div className="text-center p-3 rounded-lg border">
                  <p className="text-2xl font-bold text-green-600">{ce.valid_count || 0}</p>
                  <p className="text-xs text-muted-foreground">{t('GatewaySystemTab.lifecycle.valid')}</p>
                </div>
                <div className="text-center p-3 rounded-lg border">
                  <p className="text-2xl font-bold text-yellow-600">{expiring.length}</p>
                  <p className="text-xs text-muted-foreground">{t('GatewaySystemTab.lifecycle.expiringSoon')}</p>
                </div>
                <div className="text-center p-3 rounded-lg border">
                  <p className="text-2xl font-bold text-red-600">{expired.length}</p>
                  <p className="text-xs text-muted-foreground">{t('GatewaySystemTab.lifecycle.expired')}</p>
                </div>
              </div>
              {(expired.length > 0 || expiring.length > 0) && (
                <div className="overflow-auto max-h-[250px] rounded border">
                  <table className="w-full text-xs">
                    <thead className="bg-muted sticky top-0"><tr><th className="px-3 py-2 text-left">{t('GatewaySystemTab.lifecycle.columns.certificate')}</th><th className="px-3 py-2 text-left">{t('GatewaySystemTab.lifecycle.columns.cn')}</th><th className="px-3 py-2 text-left">{t('GatewaySystemTab.lifecycle.columns.status')}</th><th className="px-3 py-2 text-left">{t('GatewaySystemTab.lifecycle.columns.daysRemaining')}</th><th className="px-3 py-2 text-left">{t('GatewaySystemTab.lifecycle.columns.expires')}</th></tr></thead>
                    <tbody>
                      {[...expired, ...expiring].map((c: any, i: number) => (
                        <tr key={i} className="border-t">
                          <td className="px-3 py-1.5 font-medium">{c.name}</td>
                          <td className="px-3 py-1.5 font-mono">{c.common_name}</td>
                          <td className="px-3 py-1.5"><Badge variant={c.status === 'expired' ? 'destructive' : 'outline'}>{c.status === 'expired' ? t('GatewaySystemTab.lifecycle.expired') : t('GatewaySystemTab.lifecycle.expiringSoon')}</Badge></td>
                          <td className="px-3 py-1.5 font-mono">{c.days_remaining}</td>
                          <td className="px-3 py-1.5">{new Date(c.expires).toLocaleDateString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {!ce.needs_attention && <p className="text-sm text-muted-foreground">{t('GatewaySystemTab.lifecycle.allValid')}</p>}
            </CardContent>
          );
        })()}
      </Card>
    </>
  );
}
