// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * GatewayServicesTab · HAProxy load balancer, captive portal zones, system
 * services start/stop/restart, web proxy (Squid), and proxy blacklists.
 *
 * Extracted from GatewayDetailPage as part of the monolith breakup. Receives
 * all data via props and exposes a single `onServiceAction(name, action)`
 * callback so the parent can keep the mutation + queryClient invalidation.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Play, RefreshCw, RotateCcw, Server, Square, Wifi } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { Skeleton } from '@/components/ui/skeleton';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';

export interface GatewayServicesTabProps {
  vendorLabel: string;
  haproxyData: any;
  haproxyLoading: boolean;
  captivePortalData: any;
  captivePortalLoading: boolean;
  services: any[];
  servicesLoading: boolean;
  onServiceAction: (serviceName: string, action: 'start' | 'stop' | 'restart') => void;
  serviceActionPending: boolean;
  proxyData: any;
  proxyLoading: boolean;
  proxyBlacklistsData: any;
  proxyBlacklistsLoading: boolean;
}

export function GatewayServicesTab({
  vendorLabel,
  haproxyData,
  haproxyLoading,
  captivePortalData,
  captivePortalLoading,
  services,
  servicesLoading,
  onServiceAction,
  serviceActionPending,
  proxyData,
  proxyLoading,
  proxyBlacklistsData,
  proxyBlacklistsLoading,
}: GatewayServicesTabProps) {
  const { t } = useTranslation('firewall');
  // Stop / restart confirmation, connected clients may drop.
  const [pendingAction, setPendingAction] = useState<{ name: string; action: 'stop' | 'restart' } | null>(null);

  return (
    <>
      {/* HAProxy · Load Balancer */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2"><Server className="h-4 w-4" /> {t('GatewayServicesTab.haproxy.title')}</CardTitle>
          <CardDescription>{t('GatewayServicesTab.haproxy.description')}</CardDescription>
        </CardHeader>
        {haproxyLoading ? (
          <CardContent><Skeleton className="h-24" /></CardContent>
        ) : (() => {
          const hp = haproxyData?.data?.haproxy;
          const frontends = hp?.frontends || [];
          const backends = hp?.backends || [];
          const servers = hp?.servers || [];
          return (
            <CardContent noOffset className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
                <div className="text-center p-3 rounded-lg border">
                  <p className="text-2xl font-bold">{frontends.length}</p>
                  <p className="text-xs text-muted-foreground">{t('GatewayServicesTab.haproxy.frontends')}</p>
                </div>
                <div className="text-center p-3 rounded-lg border">
                  <p className="text-2xl font-bold">{backends.length}</p>
                  <p className="text-xs text-muted-foreground">{t('GatewayServicesTab.haproxy.backends')}</p>
                </div>
                <div className="text-center p-3 rounded-lg border">
                  <p className="text-2xl font-bold">{servers.length}</p>
                  <p className="text-xs text-muted-foreground">{t('GatewayServicesTab.haproxy.servers')}</p>
                </div>
              </div>

              {frontends.length > 0 && (
                <div>
                  <p className="text-sm font-medium mb-2">{t('GatewayServicesTab.haproxy.frontends')}</p>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead><tr className="border-b text-left text-muted-foreground">
                        <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.name')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.bind')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.mode')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.defaultBackend')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.ssl')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.status')}</th>
                      </tr></thead>
                      <tbody>
                        {frontends.map((f: any, i: number) => (
                          <tr key={i} className="border-b last:border-0">
                            <td className="px-3 py-2 font-medium">{f.name}</td>
                            <td className="px-3 py-2 font-mono text-xs">{f.bind || '-'}</td>
                            <td className="px-3 py-2">{f.mode || 'http'}</td>
                            <td className="px-3 py-2">{f.default_backend || '-'}</td>
                            <td className="px-3 py-2"><Badge variant={f.ssl_enabled ? 'default' : 'secondary'}>{f.ssl_enabled ? t('GatewayServicesTab.common.yes') : t('GatewayServicesTab.common.no')}</Badge></td>
                            <td className="px-3 py-2"><Badge variant={f.enabled ? 'default' : 'secondary'}>{f.enabled ? t('GatewayServicesTab.common.enabled') : t('GatewayServicesTab.common.disabled')}</Badge></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {backends.length > 0 && (
                <div>
                  <p className="text-sm font-medium mb-2">{t('GatewayServicesTab.haproxy.backends')}</p>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead><tr className="border-b text-left text-muted-foreground">
                        <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.name')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.mode')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.algorithm')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.healthCheck')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.persistence')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.status')}</th>
                      </tr></thead>
                      <tbody>
                        {backends.map((b: any, i: number) => (
                          <tr key={i} className="border-b last:border-0">
                            <td className="px-3 py-2 font-medium">{b.name}</td>
                            <td className="px-3 py-2">{b.mode || 'http'}</td>
                            <td className="px-3 py-2">{b.algorithm || '-'}</td>
                            <td className="px-3 py-2"><Badge variant={b.health_check_enabled ? 'default' : 'secondary'}>{b.health_check_enabled ? t('GatewayServicesTab.common.yes') : t('GatewayServicesTab.common.no')}</Badge></td>
                            <td className="px-3 py-2">{b.persistence || t('GatewayServicesTab.common.none')}</td>
                            <td className="px-3 py-2"><Badge variant={b.enabled ? 'default' : 'secondary'}>{b.enabled ? t('GatewayServicesTab.common.enabled') : t('GatewayServicesTab.common.disabled')}</Badge></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {servers.length > 0 && (
                <div>
                  <p className="text-sm font-medium mb-2">{t('GatewayServicesTab.haproxy.realServers')}</p>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead><tr className="border-b text-left text-muted-foreground">
                        <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.name')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.address')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.port')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.mode')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.weight')}</th>
                        <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.ssl')}</th>
                      </tr></thead>
                      <tbody>
                        {servers.map((s: any, i: number) => (
                          <tr key={i} className="border-b last:border-0">
                            <td className="px-3 py-2 font-medium">{s.name}</td>
                            <td className="px-3 py-2 font-mono text-xs">{s.address}</td>
                            <td className="px-3 py-2">{s.port || '-'}</td>
                            <td className="px-3 py-2">{s.mode || '-'}</td>
                            <td className="px-3 py-2">{s.weight || '-'}</td>
                            <td className="px-3 py-2"><Badge variant={s.ssl ? 'default' : 'secondary'}>{s.ssl ? t('GatewayServicesTab.common.yes') : t('GatewayServicesTab.common.no')}</Badge></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {frontends.length === 0 && backends.length === 0 && servers.length === 0 && (
                <p className="text-sm text-muted-foreground text-center py-4">{t('GatewayServicesTab.haproxy.empty')}</p>
              )}
            </CardContent>
          );
        })()}
      </Card>

      {/* Captive Portal */}
      {(() => {
        const zones = captivePortalData?.data?.captive_portal_zones || [];
        if (zones.length === 0 && !captivePortalLoading) return null;
        return (
          <Card className="border-border/50">
            <CardHeader className="pb-4">
              <CardTitle className="flex items-center gap-2"><Wifi className="h-4 w-4" /> {t('GatewayServicesTab.captivePortal.title')}</CardTitle>
              <CardDescription>{t('GatewayServicesTab.captivePortal.description')}</CardDescription>
            </CardHeader>
            {captivePortalLoading ? (
              <CardContent><Skeleton className="h-20" /></CardContent>
            ) : (
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead><tr className="border-b text-left text-muted-foreground">
                      <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.zoneId')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.interfaces')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.authServers')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.idleTimeout')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.hardTimeout')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.concurrent')}</th>
                      <th className="px-3 py-2 font-medium">{t('GatewayServicesTab.columns.status')}</th>
                    </tr></thead>
                    <tbody>
                      {zones.map((z: any, i: number) => (
                        <tr key={i} className="border-b last:border-0">
                          <td className="px-3 py-2 font-medium">{z.zoneid || z.description || t('GatewayServicesTab.captivePortal.zoneFallback', { n: i + 1 })}</td>
                          <td className="px-3 py-2">{z.interfaces || '-'}</td>
                          <td className="px-3 py-2">{z.auth_servers || '-'}</td>
                          <td className="px-3 py-2">{z.idle_timeout || '-'}m</td>
                          <td className="px-3 py-2">{z.hard_timeout || '-'}m</td>
                          <td className="px-3 py-2">{z.concurrent_logins ? t('GatewayServicesTab.common.yes') : t('GatewayServicesTab.common.no')}</td>
                          <td className="px-3 py-2"><Badge variant={z.enabled ? 'default' : 'secondary'}>{z.enabled ? t('GatewayServicesTab.common.enabled') : t('GatewayServicesTab.common.disabled')}</Badge></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            )}
          </Card>
        );
      })()}

      {/* System Services */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle>{t('GatewayServicesTab.services.title')}</CardTitle>
          <CardDescription>{t('GatewayServicesTab.services.description', { vendor: vendorLabel })}</CardDescription>
        </CardHeader>
        {servicesLoading ? (
          <CardContent><Skeleton className="h-48" /></CardContent>
        ) : services.length > 0 ? (
          <CardContent>
            <div className="space-y-2">
              {(Array.isArray(services) ? services : []).map((svc: any, i: number) => {
                const running = svc.running || svc.status === 'running';
                const svcName = svc.id || svc.name || `service-${i}`;
                return (
                  <div key={i} className="flex items-center justify-between py-2 px-3 rounded-lg border">
                    <div className="flex items-center gap-3">
                      <Badge variant={running ? 'default' : 'secondary'} className="text-xs w-16 justify-center">
                        {running ? t('GatewayServicesTab.services.running') : t('GatewayServicesTab.services.stopped')}
                      </Badge>
                      <div>
                        <span className="font-medium text-sm">{svc.name || svc.id || '-'}</span>
                        {svc.description && <p className="text-xs text-muted-foreground">{svc.description}</p>}
                      </div>
                    </div>
                    <div className="flex items-center gap-1">
                      {!running && (
                        <Button variant="ghost" size="sm" onClick={() => onServiceAction(svcName, 'start')} disabled={serviceActionPending}>
                          <Play className="h-3.5 w-3.5 mr-1" /> {t('GatewayServicesTab.actions.start')}
                        </Button>
                      )}
                      {running && (
                        <Button variant="ghost" size="sm" onClick={() => setPendingAction({ name: svcName, action: 'stop' })} disabled={serviceActionPending}>
                          <Square className="h-3.5 w-3.5 mr-1" /> {t('GatewayServicesTab.actions.stop')}
                        </Button>
                      )}
                      <Button variant="ghost" size="sm" onClick={() => setPendingAction({ name: svcName, action: 'restart' })} disabled={serviceActionPending}>
                        <RotateCcw className="h-3.5 w-3.5 mr-1" /> {t('GatewayServicesTab.actions.restart')}
                      </Button>
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        ) : (
          <CardContent noOffset><p className="text-sm text-muted-foreground py-4 text-center">{t('GatewayServicesTab.services.empty')}</p></CardContent>
        )}
      </Card>

      {/* ─── Web Proxy / Squid ──────────────────────────────── */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle>{t('GatewayServicesTab.proxy.title')}</CardTitle>
          <CardDescription>{t('GatewayServicesTab.proxy.description')}</CardDescription>
        </CardHeader>
        {proxyLoading ? (
          <CardContent><div className="flex items-center gap-2 text-muted-foreground"><RefreshCw className="h-4 w-4 animate-spin" /> {t('GatewayServicesTab.proxy.loading')}</div></CardContent>
        ) : (() => {
          const proxy = proxyData?.data?.proxy || {};
          const proxyEnabled = proxy.enabled === true || proxy.enabled === '1';
          const proxyRunning = proxy.running === true || proxy.running === 'running';
          return (
            <CardContent noOffset>
              <dl className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <dt className="text-muted-foreground">{t('GatewayServicesTab.proxy.proxyStatus')}</dt>
                  <dd><Badge variant={proxyEnabled ? 'default' : 'secondary'}>{proxyEnabled ? t('GatewayServicesTab.common.enabled') : t('GatewayServicesTab.common.disabled')}</Badge></dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">{t('GatewayServicesTab.proxy.service')}</dt>
                  <dd><Badge variant={proxyRunning ? 'default' : 'secondary'}>{proxyRunning ? t('GatewayServicesTab.common.on') : t('GatewayServicesTab.common.off')}</Badge></dd>
                </div>
                {proxy.port != null && (
                  <div>
                    <dt className="text-muted-foreground">{t('GatewayServicesTab.columns.port')}</dt>
                    <dd className="font-mono text-xs">{proxy.port}</dd>
                  </div>
                )}
                {proxy.ssl_inspection != null && (
                  <div>
                    <dt className="text-muted-foreground">{t('GatewayServicesTab.proxy.sslBumping')}</dt>
                    <dd><Badge variant={proxy.ssl_inspection === true || proxy.ssl_inspection === '1' ? 'default' : 'secondary'}>{proxy.ssl_inspection === true || proxy.ssl_inspection === '1' ? t('GatewayServicesTab.common.on') : t('GatewayServicesTab.common.off')}</Badge></dd>
                  </div>
                )}
                {proxy.cache_enabled != null && (
                  <div>
                    <dt className="text-muted-foreground">{t('GatewayServicesTab.proxy.cache')}</dt>
                    <dd><Badge variant={proxy.cache_enabled === true || proxy.cache_enabled === '1' ? 'default' : 'secondary'}>{proxy.cache_enabled === true || proxy.cache_enabled === '1' ? t('GatewayServicesTab.common.on') : t('GatewayServicesTab.common.off')}</Badge></dd>
                  </div>
                )}
              </dl>
            </CardContent>
          );
        })()}
      </Card>

      {/* ─── Proxy Blacklists ────────────────────────────────── */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle>{t('GatewayServicesTab.blacklists.title')}</CardTitle>
          <CardDescription>{t('GatewayServicesTab.blacklists.description')}</CardDescription>
        </CardHeader>
        {proxyBlacklistsLoading ? (
          <CardContent><div className="flex items-center gap-2 text-muted-foreground"><RefreshCw className="h-4 w-4 animate-spin" /> {t('GatewayServicesTab.blacklists.loading')}</div></CardContent>
        ) : (() => {
          const lists = proxyBlacklistsData?.data?.proxy_blacklists || [];
          return lists.length === 0 ? (
            <CardContent><p className="text-muted-foreground text-sm">{t('GatewayServicesTab.blacklists.empty')}</p></CardContent>
          ) : (
            <DataTable
              data={lists}
              isLoading={proxyBlacklistsLoading}
              columns={[
                { header: t('GatewayServicesTab.columns.enabled'), accessorKey: 'enabled', cell: ({ row }: any) => <Badge variant={String(row.original.enabled) === '1' ? 'default' : 'secondary'}>{String(row.original.enabled) === '1' ? t('GatewayServicesTab.common.yes') : t('GatewayServicesTab.common.no')}</Badge> },
                { header: t('GatewayServicesTab.columns.filename'), accessorKey: 'filename' },
                { header: t('GatewayServicesTab.columns.url'), accessorKey: 'url', cell: ({ row }: any) => <span className="font-mono text-xs truncate max-w-[300px] block">{row.original.url}</span> },
                { header: t('GatewayServicesTab.columns.description'), accessorKey: 'description' },
              ] as DataTableColumn<any>[]}
              searchable
              embedded
            />
          );
        })()}
      </Card>

      {/* Stop / Restart confirmation */}
      <AlertDialog open={!!pendingAction} onOpenChange={(o) => { if (!o) setPendingAction(null); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t('GatewayServicesTab.confirm.title', {
                action: pendingAction?.action === 'stop' ? t('GatewayServicesTab.actions.stop') : t('GatewayServicesTab.actions.restart'),
                name: pendingAction?.name,
              })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t('GatewayServicesTab.confirm.description', {
                action: pendingAction?.action === 'stop' ? t('GatewayServicesTab.actions.stop') : t('GatewayServicesTab.actions.restart'),
                name: pendingAction?.name,
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('GatewayServicesTab.actions.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (pendingAction) onServiceAction(pendingAction.name, pendingAction.action);
                setPendingAction(null);
              }}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {pendingAction?.action === 'stop' ? t('GatewayServicesTab.actions.stop') : t('GatewayServicesTab.actions.restart')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
