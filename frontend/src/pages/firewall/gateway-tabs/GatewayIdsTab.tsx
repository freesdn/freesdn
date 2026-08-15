// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * GatewayIdsTab · IDS/IPS settings, alerts, rulesets, rules, plus CrowdSec.
 *
 * Extracted from GatewayDetailPage as part of the monolith breakup. Owns the
 * idsAlertColumns definition (only used here) and receives all IDS data plus
 * IDS-control / per-rule-toggle / clear-alerts callbacks via props.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Pencil, Play, RefreshCw, RotateCcw, ShieldAlert, Square, Trash2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
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

export type IdsAction = 'start' | 'stop' | 'restart' | 'update-rules';

export interface GatewayIdsTabProps {
  idsStatusData: any;
  idsSettings: Record<string, any>;
  idsAlerts: any[];
  idsAlertsLoading: boolean;
  idsRulesetsData: any;
  idsRulesData: any;
  idsRulesLoading: boolean;
  crowdsecData: any;
  crowdsecLoading: boolean;
  onControl: (action: IdsAction) => void;
  onEditSettings: () => void;
  onClearAlerts: () => void;
  onToggleRule: (sid: string) => void;
}

export function GatewayIdsTab({
  idsStatusData,
  idsSettings,
  idsAlerts,
  idsAlertsLoading,
  idsRulesetsData,
  idsRulesData,
  idsRulesLoading,
  crowdsecData,
  crowdsecLoading,
  onControl,
  onEditSettings,
  onClearAlerts,
  onToggleRule,
}: GatewayIdsTabProps) {
  const { t } = useTranslation('firewall');
  // Confirmations for destructive / long-running IDS actions.
  const [showClearAlerts, setShowClearAlerts] = useState(false);
  const [showUpdateRules, setShowUpdateRules] = useState(false);

  const idsAlertColumns: DataTableColumn<any>[] = [
    { id: 'timestamp', header: t('GatewayIdsTab.alertColumns.time'), accessorFn: (r: any) => r.timestamp || r.date || '-', sortable: true, cell: (r: any) => (
      <span className="text-xs">{r.timestamp ? new Date(r.timestamp).toLocaleString() : r.date || '-'}</span>
    )},
    { id: 'severity', header: t('GatewayIdsTab.alertColumns.severity'), cell: (r: any) => (
      <Badge variant={r.severity === 'high' || r.severity === 1 ? 'destructive' : r.severity === 'medium' || r.severity === 2 ? 'default' : 'secondary'}>
        {r.severity || '-'}
      </Badge>
    )},
    { id: 'source', header: t('GatewayIdsTab.alertColumns.source'), accessorFn: (r: any) => `${r.src_ip || '-'}:${r.src_port || ''}` },
    { id: 'dest', header: t('GatewayIdsTab.alertColumns.destination'), accessorFn: (r: any) => `${r.dst_ip || r.dest_ip || '-'}:${r.dst_port || r.dest_port || ''}` },
    { id: 'signature', header: t('GatewayIdsTab.alertColumns.signature'), accessorFn: (r: any) => r.alert?.signature || r.signature || r.msg || '-' },
    { id: 'action', header: t('GatewayIdsTab.alertColumns.action'), accessorFn: (r: any) => r.alert?.action || r.action || '-' },
  ];

  return (
    <>
      {/* IDS Settings Card */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2"><ShieldAlert className="h-4 w-4" /> {t('GatewayIdsTab.settings.title')}</CardTitle>
            <div className="flex gap-2">
              {idsStatusData?.data?.status && (
                <Badge variant={idsStatusData.data.status.running ? 'default' : 'secondary'}>
                  {idsStatusData.data.status.running ? t('GatewayIdsTab.status.running') : t('GatewayIdsTab.status.stopped')}
                </Badge>
              )}
              <Button size="sm" variant="outline" onClick={() => onControl('start')}>
                <Play className="h-3 w-3 mr-1" /> {t('GatewayIdsTab.actions.start')}
              </Button>
              <Button size="sm" variant="outline" onClick={() => onControl('stop')}>
                <Square className="h-3 w-3 mr-1" /> {t('GatewayIdsTab.actions.stop')}
              </Button>
              <Button size="sm" variant="outline" onClick={() => onControl('restart')}>
                <RotateCcw className="h-3 w-3 mr-1" /> {t('GatewayIdsTab.actions.restart')}
              </Button>
              <Button size="sm" variant="outline" onClick={() => setShowUpdateRules(true)}>
                <RefreshCw className="h-3 w-3 mr-1" /> {t('GatewayIdsTab.actions.updateRules')}
              </Button>
              <Button size="sm" variant="outline" onClick={onEditSettings}>
                <Pencil className="h-4 w-4 mr-1" /> {t('GatewayIdsTab.actions.edit')}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {Object.keys(idsSettings).length > 0 ? (
            <dl className="grid grid-cols-2 gap-x-8 gap-y-2 text-sm">
              {[
                ['enabled', t('GatewayIdsTab.settings.fields.enabled'), idsSettings.enabled != null ? (idsSettings.enabled ? t('GatewayIdsTab.common.yes') : t('GatewayIdsTab.common.no')) : '-'],
                ['ipsMode', t('GatewayIdsTab.settings.fields.ipsMode'), idsSettings.ips_mode != null ? (idsSettings.ips_mode ? t('GatewayIdsTab.settings.values.activeDrop') : t('GatewayIdsTab.settings.values.alertOnly')) : '-'],
                ['patternMatcher', t('GatewayIdsTab.settings.fields.patternMatcher'), idsSettings.pattern_matcher || '-'],
                ['interfaces', t('GatewayIdsTab.settings.fields.interfaces'), Array.isArray(idsSettings.interfaces) ? idsSettings.interfaces.join(', ') : '-'],
              ].map(([key, label, val]) => (
                <div key={key as string} className="flex justify-between">
                  <dt className="text-muted-foreground">{label}</dt>
                  <dd className="font-medium">{val}</dd>
                </div>
              ))}
            </dl>
          ) : (
            <p className="text-sm text-muted-foreground py-4 text-center">{t('GatewayIdsTab.settings.empty')}</p>
          )}
        </CardContent>
      </Card>
      {/* IDS Alerts */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t('GatewayIdsTab.alerts.title', { count: idsAlerts.length })}</CardTitle>
              <CardDescription>{t('GatewayIdsTab.alerts.description')}</CardDescription>
            </div>
            <Button variant="destructive" size="sm" onClick={() => setShowClearAlerts(true)}>
              <Trash2 className="h-4 w-4 mr-1" /> {t('GatewayIdsTab.actions.clearAlerts')}
            </Button>
          </div>
        </CardHeader>
        <DataTable data={idsAlerts} columns={idsAlertColumns} isLoading={idsAlertsLoading} searchable searchPlaceholder={t('GatewayIdsTab.alerts.searchPlaceholder')} embedded />
      </Card>
      {/* IDS Rulesets */}
      {(idsRulesetsData?.data?.rulesets || []).length > 0 && (
        <Card className="border-border/50">
          <CardHeader className="pb-4">
            <CardTitle>{t('GatewayIdsTab.rulesets.title')}</CardTitle>
            <CardDescription>{t('GatewayIdsTab.rulesets.description')}</CardDescription>
          </CardHeader>
          <DataTable
            data={idsRulesetsData?.data?.rulesets || []}
            columns={[
              { header: t('GatewayIdsTab.rulesets.columns.name'), accessorKey: 'name' },
              { header: t('GatewayIdsTab.rulesets.columns.description'), accessorKey: 'description' },
              { header: t('GatewayIdsTab.rulesets.columns.enabled'), accessorKey: 'enabled', cell: ({ row }: any) => <Badge variant={row.original.enabled ? 'default' : 'secondary'}>{row.original.enabled ? t('GatewayIdsTab.common.yes') : t('GatewayIdsTab.common.no')}</Badge> },
            ] as DataTableColumn<any>[]}
            searchable
            embedded
          />
        </Card>
      )}
      {/* IDS Rules */}
      {(idsRulesData?.data?.rules || []).length > 0 && (
        <Card className="border-border/50">
          <CardHeader className="pb-4">
            <CardTitle>{t('GatewayIdsTab.rules.title', { count: idsRulesData?.data?.count || 0 })}</CardTitle>
            <CardDescription>{t('GatewayIdsTab.rules.description')}</CardDescription>
          </CardHeader>
          <DataTable
            data={idsRulesData?.data?.rules || []}
            isLoading={idsRulesLoading}
            columns={[
              { header: t('GatewayIdsTab.rules.columns.sid'), accessorKey: 'sid' },
              { header: t('GatewayIdsTab.rules.columns.description'), accessorKey: 'msg' },
              { header: t('GatewayIdsTab.rules.columns.severity'), accessorKey: 'severity' },
              { header: t('GatewayIdsTab.rules.columns.enabled'), accessorKey: 'enabled', cell: ({ row }: any) => <Badge variant={row.original.enabled ? 'default' : 'secondary'}>{row.original.enabled ? t('GatewayIdsTab.common.yes') : t('GatewayIdsTab.common.no')}</Badge> },
              { header: t('GatewayIdsTab.rules.columns.actions'), id: 'actions', cell: ({ row }: any) => (
                <Button variant="ghost" size="sm" onClick={() => onToggleRule(row.original.sid)}>
                  {t('GatewayIdsTab.rules.toggle')}
                </Button>
              )},
            ] as DataTableColumn<any>[]}
            searchable
            searchPlaceholder={t('GatewayIdsTab.rules.searchPlaceholder')}
            embedded
          />
        </Card>
      )}

      {/* ─── CrowdSec IPS ───────────────────────────────────── */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle>{t('GatewayIdsTab.crowdsec.title')}</CardTitle>
          <CardDescription>{t('GatewayIdsTab.crowdsec.description')}</CardDescription>
        </CardHeader>
        {crowdsecLoading ? (
          <CardContent><div className="flex items-center gap-2 text-muted-foreground"><RefreshCw className="h-4 w-4 animate-spin" /> {t('GatewayIdsTab.crowdsec.loading')}</div></CardContent>
        ) : (() => {
          const cs = crowdsecData?.data || {};
          const svc = cs.service || {};
          const alerts = cs.alerts || [];
          const decisions = cs.decisions || [];
          return (
            <CardContent noOffset className="space-y-4">
              <dl className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <dt className="text-muted-foreground">{t('GatewayIdsTab.crowdsec.service')}</dt>
                  <dd><Badge variant={svc.status === 'running' ? 'default' : 'secondary'}>{svc.status || t('GatewayIdsTab.crowdsec.unknown')}</Badge></dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">{t('GatewayIdsTab.crowdsec.alerts')}</dt>
                  <dd className="font-medium">{alerts.length}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">{t('GatewayIdsTab.crowdsec.activeDecisions')}</dt>
                  <dd className="font-medium">{decisions.length}</dd>
                </div>
              </dl>
              {decisions.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium mb-2">{t('GatewayIdsTab.crowdsec.activeDecisions')}</h4>
                  <div className="overflow-auto max-h-[200px] rounded border">
                    <table className="w-full text-xs">
                      <thead className="bg-muted sticky top-0"><tr><th className="px-3 py-2 text-left">{t('GatewayIdsTab.crowdsec.columns.ipRange')}</th><th className="px-3 py-2 text-left">{t('GatewayIdsTab.crowdsec.columns.reason')}</th><th className="px-3 py-2 text-left">{t('GatewayIdsTab.crowdsec.columns.action')}</th><th className="px-3 py-2 text-left">{t('GatewayIdsTab.crowdsec.columns.expires')}</th></tr></thead>
                      <tbody>
                        {decisions.slice(0, 50).map((d: any, i: number) => (
                          <tr key={i} className="border-t"><td className="px-3 py-1.5 font-mono">{d.value || d.ip}</td><td className="px-3 py-1.5">{d.scenario || d.reason}</td><td className="px-3 py-1.5">{d.type || d.action}</td><td className="px-3 py-1.5">{d.until || d.expires || '-'}</td></tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </CardContent>
          );
        })()}
      </Card>

      {/* Clear Alerts Confirmation */}
      <AlertDialog open={showClearAlerts} onOpenChange={setShowClearAlerts}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('GatewayIdsTab.dialogs.clearAlerts.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('GatewayIdsTab.dialogs.clearAlerts.description')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('GatewayIdsTab.actions.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                onClearAlerts();
                setShowClearAlerts(false);
              }}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {t('GatewayIdsTab.actions.clearAlerts')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Update Rules Confirmation */}
      <AlertDialog open={showUpdateRules} onOpenChange={setShowUpdateRules}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('GatewayIdsTab.dialogs.updateRules.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('GatewayIdsTab.dialogs.updateRules.description')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('GatewayIdsTab.actions.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                onControl('update-rules');
                setShowUpdateRules(false);
              }}
            >
              {t('GatewayIdsTab.actions.updateRules')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
