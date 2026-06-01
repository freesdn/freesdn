// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * PBXOverviewTab · primary dashboard summary tab for the PBX detail page.
 *
 * Extracted from PBXDetailPage as part of the monolith breakup. Receives all
 * data + callbacks via props; owns no state of its own. Pure aggregation +
 * render of the dashboard, trunk status panel, queue metric cards, and the
 * "Extensions preview" mini-table.
 */
import {
  PhoneCall, Hash, GitBranch, Voicemail, Phone, Users, ListOrdered, Layers,
  ChevronRight, RefreshCw,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Separator } from '@/components/ui/separator';
import { EmptyState } from '@/components/ui/empty-state';
import { StatsGrid } from '@/components/ui/stats-grid';
import { cn } from '@/lib/utils';
import { formatTimeAgo } from '../components';
import type {
  PBXSystem, PBXDashboard, Extension, Trunk, Queue,
} from '../types';

function ConnectionDot({ connected, label }: { connected: boolean; label: string }) {
  const { t } = useTranslation('voip');
  return (
    <div className="flex items-center gap-2">
      <div className={cn(
        'h-2.5 w-2.5 rounded-full',
        connected ? 'bg-success' : 'bg-muted-foreground/30',
      )} />
      <span className="text-sm">{label}</span>
      <span className={cn('text-xs font-medium', connected ? 'text-success' : 'text-muted-foreground')}>
        {connected ? t('PBXOverviewTab.connection.connected') : t('PBXOverviewTab.connection.disconnected')}
      </span>
    </div>
  );
}

export interface PBXOverviewTabProps {
  pbx: PBXSystem | null;
  dash: PBXDashboard | null;
  extensions: Extension[];
  trunks: Trunk[];
  queues: Queue[];
  onSync: () => void;
  onNavigateToExtensions: () => void;
}

export function PBXOverviewTab({
  pbx,
  dash,
  extensions,
  trunks,
  queues,
  onSync,
  onNavigateToExtensions,
}: PBXOverviewTabProps) {
  const { t } = useTranslation('voip');
  const trunksOnline = trunks.filter(tr => { const s = (tr.status || '').toLowerCase(); return s.includes('ok') || s.includes('registered') || s.includes('online'); }).length;
  return (
    <div className="space-y-6">
      {/* Primary Stats · V1-style 4-column with sub-values */}
      <StatsGrid
        columns={4}
        stats={[
          {
            title: t('PBXOverviewTab.stats.activeCalls'),
            value: dash?.active_calls ?? 0,
            icon: PhoneCall,
            variant: 'success',
            description: t('PBXOverviewTab.stats.rightNow'),
          },
          {
            title: t('PBXOverviewTab.stats.extensions'),
            value: dash?.total_extensions ?? 0,
            icon: Hash,
            variant: 'info',
            description: t('PBXOverviewTab.stats.registered'),
          },
          {
            title: t('PBXOverviewTab.stats.sipTrunks'),
            value: dash?.total_trunks ?? 0,
            icon: GitBranch,
            variant: 'primary',
            description: t('PBXOverviewTab.stats.online', { count: trunksOnline }),
          },
          {
            title: t('PBXOverviewTab.stats.voicemails'),
            value: dash?.unread_voicemails ?? 0,
            icon: Voicemail,
            variant: 'warning',
            description: t('PBXOverviewTab.stats.unreadMessages'),
          },
        ]}
      />

      {/* Secondary Stats Row */}
      <StatsGrid
        columns={4}
        stats={[
          { title: t('PBXOverviewTab.stats.callsToday'), value: dash?.calls_today ?? 0, icon: Phone, variant: 'info' },
          { title: t('PBXOverviewTab.stats.ringGroups'), value: dash?.ring_groups ?? 0, icon: Users, variant: 'warning' },
          { title: t('PBXOverviewTab.stats.queues'), value: dash?.queues ?? 0, icon: ListOrdered, variant: 'info' },
          { title: t('PBXOverviewTab.stats.ivrMenus'), value: dash?.ivrs ?? 0, icon: Layers, variant: 'warning' },
          { title: t('PBXOverviewTab.stats.dids'), value: dash?.dids ?? 0, icon: Phone, variant: 'primary' },
        ]}
      />

      {/* Trunk Status · V1-style rows with registration dot */}
      <div className="bg-card rounded-lg border border-border p-4">
        <h3 className="font-semibold mb-4 flex items-center gap-2">
          <GitBranch className="h-5 w-5" />
          {t('PBXOverviewTab.trunks.heading')}
        </h3>
        {trunks.length > 0 ? (
          <div className="space-y-3">
            {trunks.map((trunk, i) => {
              const s = (trunk.status || '').toLowerCase();
              const isUp = s.includes('ok') || s.includes('registered') || s.includes('online');
              const isDisabled = s.includes('disabled');
              const dotColor = isUp ? 'bg-emerald-500' : isDisabled ? 'bg-muted-foreground' : s.includes('configured') ? 'bg-amber-500' : 'bg-red-500';
              return (
                <div key={i} className="flex items-center justify-between p-3 bg-muted rounded-lg">
                  <div className="flex items-center gap-3">
                    <div className={cn('w-3 h-3 rounded-full', dotColor)} />
                    <div>
                      <p className="font-medium">{trunk.name}</p>
                      <p className="text-sm text-muted-foreground">
                        {trunk.technology || trunk.tech || trunk.trunk_type || 'SIP'} · {trunk.sip_server || trunk.host || 'N/A'}
                      </p>
                    </div>
                  </div>
                  <div className="text-sm text-muted-foreground font-mono">
                    {trunk.channels_used ?? 0}/{trunk.max_channels || '∞'} {t('PBXOverviewTab.trunks.channels')}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <p className="text-sm text-muted-foreground py-2">{t('PBXOverviewTab.trunks.empty')}</p>
        )}
      </div>

      {/* Queue Status · V1-style 3-metric cards */}
      {queues.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {queues.map((queue, i) => (
            <div key={i} className="bg-card rounded-lg border border-border p-4">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="font-semibold">{queue.display_name || queue.name}</h3>
                  <p className="text-sm text-muted-foreground">{queue.strategy || 'ringall'}</p>
                </div>
                {(queue.callers_waiting ?? 0) > 0 && (
                  <span className="px-2 py-1 bg-amber-500/10 text-amber-600 rounded text-sm font-medium">
                    {t('PBXOverviewTab.queues.waitingBadge', { count: queue.callers_waiting })}
                  </span>
                )}
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4 text-center">
                <div>
                  <p className="text-2xl font-bold text-primary">{queue.member_count ?? queue.members?.length ?? 0}</p>
                  <p className="text-xs text-muted-foreground">{t('PBXOverviewTab.queues.agents')}</p>
                </div>
                <div>
                  <p className="text-2xl font-bold text-emerald-600">{queue.completed ?? 0}</p>
                  <p className="text-xs text-muted-foreground">{t('PBXOverviewTab.queues.completed')}</p>
                </div>
                <div>
                  <p className="text-2xl font-bold text-muted-foreground">{queue.callers_waiting ?? 0}</p>
                  <p className="text-xs text-muted-foreground">{t('PBXOverviewTab.queues.waiting')}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Connection Status + Extensions Preview */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Connection Status */}
        <div className="bg-card rounded-lg border border-border p-4 lg:col-span-1">
          <h3 className="font-semibold text-sm mb-3">{t('PBXOverviewTab.connection.heading')}</h3>
          <div className="space-y-3">
            <ConnectionDot connected={dash?.ami_connected ?? false} label="AMI" />
            <ConnectionDot connected={dash?.ari_connected ?? false} label="ARI" />
            <ConnectionDot connected={dash?.rest_available ?? false} label="REST" />
          </div>
          <Separator className="my-3" />
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">{t('PBXOverviewTab.connection.ipAddress')}</span>
              <span className="font-mono">{dash?.ip_address || pbx?.ip_address}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">{t('PBXOverviewTab.connection.apiPort')}</span>
              <span className="font-mono">{dash?.api_port || pbx?.api_port}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">{t('PBXOverviewTab.connection.sipPort')}</span>
              <span className="font-mono">{dash?.sip_port || pbx?.sip_port}</span>
            </div>
            {dash?.asterisk_version && (
              <div className="flex justify-between">
                <span className="text-muted-foreground">{t('PBXOverviewTab.connection.asterisk')}</span>
                <span className="font-mono text-xs">{dash.asterisk_version}</span>
              </div>
            )}
            <div className="flex justify-between">
              <span className="text-muted-foreground">{t('PBXOverviewTab.connection.lastSync')}</span>
              <span>{dash?.last_sync ? formatTimeAgo(dash.last_sync) : t('PBXOverviewTab.connection.never')}</span>
            </div>
          </div>
        </div>

        {/* Extensions · V1-style native table with bg-muted header */}
        <div className="bg-card rounded-lg border border-border lg:col-span-2 overflow-hidden">
          <div className="p-4 border-b border-border flex items-center justify-between">
            <h3 className="font-semibold text-sm flex items-center gap-2">
              <Hash className="h-4 w-4" /> {t('PBXOverviewTab.extensions.heading')}
            </h3>
            <button
              onClick={onNavigateToExtensions}
              className="text-sm text-primary hover:underline flex items-center gap-1"
            >
              {t('PBXOverviewTab.extensions.viewAll')} <ChevronRight className="h-4 w-4" />
            </button>
          </div>
          {extensions.length === 0 ? (
            <EmptyState
              icon={Phone}
              title={t('PBXOverviewTab.extensions.emptyTitle')}
              action={{ label: t('PBXOverviewTab.extensions.syncNow'), onClick: onSync, icon: RefreshCw }}
              variant="compact"
            />
          ) : (
            <>
              <table className="w-full">
                <thead className="bg-muted">
                  <tr>
                    <th className="px-4 py-2 text-left text-xs font-medium text-muted-foreground uppercase">{t('PBXOverviewTab.extensions.colExt')}</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-muted-foreground uppercase">{t('PBXOverviewTab.extensions.colName')}</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-muted-foreground uppercase">{t('PBXOverviewTab.extensions.colStatus')}</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-muted-foreground uppercase">{t('PBXOverviewTab.extensions.colVm')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {extensions.slice(0, 10).map((ext) => (
                    <tr key={ext.id} className="hover:bg-muted/50 cursor-pointer" onClick={onNavigateToExtensions}>
                      <td className="px-4 py-2">
                        <span className="font-mono font-medium text-primary">{ext.extension_number}</span>
                      </td>
                      <td className="px-4 py-2 text-sm">{ext.display_name}</td>
                      <td className="px-4 py-2">
                        {ext.is_active
                          ? <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-emerald-500/10 text-emerald-600">{t('PBXOverviewTab.extensions.active')}</span>
                          : <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-muted text-muted-foreground">{t('PBXOverviewTab.extensions.inactive')}</span>
                        }
                      </td>
                      <td className="px-4 py-2">
                        {ext.voicemail_enabled && <Voicemail className="h-3.5 w-3.5 text-muted-foreground" />}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {extensions.length > 10 && (
                <div className="px-4 py-2 text-xs text-muted-foreground text-center border-t border-border bg-muted/30">
                  {t('PBXOverviewTab.extensions.moreCount', { count: extensions.length - 10 })}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
