// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * PBXConfigTab · full PBX configuration snapshot tab.
 *
 * Extracted from PBXDetailPage as part of the monolith breakup. This tab
 * delegates to four colocated section components in `./config/` to keep each
 * file manageable:
 *   - RoutingConfigSection (outbound routes, follow-me, day/night, time conditions)
 *   - AnnouncementsConfigSection (announcements, paging, recordings, MoH)
 *   - SecurityConfigSection (blacklist, certs, admin users, AMI)
 *   - SystemConfigSection (contacts, backups, SIP, parking, feature codes, modules)
 *
 * Receives all data via props; owns no state of its own.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { RefreshCw, Loader2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/button';
import { formatTimeAgo } from '../components';
import { RoutingConfigSection } from './config/RoutingConfigSection';
import { AnnouncementsConfigSection } from './config/AnnouncementsConfigSection';
import { SecurityConfigSection } from './config/SecurityConfigSection';
import { SystemConfigSection } from './config/SystemConfigSection';

export interface PBXConfigTabProps {
  fullConfig: any;
  configLoading: boolean;
  isSyncing: boolean;
  onSync: () => void;
}

export function PBXConfigTab({
  fullConfig,
  configLoading,
  isSyncing,
  onSync,
}: PBXConfigTabProps) {
  const { t } = useTranslation('voip');
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">{t('PBXConfigTab.heading')}</h3>
          <p className="text-sm text-muted-foreground">
            {t('PBXConfigTab.description')}
            {fullConfig?.synced_at && (
              <> &bull; {t('PBXConfigTab.lastSynced', { time: formatTimeAgo(fullConfig.synced_at) })}</>
            )}
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={onSync} disabled={isSyncing}>
          {isSyncing ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <RefreshCw className="h-4 w-4 mr-2" />}
          {t('PBXConfigTab.actions.reSync')}
        </Button>
      </div>

      {configLoading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      )}

      {fullConfig && !configLoading && (
        <div className="space-y-6">
          {/* Summary row */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
            {[
              { label: t('PBXConfigTab.summary.extensions'), count: fullConfig.extensions?.length },
              { label: t('PBXConfigTab.summary.trunks'), count: fullConfig.trunks?.length },
              { label: t('PBXConfigTab.summary.ringGroups'), count: fullConfig.ring_groups?.length },
              { label: t('PBXConfigTab.summary.dids'), count: fullConfig.dids?.length },
              { label: t('PBXConfigTab.summary.timeConditions'), count: fullConfig.time_conditions?.length },
              { label: t('PBXConfigTab.summary.contacts'), count: fullConfig.contacts?.length },
              { label: t('PBXConfigTab.summary.recordings'), count: fullConfig.system_recordings?.length },
              { label: t('PBXConfigTab.summary.featureCodes'), count: fullConfig.feature_codes?.length },
              { label: t('PBXConfigTab.summary.modules'), count: fullConfig.installed_modules?.length },
              { label: t('PBXConfigTab.summary.outboundRoutes'), count: fullConfig.outbound_routes?.length },
              { label: t('PBXConfigTab.summary.announcements'), count: fullConfig.announcements?.length },
              { label: t('PBXConfigTab.summary.certificates'), count: fullConfig.certificates?.length },
              { label: t('PBXConfigTab.summary.backupJobs'), count: fullConfig.backup_jobs?.length },
              { label: t('PBXConfigTab.summary.amiManagers'), count: fullConfig.ami_managers?.length },
            ].map(({ label, count }) => (
              <div key={label} className="bg-card rounded-lg border border-border p-3 text-center">
                <p className="text-2xl font-bold">{count ?? 0}</p>
                <p className="text-xs text-muted-foreground">{label}</p>
              </div>
            ))}
          </div>

          <RoutingConfigSection fullConfig={fullConfig} />
          <AnnouncementsConfigSection fullConfig={fullConfig} />
          <SecurityConfigSection fullConfig={fullConfig} />
          <SystemConfigSection fullConfig={fullConfig} />
        </div>
      )}
    </div>
  );
}
