// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * PBXActiveCallsTab · active calls table for the PBX detail page.
 *
 * Extracted from PBXDetailPage as part of the monolith breakup. Receives all
 * data via props; owns no state of its own.
 */
import { PhoneCall, RefreshCw, Play, Radio } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/button';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import type { ActiveCall } from '../types';

export interface PBXActiveCallsTabProps {
  activeCalls: ActiveCall[];
  callColumns: DataTableColumn<ActiveCall>[];
  callsLoading: boolean;
  onRefresh: () => void;
  onOriginate: () => void;
}

export function PBXActiveCallsTab({
  activeCalls,
  callColumns,
  callsLoading,
  onRefresh,
  onOriginate,
}: PBXActiveCallsTabProps) {
  const { t } = useTranslation('voip');
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">{t('PBXActiveCallsTab.title')}</h3>
          <p className="text-sm text-muted-foreground">
            {t('PBXActiveCallsTab.subtitle')}
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={onRefresh}>
            <RefreshCw className="h-4 w-4 mr-2" /> {t('PBXActiveCallsTab.actions.refresh')}
          </Button>
          <Button size="sm" onClick={onOriginate}>
            <Play className="h-4 w-4 mr-2" /> {t('PBXActiveCallsTab.actions.originate')}
          </Button>
        </div>
      </div>
      <DataTable
        data={activeCalls}
        columns={callColumns}
        isLoading={callsLoading}
        itemName={t('PBXActiveCallsTab.itemName')}
        emptyState={
          <div className="flex flex-col items-center gap-3 py-12">
            <PhoneCall className="h-12 w-12 text-muted-foreground/30" />
            <p className="text-muted-foreground">{t('PBXActiveCallsTab.empty.title')}</p>
            <div className="flex items-center gap-1 text-xs text-muted-foreground">
              <Radio className="h-3 w-3 animate-pulse text-green-500" />
              {t('PBXActiveCallsTab.empty.monitoring')}
            </div>
          </div>
        }
      />
    </div>
  );
}
