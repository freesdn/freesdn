// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * PBXRingGroupsTab · ring groups table for the PBX detail page.
 *
 * Extracted from PBXDetailPage as part of the monolith breakup. Receives all
 * data via props; owns no state of its own.
 */
import { useTranslation } from 'react-i18next';
import { Users, Plus } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import type { RingGroup } from '../types';

export interface PBXRingGroupsTabProps {
  ringGroups: RingGroup[];
  rgColumns: DataTableColumn<RingGroup>[];
  rgLoading: boolean;
  onSelectRingGroup: (rg: RingGroup) => void;
  onCreate?: () => void;
}

export function PBXRingGroupsTab({
  ringGroups,
  rgColumns,
  rgLoading,
  onSelectRingGroup,
  onCreate,
}: PBXRingGroupsTabProps) {
  const { t } = useTranslation('voip');
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h3 className="text-lg font-semibold">{t('PBXRingGroupsTab.heading')}</h3>
          <p className="text-sm text-muted-foreground">
            {t('PBXRingGroupsTab.configuredCount', { n: ringGroups.length })}
          </p>
        </div>
        {onCreate && (
          <Button size="sm" onClick={onCreate}>
            <Plus className="h-4 w-4 mr-2" /> {t('PBXRingGroupsTab.create')}
          </Button>
        )}
      </div>
      <DataTable
        data={ringGroups}
        columns={rgColumns}
        isLoading={rgLoading}
        searchable
        itemName={t('PBXRingGroupsTab.itemName')}
        onRowClick={(row) => onSelectRingGroup(row)}
        emptyState={
          <div className="flex flex-col items-center gap-3 py-12">
            <Users className="h-12 w-12 text-muted-foreground/30" />
            <p className="text-muted-foreground">{t('PBXRingGroupsTab.empty')}</p>
          </div>
        }
      />
    </div>
  );
}
