// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * PBXTrunksTab · SIP trunks table for the PBX detail page.
 *
 * Extracted from PBXDetailPage as part of the monolith breakup. Receives all
 * data via props; owns no state of its own.
 */
import { useTranslation } from 'react-i18next';
import { GitBranch, RefreshCw, Plus } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import type { Trunk } from '../types';

export interface PBXTrunksTabProps {
  trunks: Trunk[];
  trunkColumns: DataTableColumn<Trunk>[];
  trunkLoading: boolean;
  onRefresh: () => void;
  /** Omitted when the PBX has no trunk write API — the create button hides. */
  onCreate?: () => void;
  onSelectTrunk: (trunk: Trunk) => void;
}

export function PBXTrunksTab({
  trunks,
  trunkColumns,
  trunkLoading,
  onRefresh,
  onCreate,
  onSelectTrunk,
}: PBXTrunksTabProps) {
  const { t } = useTranslation('voip');
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">{t('PBXTrunksTab.heading')}</h3>
          <p className="text-sm text-muted-foreground">{t('PBXTrunksTab.subtitle')}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={onRefresh}>
            <RefreshCw className="h-4 w-4 mr-2" /> {t('PBXTrunksTab.actions.refresh')}
          </Button>
          {onCreate && (
            <Button size="sm" onClick={onCreate}>
              <Plus className="h-4 w-4 mr-2" /> {t('PBXTrunksTab.actions.createTrunk')}
            </Button>
          )}
        </div>
      </div>
      <DataTable
        data={trunks}
        columns={trunkColumns}
        isLoading={trunkLoading}
        searchable
        itemName={t('PBXTrunksTab.itemName')}
        onRowClick={(row) => onSelectTrunk(row)}
        emptyState={
          <div className="flex flex-col items-center gap-3 py-12">
            <GitBranch className="h-12 w-12 text-muted-foreground/30" />
            <p className="text-muted-foreground">{t('PBXTrunksTab.emptyState')}</p>
          </div>
        }
      />
    </div>
  );
}
