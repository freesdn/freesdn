// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * PBXIvrTab · IVR menus table for the PBX detail page.
 *
 * Extracted from PBXDetailPage as part of the monolith breakup. Receives all
 * data via props; owns no state of its own.
 */
import { Layers } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import type { IVR } from '../types';

export interface PBXIvrTabProps {
  ivrs: IVR[];
  ivrColumns: DataTableColumn<IVR>[];
  ivrLoading: boolean;
  onSelectIVR: (ivr: IVR) => void;
}

export function PBXIvrTab({
  ivrs,
  ivrColumns,
  ivrLoading,
  onSelectIVR,
}: PBXIvrTabProps) {
  const { t } = useTranslation('voip');
  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-lg font-semibold">{t('PBXIvrTab.heading')}</h3>
        <p className="text-sm text-muted-foreground">{t('PBXIvrTab.description')}</p>
      </div>
      <DataTable
        data={ivrs}
        columns={ivrColumns}
        isLoading={ivrLoading}
        searchable
        itemName={t('PBXIvrTab.itemName')}
        onRowClick={(row) => onSelectIVR(row)}
        emptyState={
          <div className="flex flex-col items-center gap-3 py-12">
            <Layers className="h-12 w-12 text-muted-foreground/30" />
            <p className="text-muted-foreground">{t('PBXIvrTab.empty')}</p>
          </div>
        }
      />
    </div>
  );
}
