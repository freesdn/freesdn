// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * PBXDidsTab · DIDs / inbound routes table for the PBX detail page.
 *
 * Extracted from PBXDetailPage as part of the monolith breakup. Receives all
 * data via props; owns no state of its own.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useTranslation } from 'react-i18next';
import { Phone, RefreshCw, Plus } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';

export interface PBXDidsTabProps {
  dids: any[];
  didColumns: DataTableColumn<any>[];
  didLoading: boolean;
  onSync: () => void;
  onCreate?: () => void;
}

export function PBXDidsTab({ dids, didColumns, didLoading, onSync, onCreate }: PBXDidsTabProps) {
  const { t } = useTranslation('voip');
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h3 className="text-lg font-semibold">{t('PBXDidsTab.heading')}</h3>
          <p className="text-sm text-muted-foreground">{t('PBXDidsTab.routesConfigured', { count: dids.length })}</p>
        </div>
        {onCreate && (
          <Button size="sm" onClick={onCreate}>
            <Plus className="h-4 w-4 mr-2" /> {t('PBXDidsTab.create')}
          </Button>
        )}
      </div>
      <DataTable
        data={dids}
        columns={didColumns}
        isLoading={didLoading}
        searchable
        itemName={t('PBXDidsTab.itemName')}
        emptyState={
          <div className="flex flex-col items-center gap-3 py-12">
            <Phone className="h-12 w-12 text-muted-foreground/30" />
            <p className="text-muted-foreground">{t('PBXDidsTab.emptyText')}</p>
            <Button variant="outline" size="sm" onClick={onSync}>
              <RefreshCw className="h-3.5 w-3.5 mr-1.5" /> {t('PBXDidsTab.syncFromPbx')}
            </Button>
          </div>
        }
      />
    </div>
  );
}
