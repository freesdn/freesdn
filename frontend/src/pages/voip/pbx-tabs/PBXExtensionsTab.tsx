// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * PBXExtensionsTab · extensions table for the PBX detail page.
 *
 * Extracted from PBXDetailPage as part of the monolith breakup. Receives all
 * data via props; owns no state of its own.
 */
import { useTranslation } from 'react-i18next';
import { Phone, RefreshCw, Plus } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { EmptyState } from '@/components/ui/empty-state';
import type { Extension } from '../types';

export interface PBXExtensionsTabProps {
  extensions: Extension[];
  extensionColumns: DataTableColumn<Extension>[];
  extLoading: boolean;
  onRefresh: () => void;
  onCreate: () => void;
  onSelectExtension: (ext: Extension) => void;
  onSync: () => void;
}

export function PBXExtensionsTab({
  extensions,
  extensionColumns,
  extLoading,
  onRefresh,
  onCreate,
  onSelectExtension,
  onSync,
}: PBXExtensionsTabProps) {
  const { t } = useTranslation('voip');
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">{t('PBXExtensionsTab.heading')}</h3>
          <p className="text-sm text-muted-foreground">
            {t('PBXExtensionsTab.countSummary', { count: extensions.length })}
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={onRefresh}>
            <RefreshCw className="h-4 w-4 mr-2" /> {t('PBXExtensionsTab.actions.refresh')}
          </Button>
          <Button size="sm" onClick={onCreate}>
            <Plus className="h-4 w-4 mr-2" /> {t('PBXExtensionsTab.actions.create')}
          </Button>
        </div>
      </div>
      <DataTable
        data={extensions}
        columns={extensionColumns}
        isLoading={extLoading}
        searchable
        itemName={t('PBXExtensionsTab.itemName')}
        onRowClick={(row) => onSelectExtension(row)}
        emptyState={
          <EmptyState
            icon={Phone}
            title={t('PBXExtensionsTab.empty.title')}
            action={{ label: t('PBXExtensionsTab.empty.syncAction'), onClick: onSync, icon: RefreshCw }}
          />
        }
      />
    </div>
  );
}
