// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * PBXQueuesTab · call queues table for the PBX detail page.
 *
 * Extracted from PBXDetailPage as part of the monolith breakup. Receives all
 * data via props; owns no state of its own.
 */
import { useTranslation } from 'react-i18next';
import { ListOrdered } from 'lucide-react';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import type { Queue } from '../types';

export interface PBXQueuesTabProps {
  queues: Queue[];
  queueColumns: DataTableColumn<Queue>[];
  queueLoading: boolean;
  onSelectQueue: (q: Queue) => void;
}

export function PBXQueuesTab({
  queues,
  queueColumns,
  queueLoading,
  onSelectQueue,
}: PBXQueuesTabProps) {
  const { t } = useTranslation('voip');
  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-lg font-semibold">{t('PBXQueuesTab.heading')}</h3>
        <p className="text-sm text-muted-foreground">{t('PBXQueuesTab.subtitle')}</p>
      </div>
      <DataTable
        data={queues}
        columns={queueColumns}
        isLoading={queueLoading}
        searchable
        itemName={t('PBXQueuesTab.itemName')}
        onRowClick={(row) => onSelectQueue(row)}
        emptyState={
          <div className="flex flex-col items-center gap-3 py-12">
            <ListOrdered className="h-12 w-12 text-muted-foreground/30" />
            <p className="text-muted-foreground">{t('PBXQueuesTab.empty')}</p>
          </div>
        }
      />
    </div>
  );
}
