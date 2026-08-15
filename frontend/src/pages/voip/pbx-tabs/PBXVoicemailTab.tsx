// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * PBXVoicemailTab · voicemail boxes table for the PBX detail page.
 *
 * Extracted from PBXDetailPage as part of the monolith breakup. Receives all
 * data via props; owns no state of its own.
 */
import { Voicemail } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import type { VoicemailBox } from '../types';

export interface PBXVoicemailTabProps {
  voicemailBoxes: VoicemailBox[];
  vmColumns: DataTableColumn<VoicemailBox>[];
  vmLoading: boolean;
  onSelectVoicemail: (vm: VoicemailBox) => void;
}

export function PBXVoicemailTab({
  voicemailBoxes,
  vmColumns,
  vmLoading,
  onSelectVoicemail,
}: PBXVoicemailTabProps) {
  const { t } = useTranslation('voip');
  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-lg font-semibold">{t('PBXVoicemailTab.heading')}</h3>
        <p className="text-sm text-muted-foreground">{t('PBXVoicemailTab.description')}</p>
      </div>
      <DataTable
        data={voicemailBoxes}
        columns={vmColumns}
        isLoading={vmLoading}
        searchable
        itemName={t('PBXVoicemailTab.itemName')}
        onRowClick={(row) => onSelectVoicemail(row)}
        emptyState={
          <div className="flex flex-col items-center gap-3 py-12">
            <Voicemail className="h-12 w-12 text-muted-foreground/30" />
            <p className="text-muted-foreground">{t('PBXVoicemailTab.empty')}</p>
          </div>
        }
      />
    </div>
  );
}
