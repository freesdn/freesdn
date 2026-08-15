// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * ConfigHistoryTab · config version list + diff viewer for the switch detail view.
 *
 * Extracted from SwitchesPage as part of the monolith breakup. The parent owns
 * the version/diff queries and the selected diff range; this component renders
 * the table + the unified-diff viewer.
 */
import { History, RefreshCw } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import type { ConfigVersion } from '@/lib/api';

export interface ConfigDiffData {
  has_changes: boolean;
  added_lines: number;
  removed_lines: number;
  modified_sections: string[];
  unified_diff: string;
}

// Diff range identifies versions by UUID for the backend call;
// ``aLabel``/``bLabel`` are the human-readable ``version_number``s
// used in the heading.
export type DiffRange = { a: string; b: string; aLabel: number; bLabel: number };

export interface ConfigHistoryTabProps {
  configVersions: { items: ConfigVersion[]; total: number } | null | undefined;
  configVersionsLoading: boolean;
  configDiff: ConfigDiffData | null | undefined;
  diffLoading: boolean;
  diffVersions: DiffRange | null;
  onSelectDiff: (range: DiffRange | null) => void;
}

export function ConfigHistoryTab({
  configVersions,
  configVersionsLoading,
  configDiff,
  diffLoading,
  diffVersions,
  onSelectDiff,
}: ConfigHistoryTabProps) {
  const { t } = useTranslation('switches');
  // Versions arrive newest-first. "Diff with prev" picks the row
  // immediately AFTER the current row in the list (older version).
  const items = configVersions?.items ?? [];
  const findPrev = (idx: number): ConfigVersion | null => items[idx + 1] ?? null;
  return (
    <>
      {configVersionsLoading && (
        <div className="flex items-center justify-center py-12">
          <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      )}
      {!configVersionsLoading && (!configVersions?.items || configVersions.items.length === 0) && (
        <EmptyState
          icon={History}
          title={t('ConfigHistoryTab.empty.title')}
          description={t('ConfigHistoryTab.empty.description')}
        />
      )}
      {configVersions?.items && configVersions.items.length > 0 && (
        <>
          {/* Version list table */}
          <Card>
            <CardHeader>
              <CardTitle>{t('ConfigHistoryTab.card.title')}</CardTitle>
              <CardDescription>{t('ConfigHistoryTab.card.versionsRecorded', { count: configVersions.total })}</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('ConfigHistoryTab.table.version')}</TableHead>
                    <TableHead>{t('ConfigHistoryTab.table.changeType')}</TableHead>
                    <TableHead>{t('ConfigHistoryTab.table.by')}</TableHead>
                    <TableHead>{t('ConfigHistoryTab.table.firmware')}</TableHead>
                    <TableHead>{t('ConfigHistoryTab.table.date')}</TableHead>
                    <TableHead>{t('ConfigHistoryTab.table.actions')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {configVersions.items.map((v: ConfigVersion, idx: number) => {
                    const prev = findPrev(idx);
                    return (
                      <TableRow key={v.id}>
                        <TableCell>v{v.version}</TableCell>
                        <TableCell><Badge variant="outline">{v.change_type}</Badge></TableCell>
                        <TableCell>{v.initiated_by}</TableCell>
                        <TableCell className="text-xs">{v.device_firmware || '-'}</TableCell>
                        <TableCell className="text-xs">{new Date(v.created_at).toLocaleString()}</TableCell>
                        <TableCell>
                          {prev && (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => onSelectDiff({
                                a: prev.id, b: v.id,
                                aLabel: prev.version, bLabel: v.version,
                              })}
                            >
                              {t('ConfigHistoryTab.actions.diffWithPrev')}
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          {/* Diff viewer */}
          {diffVersions && (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle>{t('ConfigHistoryTab.diff.title', { a: diffVersions.aLabel, b: diffVersions.bLabel })}</CardTitle>
                    {configDiff && (
                      <CardDescription>
                        {t('ConfigHistoryTab.diff.summary', { added: configDiff.added_lines, removed: configDiff.removed_lines })}
                        {configDiff.modified_sections.length > 0 && t('ConfigHistoryTab.diff.sections', { sections: configDiff.modified_sections.join(', ') })}
                      </CardDescription>
                    )}
                  </div>
                  <Button variant="ghost" size="sm" onClick={() => onSelectDiff(null)}>{t('ConfigHistoryTab.actions.close')}</Button>
                </div>
              </CardHeader>
              <CardContent>
                {diffLoading && (
                  <div className="flex items-center justify-center py-8">
                    <RefreshCw className="h-5 w-5 animate-spin text-muted-foreground" />
                  </div>
                )}
                {configDiff && !configDiff.has_changes && (
                  <p className="text-muted-foreground text-center py-4">{t('ConfigHistoryTab.diff.noChanges')}</p>
                )}
                {configDiff && configDiff.has_changes && (
                  <pre className="bg-muted rounded-lg p-4 text-xs font-mono overflow-auto max-h-[500px] whitespace-pre-wrap">
                    {(configDiff.unified_diff || '').split('\n').map((line: string, i: number) => (
                      <div
                        key={i}
                        className={
                          line.startsWith('+') ? 'text-green-600 bg-green-50 dark:bg-green-950/30 dark:text-green-400' :
                          line.startsWith('-') ? 'text-red-600 bg-red-50 dark:bg-red-950/30 dark:text-red-400' :
                          line.startsWith('@@') ? 'text-blue-600 bg-blue-50 dark:bg-blue-950/30 dark:text-blue-400 font-semibold' :
                          ''
                        }
                      >
                        {line}
                      </div>
                    ))}
                  </pre>
                )}
              </CardContent>
            </Card>
          )}
        </>
      )}
    </>
  );
}
