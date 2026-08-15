// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FleetActivityPanel, recent scheduled-scan runs across all agents.
 *
 * Lives on the Agents page below the agent table. One row per run with
 * site/schedule/agent labels resolved in a single backend query so we
 * don't fan out per-row lookups.
 */

import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { Activity, CheckCircle2, RefreshCw, XCircle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { agentFleetApi, type FleetRun } from '@/lib/api/agents';

function _formatRelative(
  iso: string,
  t: (key: string, opts?: Record<string, unknown>) => string,
): string {
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 0) return new Date(iso).toLocaleString();
  const s = Math.floor(ms / 1000);
  if (s < 60) return t('FleetActivityPanel.relative.seconds', { n: s });
  const m = Math.floor(s / 60);
  if (m < 60) return t('FleetActivityPanel.relative.minutes', { n: m });
  const h = Math.floor(m / 60);
  if (h < 24) return t('FleetActivityPanel.relative.hours', { n: h });
  const d = Math.floor(h / 24);
  return t('FleetActivityPanel.relative.days', { n: d });
}

export function FleetActivityPanel() {
  const { t } = useTranslation('common');
  const { data: runs = [], isLoading, isError, refetch } = useQuery({
    queryKey: ['fleet-runs'],
    queryFn: async () => {
      const resp = await agentFleetApi.runs({ limit: 20 });
      return resp.data;
    },
    refetchInterval: 30_000,
  });

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-indigo-600" />
            {t('FleetActivityPanel.title')}
            {runs.length > 0 ? (
              <Badge variant="secondary">
                {t('FleetActivityPanel.lastCount', { n: runs.length })}
              </Badge>
            ) : null}
          </CardTitle>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4" />
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {isError ? (
          <div className="text-sm text-destructive p-4">
            {t('FleetActivityPanel.error')}
          </div>
        ) : isLoading ? (
          <div className="text-sm text-muted-foreground p-4">
            {t('FleetActivityPanel.loading')}
          </div>
        ) : runs.length === 0 ? (
          <div className="text-sm text-muted-foreground p-4">
            {t('FleetActivityPanel.empty')}
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('FleetActivityPanel.columns.status')}</TableHead>
                <TableHead>{t('FleetActivityPanel.columns.siteSchedule')}</TableHead>
                <TableHead>{t('FleetActivityPanel.columns.agent')}</TableHead>
                <TableHead>{t('FleetActivityPanel.columns.when')}</TableHead>
                <TableHead>{t('FleetActivityPanel.columns.duration')}</TableHead>
                <TableHead>{t('FleetActivityPanel.columns.devices')}</TableHead>
                <TableHead>{t('FleetActivityPanel.columns.error')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {runs.map((r: FleetRun) => (
                <TableRow key={r.id}>
                  <TableCell>
                    {r.status === 'completed' ? (
                      <span className="inline-flex items-center gap-1 text-emerald-600">
                        <CheckCircle2 className="h-3.5 w-3.5" />
                      </span>
                    ) : r.status === 'failed' ? (
                      <span className="inline-flex items-center gap-1 text-destructive">
                        <XCircle className="h-3.5 w-3.5" />
                      </span>
                    ) : (
                      <Badge variant="outline" className="text-xs">
                        {r.status}
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-xs">
                    <Link
                      to={`/sites/${r.site_id}/agent`}
                      className="font-medium hover:underline"
                    >
                      {r.site_name || '?'}
                    </Link>
                    <div className="text-muted-foreground">
                      {r.schedule_name || '-'}
                    </div>
                  </TableCell>
                  <TableCell className="text-xs">
                    {r.agent_name || '-'}
                  </TableCell>
                  <TableCell
                    className="text-xs text-muted-foreground"
                    title={new Date(r.started_at).toLocaleString()}
                  >
                    {_formatRelative(r.started_at, t)}
                  </TableCell>
                  <TableCell className="text-xs">
                    {r.duration_seconds != null
                      ? `${r.duration_seconds.toFixed(1)}s`
                      : '-'}
                  </TableCell>
                  <TableCell className="text-xs tabular-nums">
                    {r.device_count}
                  </TableCell>
                  <TableCell className="text-xs text-destructive max-w-[200px] truncate">
                    {r.error_message || ''}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}
