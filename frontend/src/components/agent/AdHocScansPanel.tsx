// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * AdHocScansPanel, recent operator-triggered (interactive) scans.
 *
 * Pairs with the scheduled Runs tab on AgentDetailPage. Scheduled runs
 * live in `agent_schedule_runs`; interactive scans live in
 * `agent_tasks` with task_data.interactive=true. This panel surfaces
 * the latter so an operator can see what they kicked off, watch live
 * progress, and replay results without re-triggering the scan.
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  CheckCircle2,
  XCircle,
  Activity,
  Loader2,
  Ban,
  Clock,
} from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { useTranslation } from 'react-i18next';
import { useToast } from '@/hooks/use-toast';
import { agentsApi } from '@/lib/api/agents';
import type { AgentTask } from '@/lib/api/types';

const TERMINAL = new Set(['completed', 'failed', 'cancelled']);

interface Props {
  agentId: string;
}

export function AdHocScansPanel({ agentId }: Props) {
  const { t } = useTranslation('common');
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: tasks = [], isLoading } = useQuery({
    queryKey: ['agent-ad-hoc-scans', agentId],
    queryFn: async () => {
      const resp = await agentsApi.listAdHocScans(agentId, 25);
      return resp.data;
    },
    // Poll while any task is still running so the UI tracks live state.
    refetchInterval: (query) => {
      const rows = (query.state.data as AgentTask[] | undefined) || [];
      const hasRunning = rows.some((t) => !TERMINAL.has(t.status));
      return hasRunning ? 2000 : 15000;
    },
  });

  const cancelMutation = useMutation({
    mutationFn: async (taskId: string) => {
      await agentsApi.cancelTask(taskId);
    },
    onSuccess: () => {
      toast({ title: t('AdHocScansPanel.toasts.cancellationRequested') });
      queryClient.invalidateQueries({
        queryKey: ['agent-ad-hoc-scans', agentId],
      });
    },
    onError: (err: any) => {
      toast({
        title: t('AdHocScansPanel.toasts.cancelFailed'),
        description: err?.response?.data?.detail || String(err),
        variant: 'destructive',
      });
    },
  });

  // Show only interactive scans, scheduled-task rows live in the
  // separate Runs tab and would be duplicative noise here.
  const interactive = tasks.filter(
    (t) => t.task_type === 'scan_network' && t.task_data?.interactive === true,
  );

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-6 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 inline animate-spin mr-2" />
          {t('AdHocScansPanel.loading')}
        </CardContent>
      </Card>
    );
  }

  if (interactive.length === 0) {
    return (
      <Card>
        <CardContent className="p-6 text-sm text-muted-foreground">
          {t('AdHocScansPanel.empty')}
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardContent className="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t('AdHocScansPanel.columns.status')}</TableHead>
              <TableHead>{t('AdHocScansPanel.columns.type')}</TableHead>
              <TableHead>{t('AdHocScansPanel.columns.targets')}</TableHead>
              <TableHead>{t('AdHocScansPanel.columns.started')}</TableHead>
              <TableHead>{t('AdHocScansPanel.columns.progress')}</TableHead>
              <TableHead>{t('AdHocScansPanel.columns.devices')}</TableHead>
              <TableHead className="text-right">
                {t('AdHocScansPanel.columns.actions')}
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {interactive.map((task) => {
              const isRunning = !TERMINAL.has(task.status);
              const result = (task.result || {}) as Record<string, unknown>;
              const total =
                (result.total as number | undefined) ??
                (Array.isArray(result.devices)
                  ? (result.devices as unknown[]).length
                  : undefined);
              const targets = (task.task_data?.targets as string[]) || [];
              return (
                <TableRow key={task.id}>
                  <TableCell>
                    {task.status === 'completed' ? (
                      <span title={t('AdHocScansPanel.status.completed')}>
                        <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                      </span>
                    ) : task.status === 'failed' ? (
                      <span
                        title={
                          task.error_message ||
                          t('AdHocScansPanel.status.failed')
                        }
                      >
                        <XCircle className="h-4 w-4 text-destructive" />
                      </span>
                    ) : task.status === 'cancelled' ? (
                      <span title={t('AdHocScansPanel.status.cancelled')}>
                        <Ban className="h-4 w-4 text-muted-foreground" />
                      </span>
                    ) : (
                      <span title={task.status}>
                        <Activity className="h-4 w-4 text-sky-600 animate-pulse" />
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="text-xs font-mono">
                    {(task.task_data?.scan_type as string) || 'quick'}
                  </TableCell>
                  <TableCell className="text-xs">
                    {targets.length > 0 ? (
                      targets.join(', ')
                    ) : (
                      <span className="text-muted-foreground italic">
                        {t('AdHocScansPanel.autoDetect')}
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {task.started_at ? (
                      <span title={new Date(task.started_at).toLocaleString()}>
                        <Clock className="h-3 w-3 inline mr-1" />
                        {new Date(task.started_at).toLocaleTimeString()}
                      </span>
                    ) : (
                      '-'
                    )}
                  </TableCell>
                  <TableCell>
                    {isRunning ? (
                      <div className="w-24 bg-muted rounded h-1.5 overflow-hidden">
                        <div
                          className="h-full bg-sky-500 transition-all"
                          style={{ width: `${task.progress || 0}%` }}
                        />
                      </div>
                    ) : (
                      <span className="text-xs text-muted-foreground">
                        {task.progress || 0}%
                      </span>
                    )}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{total ?? 0}</Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    {isRunning ? (
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => cancelMutation.mutate(task.id)}
                        disabled={cancelMutation.isPending}
                      >
                        {t('AdHocScansPanel.actions.cancel')}
                      </Button>
                    ) : null}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
