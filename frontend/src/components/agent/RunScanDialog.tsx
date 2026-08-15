// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * RunScanDialog, operator-triggered network scan against a remote agent.
 *
 * Flow:
 *  1. Operator picks scan_type (filtered by agent.capabilities.scan_types)
 *     and optionally provides a target list.
 *  2. POST /agents/{id}/scan dispatches the command via the agent's
 *     live WebSocket and returns a task_id.
 *  3. Dialog polls GET /agents/{id}/scan/{task_id} every 1.5s, rendering
 *     a live progress card with percent + scanner name + device count.
 *  4. When the task reaches a terminal status (completed/failed), the
 *     polling stops and the result summary is shown.
 *
 * Closing the dialog mid-scan stops the polling but leaves the task
 * running on the agent, the user can re-open AgentDetailPage's Runs
 * tab (or re-poll the task_id) to see the eventual result.
 */

import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Activity, Loader2, Play, Search, CheckCircle2, XCircle, Ban } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { agentsApi } from '@/lib/api/agents';
import type { AgentTask } from '@/lib/api/types';

const TERMINAL_STATUSES = new Set(['completed', 'failed', 'cancelled']);

interface RunScanDialogProps {
  agentId: string;
  agentName: string;
  agentStatus: string;
  supportedScanTypes?: string[];
  onScanComplete?: (task: AgentTask) => void;
}

export function RunScanDialog({
  agentId,
  agentName,
  agentStatus,
  supportedScanTypes,
  onScanComplete,
}: RunScanDialogProps) {
  const { t } = useTranslation('common');
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [scanType, setScanType] = useState('quick');
  const [targetsText, setTargetsText] = useState('');
  const [timeoutSeconds, setTimeoutSeconds] = useState(300);
  const [activeTaskId, setActiveTaskId] = useState<string | null>(null);

  // Reset transient state every time the dialog opens
  useEffect(() => {
    if (open) {
      setActiveTaskId(null);
      if (supportedScanTypes && supportedScanTypes.length > 0) {
        if (!supportedScanTypes.includes(scanType)) {
          setScanType(supportedScanTypes[0]);
        }
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const isOnline = agentStatus === 'online';
  const scanTypeOptions =
    supportedScanTypes && supportedScanTypes.length > 0
      ? supportedScanTypes
      : ['quick', 'full'];

  const cancelMutation = useMutation({
    mutationFn: async (taskId: string) => {
      const resp = await agentsApi.cancelTask(taskId);
      return resp.data;
    },
    onSuccess: () => {
      toast({ title: t('RunScanDialog.toast.cancelRequested') });
    },
    onError: (err: any) => {
      toast({
        title: t('RunScanDialog.toast.cancelFailed'),
        description: err?.response?.data?.detail || String(err),
        variant: 'destructive',
      });
    },
  });

  const launchMutation = useMutation({
    mutationFn: async () => {
      const targets = targetsText
        .split(/[,\s]+/)
        .map((t) => t.trim())
        .filter(Boolean);
      const resp = await agentsApi.runScan(agentId, {
        scan_type: scanType,
        targets: targets.length > 0 ? targets : undefined,
        timeout_seconds: timeoutSeconds,
      });
      return resp.data;
    },
    onSuccess: (data) => {
      setActiveTaskId(data.task_id);
      toast({
        title: t('RunScanDialog.toast.dispatched'),
        description: t('RunScanDialog.toast.dispatchedDescription', {
          scanType,
          agentName,
        }),
      });
    },
    onError: (err: any) => {
      toast({
        title: t('RunScanDialog.toast.failedToStart'),
        description: err?.response?.data?.detail || String(err),
        variant: 'destructive',
      });
    },
  });

  const { data: task } = useQuery({
    queryKey: ['agent-scan-status', agentId, activeTaskId],
    queryFn: async () => {
      const resp = await agentsApi.getScanStatus(agentId, activeTaskId!);
      return resp.data;
    },
    enabled: !!activeTaskId && open,
    refetchInterval: (query) => {
      const t = query.state.data as AgentTask | undefined;
      if (t && TERMINAL_STATUSES.has(t.status)) return false;
      return 1500;
    },
  });

  // Fire onScanComplete once when terminal
  useEffect(() => {
    if (task && TERMINAL_STATUSES.has(task.status) && onScanComplete) {
      onScanComplete(task);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [task?.status]);

  const isRunning = !!activeTaskId && task && !TERMINAL_STATUSES.has(task.status);
  const isTerminal = !!task && TERMINAL_STATUSES.has(task.status);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="default" size="sm" disabled={!isOnline}>
          <Play className="h-4 w-4 mr-1" />
          {t('RunScanDialog.trigger.runScanNow')}
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{t('RunScanDialog.title', { agentName })}</DialogTitle>
        </DialogHeader>

        {!activeTaskId ? (
          <div className="space-y-3 pt-2">
            <div className="text-xs text-muted-foreground">
              {t('RunScanDialog.form.intro')}
            </div>
            <div>
              <Label htmlFor="scan-type">{t('RunScanDialog.form.scanTypeLabel')}</Label>
              <Select value={scanType} onValueChange={setScanType}>
                <SelectTrigger id="scan-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {scanTypeOptions.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {supportedScanTypes && supportedScanTypes.length > 0 ? (
                <div className="text-xs text-muted-foreground mt-1">
                  {t('RunScanDialog.form.scanTypeFilterNote')}
                </div>
              ) : null}
            </div>
            <div>
              <Label htmlFor="scan-targets">
                {t('RunScanDialog.form.targetsLabel')}
              </Label>
              <Textarea
                id="scan-targets"
                placeholder="192.168.1.0/24&#10;10.0.0.0/24"
                value={targetsText}
                onChange={(e) => setTargetsText(e.target.value)}
                rows={3}
                className="font-mono text-xs"
              />
              <div className="text-xs text-muted-foreground mt-1">
                {t('RunScanDialog.form.targetsHint')}
              </div>
            </div>
            <div>
              <Label htmlFor="scan-timeout">{t('RunScanDialog.form.timeoutLabel')}</Label>
              <Input
                id="scan-timeout"
                type="number"
                min={10}
                max={1800}
                value={timeoutSeconds}
                onChange={(e) =>
                  setTimeoutSeconds(parseInt(e.target.value, 10) || 300)
                }
              />
            </div>
          </div>
        ) : (
          <div className="space-y-3 pt-2">
            <ScanProgressCard task={task} />
            {isTerminal ? (
              <div className="text-xs text-muted-foreground">
                {t('RunScanDialog.result.discoveredHostsPrefix')}{' '}
                <span className="font-medium">
                  {t('RunScanDialog.result.discoveriesTab')}
                </span>{' '}
                {t('RunScanDialog.result.discoveredHostsSuffix')}
              </div>
            ) : null}
          </div>
        )}

        <DialogFooter>
          {!activeTaskId ? (
            <>
              <Button
                variant="outline"
                onClick={() => setOpen(false)}
                disabled={launchMutation.isPending}
              >
                {t('RunScanDialog.actions.cancel')}
              </Button>
              <Button
                onClick={() => launchMutation.mutate()}
                disabled={launchMutation.isPending || !isOnline}
              >
                {launchMutation.isPending ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                    {t('RunScanDialog.actions.dispatching')}
                  </>
                ) : (
                  <>
                    <Search className="h-4 w-4 mr-1" />
                    {t('RunScanDialog.actions.startScan')}
                  </>
                )}
              </Button>
            </>
          ) : (
            <>
              {isRunning ? (
                <>
                  <Button
                    variant="destructive"
                    onClick={() => cancelMutation.mutate(activeTaskId!)}
                    disabled={cancelMutation.isPending}
                  >
                    <Ban className="h-4 w-4 mr-1" />
                    {cancelMutation.isPending
                      ? t('RunScanDialog.actions.cancelling')
                      : t('RunScanDialog.actions.cancelScan')}
                  </Button>
                  <Button variant="outline" onClick={() => setOpen(false)}>
                    {t('RunScanDialog.actions.hideScanContinues')}
                  </Button>
                </>
              ) : (
                <Button
                  variant="outline"
                  onClick={() => {
                    setActiveTaskId(null);
                    setOpen(false);
                  }}
                >
                  {t('RunScanDialog.actions.close')}
                </Button>
              )}
              {isTerminal ? (
                <Button
                  onClick={() => {
                    setActiveTaskId(null);
                  }}
                >
                  {t('RunScanDialog.actions.runAnother')}
                </Button>
              ) : null}
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

interface ScanProgressCardProps {
  task: AgentTask | undefined;
}

function ScanProgressCard({ task }: ScanProgressCardProps) {
  const { t } = useTranslation('common');
  if (!task) {
    return (
      <Card>
        <CardContent className="p-4 flex items-center gap-3 text-sm">
          <Loader2 className="h-4 w-4 animate-spin" />
          <span>{t('RunScanDialog.progress.waitingForAgent')}</span>
        </CardContent>
      </Card>
    );
  }

  const isCompleted = task.status === 'completed';
  const isFailed = task.status === 'failed';
  const live = task.result || {};
  const devicesFound =
    (live.total as number) ?? (live.devices_found as number) ?? 0;

  return (
    <Card>
      <CardContent className="p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm font-medium">
            {isCompleted ? (
              <CheckCircle2 className="h-4 w-4 text-emerald-600" />
            ) : isFailed ? (
              <XCircle className="h-4 w-4 text-destructive" />
            ) : (
              <Activity className="h-4 w-4 text-sky-600 animate-pulse" />
            )}
            <span>
              {isCompleted
                ? t('RunScanDialog.progress.complete')
                : isFailed
                ? t('RunScanDialog.progress.failed')
                : t('RunScanDialog.progress.scanning', {
                    percent: task.progress || 0,
                  })}
            </span>
          </div>
          <Badge variant="outline" className="text-xs">
            {task.status}
          </Badge>
        </div>

        <div className="w-full bg-muted rounded h-2 overflow-hidden">
          <div
            className={`h-full transition-all ${
              isFailed
                ? 'bg-destructive'
                : isCompleted
                ? 'bg-emerald-500'
                : 'bg-sky-500'
            }`}
            style={{ width: `${isCompleted ? 100 : task.progress || 0}%` }}
          />
        </div>

        <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
          <dt className="text-muted-foreground">{t('RunScanDialog.progress.devicesFound')}</dt>
          <dd className="font-medium">{devicesFound}</dd>
          {live.scanner ? (
            <>
              <dt className="text-muted-foreground">{t('RunScanDialog.progress.currentScanner')}</dt>
              <dd className="font-mono">{String(live.scanner)}</dd>
            </>
          ) : null}
          {task.started_at ? (
            <>
              <dt className="text-muted-foreground">{t('RunScanDialog.progress.started')}</dt>
              <dd>{new Date(task.started_at).toLocaleTimeString()}</dd>
            </>
          ) : null}
          {task.completed_at ? (
            <>
              <dt className="text-muted-foreground">{t('RunScanDialog.progress.completed')}</dt>
              <dd>{new Date(task.completed_at).toLocaleTimeString()}</dd>
            </>
          ) : null}
        </dl>

        {isFailed && task.error_message ? (
          <div className="text-xs text-destructive bg-destructive/10 p-2 rounded">
            {task.error_message}
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
