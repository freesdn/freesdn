// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * AgentSchedulesPanel, manage cron-based scan schedules for a site.
 *
 * Backend stores schedules in `agents.agent_schedules` and pushes
 * changes to connected agents via the `update_schedule` WS command.
 * The agent's SchedulerService hot-reloads, no daemon restart needed.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Clock, Plus, Trash2, Pause, Play, RefreshCw, History, CheckCircle2, XCircle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { agentSchedulesApi, type AgentSchedule, type AgentScheduleRun } from '@/lib/api/agents';
import { useToast } from '@/hooks/use-toast';

interface Props {
  siteId?: string;
}

type TFunc = (key: string, opts?: Record<string, unknown>) => string;

const buildScanTypes = (t: TFunc) => [
  { value: 'quick', label: t('AgentSchedulesPanel.scanTypes.quick') },
  { value: 'camera', label: t('AgentSchedulesPanel.scanTypes.camera') },
  { value: 'voip', label: t('AgentSchedulesPanel.scanTypes.voip') },
  { value: 'iot', label: t('AgentSchedulesPanel.scanTypes.iot') },
  { value: 'port', label: t('AgentSchedulesPanel.scanTypes.port') },
  { value: 'windows', label: t('AgentSchedulesPanel.scanTypes.windows') },
  { value: 'full', label: t('AgentSchedulesPanel.scanTypes.full') },
];

// Common cron presets, operators rarely need finer than this.
const buildCronPresets = (t: TFunc) => [
  { value: '0 * * * *', label: t('AgentSchedulesPanel.cronPresets.hourly') },
  { value: '0 */4 * * *', label: t('AgentSchedulesPanel.cronPresets.every4h') },
  { value: '0 */6 * * *', label: t('AgentSchedulesPanel.cronPresets.every6h') },
  { value: '0 2 * * *', label: t('AgentSchedulesPanel.cronPresets.daily0200') },
  { value: '0 2 * * 0', label: t('AgentSchedulesPanel.cronPresets.weeklySun0200') },
];

interface FormState {
  name: string;
  scan_type: string;
  cron: string;
  targets: string;
  // Notification config (joined into the JSONB body server-side)
  email_to: string;
  slack_channel: string;
  notify_on_failure: boolean;
  notify_on_new_devices: number;
}

function _formatRelative(iso: string | null, t: TFunc): string {
  if (!iso) return t('AgentSchedulesPanel.relative.never');
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 0) return new Date(iso).toLocaleString();
  const s = Math.floor(ms / 1000);
  if (s < 60) return t('AgentSchedulesPanel.relative.secondsAgo', { n: s });
  const m = Math.floor(s / 60);
  if (m < 60) return t('AgentSchedulesPanel.relative.minutesAgo', { n: m });
  const h = Math.floor(m / 60);
  if (h < 24) return t('AgentSchedulesPanel.relative.hoursAgo', { n: h });
  const d = Math.floor(h / 24);
  if (d < 14) return t('AgentSchedulesPanel.relative.daysAgo', { n: d });
  return new Date(iso).toLocaleDateString();
}

function HistoryDialog({
  schedule,
  open,
  onOpenChange,
}: {
  schedule: AgentSchedule | null;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const { t } = useTranslation('common');
  const { data: runs = [], isLoading } = useQuery({
    queryKey: ['schedule-runs', schedule?.id],
    queryFn: async () => {
      if (!schedule) return [];
      const resp = await agentSchedulesApi.listRuns(schedule.id, 50);
      return resp.data;
    },
    enabled: !!schedule && open,
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>
            {t('AgentSchedulesPanel.history.title', { name: schedule?.name || '' })}
          </DialogTitle>
        </DialogHeader>
        <div className="max-h-[400px] overflow-y-auto">
          {isLoading ? (
            <div className="text-sm text-muted-foreground p-4">{t('AgentSchedulesPanel.loading')}</div>
          ) : runs.length === 0 ? (
            <div className="text-sm text-muted-foreground p-4">
              {t('AgentSchedulesPanel.history.empty')}
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('AgentSchedulesPanel.history.columns.status')}</TableHead>
                  <TableHead>{t('AgentSchedulesPanel.history.columns.started')}</TableHead>
                  <TableHead>{t('AgentSchedulesPanel.history.columns.duration')}</TableHead>
                  <TableHead>{t('AgentSchedulesPanel.history.columns.devices')}</TableHead>
                  <TableHead>{t('AgentSchedulesPanel.history.columns.error')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {runs.map((r: AgentScheduleRun) => (
                  <TableRow key={r.id}>
                    <TableCell>
                      {r.status === 'completed' ? (
                        <span className="inline-flex items-center gap-1 text-emerald-600">
                          <CheckCircle2 className="h-3.5 w-3.5" />
                          {t('AgentSchedulesPanel.runStatus.completed')}
                        </span>
                      ) : r.status === 'failed' ? (
                        <span className="inline-flex items-center gap-1 text-destructive">
                          <XCircle className="h-3.5 w-3.5" />
                          {t('AgentSchedulesPanel.runStatus.failed')}
                        </span>
                      ) : (
                        <Badge variant="outline">{r.status}</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-xs">
                      {new Date(r.started_at).toLocaleString()}
                    </TableCell>
                    <TableCell className="text-xs">
                      {r.duration_seconds != null
                        ? `${r.duration_seconds.toFixed(1)}s`
                        : '-'}
                    </TableCell>
                    <TableCell className="text-xs">{r.device_count}</TableCell>
                    <TableCell className="text-xs text-destructive max-w-[200px] truncate">
                      {r.error_message || ''}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

const EMPTY_FORM: FormState = {
  name: '',
  scan_type: 'quick',
  cron: '0 */4 * * *',
  targets: '',
  email_to: '',
  slack_channel: '',
  notify_on_failure: false,
  notify_on_new_devices: 0,
};

export function AgentSchedulesPanel({ siteId }: Props) {
  const { t } = useTranslation('common');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const scanTypes = buildScanTypes(t);
  const cronPresets = buildCronPresets(t);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [historyFor, setHistoryFor] = useState<AgentSchedule | null>(null);

  const { data: schedules = [], isLoading, isError, refetch } = useQuery({
    queryKey: ['agent-schedules', siteId],
    queryFn: async () => {
      const resp = await agentSchedulesApi.list({ site_id: siteId });
      return resp.data;
    },
    enabled: !!siteId,
  });

  const createMutation = useMutation({
    mutationFn: async (data: FormState) => {
      if (!siteId) throw new Error(t('AgentSchedulesPanel.errors.siteRequired'));
      const channels: Record<string, unknown> = {};
      const emails = data.email_to
        .split(/[,;]/)
        .map((s) => s.trim())
        .filter(Boolean);
      if (emails.length > 0) channels.email = { to: emails };
      if (data.slack_channel.trim()) {
        channels.slack = { channel: data.slack_channel.trim() };
      }
      return agentSchedulesApi.create(siteId, {
        name: data.name,
        scan_type: data.scan_type,
        cron: data.cron,
        targets: data.targets
          .split(/[,\n]/)
          .map((t) => t.trim())
          .filter(Boolean),
        enabled: true,
        notification_channels: channels,
        notify_on_failure: data.notify_on_failure,
        notify_on_new_devices: Math.max(0, data.notify_on_new_devices || 0),
      });
    },
    onSuccess: () => {
      toast({ title: t('AgentSchedulesPanel.toasts.created') });
      setDialogOpen(false);
      setForm(EMPTY_FORM);
      queryClient.invalidateQueries({ queryKey: ['agent-schedules'] });
    },
    onError: (err: any) => {
      toast({
        title: t('AgentSchedulesPanel.toasts.createFailed'),
        description: err?.response?.data?.detail || String(err),
        variant: 'destructive',
      });
    },
  });

  const toggleMutation = useMutation({
    mutationFn: async (s: AgentSchedule) =>
      agentSchedulesApi.update(s.id, {
        name: s.name,
        scan_type: s.scan_type,
        cron: s.cron,
        targets: s.targets,
        interface: s.interface,
        enabled: !s.enabled,
        agent_id: s.agent_id,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agent-schedules'] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => agentSchedulesApi.remove(id),
    onSuccess: () => {
      toast({ title: t('AgentSchedulesPanel.toasts.deleted') });
      queryClient.invalidateQueries({ queryKey: ['agent-schedules'] });
    },
  });

  if (!siteId) {
    return (
      <Card>
        <CardContent className="p-6 text-sm text-muted-foreground">
          {t('AgentSchedulesPanel.selectSite')}
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Clock className="h-5 w-5 text-indigo-600" />
            {t('AgentSchedulesPanel.title')}
            <Badge variant="secondary">{schedules.length}</Badge>
          </CardTitle>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => refetch()}>
              <RefreshCw className="h-4 w-4" />
            </Button>
            <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
              <DialogTrigger asChild>
                <Button size="sm">
                  <Plus className="h-4 w-4 mr-1" />
                  {t('AgentSchedulesPanel.actions.newSchedule')}
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>{t('AgentSchedulesPanel.dialog.title')}</DialogTitle>
                </DialogHeader>
                <div className="space-y-3 pt-2">
                  <div>
                    <Label>{t('AgentSchedulesPanel.fields.name')}</Label>
                    <Input
                      placeholder={t('AgentSchedulesPanel.fields.namePlaceholder')}
                      value={form.name}
                      onChange={(e) => setForm({ ...form, name: e.target.value })}
                    />
                  </div>
                  <div>
                    <Label>{t('AgentSchedulesPanel.fields.scanType')}</Label>
                    <Select
                      value={form.scan_type}
                      onValueChange={(v) => setForm({ ...form, scan_type: v })}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {scanTypes.map((s) => (
                          <SelectItem key={s.value} value={s.value}>
                            {s.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label>{t('AgentSchedulesPanel.fields.cron')}</Label>
                    <Select
                      value={form.cron}
                      onValueChange={(v) => setForm({ ...form, cron: v })}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {cronPresets.map((p) => (
                          <SelectItem key={p.value} value={p.value}>
                            {p.label} ({p.value})
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Input
                      className="mt-2"
                      placeholder={t('AgentSchedulesPanel.fields.cronPlaceholder')}
                      value={form.cron}
                      onChange={(e) => setForm({ ...form, cron: e.target.value })}
                    />
                  </div>
                  <div>
                    <Label>{t('AgentSchedulesPanel.fields.targets')}</Label>
                    <Input
                      placeholder="192.168.1.0/24"
                      value={form.targets}
                      onChange={(e) => setForm({ ...form, targets: e.target.value })}
                    />
                  </div>

                  {/* Notifications block, optional, all fields blank by default */}
                  <div className="border-t pt-3 space-y-3">
                    <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
                      {t('AgentSchedulesPanel.notifications.heading')}
                    </div>
                    <div>
                      <Label>{t('AgentSchedulesPanel.notifications.emailRecipients')}</Label>
                      <Input
                        placeholder="ops@example.com, alerts@example.com"
                        value={form.email_to}
                        onChange={(e) => setForm({ ...form, email_to: e.target.value })}
                      />
                    </div>
                    <div>
                      <Label>{t('AgentSchedulesPanel.notifications.slackChannel')}</Label>
                      <Input
                        placeholder="#alerts"
                        value={form.slack_channel}
                        onChange={(e) =>
                          setForm({ ...form, slack_channel: e.target.value })
                        }
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <label className="flex items-center gap-2 text-sm">
                        <input
                          type="checkbox"
                          checked={form.notify_on_failure}
                          onChange={(e) =>
                            setForm({ ...form, notify_on_failure: e.target.checked })
                          }
                        />
                        {t('AgentSchedulesPanel.notifications.notifyOnFailure')}
                      </label>
                      <div>
                        <Label className="text-xs">{t('AgentSchedulesPanel.notifications.alertNewHosts')}</Label>
                        <Input
                          type="number"
                          min={0}
                          value={form.notify_on_new_devices}
                          onChange={(e) =>
                            setForm({
                              ...form,
                              notify_on_new_devices: parseInt(e.target.value, 10) || 0,
                            })
                          }
                        />
                      </div>
                    </div>
                  </div>
                </div>
                <DialogFooter>
                  <Button
                    variant="outline"
                    onClick={() => setDialogOpen(false)}
                  >
                    {t('AgentSchedulesPanel.actions.cancel')}
                  </Button>
                  <Button
                    onClick={() => createMutation.mutate(form)}
                    disabled={!form.name.trim() || createMutation.isPending}
                  >
                    {t('AgentSchedulesPanel.actions.create')}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {isError ? (
          <div className="text-sm text-destructive p-4">
            {t('AgentSchedulesPanel.loadError')}
          </div>
        ) : isLoading ? (
          <div className="text-sm text-muted-foreground p-4">{t('AgentSchedulesPanel.loading')}</div>
        ) : schedules.length === 0 ? (
          <div className="text-sm text-muted-foreground p-4">
            {t('AgentSchedulesPanel.empty')}
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('AgentSchedulesPanel.columns.name')}</TableHead>
                <TableHead>{t('AgentSchedulesPanel.columns.cron')}</TableHead>
                <TableHead>{t('AgentSchedulesPanel.columns.type')}</TableHead>
                <TableHead>{t('AgentSchedulesPanel.columns.targets')}</TableHead>
                <TableHead>{t('AgentSchedulesPanel.columns.lastFired')}</TableHead>
                <TableHead></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {schedules.map((s) => (
                <TableRow key={s.id}>
                  <TableCell className="font-medium">
                    {s.name}
                    {!s.enabled ? (
                      <Badge variant="outline" className="ml-2 text-xs">
                        {t('AgentSchedulesPanel.disabled')}
                      </Badge>
                    ) : null}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{s.cron}</TableCell>
                  <TableCell>{s.scan_type}</TableCell>
                  <TableCell className="text-xs">
                    {(s.targets || []).join(', ') || '-'}
                  </TableCell>
                  <TableCell
                    className="text-xs text-muted-foreground"
                    title={
                      s.last_fired_at
                        ? new Date(s.last_fired_at).toLocaleString()
                        : t('AgentSchedulesPanel.neverFired')
                    }
                  >
                    {_formatRelative(s.last_fired_at, t)}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => setHistoryFor(s)}
                      title={t('AgentSchedulesPanel.actions.viewHistory')}
                    >
                      <History className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => toggleMutation.mutate(s)}
                      title={s.enabled ? t('AgentSchedulesPanel.actions.disable') : t('AgentSchedulesPanel.actions.enable')}
                    >
                      {s.enabled ? (
                        <Pause className="h-4 w-4" />
                      ) : (
                        <Play className="h-4 w-4" />
                      )}
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => {
                        if (confirm(t('AgentSchedulesPanel.confirmDelete', { name: s.name }))) {
                          deleteMutation.mutate(s.id);
                        }
                      }}
                    >
                      <Trash2 className="h-4 w-4 text-destructive" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
      <HistoryDialog
        schedule={historyFor}
        open={!!historyFor}
        onOpenChange={(o) => !o && setHistoryFor(null)}
      />
    </Card>
  );
}
