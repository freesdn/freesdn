// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Hypervisor Module - Backup Job Create/Edit Dialog
 *
 * Built on the canonical FormDialog primitive (zod + react-hook-form).
 * Day/time are stored as separate fields and joined into the API
 * `schedule` string on submit; the same applies to the "All nodes" sentinel.
 */
import { useMemo } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { z } from 'zod';
import { FormDialog } from '@/components/ui/form-dialog';
import { FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/checkbox';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import { hypervisorApi } from '@/lib/api';
import type { HypervisorBackupJob, HypervisorNode } from '@/lib/api';

interface BackupJobDialogProps {
  open: boolean;
  onClose: () => void;
  controllerId: string;
  nodes: HypervisorNode[];
  editJob?: HypervisorBackupJob | null;
}

// Day option values are stable identifiers; labels are translated at render.
const DAYS = [
  { value: 'mon', labelKey: 'days.mon' },
  { value: 'tue', labelKey: 'days.tue' },
  { value: 'wed', labelKey: 'days.wed' },
  { value: 'thu', labelKey: 'days.thu' },
  { value: 'fri', labelKey: 'days.fri' },
  { value: 'sat', labelKey: 'days.sat' },
  { value: 'sun', labelKey: 'days.sun' },
];

// Sentinels · Radix <SelectItem> rejects empty-string values.
const ANY_DAY = '__any_day__';
const ALL_NODES = '__all_nodes__';

const buildSchema = (t: TFunction) => z.object({
  scheduleDay: z.string().min(1),
  scheduleTime: z.string().min(1, t('BackupJobDialog.validation.timeRequired')),
  storage: z.string().min(1, t('BackupJobDialog.validation.storageRequired')),
  vmid: z.string(),
  node: z.string().min(1),
  mode: z.string().min(1),
  compress: z.string().min(1),
  enabled: z.boolean(),
  mailto: z.string(),
});
type BackupJobFormValues = z.infer<ReturnType<typeof buildSchema>>;

export function BackupJobDialog({ open, onClose, controllerId, nodes, editJob }: BackupJobDialogProps) {
  const { t } = useTranslation('hypervisor');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const isEdit = !!editJob;

  const schema = useMemo(() => buildSchema(t), [t]);

  // Derive default values from `editJob` (parsing schedule into day + time).
  const defaultValues = useMemo<BackupJobFormValues>(() => {
    if (editJob) {
      const parts = editJob.schedule.split(' ');
      let day = ANY_DAY;
      let time = editJob.schedule;
      if (parts.length === 2) {
        day = parts[0];
        time = parts[1];
      }
      return {
        scheduleDay: day,
        scheduleTime: time,
        storage: editJob.storage,
        vmid: editJob.vmid || '',
        node: editJob.node || ALL_NODES,
        mode: editJob.mode,
        compress: editJob.compress,
        enabled: editJob.enabled,
        mailto: editJob.mailto || '',
      };
    }
    return {
      scheduleDay: 'sat',
      scheduleTime: '02:00',
      storage: 'local',
      vmid: '',
      node: ALL_NODES,
      mode: 'snapshot',
      compress: 'zstd',
      enabled: true,
      mailto: '',
    };
  }, [editJob]);

  const buildPayload = (values: BackupJobFormValues) => {
    const schedule = values.scheduleDay && values.scheduleDay !== ANY_DAY
      ? `${values.scheduleDay} ${values.scheduleTime}`
      : values.scheduleTime;
    const nodeForApi = values.node && values.node !== ALL_NODES ? values.node : undefined;
    return {
      storage: values.storage,
      schedule,
      vmid: values.vmid || undefined,
      mode: values.mode,
      compress: values.compress,
      node: nodeForApi,
      enabled: values.enabled,
      mailto: values.mailto || undefined,
    };
  };

  const createMutation = useMutation({
    mutationFn: (values: BackupJobFormValues) =>
      hypervisorApi.createBackupJob(controllerId, buildPayload(values)),
    onSuccess: () => {
      toast({ title: t('BackupJobDialog.toasts.created') });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'backup'] });
      onClose();
    },
  });

  const updateMutation = useMutation({
    mutationFn: (values: BackupJobFormValues) => {
      if (!editJob) throw new Error('No job');
      return hypervisorApi.updateBackupJob(controllerId, editJob.id, buildPayload(values));
    },
    onSuccess: () => {
      toast({ title: t('BackupJobDialog.toasts.updated') });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'backup'] });
      onClose();
    },
  });

  return (
    <FormDialog<BackupJobFormValues>
      open={open}
      onOpenChange={(o) => { if (!o) onClose(); }}
      title={isEdit ? t('BackupJobDialog.title.edit') : t('BackupJobDialog.title.create')}
      description={isEdit ? t('BackupJobDialog.description.edit', { id: editJob?.id }) : t('BackupJobDialog.description.create')}
      schema={schema}
      defaultValues={defaultValues}
      submitLabel={isEdit ? t('BackupJobDialog.submit.update') : t('BackupJobDialog.submit.create')}
      contentClassName="sm:max-w-lg"
      onSubmit={async (values) => {
        if (isEdit) {
          await updateMutation.mutateAsync(values);
        } else {
          await createMutation.mutateAsync(values);
        }
      }}
    >
      {(form) => (
        <div className="space-y-4 max-h-[60vh] overflow-y-auto pr-1">
          {/* Schedule */}
          <div className="grid grid-cols-2 gap-4">
            <FormField
              control={form.control}
              name="scheduleDay"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('BackupJobDialog.fields.day.label')}</FormLabel>
                  <Select value={field.value} onValueChange={field.onChange}>
                    <FormControl>
                      <SelectTrigger><SelectValue placeholder={t('BackupJobDialog.fields.day.placeholder')} /></SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value={ANY_DAY}>{t('BackupJobDialog.fields.day.everyDay')}</SelectItem>
                      {DAYS.map((d) => (
                        <SelectItem key={d.value} value={d.value}>{t(`BackupJobDialog.${d.labelKey}`)}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="scheduleTime"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('BackupJobDialog.fields.time.label')}</FormLabel>
                  <FormControl>
                    <Input type="time" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>

          {/* Storage */}
          <FormField
            control={form.control}
            name="storage"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('BackupJobDialog.fields.storage.label')}</FormLabel>
                <FormControl>
                  <Input placeholder="local" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          {/* VMIDs */}
          <FormField
            control={form.control}
            name="vmid"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('BackupJobDialog.fields.vmid.label')}</FormLabel>
                <FormControl>
                  <Input placeholder={t('BackupJobDialog.fields.vmid.placeholder')} {...field} />
                </FormControl>
                <FormDescription>{t('BackupJobDialog.fields.vmid.description')}</FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />

          {/* Node */}
          <FormField
            control={form.control}
            name="node"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('BackupJobDialog.fields.node.label')}</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger><SelectValue placeholder={t('BackupJobDialog.fields.node.allNodes')} /></SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    <SelectItem value={ALL_NODES}>{t('BackupJobDialog.fields.node.allNodes')}</SelectItem>
                    {nodes.map((n) => (
                      <SelectItem key={n.node} value={n.node}>{n.node}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />

          {/* Mode & Compress */}
          <div className="grid grid-cols-2 gap-4">
            <FormField
              control={form.control}
              name="mode"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('BackupJobDialog.fields.mode.label')}</FormLabel>
                  <Select value={field.value} onValueChange={field.onChange}>
                    <FormControl>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="snapshot">{t('BackupJobDialog.fields.mode.snapshot')}</SelectItem>
                      <SelectItem value="suspend">{t('BackupJobDialog.fields.mode.suspend')}</SelectItem>
                      <SelectItem value="stop">{t('BackupJobDialog.fields.mode.stop')}</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="compress"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('BackupJobDialog.fields.compress.label')}</FormLabel>
                  <Select value={field.value} onValueChange={field.onChange}>
                    <FormControl>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="zstd">ZSTD</SelectItem>
                      <SelectItem value="lzo">LZO</SelectItem>
                      <SelectItem value="gzip">GZIP</SelectItem>
                      <SelectItem value="none">{t('BackupJobDialog.fields.compress.none')}</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>

          {/* Email */}
          <FormField
            control={form.control}
            name="mailto"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('BackupJobDialog.fields.mailto.label')}</FormLabel>
                <FormControl>
                  <Input type="email" placeholder="admin@example.com" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          {/* Enabled */}
          <FormField
            control={form.control}
            name="enabled"
            render={({ field }) => (
              <FormItem>
                <label className="flex items-center gap-2 cursor-pointer">
                  <FormControl>
                    <Checkbox checked={field.value} onCheckedChange={(v) => field.onChange(!!v)} />
                  </FormControl>
                  <span className="text-sm">{t('BackupJobDialog.fields.enabled.label')}</span>
                </label>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>
      )}
    </FormDialog>
  );
}
