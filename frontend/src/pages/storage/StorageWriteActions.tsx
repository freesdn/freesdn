// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Storage write actions: snapshot, dataset create, scrub, snapshot delete.
 *
 * Every one STAGES a change (never touches the appliance directly) via
 * ``POST /gateway-storage/{id}/changes/{feature}``, and the operator applies it
 * from the Pending Changes drawer, which rides the ADAPTER_READ_ONLY + force
 * dual-gate. This mirrors how the gateway pages stage writes; storage is a
 * first-class Pending Changes vendor.
 *
 * Writes are WS-only (SCALE 25.04+). On a legacy REST appliance the actions are
 * disabled with an explanation rather than hidden, so an operator understands
 * WHY they cannot act rather than wondering where the buttons went.
 */
import { useMemo } from 'react';
import { z } from 'zod';
import { useQueryClient } from '@tanstack/react-query';
import { Trans, useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { Camera, Database, Play, Trash2 } from 'lucide-react';
import { FormDialog } from '@/components/ui/form-dialog';
import {
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/checkbox';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { useToast } from '@/hooks/use-toast';
import { stageStorageChange } from '@/lib/api';
import { pendingChangesQueryKey } from '@/components/gateways/PendingChangesDrawer';
import type { StorageDataset, StoragePool, StorageSnapshot } from '@/lib/api';
import { getApiErrorMessage } from '@/lib/api/errors';

// A ZFS snapshot/dataset name segment: TrueNAS accepts a conservative set, and
// the backend re-validates -- this catches the obvious typo before a round trip.
const ZFS_NAME = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const zfsName = (t: TFunction, label: string) =>
  z
    .string()
    .min(1, t('validation.required', { label }))
    .max(200)
    .regex(ZFS_NAME, t('validation.zfsName', { label }));

/** Suggest a sortable, human snapshot name. Local time is fine for a label. */
function suggestSnapshotName(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, '0');
  return `freesdn-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
}

function useStageStorage(controllerId: string, onStaged: () => void) {
  const { t } = useTranslation('storage');
  const { toast } = useToast();
  const queryClient = useQueryClient();

  return async (
    params: Omit<Parameters<typeof stageStorageChange>[0], 'controllerId'>,
    successMessage: string,
  ) => {
    try {
      await stageStorageChange({ ...params, controllerId });
      toast({ title: t('stage.staged'), description: successMessage });
      // The drawer/badge share this key; nudge both to show the new row.
      queryClient.invalidateQueries({ queryKey: pendingChangesQueryKey('storage', controllerId) });
      onStaged();
    } catch (err) {
      const detail = getApiErrorMessage(err, t('stage.failedDetail'));
      toast({ title: t('stage.failed'), description: detail, variant: 'destructive' });
      throw err; // keep the FormDialog open on failure
    }
  };
}

// ── snapshot a dataset ──────────────────────────────────────────────────

const snapshotSchema = (t: TFunction) =>
  z.object({
    name: zfsName(t, t('snapshotDialog.nameLabel')),
    recursive: z.boolean(),
  });
type SnapshotValues = z.infer<ReturnType<typeof snapshotSchema>>;

export function SnapshotDatasetDialog({
  controllerId,
  dataset,
  open,
  onOpenChange,
  onStaged,
}: {
  controllerId: string;
  dataset: StorageDataset | null;
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onStaged: () => void;
}) {
  const { t } = useTranslation('storage');
  const schema = useMemo(() => snapshotSchema(t), [t]);
  const stage = useStageStorage(controllerId, onStaged);
  if (!dataset) return null;

  return (
    <FormDialog<SnapshotValues>
      open={open}
      onOpenChange={onOpenChange}
      title={t('snapshotDialog.title')}
      description={t('snapshotDialog.description', { dataset: dataset.name })}
      schema={schema}
      defaultValues={{ name: suggestSnapshotName(), recursive: false }}
      submitLabel={t('snapshotDialog.submit')}
      onSubmit={async (values) => {
        await stage(
          {
            feature: 'storage.snapshot',
            operation: 'create',
            payload: { dataset: dataset.name, name: values.name, recursive: values.recursive },
          },
          t('snapshotDialog.staged', { snapshot: `${dataset.name}@${values.name}` }),
        );
      }}
    >
      {(form) => (
        <>
          <FormField
            control={form.control}
            name="name"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('snapshotDialog.nameLabel')}</FormLabel>
                <FormControl>
                  <Input placeholder="freesdn-20260824-1830" {...field} />
                </FormControl>
                <FormDescription>
                  <Trans
                    i18nKey="snapshotDialog.storedAs"
                    t={t}
                    values={{ snapshot: `${dataset.name}@${field.value || t('snapshotDialog.namePlaceholder')}` }}
                    components={{ mono: <span className="font-mono" /> }}
                  />
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="recursive"
            render={({ field }) => (
              <FormItem className="flex flex-row items-start gap-3 rounded-lg border p-3">
                <FormControl>
                  {/* The shared Checkbox: a native box is a bright white square in the dark theme. */}
                  <Checkbox
                    checked={field.value}
                    onCheckedChange={(checked) => field.onChange(checked === true)}
                    className="mt-0.5"
                  />
                </FormControl>
                <div className="space-y-0.5">
                  <FormLabel className="cursor-pointer">{t('snapshotDialog.recursiveLabel')}</FormLabel>
                  <FormDescription>{t('snapshotDialog.recursiveDescription')}</FormDescription>
                </div>
              </FormItem>
            )}
          />
        </>
      )}
    </FormDialog>
  );
}

// ── create a dataset ────────────────────────────────────────────────────

const datasetSchema = (t: TFunction) =>
  z.object({
    name: zfsName(t, t('datasetDialog.nameLabel')),
    comments: z.string().max(1024),
  });
type DatasetValues = z.infer<ReturnType<typeof datasetSchema>>;

export function CreateDatasetDialog({
  controllerId,
  poolName,
  open,
  onOpenChange,
  onStaged,
}: {
  controllerId: string;
  poolName: string;
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onStaged: () => void;
}) {
  const { t } = useTranslation('storage');
  const schema = useMemo(() => datasetSchema(t), [t]);
  const stage = useStageStorage(controllerId, onStaged);

  return (
    <FormDialog<DatasetValues>
      open={open}
      onOpenChange={onOpenChange}
      title={t('datasetDialog.title')}
      description={t('datasetDialog.description')}
      schema={schema}
      defaultValues={{ name: '', comments: '' }}
      submitLabel={t('datasetDialog.submit')}
      onSubmit={async (values) => {
        // The pool prefixes a bare name so the operator does not have to repeat
        // it; a name that already starts with the pool is left as-is.
        const full = values.name.startsWith(`${poolName}/`) ? values.name : `${poolName}/${values.name}`;
        await stage(
          {
            feature: 'storage.dataset',
            operation: 'create',
            payload: { name: full, comments: values.comments || undefined },
          },
          t('datasetDialog.staged', { dataset: full }),
        );
      }}
    >
      {(form) => (
        <>
          <FormField
            control={form.control}
            name="name"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('datasetDialog.pathLabel')}</FormLabel>
                <FormControl>
                  <Input placeholder="backups" {...field} />
                </FormControl>
                <FormDescription>
                  <Trans
                    i18nKey="datasetDialog.createdAs"
                    t={t}
                    values={{
                      dataset: field.value?.startsWith(`${poolName}/`)
                        ? field.value
                        : `${poolName}/${field.value || t('datasetDialog.namePlaceholder')}`,
                    }}
                    components={{ mono: <span className="font-mono" /> }}
                  />
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="comments"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('datasetDialog.commentLabel')}</FormLabel>
                <FormControl>
                  <Input placeholder={t('datasetDialog.commentPlaceholder')} {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </>
      )}
    </FormDialog>
  );
}

// ── start a scrub (confirm, no form) ────────────────────────────────────

export function ScrubPoolDialog({
  controllerId,
  pool,
  open,
  onOpenChange,
  onStaged,
}: {
  controllerId: string;
  pool: StoragePool | null;
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onStaged: () => void;
}) {
  const { t } = useTranslation('storage');
  const stage = useStageStorage(controllerId, onStaged);
  if (!pool) return null;

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{t('scrubDialog.title', { pool: pool.name })}</AlertDialogTitle>
          <AlertDialogDescription>{t('scrubDialog.description')}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>{t('dialog.cancel')}</AlertDialogCancel>
          <AlertDialogAction
            onClick={async () => {
              await stage(
                { feature: 'storage.scrub', operation: 'start', payload: { pool: pool.name } },
                t('scrubDialog.staged', { pool: pool.name }),
              );
            }}
          >
            <Play className="mr-2 h-4 w-4" /> {t('scrubDialog.submit')}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

// ── delete a snapshot (destructive confirm) ─────────────────────────────

export function DeleteSnapshotDialog({
  controllerId,
  snapshot,
  open,
  onOpenChange,
  onStaged,
}: {
  controllerId: string;
  snapshot: StorageSnapshot | null;
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onStaged: () => void;
}) {
  const { t } = useTranslation('storage');
  const stage = useStageStorage(controllerId, onStaged);
  if (!snapshot) return null;

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{t('deleteSnapshotDialog.title')}</AlertDialogTitle>
          <AlertDialogDescription>
            <Trans
              i18nKey="deleteSnapshotDialog.description"
              t={t}
              values={{ snapshot: snapshot.id }}
              components={{ mono: <span className="font-mono" /> }}
            />
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>{t('dialog.cancel')}</AlertDialogCancel>
          <AlertDialogAction
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            onClick={async () => {
              await stage(
                {
                  feature: 'storage.snapshot',
                  operation: 'delete',
                  payload: { snapshot_id: snapshot.id },
                },
                t('deleteSnapshotDialog.staged', { snapshot: snapshot.id }),
              );
            }}
          >
            <Trash2 className="mr-2 h-4 w-4" /> {t('deleteSnapshotDialog.submit')}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

export const StorageActionIcons = { Camera, Database, Play, Trash2 };
