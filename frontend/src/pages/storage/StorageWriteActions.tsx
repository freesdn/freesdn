// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Storage write actions — snapshot, dataset create, scrub, snapshot delete.
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
import { z } from 'zod';
import { useQueryClient } from '@tanstack/react-query';
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

// A ZFS snapshot/dataset name segment: TrueNAS accepts a conservative set, and
// the backend re-validates -- this catches the obvious typo before a round trip.
const ZFS_NAME = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const zfsName = (label: string) =>
  z
    .string()
    .min(1, `${label} is required`)
    .max(200)
    .regex(ZFS_NAME, `${label} may use letters, numbers, and . _ - :`);

/** Suggest a sortable, human snapshot name. Local time is fine for a label. */
function suggestSnapshotName(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, '0');
  return `freesdn-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
}

function useStageStorage(controllerId: string, onStaged: () => void) {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  return async (
    params: Omit<Parameters<typeof stageStorageChange>[0], 'controllerId'>,
    successMessage: string,
  ) => {
    try {
      await stageStorageChange({ ...params, controllerId });
      toast({ title: 'Change staged', description: successMessage });
      // The drawer/badge share this key; nudge both to show the new row.
      queryClient.invalidateQueries({ queryKey: pendingChangesQueryKey('storage', controllerId) });
      onStaged();
    } catch (err) {
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ||
        (err as { message?: string })?.message ||
        'Could not stage the change.';
      toast({ title: 'Could not stage the change', description: detail, variant: 'destructive' });
      throw err; // keep the FormDialog open on failure
    }
  };
}

// ── snapshot a dataset ──────────────────────────────────────────────────

const snapshotSchema = z.object({
  name: zfsName('Snapshot name'),
  recursive: z.boolean(),
});

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
  const stage = useStageStorage(controllerId, onStaged);
  if (!dataset) return null;

  return (
    <FormDialog<z.infer<typeof snapshotSchema>>
      open={open}
      onOpenChange={onOpenChange}
      title="Take a snapshot"
      description={`A point-in-time snapshot of ${dataset.name}. Additive — it creates a restore point and changes nothing on disk.`}
      schema={snapshotSchema}
      defaultValues={{ name: suggestSnapshotName(), recursive: false }}
      submitLabel="Stage snapshot"
      onSubmit={async (values) => {
        await stage(
          {
            feature: 'storage.snapshot',
            operation: 'create',
            payload: { dataset: dataset.name, name: values.name, recursive: values.recursive },
          },
          `Snapshot ${dataset.name}@${values.name} staged for review.`,
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
                <FormLabel>Snapshot name</FormLabel>
                <FormControl>
                  <Input placeholder="freesdn-20260824-1830" {...field} />
                </FormControl>
                <FormDescription>
                  Stored as <span className="font-mono">{dataset.name}@{field.value || 'name'}</span>
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
                  <input
                    type="checkbox"
                    checked={field.value}
                    onChange={(e) => field.onChange(e.target.checked)}
                    className="mt-0.5 h-4 w-4 rounded border-input"
                  />
                </FormControl>
                <div className="space-y-0.5">
                  <FormLabel className="cursor-pointer">Include child datasets</FormLabel>
                  <FormDescription>
                    Snapshot every dataset nested under this one, atomically.
                  </FormDescription>
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

const datasetSchema = z.object({
  name: zfsName('Dataset name'),
  comments: z.string().max(1024),
});

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
  const stage = useStageStorage(controllerId, onStaged);

  return (
    <FormDialog<z.infer<typeof datasetSchema>>
      open={open}
      onOpenChange={onOpenChange}
      title="Create a dataset"
      description="A new ZFS dataset. Give it as a pool-relative path, e.g. backups or media/photos — not a /mnt path."
      schema={datasetSchema}
      defaultValues={{ name: '', comments: '' }}
      submitLabel="Stage dataset"
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
          `Dataset ${full} staged for review.`,
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
                <FormLabel>Dataset path</FormLabel>
                <FormControl>
                  <Input placeholder="backups" {...field} />
                </FormControl>
                <FormDescription>
                  Created as{' '}
                  <span className="font-mono">
                    {field.value?.startsWith(`${poolName}/`) ? field.value : `${poolName}/${field.value || 'name'}`}
                  </span>
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
                <FormLabel>Comment (optional)</FormLabel>
                <FormControl>
                  <Input placeholder="What this dataset is for" {...field} />
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
  const stage = useStageStorage(controllerId, onStaged);
  if (!pool) return null;

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Start a scrub on {pool.name}?</AlertDialogTitle>
          <AlertDialogDescription>
            A scrub verifies every block in the pool against its checksums and repairs what it
            can. It is safe and read-heavy — it runs in the background for a while and the
            dashboard shows its progress. This stages the request for you to apply.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction
            onClick={async () => {
              await stage(
                { feature: 'storage.scrub', operation: 'start', payload: { pool: pool.name } },
                `Scrub of ${pool.name} staged for review.`,
              );
            }}
          >
            <Play className="mr-2 h-4 w-4" /> Stage scrub
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
  const stage = useStageStorage(controllerId, onStaged);
  if (!snapshot) return null;

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete this snapshot?</AlertDialogTitle>
          <AlertDialogDescription>
            <span className="font-mono">{snapshot.id}</span> will be destroyed when you apply the
            change. The dataset and its live data are untouched — only this restore point is
            removed, and only after you apply.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            onClick={async () => {
              await stage(
                {
                  feature: 'storage.snapshot',
                  operation: 'delete',
                  payload: { snapshot_id: snapshot.id },
                },
                `Deletion of ${snapshot.id} staged for review.`,
              );
            }}
          >
            <Trash2 className="mr-2 h-4 w-4" /> Stage delete
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

export const StorageActionIcons = { Camera, Database, Play, Trash2 };
