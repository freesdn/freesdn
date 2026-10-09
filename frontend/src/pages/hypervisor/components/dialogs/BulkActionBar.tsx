// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Hypervisor Module - Bulk Action Bar
 *
 * Floating toolbar shown when VMs/CTs are selected for bulk operations.
 * The Migrate dialog is built on the canonical FormDialog primitive
 * (target node + online checkbox). The Results dialog is read-only and
 * stays as a plain Dialog.
 */
import { useState, useRef } from 'react';
import { newHypervisorRequestId } from '@/lib/api/hypervisor';
import { useTranslation } from 'react-i18next';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';
import {
  Play, Square, Power, RotateCcw, Trash2, ArrowRightLeft,
  Loader2, CheckCircle, XCircle, X,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import { FormDialog } from '@/components/ui/form-dialog';
import { DeleteGuestDialog } from './DeleteGuestDialog';
import { FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Checkbox } from '@/components/ui/checkbox';
import { useToast } from '@/hooks/use-toast';
import { hypervisorApi } from '@/lib/api';
import type { HypervisorNode, BulkActionResult } from '@/lib/api';
import type { BulkTarget } from '../types';

interface BulkActionBarProps {
  controllerId: string;
  selectedTargets: BulkTarget[];
  nodes: HypervisorNode[];
  onClear: () => void;
}

interface MigrateFormValues {
  target_node: string;
  online: boolean;
  restart: boolean;
}

export function BulkActionBar({ controllerId, selectedTargets, nodes, onClear }: BulkActionBarProps) {
  const { t } = useTranslation('hypervisor');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const count = selectedTargets.length;

  const localizedMigrateSchema = z.object({
    target_node: z.string().min(1, t('BulkActionBar.migrate.targetNodeRequired')),
    online: z.boolean(),
    restart: z.boolean(),
  });

  const [migrateOpen, setMigrateOpen] = useState(false);
  // Keep IDs through response loss and manual resubmission of this dialog.
  const migrationIds = useRef(new Map<string, string>());
  const [results, setResults] = useState<BulkActionResult[] | null>(null);
  // Bulk-delete is irreversible; gate behind the typed-confirm dialog
  // instead of native confirm().
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);

  const actionMutation = useMutation({
    retry: false, // Inspect durable receipts before submitting another intent.
    mutationFn: (action: string) =>
      hypervisorApi.bulkAction(controllerId, {
        targets: selectedTargets.map((t) => ({ node: t.node, vm_type: t.vm_type, vmid: t.vmid })),
        action,
      }),
    onSuccess: (resp) => {
      const data = resp.data || [];
      setResults(data);
      const succeeded = data.filter((r) => r.success).length;
      const failed = data.filter((r) => !r.success).length;
      toast({
        title: t('BulkActionBar.toast.actionCompleteTitle'),
        description: t('BulkActionBar.toast.actionCompleteDescription', { succeeded, failed }),
        variant: failed > 0 ? 'destructive' : undefined,
      });
      queryClient.invalidateQueries({ queryKey: ['hypervisor'] });
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      toast({ title: t('BulkActionBar.toast.actionFailedTitle'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  const migrateMutation = useMutation({
    retry: false,
    mutationFn: (values: MigrateFormValues) =>
      hypervisorApi.bulkMigrate(controllerId, {
        targets: selectedTargets.map((target) => {
          const key = `${controllerId}:${target.vm_type}:${target.vmid}`;
          const request_id = migrationIds.current.get(key) ?? newHypervisorRequestId();
          migrationIds.current.set(key, request_id);
          return { node: target.node, vm_type: target.vm_type, vmid: target.vmid, request_id };
        }),
        target_node: values.target_node,
        online: values.online,
        restart: values.restart,
      }),
    onSuccess: (resp) => {
      const data = resp.data || [];
      setResults(data);
      const succeeded = data.filter((r) => r.success).length;
      const failed = data.length - succeeded;
      toast({
        title: t('BulkActionBar.toast.actionCompleteTitle'),
        description: t('BulkActionBar.toast.actionCompleteDescription', { succeeded, failed }),
        variant: failed > 0 ? 'destructive' : undefined,
      });
      setMigrateOpen(false);
      queryClient.invalidateQueries({ queryKey: ['hypervisor'] });
    },
    onError: () => {
      toast({ title: t('HypervisorPage.toast.actionNeedsReview'), description: t('HypervisorPage.toast.operationResponseLost'), variant: 'destructive' });
    },
  });

  if (count === 0) return null;

  const isPending = actionMutation.isPending || migrateMutation.isPending;

  return (
    <>
      {/* Floating bar */}
      <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 bg-background border rounded-lg shadow-lg px-4 py-3 flex items-center gap-3">
        <Badge variant="secondary" className="text-sm">
          {t('BulkActionBar.selectedCount', { count })}
        </Badge>

        <div className="h-6 border-l" />

        <Button size="sm" variant="outline" disabled={isPending} onClick={() => {
          if (!confirm(t('BulkActionBar.confirm.start', { count }))) return;
          actionMutation.mutate('start');
        }}>
          <Play className="h-3.5 w-3.5 mr-1 text-green-500" /> {t('BulkActionBar.actions.start')}
        </Button>
        <Button size="sm" variant="outline" disabled={isPending} onClick={() => {
          if (!confirm(t('BulkActionBar.confirm.shutdown', { count }))) return;
          actionMutation.mutate('shutdown');
        }}>
          <Power className="h-3.5 w-3.5 mr-1 text-amber-500" /> {t('BulkActionBar.actions.shutdown')}
        </Button>
        <Button size="sm" variant="outline" disabled={isPending} onClick={() => {
          if (!confirm(t('BulkActionBar.confirm.stop', { count }))) return;
          actionMutation.mutate('stop');
        }}>
          <Square className="h-3.5 w-3.5 mr-1 text-red-500" /> {t('BulkActionBar.actions.forceStop')}
        </Button>
        <Button size="sm" variant="outline" disabled={isPending} onClick={() => {
          if (!confirm(t('BulkActionBar.confirm.reboot', { count }))) return;
          actionMutation.mutate('reboot');
        }}>
          <RotateCcw className="h-3.5 w-3.5 mr-1 text-blue-500" /> {t('BulkActionBar.actions.reboot')}
        </Button>
        <Button size="sm" variant="outline" disabled={isPending} onClick={() => { migrationIds.current.clear(); setMigrateOpen(true); }}>
          <ArrowRightLeft className="h-3.5 w-3.5 mr-1" /> {t('BulkActionBar.actions.migrate')}
        </Button>
        <Button
          size="sm"
          variant="outline"
          disabled={isPending}
          className="text-destructive"
          onClick={() => setDeleteConfirmOpen(true)}
        >
          <Trash2 className="h-3.5 w-3.5 mr-1" /> {t('BulkActionBar.actions.delete')}
        </Button>

        {isPending && <Loader2 className="h-4 w-4 animate-spin" />}

        <div className="h-6 border-l" />

        <Button size="sm" variant="ghost" onClick={onClear}>
          <X className="h-3.5 w-3.5" />
        </Button>
      </div>

      {deleteConfirmOpen && <DeleteGuestDialog
        controllerId={controllerId}
        targets={selectedTargets.map((target) => ({ node: target.node, vm_type: target.vm_type, vmid: target.vmid }))}
        onClose={() => setDeleteConfirmOpen(false)}
      />}

      {/* Results dialog */}
      <Dialog open={!!results} onOpenChange={(o) => { if (!o) { setResults(null); onClear(); } }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('BulkActionBar.results.title')}</DialogTitle>
          </DialogHeader>
          <div className="space-y-2 max-h-[50vh] overflow-y-auto">
            {results?.map((r) => (
              <div key={`${r.node}-${r.vmid}`} className="flex items-center gap-2 text-sm">
                {r.success ? (
                  <CheckCircle className="h-4 w-4 text-green-500 shrink-0" />
                ) : (
                  <XCircle className="h-4 w-4 text-red-500 shrink-0" />
                )}
                <span className="font-mono text-xs">{r.vmid}</span>
                <span className="text-muted-foreground text-xs">{r.node}</span>
                {r.change_id && <span className="text-xs text-muted-foreground" title={r.change_id}>{t('BulkActionBar.results.tracked')}</span>}
                {r.error && <span className="text-xs text-destructive truncate">{r.error}</span>}
              </div>
            ))}
          </div>
          <DialogFooter>
            <Button onClick={() => { setResults(null); onClear(); }}>{t('BulkActionBar.results.close')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Migrate dialog */}
      <FormDialog<MigrateFormValues>
        open={migrateOpen}
        onOpenChange={setMigrateOpen}
        title={t('BulkActionBar.migrate.title', { count })}
        description={t('BulkActionBar.migrate.description')}
        schema={localizedMigrateSchema}
        defaultValues={{ target_node: '', online: true, restart: false }}
        submitLabel={t('BulkActionBar.migrate.submit', { count })}
        contentClassName="sm:max-w-md"
        onSubmit={async (values) => {
          await migrateMutation.mutateAsync(values);
        }}
      >
        {(form) => (
          <>
            <FormField
              control={form.control}
              name="target_node"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('BulkActionBar.migrate.targetNodeLabel')}</FormLabel>
                  <Select value={field.value} onValueChange={field.onChange}>
                    <FormControl>
                      <SelectTrigger><SelectValue placeholder={t('BulkActionBar.migrate.targetNodePlaceholder')} /></SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {nodes.filter((n) => n.status === 'online').map((n) => (
                        <SelectItem key={n.node} value={n.node}>{n.node}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="online"
              render={({ field }) => (
                <FormItem>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <FormControl>
                      <Checkbox checked={field.value} onCheckedChange={(v) => field.onChange(!!v)} />
                    </FormControl>
                    <span className="text-sm">{t('BulkActionBar.migrate.onlineLabel')}</span>
                  </label>
                  <FormMessage />
                </FormItem>
              )}
            />
            {selectedTargets.some((target) => target.vm_type === 'lxc') && <>
              <FormField
                control={form.control}
                name="restart"
                render={({ field }) => (
                  <FormItem>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <FormControl><Checkbox checked={field.value} onCheckedChange={(v) => field.onChange(!!v)} /></FormControl>
                      <span className="text-sm">{t('HypervisorPage.migrateDialog.restartMigration')}</span>
                    </label>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <p className="text-sm text-amber-600">{t('HypervisorPage.migrateDialog.restartWarning')}</p>
            </>}
          </>
        )}
      </FormDialog>
    </>
  );
}
