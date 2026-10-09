// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useEffect, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { hypervisorApi, type BulkVMTarget, type BulkActionResult } from '@/lib/api';
import { newHypervisorRequestId, reviewedGuestDigest } from '@/lib/api/hypervisor';
import { useUIStore } from '@/stores';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

type ReviewedTarget = BulkVMTarget & { request_id: string; expected_digest: string; summary: string };

/** Mount once per explicit review. Selection, refresh and retries cannot change its intent. */
export function DeleteGuestDialog({ controllerId, targets, onClose }: {
  controllerId: string; targets: BulkVMTarget[]; onClose: () => void;
}) {
  const { t } = useTranslation('hypervisor');
  const queryClient = useQueryClient();
  const readOnly = useUIStore((s) => s.readOnlyMode);
  const [intent] = useState(() => ({ controllerId, targets: targets.map((target) => ({
    node: target.node, vm_type: target.vm_type, vmid: target.vmid, request_id: newHypervisorRequestId(),
  })) }));
  const [review, setReview] = useState<ReviewedTarget[] | null>(null);
  const [reviewFailed, setReviewFailed] = useState(false);
  const [typed, setTyped] = useState('');
  const [receipts, setReceipts] = useState<BulkActionResult[] | null>(null);
  const controllerChanged = controllerId !== intent.controllerId;
  useEffect(() => {
    let cancelled = false;
    Promise.all(intent.targets.map(async (target) => {
      const response = await hypervisorApi.getVMConfig(intent.controllerId, target.node, target.vm_type, target.vmid);
      const config = response.data;
      const digest = reviewedGuestDigest(config);
      if (!digest || config.lock || ![undefined, 0, false, '0'].some((value) => value === config.protection)) throw new Error('Review unavailable');
      // Show relevant identity and disks without copying password/cloud-init fields.
      const identity = String(config.name ?? config.hostname ?? target.vmid);
      const disks = Object.entries(config).filter(([key]) => /^(scsi|virtio|ide|sata|mp)\d+$|^rootfs$/.test(key))
        .map(([key, value]) => `${key}: ${String(value)}`).join('\n');
      return { ...target, expected_digest: digest, summary: `${identity}\n${disks}` };
    })).then((value) => { if (!cancelled) setReview(value); })
      .catch(() => { if (!cancelled) setReviewFailed(true); });
    return () => { cancelled = true; };
  }, [intent]);
  const mutation = useMutation({
    retry: false,
    mutationFn: async () => {
      if (!review || controllerChanged || readOnly || typed !== 'DELETE') throw new Error('Deletion not reviewed');
      const payload = review.map(({ node, vm_type, vmid, request_id, expected_digest }) => ({ node, vm_type, vmid, request_id, expected_digest }));
      if (payload.length === 1) {
        const target = payload[0];
        const { data } = await hypervisorApi.deleteVM(intent.controllerId, target.node, target.vm_type, target.vmid, {
          request_id: target.request_id, expected_digest: target.expected_digest,
        });
        return [{ ...data, node: target.node, success: data.status === 'applied' }];
      }
      return (await hypervisorApi.bulkAction(intent.controllerId, { action: 'delete', targets: payload })).data;
    },
    onSuccess: (data) => { setReceipts(data); queryClient.invalidateQueries({ queryKey: ['hypervisor'] }); },
  });
  return <Dialog open onOpenChange={(open) => { if (!open && !mutation.isPending) onClose(); }}>
    <DialogContent className="sm:max-w-xl">
      <DialogHeader>
        <DialogTitle>{t('DeleteGuestDialog.title')}</DialogTitle>
        <DialogDescription>{t('DeleteGuestDialog.warning')}</DialogDescription>
      </DialogHeader>
      <p className="text-sm">{t('DeleteGuestDialog.limit')}</p>
      <div className="max-h-60 overflow-auto space-y-2">
        {(review ?? intent.targets).map((target) => <div key={target.request_id} className="rounded border p-2 text-sm">
          <p>{target.vm_type === 'lxc' ? 'CT' : 'VM'} {target.vmid} · {target.node}</p>
          {'summary' in target && typeof target.summary === 'string' && <pre className="whitespace-pre-wrap break-all text-xs">{target.summary}</pre>}
          <p className="font-mono text-xs">{target.request_id}</p>
        </div>)}
      </div>
      {!review && !reviewFailed && <p role="status">{t('DeleteGuestDialog.loading')}</p>}
      {(reviewFailed || controllerChanged) && <p role="alert">{t('DeleteGuestDialog.reviewFailed')}</p>}
      {readOnly && <p role="alert">{t('DeleteGuestDialog.readOnly')}</p>}
      {mutation.isError && <p role="alert">{t('HypervisorPage.toast.operationResponseLost')}</p>}
      {receipts && <div role="status"><p>{t('DeleteGuestDialog.accepted')}</p>{receipts.map((r) => <p key={r.request_id ?? r.vmid}>
        {r.vmid}: {r.status ?? t('DeleteGuestDialog.notAccepted')} {r.change_id} {r.error}
      </p>)}</div>}
      <Label htmlFor="delete-guest-confirm">{t('DeleteGuestDialog.type')}</Label>
      <Input id="delete-guest-confirm" value={typed} onChange={(event) => setTyped(event.target.value)} autoComplete="off" />
      <DialogFooter>
        <Button variant="outline" disabled={mutation.isPending} onClick={onClose}>{t('HypervisorPage.actions.cancel')}</Button>
        <Button variant="destructive" disabled={!review?.length || reviewFailed || controllerChanged || readOnly || typed !== 'DELETE' || mutation.isPending || receipts !== null}
          onClick={() => mutation.mutate()}>{t('DeleteGuestDialog.submit')}</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>;
}
