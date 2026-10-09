// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { hypervisorApi } from '@/lib/api';
import { newHypervisorRequestId } from '@/lib/api/hypervisor';
import { useUIStore } from '@/stores';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

interface Props {
  controllerId: string;
  target: { controllerId: string; node: string; upid: string };
  onClose: () => void;
  onTracked: () => void;
}

export function TaskStopDialog({ controllerId, target, onClose, onTracked }: Props) {
  const { t } = useTranslation('hypervisor');
  const readOnly = useUIStore((s) => s.readOnlyMode);
  const [frozen] = useState(() => ({ ...target, request_id: newHypervisorRequestId() }));
  const [confirmation, setConfirmation] = useState('');
  const changed = controllerId !== frozen.controllerId || target.controllerId !== frozen.controllerId
    || target.node !== frozen.node || target.upid !== frozen.upid;
  const review = useMutation({
    retry: false, gcTime: 0,
    mutationFn: () => {
      if (changed) throw new Error('Task target changed');
      return hypervisorApi.reviewTaskStop(frozen.controllerId, frozen.node, frozen.upid);
    },
  });
  const reviewed = review.data?.data;
  const valid = !!reviewed && /^[a-f0-9]{64}$/.test(reviewed.expected_digest)
    && reviewed.snapshot.node === frozen.node && reviewed.snapshot.upid === frozen.upid
    && reviewed.snapshot.status === 'running' && reviewed.snapshot.task_type === frozen.upid.split(':')[5];
  const mutation = useMutation({
    retry: false, gcTime: 0,
    mutationFn: () => {
      if (!valid || !reviewed || changed || readOnly || confirmation !== frozen.node) throw new Error('Task review unavailable');
      return hypervisorApi.stopTask(frozen.controllerId, frozen.node, frozen.upid, {
        request_id: frozen.request_id, expected_digest: reviewed.expected_digest, force: true, confirmed: true,
      });
    },
    onSuccess: onTracked,
  });
  const pending = review.isPending || mutation.isPending;
  return <Dialog open onOpenChange={(open) => { if (!open && !pending) onClose(); }}>
    <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto">
      <DialogHeader><DialogTitle>{t('TaskStop.title')}</DialogTitle><DialogDescription>{t('TaskStop.warning')}</DialogDescription></DialogHeader>
      <p className="font-mono text-xs break-all">{frozen.upid}</p>
      <p className="text-sm">{t('TaskStop.requirements')}</p>
      {valid && <>
        <p>{t('TaskStop.reviewed', { node: frozen.node, type: reviewed.snapshot.task_type })}</p>
        <Label htmlFor="task-stop-confirm">{t('TaskStop.confirm', { node: frozen.node })}</Label>
        <Input id="task-stop-confirm" value={confirmation} onChange={(e) => setConfirmation(e.target.value)} disabled={pending} autoComplete="off" />
      </>}
      {(changed || review.isError || mutation.isError || (reviewed && !valid)) && <p role="alert" className="text-sm text-destructive">{t('TaskStop.error')}</p>}
      <DialogFooter>
        <Button variant="outline" disabled={pending} onClick={onClose}>{t('common:actions.cancel')}</Button>
        <Button variant="outline" disabled={pending || changed || !!reviewed} onClick={() => review.mutate()}>{t('TaskStop.review')}</Button>
        <Button variant="destructive" disabled={!valid || pending || changed || readOnly || confirmation !== frozen.node} onClick={() => mutation.mutate()}>{t('TaskStop.submit')}</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>;
}
