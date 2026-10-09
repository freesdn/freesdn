// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { hypervisorApi } from '@/lib/api';
import { newHypervisorRequestId, type FirewallReviewIntent } from '@/lib/api/hypervisor';
import { useUIStore } from '@/stores';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

type Props = { controllerId: string; originControllerId?: string; currentTarget?: FirewallReviewIntent['target']; intent: FirewallReviewIntent; onClose: () => void; onTracked: () => void };
const identity = (t: FirewallReviewIntent['target']) => [t.scope, t.node ?? '', t.vm_type ?? '', t.vmid ?? ''].join(':');
export function FirewallOperationDialog({ controllerId, intent, originControllerId = controllerId, currentTarget = intent.target, onClose, onTracked }: Props) {
  const { t } = useTranslation('hypervisor');
  const readOnly = useUIStore((s) => s.readOnlyMode);
  const [frozen] = useState(() => ({ controllerId: originControllerId, intent: structuredClone(intent), requestId: newHypervisorRequestId() }));
  const [confirmation, setConfirmation] = useState('');
  const [recovery, setRecovery] = useState(false);
  const changed = controllerId !== frozen.controllerId || originControllerId !== frozen.controllerId || identity(currentTarget) !== identity(frozen.intent.target) || JSON.stringify(intent) !== JSON.stringify(frozen.intent);
  const name = identity(frozen.intent.target);
  const review = useMutation({ retry: false, gcTime: 0, mutationFn: () => {
    if (changed) throw new Error('Firewall target changed');
    return hypervisorApi.reviewFirewallOperation(frozen.controllerId, frozen.intent);
  } });
  const reviewed = review.data?.data;
  const valid = !!reviewed && /^[a-f0-9]{64}$/.test(reviewed.expected_digest)
    && identity(reviewed.target) === name && reviewed.action === frozen.intent.action;
  const mutation = useMutation({ retry: false, gcTime: 0, mutationFn: () => {
    if (!valid || !reviewed || changed || readOnly || confirmation !== name || !recovery) throw new Error('Firewall review unavailable');
    return hypervisorApi.submitFirewallOperation(frozen.controllerId, { ...frozen.intent,
      request_id: frozen.requestId, expected_digest: reviewed.expected_digest, force: true, confirmed: true, recovery_confirmed: true });
  }, onSuccess: onTracked });
  const pending = review.isPending || mutation.isPending;
  return <Dialog open onOpenChange={(open) => { if (!open && !pending) onClose(); }}>
    <DialogContent className="sm:max-w-3xl max-h-[90vh] overflow-y-auto">
      <DialogHeader><DialogTitle>{t('FirewallOps.title')}</DialogTitle><DialogDescription>{t('FirewallOps.warning')}</DialogDescription></DialogHeader>
      <p className="font-mono text-sm">{name} / {frozen.intent.action}</p>
      {valid && <>
        <div className="grid gap-3 md:grid-cols-2">
          <div><h4>{t('FirewallOps.before')}</h4><pre className="max-h-64 overflow-auto text-xs whitespace-pre-wrap">{JSON.stringify(reviewed.before, null, 2)}</pre></div>
          <div><h4>{t('FirewallOps.desired')}</h4><pre className="max-h-64 overflow-auto text-xs whitespace-pre-wrap">{JSON.stringify(reviewed.desired, null, 2)}</pre></div>
        </div>
        <ul className="list-disc pl-5 text-sm">{reviewed.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul>
        <Label htmlFor="firewall-confirm">{t('FirewallOps.confirm', { target: name })}</Label>
        <Input id="firewall-confirm" value={confirmation} disabled={pending} autoComplete="off" onChange={(e) => setConfirmation(e.target.value)} />
        <label className="flex gap-2 text-sm"><input type="checkbox" checked={recovery} disabled={pending} onChange={(e) => setRecovery(e.target.checked)} />{t('FirewallOps.recovery')}</label>
      </>}
      {(changed || review.isError || mutation.isError || (reviewed && !valid)) && <p role="alert" className="text-sm text-destructive">{t('FirewallOps.error')}</p>}
      <DialogFooter>
        <Button variant="outline" disabled={pending} onClick={onClose}>{t('common:actions.cancel')}</Button>
        <Button variant="outline" disabled={pending || changed || !!reviewed} onClick={() => review.mutate()}>{t('FirewallOps.review')}</Button>
        <Button variant="destructive" disabled={!valid || pending || changed || readOnly || confirmation !== name || !recovery} onClick={() => mutation.mutate()}>{t('FirewallOps.submit')}</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>;
}
