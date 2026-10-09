// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { hypervisorApi } from '@/lib/api';
import { newHypervisorRequestId, type ClusterOperationSpec } from '@/lib/api/hypervisor';
import { useUIStore } from '@/stores';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

export function ClusterOperationDialog({ controllerId, intent, onClose, onTracked }: {
  controllerId: string; intent: ClusterOperationSpec; onClose: () => void; onTracked: () => void;
}) {
  const { t } = useTranslation('hypervisor');
  const client = useQueryClient();
  const readOnly = useUIStore((s) => s.readOnlyMode);
  const [frozen] = useState(() => ({ controllerId, intent: structuredClone(intent), request_id: newHypervisorRequestId() }));
  const [confirmation, setConfirmation] = useState('');
  const changed = controllerId !== frozen.controllerId || JSON.stringify(intent) !== JSON.stringify(frozen.intent);
  const review = useQuery({
    queryKey: ['hypervisor', 'cluster-review', frozen.request_id],
    queryFn: () => hypervisorApi.reviewClusterOperation(frozen.controllerId, frozen.intent.action, frozen.intent.target,
      frozen.intent.action === 'ha.resource.create' ? frozen.intent.options.group : ''),
    retry: false, staleTime: Infinity, refetchOnWindowFocus: false, refetchOnReconnect: false,
  });
  const reviewed = review.data?.data;
  const valid = reviewed && /^[0-9a-f]{64}$/.test(reviewed.expected_digest)
    && reviewed.snapshot.action === frozen.intent.action && reviewed.snapshot.target === frozen.intent.target;
  const mutation = useMutation({
    retry: false,
    mutationFn: () => {
      if (!valid || !reviewed || changed || readOnly || confirmation !== frozen.intent.target) throw new Error('Cluster review unavailable');
      const body = { request_id: frozen.request_id, expected_digest: reviewed.expected_digest, force: true, confirmed: true };
      const selected = frozen.intent;
      switch (selected.action) {
        case 'node.reboot': return hypervisorApi.rebootNode(frozen.controllerId, selected.target, body);
        case 'node.shutdown': return hypervisorApi.shutdownNode(frozen.controllerId, selected.target, body);
        case 'ha.resource.create': return hypervisorApi.createHAResource(frozen.controllerId, { ...selected.options, ...body });
        case 'ha.resource.delete': return hypervisorApi.deleteHAResource(frozen.controllerId, selected.target, body);
        case 'ha.group.create': return hypervisorApi.createHAGroup(frozen.controllerId, { ...selected.options, ...body });
        case 'ha.group.delete': return hypervisorApi.deleteHAGroup(frozen.controllerId, selected.target, body);
      }
    },
    onSuccess: () => { client.invalidateQueries({ queryKey: ['hypervisor'], predicate: (q) => q.queryKey[1] !== 'cluster-review' }); onTracked(); },
  });
  const blocked = !valid || changed || readOnly || mutation.isPending || !!mutation.data || confirmation !== frozen.intent.target;
  return <Dialog open onOpenChange={(open) => { if (!open && !mutation.isPending) onClose(); }}>
    <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto">
      <DialogHeader><DialogTitle>{t('ClusterOperationDialog.title')}</DialogTitle><DialogDescription>{t('ClusterOperationDialog.warning')}</DialogDescription></DialogHeader>
      <p className="font-semibold">{frozen.intent.action} · {frozen.intent.target}</p>
      <p className="text-sm">{t('ClusterOperationDialog.limits')}</p>
      <p className="text-sm text-warning">{t(frozen.intent.action.startsWith('node.') ? 'ClusterOperationDialog.manual' : 'ClusterOperationDialog.ha')}</p>
      {review.isPending && <p role="status">{t('ClusterOperationDialog.loading')}</p>}
      {(review.isError || (review.isSuccess && !valid)) && <p role="alert">{t('ClusterOperationDialog.failed')}</p>}
      {valid && reviewed && <div className="space-y-3 text-sm">
        <p>{reviewed.snapshot.cluster.name} · {t('ClusterOperationDialog.quorum')}: {reviewed.snapshot.cluster.quorate === null ? 'standalone' : String(reviewed.snapshot.cluster.quorate)}</p>
        <div><h3 className="font-semibold">{t('ClusterOperationDialog.nodes')}</h3><ul className="list-disc pl-5">{reviewed.snapshot.nodes.map((node) => <li key={node.name}>{node.name} · {node.online ? 'online' : 'offline'}</li>)}</ul></div>
        <div><h3 className="font-semibold">{t('ClusterOperationDialog.guests')} ({reviewed.snapshot.guests.length})</h3><ul className="list-disc pl-5">{reviewed.snapshot.guests.map((guest) => <li key={guest.vmid}>{guest.type} {guest.vmid} {guest.name} · {guest.node} · {guest.status}</li>)}</ul></div>
        <details><summary>{t('ClusterOperationDialog.resources')}</summary><pre className="whitespace-pre-wrap break-all">{JSON.stringify({ resources: reviewed.snapshot.resources, groups: reviewed.snapshot.groups }, null, 2)}</pre></details>
      </div>}
      {'options' in frozen.intent && <div><h3 className="text-sm font-semibold">{t('ClusterOperationDialog.options')}</h3><pre className="text-xs whitespace-pre-wrap break-all">{JSON.stringify(frozen.intent.options, null, 2)}</pre></div>}
      <p className="font-mono text-xs break-all">{frozen.controllerId} · {frozen.request_id}</p>
      <div><Label htmlFor="cluster-confirm">{t('ClusterOperationDialog.confirm', { target: frozen.intent.target })}</Label><Input id="cluster-confirm" value={confirmation} onChange={(e) => setConfirmation(e.target.value)} disabled={mutation.isPending || !!mutation.data} autoComplete="off" /></div>
      {changed && <p role="alert">{t('ClusterOperationDialog.changed')}</p>}
      {readOnly && <p role="alert">{t('DeleteGuestDialog.readOnly')}</p>}
      {mutation.isError && <p role="alert">{t('ClusterOperationDialog.retry')}</p>}
      {mutation.data && <div role="status"><p>{t('ClusterOperationDialog.receipt')}</p><p>{mutation.data.data.status} · {mutation.data.data.change_id} · {mutation.data.data.provider_task?.status}</p></div>}
      <DialogFooter><Button variant="outline" disabled={mutation.isPending} onClick={onClose}>{t('HypervisorPage.actions.close')}</Button><Button disabled={blocked} onClick={() => mutation.mutate()}>{t('ClusterOperationDialog.submit')}</Button></DialogFooter>
    </DialogContent>
  </Dialog>;
}
