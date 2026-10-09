// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { hypervisorApi, type CreateVMRequest, type CreateContainerRequest } from '@/lib/api';
import { newHypervisorRequestId } from '@/lib/api/hypervisor';
import { useUIStore } from '@/stores';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

type Review = { kind: 'vm'; body: CreateVMRequest } | { kind: 'ct'; body: CreateContainerRequest };

export function CreateGuestDialog({ controllerId, kind, nodes, onClose }: {
  controllerId: string; kind: 'vm' | 'ct'; nodes: string[]; onClose: () => void;
}) {
  const { t } = useTranslation('hypervisor');
  const queryClient = useQueryClient();
  const readOnly = useUIStore((s) => s.readOnlyMode);
  const [target] = useState(() => ({ controllerId, kind, nodes: [...nodes] }));
  const [draft, setDraft] = useState({ vmid: '', node: target.nodes[0] ?? '', name: '', cores: '2', memory: '2048', disk: '32', storage: 'local-lvm', image: '', password: '', start: false });
  const [review, setReview] = useState<Review | null>(null);
  const [invalid, setInvalid] = useState(false);
  const changed = target.controllerId !== controllerId || target.kind !== kind;
  const suggestion = useMutation({
    retry: false,
    mutationFn: () => hypervisorApi.getNextVMID(target.controllerId),
    onSuccess: ({ data }) => {
      if (Number.isInteger(data.vmid) && data.vmid >= 100 && data.vmid <= 999999999) setDraft((d) => ({ ...d, vmid: String(data.vmid) }));
    },
  });
  const mutation = useMutation({
    retry: false,
    mutationFn: () => {
      if (!review || readOnly || changed) throw new Error('Creation review unavailable');
      return review.kind === 'vm' ? hypervisorApi.createVM(target.controllerId, review.body) : hypervisorApi.createContainer(target.controllerId, review.body);
    },
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['hypervisor'] }); },
  });
  function freeze() {
    const vmid = Number(draft.vmid), cores = Number(draft.cores), memory = Number(draft.memory);
    if (!Number.isInteger(vmid) || vmid < 100 || vmid > 999999999 || !draft.node || !draft.name || !draft.storage || !Number.isInteger(cores) || cores < 1 || !Number.isInteger(memory) || memory < 16 || !/^\d+(\.\d+)?$/.test(draft.disk) || Number(draft.disk) <= 0 || (kind === 'ct' && !draft.image)) { setInvalid(true); return; }
    const common = { request_id: newHypervisorRequestId(), force: true as const, vmid, node: draft.node, cores, memory, storage: draft.storage, start_after_create: draft.start };
    setReview(target.kind === 'vm'
      ? { kind: 'vm', body: { ...common, name: draft.name, disk_size: `${draft.disk}G`, iso: draft.image } }
      : { kind: 'ct', body: { ...common, hostname: draft.name, rootfs_size: draft.disk, ostemplate: draft.image, password: draft.password } });
    setDraft((d) => ({ ...d, password: '' }));
    setInvalid(false);
  }
  const fields = [
    ['vmid', t('CreateGuestDialog.vmid')], ['node', t('HypervisorPage.tableHeaders.node')],
    ['name', t('HypervisorPage.tableHeaders.name')], ['cores', t('HypervisorPage.createDialog.cpuCores')],
    ['memory', t('HypervisorPage.createDialog.memoryMb')], ['disk', t('HypervisorPage.createDialog.diskSize')],
    ['storage', t('HypervisorPage.tableHeaders.storage')], ['image', target.kind === 'vm' ? 'ISO' : t('HypervisorPage.createDialog.osTemplate')],
  ] as const;
  return <Dialog open onOpenChange={(open) => { if (!open && !mutation.isPending && !suggestion.isPending) onClose(); }}>
    <DialogContent className="sm:max-w-lg max-h-[90vh] overflow-y-auto">
      <DialogHeader><DialogTitle>{t('CreateGuestDialog.title')}</DialogTitle><DialogDescription>{t('CreateGuestDialog.warning')}</DialogDescription></DialogHeader>
      <fieldset disabled={!!review || changed || readOnly || suggestion.isPending} className="grid grid-cols-2 gap-3">
        {fields.map(([key, label]) => <div key={key}><Label htmlFor={`create-${key}`}>{label}</Label><Input id={`create-${key}`} value={draft[key]} onChange={(e) => setDraft((d) => ({ ...d, [key]: e.target.value }))} /></div>)}
        <Button type="button" variant="outline" onClick={() => suggestion.mutate()}>{t('CreateGuestDialog.suggest')}</Button>
        {target.kind === 'ct' && <div className="col-span-2"><Label htmlFor="create-password">{t('CreateGuestDialog.password')}</Label><Input id="create-password" type="password" autoComplete="new-password" value={draft.password} onChange={(e) => setDraft((d) => ({ ...d, password: e.target.value }))} /><p className="text-xs">{t('CreateGuestDialog.passwordHint')}</p></div>}
        <Label className="col-span-2 flex gap-2"><input type="checkbox" checked={draft.start} onChange={(e) => setDraft((d) => ({ ...d, start: e.target.checked }))} />{t('HypervisorPage.createDialog.startAfterCreation')}</Label>
      </fieldset>
      {review && <div className="rounded border p-3 text-sm"><p>{t('CreateGuestDialog.frozen')}</p><p>{target.kind.toUpperCase()} {review.body.vmid} · {review.body.node}</p><p className="font-mono break-all">{review.body.request_id}</p></div>}
      {invalid && <p role="alert">{t('CreateGuestDialog.invalid')}</p>}
      {changed && <p role="alert">{t('CreateGuestDialog.changed')}</p>}
      {readOnly && <p role="alert">{t('DeleteGuestDialog.readOnly')}</p>}
      {suggestion.isError && <p role="alert">{t('CreateGuestDialog.suggestFailed')}</p>}
      {mutation.isError && <p role="alert">{t('HypervisorPage.toast.operationResponseLost')}</p>}
      {mutation.data && <div role="status"><p>{t('CreateGuestDialog.receipt')}</p><p>{mutation.data.data.status} · {mutation.data.data.change_id} · {mutation.data.data.provider_task?.status}</p></div>}
      <DialogFooter>
        <Button variant="outline" disabled={mutation.isPending || suggestion.isPending} onClick={onClose}>{t('HypervisorPage.actions.close')}</Button>
        {!review ? <Button disabled={changed || readOnly || suggestion.isPending} onClick={freeze}>{t('CreateGuestDialog.review')}</Button>
          : <Button disabled={changed || readOnly || mutation.isPending || !!mutation.data} onClick={() => mutation.mutate()}>{t('CreateGuestDialog.submit')}</Button>}
      </DialogFooter>
    </DialogContent>
  </Dialog>;
}
