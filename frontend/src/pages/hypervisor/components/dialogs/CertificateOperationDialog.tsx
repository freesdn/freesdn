// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { hypervisorApi } from '@/lib/api';
import { newHypervisorRequestId, type CertificateReviewIntent } from '@/lib/api/hypervisor';
import { useUIStore } from '@/stores';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';

export function CertificateOperationDialog({ controllerId, node, action, onClose, onTracked }: {
  controllerId: string; node: string; action: 'upload' | 'delete' | 'renew'; onClose: () => void; onTracked: () => void;
}) {
  const { t } = useTranslation('hypervisor');
  const client = useQueryClient();
  const readOnly = useUIStore((s) => s.readOnlyMode);
  const [target] = useState(() => ({ controllerId, node, action, request_id: newHypervisorRequestId() }));
  const draft = useRef<CertificateReviewIntent | null>(null);
  const [frozen, setFrozen] = useState(false);
  const [cert, setCert] = useState('');
  const [key, setKey] = useState('');
  const [overwrite, setOverwrite] = useState(false);
  const [restart, setRestart] = useState(false);
  const [acmeForce, setAcmeForce] = useState(false);
  const [confirmation, setConfirmation] = useState('');
  const changed = controllerId !== target.controllerId || node !== target.node || action !== target.action;
  // Secrets remain only in this dialog's memory and outgoing requests. Do not
  // put them in query keys, persistent stores, receipts, or review rendering.
  const review = useMutation({
    retry: false, gcTime: 0,
    mutationFn: () => {
      if (!draft.current || changed) throw new Error('Certificate target changed');
      return hypervisorApi.reviewCertificate(target.controllerId, target.node, draft.current);
    },
    onSuccess: () => { setCert(''); setKey(''); },
  });
  const reviewed = review.data?.data;
  const valid = reviewed && /^[a-f0-9]{64}$/.test(reviewed.expected_digest)
    && reviewed.snapshot.node === target.node && reviewed.snapshot.action === target.action;
  const mutation = useMutation({
    retry: false, gcTime: 0,
    mutationFn: () => {
      if (!draft.current || !valid || !reviewed || readOnly || changed || confirmation !== target.node) throw new Error('Certificate review unavailable');
      const body = { ...draft.current, expected_digest: reviewed.expected_digest, request_id: target.request_id, force: true, confirmed: true };
      switch (target.action) {
        case 'upload': return hypervisorApi.uploadCustomCertificate(target.controllerId, target.node, body);
        case 'delete': return hypervisorApi.deleteCustomCertificate(target.controllerId, target.node, body);
        case 'renew': return hypervisorApi.renewAcmeCertificate(target.controllerId, target.node, body);
      }
    },
    onSuccess: () => {
      draft.current = null; setCert(''); setKey('');
      client.invalidateQueries({ queryKey: ['hypervisor', 'certificates', target.controllerId, target.node] }); onTracked();
    },
  });
  const pending = review.isPending || mutation.isPending;
  const close = () => { if (!pending) { draft.current = null; setCert(''); setKey(''); onClose(); } };
  const startReview = () => {
    if (!draft.current) {
      draft.current = { action: target.action, certificates: cert, key, overwrite, restart, acme_force: acmeForce };
      setFrozen(true);
    }
    review.mutate();
  };
  return <Dialog open onOpenChange={(open) => { if (!open) close(); }}>
    <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto">
      <DialogHeader><DialogTitle>{t('CertificateOperationDialog.title')}</DialogTitle><DialogDescription>{t('CertificateOperationDialog.warning')}</DialogDescription></DialogHeader>
      <p className="font-semibold">{target.action} · {target.node}</p>
      <p className="text-sm">{t('CertificateOperationDialog.limits')}</p>
      <p className="text-sm">{t(target.action === 'renew' ? 'CertificateOperationDialog.acmeWarning' : 'CertificateOperationDialog.restartWarning')}</p>
      {!reviewed && <fieldset disabled={frozen || pending || changed} className="space-y-3">
        {target.action === 'upload' && <>
          <div><Label htmlFor="certificate-pem">{t('CertificatesTab.dialog.certLabel')}</Label><textarea id="certificate-pem" className="w-full rounded border p-2 font-mono text-xs" maxLength={65536} value={cert} onChange={(e) => setCert(e.target.value)} autoComplete="off" spellCheck={false} /></div>
          <div><Label htmlFor="certificate-key">{t('CertificatesTab.dialog.keyLabel')}</Label><textarea id="certificate-key" className="w-full rounded border p-2 font-mono text-xs" maxLength={32768} value={key} onChange={(e) => setKey(e.target.value)} autoComplete="off" spellCheck={false} /></div>
          <div className="flex gap-2"><Checkbox id="certificate-overwrite" checked={overwrite} onCheckedChange={(v) => setOverwrite(v === true)} /><Label htmlFor="certificate-overwrite">{t('CertificatesTab.dialog.forceOverwrite')}</Label></div>
        </>}
        {target.action !== 'renew' && <div className="flex gap-2"><Checkbox id="certificate-restart" checked={restart} onCheckedChange={(v) => setRestart(v === true)} /><Label htmlFor="certificate-restart">{t('CertificatesTab.dialog.restartServices')}</Label></div>}
        {target.action === 'renew' && <div className="flex gap-2"><Checkbox id="certificate-acme-force" checked={acmeForce} onCheckedChange={(v) => setAcmeForce(v === true)} /><Label htmlFor="certificate-acme-force">{t('CertificateOperationDialog.acmeForce')}</Label></div>}
      </fieldset>}
      {!reviewed && <Button onClick={startReview} disabled={pending || changed || (target.action === 'upload' && !cert && !draft.current)}>{t('CertificateOperationDialog.review')}</Button>}
      {(review.isError || (review.isSuccess && !valid)) && <p role="alert">{t('CertificateOperationDialog.reviewFailed')}</p>}
      {valid && reviewed && <div className="space-y-3 text-sm">
        <p>{t('CertificateOperationDialog.endpoint')}: {reviewed.snapshot.endpoint_node}</p>
        <p>{t('CertificateOperationDialog.options', { overwrite: String(reviewed.snapshot.overwrite), restart: String(reviewed.snapshot.restart), acmeForce: String(reviewed.snapshot.acme_force) })}</p>
        {reviewed.snapshot.candidate && <div><h3 className="font-semibold">{t('CertificateOperationDialog.candidate')}</h3><p>{reviewed.snapshot.candidate.subject}</p><p>{reviewed.snapshot.candidate.san.join(', ')}</p><p>{new Date(reviewed.snapshot.candidate.notafter * 1000).toLocaleString()}</p><p className="font-mono break-all">{reviewed.snapshot.candidate.fingerprint}</p></div>}
        <details><summary>{t('CertificateOperationDialog.current')}</summary>{Object.entries(reviewed.snapshot.inventory).map(([name, info]) => <p className="break-all font-mono text-xs" key={name}>{name} · {info.fingerprint}</p>)}</details>
        {target.action === 'renew' && <p>{t('CertificateOperationDialog.domains')}: {reviewed.snapshot.expected_domains.join(', ')}</p>}
        <div><Label htmlFor="certificate-confirm">{t('CertificateOperationDialog.confirm', { node: target.node })}</Label><Input id="certificate-confirm" value={confirmation} onChange={(e) => setConfirmation(e.target.value)} disabled={pending || !!mutation.data} autoComplete="off" /></div>
      </div>}
      <p className="font-mono text-xs break-all">{target.controllerId} · {target.request_id}</p>
      {changed && <p role="alert">{t('CertificateOperationDialog.changed')}</p>}
      {readOnly && <p role="alert">{t('DeleteGuestDialog.readOnly')}</p>}
      {mutation.isError && <p role="alert">{t('CertificateOperationDialog.retry')}</p>}
      {mutation.data && <div role="status"><p>{t('CertificateOperationDialog.receipt')}</p><p>{mutation.data.data.status} · {mutation.data.data.change_id} · {mutation.data.data.provider_task?.status}</p></div>}
      <DialogFooter><Button variant="outline" disabled={pending} onClick={close}>{t('HypervisorPage.actions.close')}</Button><Button disabled={!valid || pending || changed || readOnly || !!mutation.data || confirmation !== target.node} onClick={() => mutation.mutate()}>{t('CertificateOperationDialog.submit')}</Button></DialogFooter>
    </DialogContent>
  </Dialog>;
}
