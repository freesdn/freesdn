// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useRef, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { hypervisorApi } from '@/lib/api';
import { newHypervisorRequestId, type StorageReviewIntent } from '@/lib/api/hypervisor';
import { useUIStore } from '@/stores';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

export function StorageOperationDialog({ controllerId, node, storage, action, volume = '', onClose, onTracked }: {
  controllerId: string; node: string; storage: string; action: 'upload' | 'delete'; volume?: string;
  onClose: () => void; onTracked: () => void;
}) {
  const { t } = useTranslation('hypervisor');
  const readOnly = useUIStore((s) => s.readOnlyMode);
  const [target] = useState(() => ({ controllerId, node, storage, action, volume, request_id: newHypervisorRequestId() }));
  const [file, setFile] = useState<File | null>(null);
  const [content, setContent] = useState<'iso' | 'vztmpl'>('iso');
  const [confirmation, setConfirmation] = useState('');
  const [frozen, setFrozen] = useState(false);
  const draft = useRef<StorageReviewIntent | null>(null);
  const changed = controllerId !== target.controllerId || node !== target.node || storage !== target.storage || action !== target.action || volume !== target.volume;
  const review = useMutation({
    retry: false, gcTime: 0,
    mutationFn: () => {
      if (!draft.current || changed) throw new Error('Storage target changed');
      return hypervisorApi.reviewStorageOperation(target.controllerId, target.node, target.storage, draft.current);
    },
  });
  const reviewed = review.data?.data;
  const expectedVolume = target.action === 'delete' ? target.volume : `${target.storage}:${content}/${file?.name}`;
  const valid = reviewed && /^[a-f0-9]{64}$/.test(reviewed.expected_digest)
    && reviewed.snapshot.node === target.node && reviewed.snapshot.storage === target.storage
    && reviewed.snapshot.action === target.action && reviewed.snapshot.volume === expectedVolume
    && (target.action !== 'upload' || reviewed.snapshot.size === file?.size);
  const mutation = useMutation({
    retry: false, gcTime: 0,
    mutationFn: () => {
      if (!draft.current || !valid || !reviewed || changed || readOnly || confirmation !== expectedVolume) throw new Error('Storage review unavailable');
      const body = { ...draft.current, request_id: target.request_id, expected_digest: reviewed.expected_digest, force: true, confirmed: true };
      if (target.action === 'delete') return hypervisorApi.deleteStorageVolume(target.controllerId, target.node, target.storage, target.volume, body);
      if (!file) throw new Error('Upload source unavailable');
      return hypervisorApi.uploadToStorage(target.controllerId, target.node, target.storage, file, body);
    },
    onSuccess: () => { draft.current = null; setFile(null); onTracked(); },
  });
  const pending = review.isPending || mutation.isPending;
  const startReview = () => {
    if (!draft.current) {
      draft.current = target.action === 'delete'
        ? { action: 'delete', volume: target.volume, filename: '', content: 'iso', size: 0 }
        : { action: 'upload', volume: '', filename: file!.name, content, size: file!.size };
      setFrozen(true);
    }
    review.mutate();
  };
  const fileValid = !!file && file.size > 0 && file.size <= 4 * 1024 ** 3
    && /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/.test(file.name) && !file.name.includes('..')
    && (content === 'iso' ? file.name.endsWith('.iso') : /\.tar\.(gz|xz|zst)$/.test(file.name));
  return <Dialog open onOpenChange={(open) => { if (!open && !pending) onClose(); }}>
    <DialogContent className="sm:max-w-xl">
      <DialogHeader><DialogTitle>{t(`StorageOperationDialog.${action}`)}</DialogTitle><DialogDescription>{t('StorageOperationDialog.warning')}</DialogDescription></DialogHeader>
      <p>{target.node} · {target.storage}</p>
      <p className="text-sm">{t('StorageOperationDialog.limits')}</p>
      {target.action === 'upload' && <fieldset disabled={frozen || pending || changed} className="space-y-3">
        <div><Label htmlFor="storage-content">{t('UploadDialog.fields.contentType')}</Label><select id="storage-content" value={content} onChange={(e) => setContent(e.target.value as 'iso' | 'vztmpl')} className="w-full rounded border bg-background p-2"><option value="iso">ISO</option><option value="vztmpl">{t('UploadDialog.contentTypes.vztmpl')}</option></select></div>
        <div><Label htmlFor="storage-file">{t('UploadDialog.fields.file')}</Label><Input id="storage-file" type="file" accept={content === 'iso' ? '.iso' : '.tar.gz,.tar.xz,.tar.zst'} onChange={(e) => setFile(e.target.files?.[0] || null)} /></div>
        <p className="text-xs">{t('StorageOperationDialog.filePolicy')}</p>
      </fieldset>}
      {!reviewed && <Button onClick={startReview} disabled={pending || changed || (target.action === 'upload' && !fileValid)}>{t('StorageOperationDialog.review')}</Button>}
      {(review.isError || (review.isSuccess && !valid)) && <p role="alert">{t('StorageOperationDialog.reviewFailed')}</p>}
      {valid && reviewed && <div className="space-y-3">
        <p className="font-mono break-all">{reviewed.snapshot.volume}</p>
        <p>{reviewed.snapshot.size.toLocaleString()} bytes · {reviewed.snapshot.storage_type}</p>
        <p className="text-xs font-mono break-all">{reviewed.expected_digest}</p>
        <Label htmlFor="storage-confirm">{t('StorageOperationDialog.confirm', { volume: expectedVolume })}</Label>
        <Input id="storage-confirm" value={confirmation} onChange={(e) => setConfirmation(e.target.value)} disabled={pending || changed} autoComplete="off" />
      </div>}
      {changed && <p role="alert">{t('StorageOperationDialog.changed')}</p>}
      {mutation.isError && <p role="alert">{t('StorageOperationDialog.failed')}</p>}
      <DialogFooter><Button variant="outline" disabled={pending} onClick={onClose}>{t('StorageOperationDialog.cancel')}</Button><Button variant={action === 'delete' ? 'destructive' : 'default'} disabled={!valid || pending || changed || readOnly || confirmation !== expectedVolume} onClick={() => mutation.mutate()}>{t('StorageOperationDialog.submit')}</Button></DialogFooter>
    </DialogContent>
  </Dialog>;
}
