// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useRef, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { hypervisorApi, type HypervisorBackupJob, type HypervisorNode } from '@/lib/api';
import { newHypervisorRequestId, type BackupJobReviewIntent, type BackupJobSettings } from '@/lib/api/hypervisor';
import { useUIStore } from '@/stores';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

interface Props {
  open: boolean; onClose: () => void; onTracked: () => void; controllerId: string;
  nodes: HypervisorNode[]; editJob?: HypervisorBackupJob | null; deleteJob?: HypervisorBackupJob | null;
}
export function BackupJobDialog(props: Props) {
  return props.open ? <ReviewedBackupJob {...props} /> : null;
}
function ReviewedBackupJob({ controllerId, nodes, editJob, deleteJob, onClose, onTracked }: Props) {
  const { t } = useTranslation('hypervisor');
  const readOnly = useUIStore((s) => s.readOnlyMode);
  const action = deleteJob ? 'delete' : editJob ? 'update' : 'create';
  const job = deleteJob ?? editJob;
  const [target] = useState<{ controllerId: string; action: BackupJobReviewIntent['action']; job_id: string; request_id: string }>(() => {
    const request_id = newHypervisorRequestId();
    return { controllerId, action, job_id: job?.id ?? `freesdn-${request_id}`, request_id };
  });
  const [settings, setSettings] = useState<BackupJobSettings>(() => ({
    node: job?.node ?? nodes[0]?.node ?? '', storage: job?.storage ?? 'local',
    schedule: job?.schedule ?? 'sat 02:00', vmid: job?.vmid ?? '',
    mode: (job?.mode ?? 'snapshot') as BackupJobSettings['mode'],
    compress: (job?.compress === 'none' ? '0' : job?.compress ?? 'zstd') as BackupJobSettings['compress'],
    enabled: job?.enabled ?? false,
  }));
  const [confirmation, setConfirmation] = useState('');
  const [frozen, setFrozen] = useState(false);
  const intent = useRef<BackupJobReviewIntent | null>(null);
  const changed = target.controllerId !== controllerId || target.action !== action || (!!job && target.job_id !== job.id);
  const review = useMutation({
    retry: false, gcTime: 0,
    mutationFn: () => {
      if (!intent.current || changed) throw new Error('Backup job target changed');
      return hypervisorApi.reviewBackupJob(target.controllerId, intent.current);
    },
  });
  const reviewed = review.data?.data;
  const desired = reviewed?.snapshot.desired;
  const valid = Boolean(!!reviewed && /^[a-f0-9]{64}$/.test(reviewed.expected_digest)
    && reviewed.snapshot.action === target.action && reviewed.snapshot.job_id === target.job_id
    && (action === 'delete' ? desired === null : desired && typeof desired === 'object'
      && Object.entries(settings).every(([key, value]) => {
        const actual = (desired as Record<string, unknown>)[key];
        return key === 'enabled' ? actual === Number(value) : key === 'vmid'
          ? actual === String(value).split(',').sort((a, b) => Number(a) - Number(b)).join(',') : actual === value;
      })));
  const mutation = useMutation({
    retry: false, gcTime: 0,
    mutationFn: () => {
      if (!intent.current || !valid || !reviewed || changed || readOnly || confirmation !== target.job_id) throw new Error('Backup job review unavailable');
      const body = { ...intent.current, request_id: target.request_id, expected_digest: reviewed.expected_digest, force: true, confirmed: true };
      if (target.action === 'create') return hypervisorApi.createBackupJob(target.controllerId, body);
      if (target.action === 'update') return hypervisorApi.updateBackupJob(target.controllerId, target.job_id, body);
      return hypervisorApi.deleteBackupJob(target.controllerId, target.job_id, body);
    },
    onSuccess: onTracked,
  });
  const pending = review.isPending || mutation.isPending;
  const startReview = () => {
    if (!intent.current) {
      intent.current = { action: target.action, job_id: target.job_id, settings: target.action === 'delete' ? null : { ...settings } };
      setFrozen(true);
    }
    review.mutate();
  };
  return <Dialog open onOpenChange={(open) => { if (!open && !pending) onClose(); }}>
    <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto">
      <DialogHeader><DialogTitle>{t(`ReviewedBackupJob.${action}`)}</DialogTitle><DialogDescription>{t('ReviewedBackupJob.warning')}</DialogDescription></DialogHeader>
      <p className="break-all font-mono text-sm">{target.job_id}</p>
      <p className="text-sm">{t('ReviewedBackupJob.limits')}</p>
      {action !== 'delete' && <fieldset disabled={frozen || pending || changed} className="space-y-3">
        {(['node', 'storage', 'schedule', 'vmid'] as const).map((key) => <div key={key}>
          <Label htmlFor={`backup-${key}`}>{t(`ReviewedBackupJob.${key}`)}</Label>
          <Input id={`backup-${key}`} value={settings[key]} onChange={(e) => setSettings({ ...settings, [key]: e.target.value })} />
        </div>)}
        <div><Label htmlFor="backup-mode">{t('BackupJobDialog.fields.mode.label')}</Label>
          <select id="backup-mode" className="flex h-9 w-full rounded-md border border-input bg-background px-3 text-sm" value={settings.mode} onChange={(e) => setSettings({ ...settings, mode: e.target.value as BackupJobSettings['mode'] })}>
            {(['snapshot', 'suspend', 'stop'] as const).map((v) => <option key={v} value={v}>{t(`BackupJobDialog.fields.mode.${v}`)}</option>)}
          </select></div>
        <div><Label htmlFor="backup-compress">{t('BackupJobDialog.fields.compress.label')}</Label>
          <select id="backup-compress" className="flex h-9 w-full rounded-md border border-input bg-background px-3 text-sm" value={settings.compress} onChange={(e) => setSettings({ ...settings, compress: e.target.value as BackupJobSettings['compress'] })}>
            {['zstd', 'lzo', 'gzip', '0'].map((v) => <option key={v} value={v}>{v === '0' ? t('BackupJobDialog.fields.compress.none') : v}</option>)}
          </select></div>
        <label className="flex items-center gap-2"><input type="checkbox" checked={settings.enabled} onChange={(e) => setSettings({ ...settings, enabled: e.target.checked })} />{t('BackupJobDialog.fields.enabled.label')}</label>
      </fieldset>}
      {reviewed && valid && <>
        <Label>{t('ReviewedBackupJob.snapshot')}</Label>
        <pre className="max-h-64 overflow-auto rounded bg-muted p-3 text-xs">{JSON.stringify(reviewed.snapshot, null, 2)}</pre>
        <Label htmlFor="backup-confirmation">{t('ReviewedBackupJob.confirm', { id: target.job_id })}</Label>
        <Input id="backup-confirmation" value={confirmation} onChange={(e) => setConfirmation(e.target.value)} disabled={pending} autoComplete="off" />
      </>}
      {(review.isError || mutation.isError || changed || (reviewed && !valid)) && <p role="alert" className="text-sm text-destructive">{t('ReviewedBackupJob.error')}</p>}
      <DialogFooter>
        <Button variant="outline" disabled={pending} onClick={onClose}>{t('common:actions.cancel')}</Button>
        <Button variant="outline" disabled={pending || changed || !!reviewed} onClick={startReview}>{t('ReviewedBackupJob.review')}</Button>
        <Button disabled={!valid || pending || changed || readOnly || confirmation !== target.job_id} onClick={() => mutation.mutate()}>{t('ReviewedBackupJob.submit')}</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>;
}
