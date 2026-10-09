// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** PRIVATE workflow composition. Not registered in the application. */
import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useAuthStore } from '@/stores/authStore';
import { captureReleasePublication, type ReleasePublicationDraft } from '@/lib/api/releasePublicationComposer';
import { ReleaseIntentRecoveryPanel } from './ReleaseIntentRecoveryPanel';

type Form = { storage: 'owned' | 'external'; organization: string; version: string;
  platform: 'linux' | 'windows' | 'macos'; agentType: 'daemon' | 'desktop'; notes: string;
  minimumVersion: string; prerelease: boolean; latest: boolean; file?: File;
  url: string; checksum: string; size: string };
function freshForm(): Form { return { storage: 'owned', organization: useAuthStore.getState().user?.organization_id ?? '',
  version: '', platform: 'linux', agentType: 'daemon', notes: '', minimumVersion: '', prerelease: false, latest: true,
  url: '', checksum: '', size: '' }; }
// This only clears local presentation. Backend and transport authorization
// remain authoritative; no permission is granted by this UI fingerprint.
function presentationContext(): string {
  const s = useAuthStore.getState(); const u = s.user;
  return JSON.stringify([u?.id, u?.organization_id, u?.role, u?.is_active, u?.is_superuser, u?.is_org_admin,
    u?.mfa_enabled, [...(u?.roles ?? [])].sort(), [...(u?.permissions ?? [])].sort(), s.isAuthenticated,
    s._isHydrated, s._isAuthInitialized, s.isLoading, s.mfaPending, s.hasPermission('agent:admin')]);
}
export function ReleasePublicationWorkflow() {
  const { t } = useTranslation('agents');
  const id = useId();
  const [form, setForm] = useState<Form>(freshForm);
  const [hashing, setHashing] = useState(false);
  const [ready, setReady] = useState(false);
  const [progress, setProgress] = useState(0);
  const [notice, setNotice] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [epoch, setEpoch] = useState(0);
  const [activity, setActivity] = useState({ hasIntent: false, busy: false });
  const activityRef = useRef(activity);
  const builder = useRef<ReturnType<typeof captureReleasePublication> | undefined>(undefined);
  const pending = useRef<AbortController | undefined>(undefined);
  const generation = useRef(0);
  const alive = useRef(false);
  const reset = useCallback((message: string) => {
    generation.current += 1; pending.current?.abort(); pending.current = undefined;
    builder.current?.dispose(); builder.current = undefined;
    activityRef.current = { hasIntent: false, busy: false }; setActivity(activityRef.current);
    setForm(freshForm()); setReady(false); setHashing(false); setProgress(0); setAcknowledged(false);
    setNotice(message); setEpoch(value => value + 1);
  }, []);
  useEffect(() => {
    alive.current = true;
    let context = presentationContext();
    const unsubscribe = useAuthStore.subscribe(() => {
      const next = presentationContext();
      if (next !== context) {
        context = next;
        if (alive.current) reset('notices.contextChanged');
      }
    });
    return () => { alive.current = false; generation.current += 1; unsubscribe(); pending.current?.abort(); builder.current?.dispose(); };
  }, [reset]);
  const reportActivity = useCallback((next: { hasIntent: boolean; busy: boolean }) => {
    activityRef.current = next; if (alive.current) setActivity(next);
  }, []);
  const edit = (patch: Partial<Form>) => {
    if (pending.current || activityRef.current.hasIntent || activityRef.current.busy) return;
    builder.current?.dispose(); builder.current = undefined; setReady(false); setProgress(0); setAcknowledged(false); setNotice('');
    setForm(current => ({ ...current, ...patch }));
  };
  const prepare = async () => {
    if (pending.current || activityRef.current.hasIntent || activityRef.current.busy) return;
    const token = ++generation.current;
    const controller = new AbortController(); pending.current = controller;
    builder.current?.dispose(); builder.current = undefined; setReady(false); setHashing(true); setProgress(0); setNotice('');
    try {
      // Ordinary org admins cannot select a different local target. The actual
      // server still checks scope even for a superuser's explicit target.
      const user = useAuthStore.getState().user;
      if (!user) throw new Error('Current account required');
      const common = { organization_id: user.is_superuser ? (form.organization || null) : user.organization_id,
        version: form.version, platform: form.platform, agent_type: form.agentType, release_notes: form.notes,
        min_backend_version: form.minimumVersion, is_prerelease: form.prerelease, is_latest: form.latest };
      let selection: ReleasePublicationDraft;
      if (form.storage === 'owned') {
        if (!form.file) throw new Error('A binary is required');
        selection = { ...common, storage_kind: 'owned', file: form.file };
      } else {
        if (!/^(0|[1-9][0-9]{0,10})$/.test(form.size)) throw new Error('A complete integer size is required');
        selection = { ...common, storage_kind: 'external', download_url: form.url,
          checksum_sha256: form.checksum, file_size: Number(form.size) };
      }
      // Capture synchronously in the initiating handler, before its first await.
      const current = captureReleasePublication(selection); builder.current = current;
      await current.execute(controller.signal, (bytes, total) => {
        if (alive.current && generation.current === token && !controller.signal.aborted) setProgress(total ? Math.floor(bytes * 100 / total) : 100);
      });
      current.getIntent();
      if (alive.current && generation.current === token && !controller.signal.aborted) {
        setReady(true); setProgress(100); setNotice('notices.prepared');
      }
    } catch {
      if (alive.current && generation.current === token) {
        builder.current?.dispose(); builder.current = undefined; setReady(false);
        setNotice('notices.failed');
      }
    } finally {
      if (alive.current && generation.current === token) { pending.current = undefined; setHashing(false); }
    }
  };
  const locked = hashing || activity.hasIntent || activity.busy;
  const account = useAuthStore.getState().user;
  return <div className="space-y-6">
    <section aria-label={t('ReleasePublicationWorkflow.section')} className="rounded border p-4 space-y-4">
      <h2 className="text-lg font-semibold">{t('ReleasePublicationWorkflow.title')}</h2>
      <p>{t('ReleasePublicationWorkflow.scope')}</p>
      <form onSubmit={event => { event.preventDefault(); void prepare(); }}>
        <fieldset disabled={locked} className="space-y-3">
          <div><label htmlFor={`${id}-storage`}>{t('ReleasePublicationWorkflow.storage')}</label><select id={`${id}-storage`} value={form.storage}
            onChange={event => edit({ storage: event.currentTarget.value as Form['storage'], file: undefined })}>
            <option value="owned">{t('ReleasePublicationWorkflow.owned')}</option><option value="external">{t('ReleasePublicationWorkflow.external')}</option>
          </select></div>
          <div><label htmlFor={`${id}-organization`}>{t('ReleasePublicationWorkflow.organization')}</label>
            <input id={`${id}-organization`} value={form.organization} readOnly={!account?.is_superuser} autoComplete="off"
              onChange={event => edit({ organization: event.currentTarget.value })} />
            <p>{t('ReleasePublicationWorkflow.organizationHelp')}</p></div>
          <div><label htmlFor={`${id}-version`}>{t('ReleasePublicationWorkflow.version')}</label><input id={`${id}-version`} value={form.version} required maxLength={100}
            onChange={event => edit({ version: event.currentTarget.value })} /></div>
          <div><label htmlFor={`${id}-platform`}>{t('ReleasePublicationWorkflow.platform')}</label><select id={`${id}-platform`} value={form.platform}
            onChange={event => edit({ platform: event.currentTarget.value as Form['platform'] })}>
            <option value="linux">linux</option><option value="windows">windows</option><option value="macos">macos</option>
          </select></div>
          <div><label htmlFor={`${id}-type`}>{t('ReleasePublicationWorkflow.agentType')}</label><select id={`${id}-type`} value={form.agentType}
            onChange={event => edit({ agentType: event.currentTarget.value as Form['agentType'] })}>
            <option value="daemon">daemon</option><option value="desktop">desktop</option>
          </select></div>
          <div><label htmlFor={`${id}-notes`}>{t('ReleasePublicationWorkflow.notes')}</label><textarea id={`${id}-notes`} value={form.notes} maxLength={40000}
            onChange={event => edit({ notes: event.currentTarget.value })} /><p>{t('ReleasePublicationWorkflow.notesHelp')}</p></div>
          <div><label htmlFor={`${id}-minimum`}>{t('ReleasePublicationWorkflow.minimum')}</label><input id={`${id}-minimum`} value={form.minimumVersion} maxLength={100}
            onChange={event => edit({ minimumVersion: event.currentTarget.value })} /></div>
          <label><input type="checkbox" checked={form.prerelease} onChange={event => edit({ prerelease: event.currentTarget.checked })} />{t('ReleasePublicationWorkflow.prerelease')}</label>
          <label><input type="checkbox" checked={form.latest} onChange={event => edit({ latest: event.currentTarget.checked })} />{t('ReleasePublicationWorkflow.latest')}</label>
          <p>{t('ReleasePublicationWorkflow.signingHelp')}</p>
          {form.storage === 'owned' ? <div><label htmlFor={`${id}-binary`}>{t('ReleasePublicationWorkflow.binary')}</label>
            <input key={`${epoch}-${form.storage}`} id={`${id}-binary`} type="file" onChange={event => edit({ file: event.currentTarget.files?.[0] })} />
            <p>{form.file ? t('ReleasePublicationWorkflow.fileSelected', { name: form.file.name, bytes: form.file.size }) : t('ReleasePublicationWorkflow.chooseFile')} {t('ReleasePublicationWorkflow.verifyBytes')}</p>
          </div> : <>
            <div><label htmlFor={`${id}-url`}>{t('ReleasePublicationWorkflow.url')}</label><input id={`${id}-url`} value={form.url} required maxLength={1000}
              onChange={event => edit({ url: event.currentTarget.value })} /></div>
            <div><label htmlFor={`${id}-checksum`}>{t('ReleasePublicationWorkflow.checksum')}</label><input id={`${id}-checksum`} value={form.checksum} required maxLength={64}
              onChange={event => edit({ checksum: event.currentTarget.value })} /><p>{t('ReleasePublicationWorkflow.checksumHelp')}</p></div>
            <div><label htmlFor={`${id}-size`}>{t('ReleasePublicationWorkflow.size')}</label><input id={`${id}-size`} inputMode="numeric" value={form.size} required maxLength={11}
              onChange={event => edit({ size: event.currentTarget.value })} /><p>{t('ReleasePublicationWorkflow.sizeHelp')}</p></div>
          </>}
          <button type="submit">{t('ReleasePublicationWorkflow.prepare')}</button>
        </fieldset>
      </form>
      {hashing && <div><progress aria-label={t('ReleasePublicationWorkflow.progress')} value={progress} max={100} />
        <button type="button" onClick={() => pending.current?.abort()}>{t('ReleasePublicationWorkflow.cancel')}</button></div>}
      {notice && <p role="status">{t(`ReleasePublicationWorkflow.${notice}`)}</p>}
      {activity.hasIntent && <p>{t('ReleasePublicationWorkflow.locked')}</p>}
      <label><input type="checkbox" checked={acknowledged} disabled={hashing || activity.busy}
        onChange={event => setAcknowledged(event.currentTarget.checked)} />{t('ReleasePublicationWorkflow.acknowledgement')}</label>
      <button type="button" disabled={hashing || activity.busy || !acknowledged} onClick={() => {
        if (!pending.current && !activityRef.current.busy && acknowledged) reset('notices.closed');
      }}>{t('ReleasePublicationWorkflow.close')}</button>
    </section>
    <ReleaseIntentRecoveryPanel key={epoch} disabled={hashing} lockReplacement onActivityChange={reportActivity}
      prepareIntent={ready && !activity.hasIntent ? () => {
        const current = builder.current; if (!current) throw new Error('No prepared intent'); return current.getIntent();
      } : undefined}
      preparePayload={ready && !activity.hasIntent ? () => {
        const current = builder.current; if (!current) throw new Error('No prepared payload'); return current.getPayload();
      } : undefined} />
  </div>;
}
