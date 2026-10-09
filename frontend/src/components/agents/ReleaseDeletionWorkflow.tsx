// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Private composition; public routing/localization remains separate. */
import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useAuthStore } from '@/stores/authStore';
import { captureReleaseDeletion } from '@/lib/api/releaseDeletionComposer';
import { ReleaseIntentRecoveryPanel } from './ReleaseIntentRecoveryPanel';

// Presentation cleanup only. The captured transport and server enforce authority.
function presentationContext(): string {
  const state = useAuthStore.getState(); const user = state.user;
  return JSON.stringify([user?.id, user?.organization_id, user?.role, user?.is_active, user?.is_superuser,
    user?.is_org_admin, user?.mfa_enabled, [...(user?.roles ?? [])].sort(), [...(user?.permissions ?? [])].sort(),
    state.isAuthenticated, state._isHydrated, state._isAuthInitialized, state.isLoading, state.mfaPending,
    state.hasPermission('agent:admin')]);
}

export function ReleaseDeletionWorkflow() {
  const { t } = useTranslation('agents');
  const id = useId();
  const [releaseId, setReleaseId] = useState('');
  const [working, setWorking] = useState(false);
  const [ready, setReady] = useState(false);
  const [notice, setNotice] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [epoch, setEpoch] = useState(0);
  const [activity, setActivity] = useState({ hasIntent: false, busy: false });
  const activityRef = useRef(activity);
  const builder = useRef<ReturnType<typeof captureReleaseDeletion> | undefined>(undefined);
  const pending = useRef<AbortController | undefined>(undefined);
  const generation = useRef(0);
  const alive = useRef(false);
  const reset = useCallback((message: string) => {
    generation.current += 1; pending.current?.abort(); pending.current = undefined;
    builder.current?.dispose(); builder.current = undefined;
    activityRef.current = { hasIntent: false, busy: false }; setActivity(activityRef.current);
    setReleaseId(''); setReady(false); setWorking(false); setAcknowledged(false); setNotice(message);
    setEpoch(value => value + 1);
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
    return () => {
      alive.current = false; generation.current += 1; unsubscribe(); pending.current?.abort(); builder.current?.dispose();
    };
  }, [reset]);
  const reportActivity = useCallback((next: { hasIntent: boolean; busy: boolean }) => {
    activityRef.current = next; if (alive.current) setActivity(next);
  }, []);
  const edit = (value: string) => {
    if (pending.current || activityRef.current.hasIntent || activityRef.current.busy) return;
    builder.current?.dispose(); builder.current = undefined;
    setReleaseId(value); setReady(false); setNotice(''); setAcknowledged(false);
  };
  const prepare = async () => {
    if (pending.current || activityRef.current.hasIntent || activityRef.current.busy) return;
    const token = ++generation.current;
    const controller = new AbortController(); pending.current = controller;
    builder.current?.dispose(); builder.current = undefined;
    setReady(false); setWorking(true); setNotice(''); setAcknowledged(false);
    try {
      // Capture the exact selected UUID and initiating account before any await.
      const current = captureReleaseDeletion(releaseId); builder.current = current;
      await current.execute(controller.signal);
      current.getIntent();
      if (alive.current && generation.current === token && !controller.signal.aborted) {
        setReady(true);
        setNotice('notices.prepared');
      }
    } catch {
      if (alive.current && generation.current === token) {
        builder.current?.dispose(); builder.current = undefined; setReady(false);
        setNotice('notices.failed');
      }
    } finally {
      if (alive.current && generation.current === token) { pending.current = undefined; setWorking(false); }
    }
  };
  const locked = working || activity.hasIntent || activity.busy;
  return <div className="space-y-6">
    <section aria-label={t('ReleaseDeletionWorkflow.section')} className="rounded border p-4 space-y-4">
      <h2 className="text-lg font-semibold">{t('ReleaseDeletionWorkflow.title')}</h2>
      <p>{t('ReleaseDeletionWorkflow.scope')}</p>
      <form onSubmit={event => { event.preventDefault(); void prepare(); }}>
        <fieldset disabled={locked} className="space-y-3">
          <label htmlFor={`${id}-release`}>{t('ReleaseDeletionWorkflow.releaseId')}</label>
          <input id={`${id}-release`} autoComplete="off" spellCheck={false} required maxLength={36}
            value={releaseId} onChange={event => edit(event.currentTarget.value)} />
          <button type="submit">{t('ReleaseDeletionWorkflow.prepare')}</button>
        </fieldset>
      </form>
      {working && <button type="button" onClick={() => pending.current?.abort()}>{t('ReleaseDeletionWorkflow.cancel')}</button>}
      {notice && <p role="status">{t(`ReleaseDeletionWorkflow.${notice}`)}</p>}
      {activity.hasIntent && <p>{t('ReleaseDeletionWorkflow.locked')}</p>}
      <label><input type="checkbox" checked={acknowledged} disabled={working || activity.busy}
        onChange={event => setAcknowledged(event.currentTarget.checked)} />{t('ReleaseDeletionWorkflow.acknowledgement')}</label>
      <button type="button" disabled={working || activity.busy || !acknowledged} onClick={() => {
        if (!pending.current && !activityRef.current.busy && acknowledged) reset('notices.closed');
      }}>{t('ReleaseDeletionWorkflow.close')}</button>
    </section>
    <ReleaseIntentRecoveryPanel key={epoch} disabled={working} lockReplacement onActivityChange={reportActivity}
      prepareIntent={ready && !activity.hasIntent ? () => {
        const current = builder.current; if (!current) throw new Error('No prepared deletion intent'); return current.getIntent();
      } : undefined} />
  </div>;
}
