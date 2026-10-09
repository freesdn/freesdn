// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Private one-attempt UI. A response is an observation, not lasting latest state. */
import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useAuthStore } from '@/stores/authStore';
import { captureReleasePromotion } from '@/lib/api/releasePromotionClient';
import { ReleaseTransportError } from '@/lib/api/releaseOperationTransport';
import type { ReleasePromotionObservation } from '@/lib/api/releaseCatalogueCodec';

function presentationContext() {
  const s = useAuthStore.getState(); const u = s.user;
  return JSON.stringify([u?.id, u?.organization_id, u?.role, u?.is_active, u?.is_superuser, u?.is_org_admin,
    u?.mfa_enabled, [...(u?.roles ?? [])].sort(), [...(u?.permissions ?? [])].sort(), s.isAuthenticated,
    s._isHydrated, s._isAuthInitialized, s.isLoading, s.mfaPending, s.hasPermission('agent:admin')]);
}
type Notice = 'initial' | 'prepared' | 'invalid' | 'working' | 'notIssued' | 'unconfirmed' | 'confirmed' | 'cancelled' | 'contextChanged' | 'closed';

export function ReleasePromotionWorkflow() {
  const { t } = useTranslation('agents'); const id = useId();
  const [input, setInput] = useState(''); const [confirmation, setConfirmation] = useState('');
  const [prepared, setPrepared] = useState(''); const [attempted, setAttempted] = useState(false);
  const [busy, setBusy] = useState(false); const [acknowledged, setAcknowledged] = useState(false);
  const [notice, setNotice] = useState<Notice>('initial');
  const [observation, setObservation] = useState<ReleasePromotionObservation>();
  const action = useRef<ReturnType<typeof captureReleasePromotion> | undefined>(undefined);
  const pending = useRef<AbortController | undefined>(undefined);
  const generation = useRef(0); const alive = useRef(false); const used = useRef(false);
  const reset = useCallback((next: Notice) => {
    generation.current += 1; pending.current?.abort(); pending.current = undefined;
    action.current?.dispose(); action.current = undefined; used.current = false;
    setInput(''); setConfirmation(''); setPrepared(''); setAttempted(false); setBusy(false);
    setAcknowledged(false); setObservation(undefined); setNotice(next);
  }, []);
  useEffect(() => {
    alive.current = true; let previous = presentationContext();
    const unsubscribe = useAuthStore.subscribe(() => {
      const next = presentationContext();
      if (next !== previous) { previous = next; if (alive.current) reset('contextChanged'); }
    });
    return () => { alive.current = false; generation.current += 1; unsubscribe(); pending.current?.abort(); action.current?.dispose(); };
  }, [reset]);
  const prepare = () => {
    if (action.current || pending.current) return;
    try {
      const current = captureReleasePromotion(input); action.current = current;
      setPrepared(current.releaseId); setConfirmation(''); setAcknowledged(false); setNotice('prepared');
    } catch { setNotice('invalid'); }
  };
  const execute = async () => {
    const current = action.current;
    if (!current || used.current || pending.current || confirmation !== current.releaseId) return;
    used.current = true; setAttempted(true); setBusy(true); setNotice('working');
    const token = ++generation.current; const context = presentationContext();
    const controller = new AbortController(); pending.current = controller;
    let acknowledgmentReceived = false;
    try {
      const received = await current.execute(controller.signal);
      acknowledgmentReceived = true;
      current.assertCurrent();
      if (alive.current && generation.current === token && presentationContext() === context) {
        setObservation(received); setNotice('confirmed');
      }
    } catch (error: unknown) {
      if (alive.current && generation.current === token) {
        setObservation(undefined);
        setNotice(!acknowledgmentReceived && error instanceof ReleaseTransportError && error.outcome === 'not-issued' ? 'notIssued' : 'unconfirmed');
      }
    } finally {
      current.dispose();
      if (alive.current && generation.current === token) { pending.current = undefined; setBusy(false); }
    }
  };
  return <section aria-labelledby={`${id}-title`} className="rounded border p-4 space-y-4">
    <h2 id={`${id}-title`} className="text-lg font-semibold">{t('ReleasePromotionWorkflow.title')}</h2>
    <p>{t('ReleasePromotionWorkflow.scope')}</p>
    <form onSubmit={event => { event.preventDefault(); prepare(); }}>
      <fieldset disabled={!!prepared || busy} className="space-y-2">
        <label htmlFor={`${id}-release`}>{t('ReleasePromotionWorkflow.releaseId')}</label>
        <input id={`${id}-release`} value={input} maxLength={36} autoComplete="off" spellCheck={false} required
          onChange={event => setInput(event.currentTarget.value)} />
        <button type="submit">{t('ReleasePromotionWorkflow.prepare')}</button>
      </fieldset>
    </form>
    {prepared && <div className="space-y-2">
      <p>{t('ReleasePromotionWorkflow.selected')} <code>{prepared}</code></p>
      <label htmlFor={`${id}-confirmation`}>{t('ReleasePromotionWorkflow.confirmation')}</label>
      <input id={`${id}-confirmation`} value={confirmation} disabled={attempted || busy} maxLength={36}
        autoComplete="off" spellCheck={false} onChange={event => setConfirmation(event.currentTarget.value)} />
      <button type="button" disabled={attempted || busy || confirmation !== prepared} onClick={() => { void execute(); }}>
        {t('ReleasePromotionWorkflow.promote')}
      </button>
    </div>}
    {busy && <button type="button" onClick={() => {
      generation.current += 1; pending.current?.abort(); pending.current = undefined; action.current?.dispose();
      setBusy(false); setObservation(undefined); setNotice('cancelled');
    }}>{t('ReleasePromotionWorkflow.stopWaiting')}</button>}
    <p role={notice === 'invalid' || notice === 'notIssued' || notice === 'unconfirmed' ? 'alert' : 'status'}>
      {t(`ReleasePromotionWorkflow.notices.${notice}`)}
    </p>
    {observation && <dl>
      <dt>{t('ReleasePromotionWorkflow.observedVersion')}</dt><dd>{observation.version}</dd>
      <dt>{t('ReleasePromotionWorkflow.observedTarget')}</dt><dd>{observation.platform} / {observation.agent_type}</dd>
      <dt>SHA-256</dt><dd><code>{observation.checksum_sha256}</code></dd>
    </dl>}
    {prepared && <div className="space-y-2">
      <label><input type="checkbox" checked={acknowledged} disabled={busy}
        onChange={event => setAcknowledged(event.currentTarget.checked)} />{t('ReleasePromotionWorkflow.acknowledgement')}</label>
      <button type="button" disabled={busy || !acknowledged} onClick={() => { if (!pending.current && acknowledged) reset('closed'); }}>
        {t('ReleasePromotionWorkflow.close')}
      </button>
    </div>}
  </section>;
}
