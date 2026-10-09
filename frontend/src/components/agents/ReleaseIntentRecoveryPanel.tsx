// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** PRIVATE, unregistered operator panel. The parent composer must create a
 * context-bound prepared intent at the user gesture; no raw stale query prop.
 * Page/router/i18n/audit and actual browser acceptance remain separate gates.
 */
import { useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { beginReleaseIntentRetention, importReleaseIntentFile, ReleaseIntentFileError,
  type ReleaseIntentRetention, type ReleaseRecoveryAction } from '@/lib/api/releaseIntentRetention';
import { ReleaseTransportError } from '@/lib/api/releaseOperationTransport';

type View = ReturnType<ReleaseIntentRetention['getState']>;
type Props = { prepareIntent?: () => string; preparePayload?: () => Blob | undefined; disabled?: boolean; lockReplacement?: boolean;
  onActivityChange?: (activity: { hasIntent: boolean; busy: boolean }) => void };

export function ReleaseIntentRecoveryPanel({ prepareIntent, preparePayload, disabled = false, lockReplacement = false, onActivityChange }: Props) {
  const { t } = useTranslation('agents');
  const id = useId();
  const session = useRef<ReleaseIntentRetention | undefined>(undefined);
  const detach = useRef<(() => void) | undefined>(undefined);
  const pending = useRef<AbortController | undefined>(undefined);
  const generation = useRef(0);
  const alive = useRef(false);
  const [view, setView] = useState<View>();
  const [working, setWorking] = useState(false);
  const [error, setError] = useState('');
  const [observation, setObservation] = useState<unknown>();
  const [confirmation, setConfirmation] = useState('');
  const [action, setAction] = useState<ReleaseRecoveryAction>('reserve');
  const [payload, setPayload] = useState<Blob>();
  const observer = useRef(onActivityChange); observer.current = onActivityChange;
  const announce = () => {
    const state = session.current?.getState();
    try { observer.current?.({ hasIntent: !!state && !state.closed, busy: !!pending.current || !!(state && !state.closed && state.busy) }); }
    catch { /* A display observer cannot change operation lifetime or authority. */ }
  };

  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false; generation.current += 1; pending.current?.abort(); pending.current = undefined;
      detach.current?.(); session.current?.dispose(); session.current = undefined;
    };
  }, []);
  const safeError = (value: unknown) => value instanceof ReleaseIntentFileError ? 'errors.file'
    : value instanceof ReleaseTransportError ? (value.outcome === 'not-issued' ? 'errors.notIssued' : 'errors.unconfirmed') : 'errors.generic';
  const adopt = (next: ReleaseIntentRetention) => {
    detach.current?.(); session.current?.dispose(); session.current = next;
    const refresh = () => {
      if (!alive.current || session.current !== next) return;
      const state = next.getState(); setView(state);
      if (state.closed) {
        generation.current += 1; pending.current?.abort(); pending.current = undefined; setWorking(false);
        setObservation(undefined); setPayload(undefined); setConfirmation(''); setError('');
      }
      announce();
    };
    detach.current = next.subscribe(refresh); refresh();
    setAction('reserve'); setPayload(undefined); setConfirmation(''); setObservation(undefined); setError('');
  };
  const run = async (work: (signal: AbortSignal) => Promise<unknown>, show = true) => {
    if (disabled || working || pending.current) return;
    const token = ++generation.current; const controller = new AbortController(); pending.current = controller;
    setWorking(true); setError(''); if (show) setObservation(undefined); announce();
    try {
      const result = await work(controller.signal);
      if (alive.current && generation.current === token) {
        session.current?.assertCurrent(); if (show) setObservation(result);
      }
    } catch (failure) {
      if (alive.current && generation.current === token) setError(safeError(failure));
    } finally {
      if (alive.current && generation.current === token) { pending.current = undefined; setWorking(false); announce(); }
    }
  };
  const replacementBlocked = () => { const state = session.current?.getState(); return !!(lockReplacement && state && !state.closed); };
  const importFile = (file: File) => {
    if (replacementBlocked()) return;
    void run(async signal => {
      const next = await importReleaseIntentFile(file, signal);
      if (!alive.current || signal.aborted) { next.dispose(); return; }
      adopt(next);
    }, false);
  };
  const read = (which: 'review' | 'inspect') => {
    if (disabled || pending.current) return;
    try {
      const current = session.current; if (!current) return;
      // Capture at this click, not inside a mutation library's retried callback.
      const request = which === 'review' ? current.captureReview() : current.captureInspection();
      void run(signal => request.execute(signal));
    } catch (failure) { setError(safeError(failure)); }
  };
  const mutate = () => {
    if (disabled || pending.current) return;
    try {
      const current = session.current; if (!current) return;
      const request = current.captureMutation(action, confirmation, payload);
      void run(signal => request.execute(signal));
    } catch (failure) { setError(safeError(failure)); }
  };
  const active = view && !view.closed ? view : undefined;
  const choices: ReleaseRecoveryAction[] = active?.document.kind === 'delete' ? ['reserve', 'delete', 'cancel', 'cleanup']
    : active?.document.kind === 'publish' && active.document.storage_kind === 'owned'
      ? ['reserve', 'upload', 'resume', 'publish', 'cancel', 'cleanup'] : ['reserve', 'publish', 'cancel', 'cleanup'];
  const canMutate = active && !disabled && !working && !active.busy && active.fileVerified && active.reviewed && !active.inspectionRequired
    && (action === 'reserve' || active.journalObserved) && confirmation === active.document.operation_id
    && (action !== 'upload' || payload !== undefined);
  return <section aria-label={t('ReleaseIntentRecoveryPanel.section')} className="rounded border p-4">
    <fieldset disabled={disabled} className="space-y-4">
    <h2 className="text-lg font-semibold">{t('ReleaseIntentRecoveryPanel.title')}</h2>
    <p>{t('ReleaseIntentRecoveryPanel.retentionHelp')}</p>
    <p>{t('ReleaseIntentRecoveryPanel.authorityHelp')}</p>
    {prepareIntent && <button type="button" disabled={working} onClick={() => {
      try {
        if (disabled || pending.current || replacementBlocked()) return;
        const raw = prepareIntent(); const selected = preparePayload?.();
        if (selected !== undefined && !(selected instanceof Blob)) throw new ReleaseIntentFileError();
        const captured = selected?.slice(0, selected.size, 'application/octet-stream');
        const next = beginReleaseIntentRetention(raw);
        const state = next.getState();
        if (captured && (state.closed || state.document.kind !== 'publish' || state.document.storage_kind !== 'owned'
          || captured.size !== state.document.metadata.file_size)) { next.dispose(); throw new ReleaseIntentFileError(); }
        adopt(next); setPayload(captured);
      } catch (failure) { setError(safeError(failure)); }
    }}>{t('ReleaseIntentRecoveryPanel.usePrepared')}</button>}
    <div><label htmlFor={`${id}-import`}>{t('ReleaseIntentRecoveryPanel.import')}</label>
      <input id={`${id}-import`} type="file" accept=".json,application/json" disabled={working || !!(lockReplacement && active)} onChange={event => {
        const file = event.currentTarget.files?.[0]; event.currentTarget.value = ''; if (file) importFile(file);
      }} /></div>
    {view?.closed && <p role="status">{t('ReleaseIntentRecoveryPanel.expired')}</p>}
    {active && <>
      <dl className="grid gap-1">
        <dt>{t('ReleaseIntentRecoveryPanel.operation')}</dt><dd>{active.document.operation_id}</dd>
        <dt>{t('ReleaseIntentRecoveryPanel.release')}</dt><dd>{active.document.release_id}</dd>
        <dt>{t('ReleaseIntentRecoveryPanel.organization')}</dt><dd>{active.document.organization_id ?? t('ReleaseIntentRecoveryPanel.platformScope')}</dd>
        <dt>{t('ReleaseIntentRecoveryPanel.intent')}</dt><dd>{active.document.kind}</dd>
        <dt>{t('ReleaseIntentRecoveryPanel.versionTarget')}</dt><dd>{active.document.metadata.version} / {active.document.metadata.platform} / {active.document.metadata.agent_type}</dd>
        <dt>{t('ReleaseIntentRecoveryPanel.bytes')}</dt><dd>{active.document.metadata.file_size}</dd>
        <dt>{t('ReleaseIntentRecoveryPanel.checksum')}</dt><dd className="break-all">{active.document.metadata.checksum_sha256}</dd>
      </dl>
      <button type="button" disabled={working} onClick={() => {
        try { if (!disabled && !pending.current) session.current?.download(); } catch (failure) { setError(safeError(failure)); }
      }}>{t('ReleaseIntentRecoveryPanel.downloadIntent')}</button>
      <p role="status">{active.fileVerified ? t('ReleaseIntentRecoveryPanel.verified')
        : active.downloadIssued ? t('ReleaseIntentRecoveryPanel.downloadIssued')
          : t('ReleaseIntentRecoveryPanel.saveRequired')}</p>
      <div><label htmlFor={`${id}-verify`}>{t('ReleaseIntentRecoveryPanel.verifyFile')}</label>
        <input id={`${id}-verify`} type="file" accept=".json,application/json" disabled={working} onChange={event => {
          const file = event.currentTarget.files?.[0]; event.currentTarget.value = '';
          const current = session.current;
          if (file && current) void run(signal => current.verifySelectedFile(file, signal), false);
        }} /></div>
      <div className="flex gap-3">
        <button type="button" disabled={working} onClick={() => read('review')}>{t('ReleaseIntentRecoveryPanel.review')}</button>
        <button type="button" disabled={working} onClick={() => read('inspect')}>{t('ReleaseIntentRecoveryPanel.inspect')}</button>
      </div>
      {!active.reviewed && <p>{t('ReleaseIntentRecoveryPanel.reviewRequired')}</p>}
      {active.reviewed && !active.journalObserved && <p>{t('ReleaseIntentRecoveryPanel.noHistory')}</p>}
      {active.inspectionRequired && <p role="alert">{t('ReleaseIntentRecoveryPanel.uncertain')}</p>}
      <div><label htmlFor={`${id}-action`}>{t('ReleaseIntentRecoveryPanel.action')}</label>
        <select id={`${id}-action`} value={action} disabled={working} onChange={event => setAction(event.currentTarget.value as ReleaseRecoveryAction)}>
          {choices.map(choice => <option key={choice} value={choice}>{t(`ReleaseIntentRecoveryPanel.actions.${choice}`)}</option>)}
        </select></div>
      {action === 'upload' && <div><label htmlFor={`${id}-payload`}>{t('ReleaseIntentRecoveryPanel.originalBinary')}</label>
        <input id={`${id}-payload`} type="file" disabled={working} onChange={event => setPayload(event.currentTarget.files?.[0])} />
        <p>{payload ? t('ReleaseIntentRecoveryPanel.binarySelected') : ''}{t('ReleaseIntentRecoveryPanel.binaryHelp')}</p></div>}
      <div><label htmlFor={`${id}-confirmation`}>{t('ReleaseIntentRecoveryPanel.confirmation')}</label>
        <input id={`${id}-confirmation`} autoComplete="off" value={confirmation} disabled={working} onChange={event => setConfirmation(event.currentTarget.value)} /></div>
      <button type="button" disabled={!canMutate} onClick={mutate}>{t('ReleaseIntentRecoveryPanel.execute', { action: t(`ReleaseIntentRecoveryPanel.actions.${action}`) })}</button>
    </>}
    {working && <button type="button" onClick={() => pending.current?.abort()}>{t('ReleaseIntentRecoveryPanel.cancelWait')}</button>}
    {error && <p role="alert">{t(`ReleaseIntentRecoveryPanel.${error}`)}</p>}
    {observation !== undefined && <div><h3>{t('ReleaseIntentRecoveryPanel.observation')}</h3>
      <p>{t('ReleaseIntentRecoveryPanel.observationHelp')}</p>
      <pre className="max-h-80 overflow-auto whitespace-pre-wrap">{JSON.stringify(observation, null, 2)}</pre>
    </div>}
    </fieldset>
  </section>;
}
