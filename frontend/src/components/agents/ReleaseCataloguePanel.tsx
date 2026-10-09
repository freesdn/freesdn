// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Private composition, not yet mounted on the public release page.
 * Each page is an independent observation, not a database snapshot or authority
 * to publish, delete, promote, clean up or open an unverified download URL.
 */
import { useCallback, useEffect, useId, useRef, useState, useSyncExternalStore } from 'react';
import { useTranslation } from 'react-i18next';
import { useAuthStore } from '@/stores/authStore';
import { requestReleaseBinaryDownload } from '@/lib/api/releaseBinaryDownload';
import { beginReleaseOperationAction, type ReleaseCatalogueFilters } from '@/lib/api/releaseOperationTransport';
import type { ReleaseCataloguePage, ReleaseCataloguePosition } from '@/lib/api/releaseCatalogueCodec';

function presentationContext(): string {
  const s = useAuthStore.getState(); const u = s.user;
  return JSON.stringify([u?.id, u?.organization_id, u?.role, u?.is_active, u?.is_superuser, u?.is_org_admin,
    u?.mfa_enabled, [...(u?.roles ?? [])].sort(), [...(u?.permissions ?? [])].sort(), s.isAuthenticated,
    s._isHydrated, s._isAuthInitialized, s.isLoading, s.mfaPending, s.hasPermission('agent:admin')]);
}
type Observation = { generation: number; context: string; page: ReleaseCataloguePage; filters: ReleaseCatalogueFilters };
type Notice = 'initial' | 'loading' | 'failed' | 'cancelled' | 'contextChanged' | 'filterChanged' | 'loaded';
type Active = { action: ReturnType<typeof beginReleaseOperationAction>; controller: AbortController };

export function ReleaseCataloguePanel() {
  const { t } = useTranslation('agents'); const id = useId();
  const controlClassName = 'h-10 rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring';
  const buttonClassName = 'inline-flex min-h-10 items-center justify-center rounded-md border border-input bg-background px-3 py-2 text-sm font-medium transition-colors hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50';
  const context = useSyncExternalStore(useAuthStore.subscribe, presentationContext, presentationContext);
  const [platform, setPlatform] = useState(''); const [agentType, setAgentType] = useState('');
  const [limit, setLimit] = useState(50);
  const [observation, setObservation] = useState<Observation>();
  const [notice, setNotice] = useState<Notice>('initial');
  const [busy, setBusy] = useState(false);
  const [downloadNotice, setDownloadNotice] = useState<'requested' | 'unconfirmed'>();
  const active = useRef<Active | undefined>(undefined); const generation = useRef(0); const alive = useRef(false);
  const invalidate = useCallback(() => {
    generation.current += 1;
    active.current?.controller.abort(); active.current?.action.dispose(); active.current = undefined;
  }, []);
  useEffect(() => {
    alive.current = true;
    let previous = presentationContext();
    const unsubscribe = useAuthStore.subscribe(() => {
      const next = presentationContext();
      if (next === previous) return;
      previous = next; invalidate();
      // A -> B -> A also clears the observation, even within one React batch.
      if (alive.current) {
        setObservation(undefined); setDownloadNotice(undefined); setBusy(false); setNotice('contextChanged');
        setPlatform(''); setAgentType(''); setLimit(50);
      }
    });
    return () => { alive.current = false; unsubscribe(); invalidate(); };
  }, [invalidate]);
  const visible = observation?.context === context ? observation : undefined;
  const edit = (change: () => void) => {
    if (active.current) return;
    invalidate(); change(); setObservation(undefined); setDownloadNotice(undefined); setNotice('filterChanged');
  };
  const load = async (position: ReleaseCataloguePosition, filters: ReleaseCatalogueFilters) => {
    if (active.current || !alive.current) return;
    const token = ++generation.current; const initial = presentationContext();
    setObservation(undefined); setDownloadNotice(undefined); setNotice('loading'); setBusy(true);
    let owned: Active | undefined;
    try {
      // Capture in the explicit initiating click, before the first await.
      const action = beginReleaseOperationAction();
      owned = { action, controller: new AbortController() }; active.current = owned;
      const capturedFilters = Object.freeze({ ...filters });
      const page = await action.cataloguePage(position, capturedFilters, owned.controller.signal);
      action.assertCurrent();
      if (alive.current && generation.current === token && presentationContext() === initial) {
        setObservation({ generation: token, context: initial, page, filters: capturedFilters }); setNotice('loaded');
      }
    } catch {
      if (alive.current && generation.current === token) { setObservation(undefined); setNotice('failed'); }
    } finally {
      owned?.controller.abort(); owned?.action.dispose();
      if (alive.current && generation.current === token) { active.current = undefined; setBusy(false); }
    }
  };
  return <section aria-labelledby={`${id}-heading`} className="rounded border p-4 space-y-4">
    <h2 id={`${id}-heading`} className="text-lg font-semibold">{t('ReleaseCataloguePanel.title')}</h2>
    <p>{t('ReleaseCataloguePanel.scope')}</p>
    <form onSubmit={event => {
      event.preventDefault(); void load({ limit }, { ...(platform ? { platform } : {}), ...(agentType ? { agent_type: agentType } : {}) });
    }}>
      <fieldset disabled={busy} className="flex flex-wrap items-end gap-4">
        <div className="flex min-w-40 flex-col gap-2"><label className="text-sm font-medium" htmlFor={`${id}-platform`}>{t('ReleaseCataloguePanel.platform')}</label>
          <select className={controlClassName} id={`${id}-platform`} value={platform} onChange={event => edit(() => setPlatform(event.target.value))}>
            <option value="">{t('ReleaseCataloguePanel.all')}</option>
            <option value="linux">linux</option><option value="windows">windows</option><option value="macos">macos</option>
          </select></div>
        <div className="flex min-w-40 flex-col gap-2"><label className="text-sm font-medium" htmlFor={`${id}-type`}>{t('ReleaseCataloguePanel.agentType')}</label>
          <select className={controlClassName} id={`${id}-type`} value={agentType} onChange={event => edit(() => setAgentType(event.target.value))}>
            <option value="">{t('ReleaseCataloguePanel.all')}</option><option value="daemon">daemon</option><option value="desktop">desktop</option>
          </select></div>
        <div className="flex min-w-32 flex-col gap-2"><label className="text-sm font-medium" htmlFor={`${id}-limit`}>{t('ReleaseCataloguePanel.pageSize')}</label>
          <select className={controlClassName} id={`${id}-limit`} value={limit} onChange={event => edit(() => setLimit(Number(event.target.value)))}>
            {[10, 25, 50, 100].map(value => <option key={value} value={value}>{value}</option>)}
          </select></div>
        <button className={buttonClassName} type="submit">{t('ReleaseCataloguePanel.loadFirst')}</button>
      </fieldset>
    </form>
    {busy && <button className={buttonClassName} type="button" onClick={() => {
      invalidate(); setObservation(undefined); setBusy(false); setNotice('cancelled');
    }}>{t('ReleaseCataloguePanel.cancel')}</button>}
    <p role={notice === 'failed' ? 'alert' : 'status'}>{t(`ReleaseCataloguePanel.notices.${notice}`)}</p>
    {downloadNotice && <p role={downloadNotice === 'requested' ? 'status' : 'alert'}>{t(`ReleaseCataloguePanel.downloadNotices.${downloadNotice}`)}</p>}
    {visible && <div className="space-y-3">
      <p>{t('ReleaseCataloguePanel.count', { count: visible.page.items.length })}</p>
      {!visible.page.items.length && <p>{t('ReleaseCataloguePanel.empty')}</p>}
      <div className="overflow-x-auto rounded-md border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" role="region" aria-label={t('ReleaseCataloguePanel.table')} tabIndex={0}>
        <table className="w-full min-w-[1180px] border-collapse text-sm [&_th]:px-4 [&_th]:py-3 [&_th]:text-left [&_th]:align-top [&_td]:px-4 [&_td]:py-3 [&_td]:align-top" aria-label={t('ReleaseCataloguePanel.table')}>
          <thead className="border-b bg-muted/40 [&_th]:whitespace-nowrap [&_th]:font-medium"><tr>{['identity', 'version', 'platform', 'agentType', 'organization', 'published', 'size', 'flags', 'metadata', 'download'].map(key =>
            <th scope="col" key={key}>{t(`ReleaseCataloguePanel.columns.${key}`)}</th>)}</tr></thead>
          <tbody className="divide-y">{visible.page.items.map(row => <tr key={row.id}>
            <th scope="row"><code className="block w-40 break-all text-xs font-normal leading-5">{row.id}</code></th>
            <td className="whitespace-nowrap">{row.version}</td><td className="whitespace-nowrap">{row.platform}</td><td className="whitespace-nowrap">{row.agent_type}</td>
            <td className="min-w-44 break-all font-mono text-xs leading-5">{row.organization_id ?? t('ReleaseCataloguePanel.platformScope')}</td>
            <td><time className="block min-w-40 break-words text-xs leading-5" dateTime={row.published_at}>{row.published_at}</time></td><td className="whitespace-nowrap tabular-nums">{row.file_size}</td>
            <td className="whitespace-nowrap">{row.is_latest && <span>{t('ReleaseCataloguePanel.latest')} </span>}
              {row.is_prerelease && <span>{t('ReleaseCataloguePanel.prerelease')}</span>}</td>
            <td><details><summary className="cursor-pointer whitespace-nowrap rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">{t('ReleaseCataloguePanel.details')}</summary>
              <dl className="mt-3 min-w-56 max-w-sm space-y-2 [&_dt]:font-medium [&_dd]:break-words">
                <dt>{t('ReleaseCataloguePanel.url')}</dt><dd className="break-all">{row.download_url}</dd>
                <dt>SHA-256</dt><dd><code>{row.checksum_sha256}</code></dd>
                <dt>{t('ReleaseCataloguePanel.signature')}</dt><dd className="break-all">{row.signature ?? t('ReleaseCataloguePanel.noSignature')}</dd>
                <dt>{t('ReleaseCataloguePanel.minimum')}</dt><dd>{row.min_backend_version || '—'}</dd>
                <dt>{t('ReleaseCataloguePanel.downloads')}</dt><dd>{row.download_count}</dd>
                <dt>{t('ReleaseCataloguePanel.notes')}</dt><dd className="whitespace-pre-wrap">{row.release_notes}</dd>
              </dl>
            </details></td>
            <td><button className={`${buttonClassName} min-w-36`} type="button" onClick={() => {
              // A -> B -> A in one React batch cannot reuse a stale row click.
              const current = () => alive.current && generation.current === visible.generation && presentationContext() === visible.context;
              try {
                if (!current()) return;
                requestReleaseBinaryDownload(row.id);
                if (current()) setDownloadNotice('requested');
              } catch { if (current()) setDownloadNotice('unconfirmed'); }
            }}>{t('ReleaseCataloguePanel.download')}</button></td>
          </tr>)}</tbody>
        </table>
      </div>
      <button className={buttonClassName} type="button" disabled={busy || !visible.page.has_more} onClick={() => {
        if (!visible.page.has_more || !visible.page.next_id || !visible.page.next_published_at) return;
        void load({ limit: visible.page.limit, before_id: visible.page.next_id,
          before_published_at: visible.page.next_published_at }, visible.filters);
      }}>{t('ReleaseCataloguePanel.next')}</button>
      <p>{t('ReleaseCataloguePanel.pagination')}</p>
    </div>}
  </section>;
}
