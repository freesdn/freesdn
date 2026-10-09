// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useId, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { hypervisorApi } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ErrorState } from '@/components/ui/empty-state';
import { Label } from '@/components/ui/label';
import type { SdnDependencyInspection } from '@/lib/api/hypervisor';

type Resource = SdnDependencyInspection['collections'][number]['resource'];
type View = SdnDependencyInspection['collections'][number]['view'];
const resources: Resource[] = ['zones', 'vnets', 'controllers', 'subnets', 'ipams', 'dns', 'fabrics', 'fabric-nodes', 'prefix-lists', 'route-maps', 'prefix-list-entries', 'route-map-entries'];
const views: View[] = ['configured', 'running', 'pending'];

export function SdnDependencies({ controllerId }: { controllerId: string }) {
  return <DependencyPanel key={controllerId} controllerId={controllerId} />;
}

function DependencyPanel({ controllerId }: { controllerId: string }) {
  const { t } = useTranslation('hypervisor');
  const id = useId();
  const [requested, setRequested] = useState(false);
  const [resource, setResource] = useState<Resource>('subnets');
  const [view, setView] = useState<View>('configured');
  const query = useQuery({
    queryKey: ['hypervisor', 'sdn', 'dependencies', controllerId],
    queryFn: () => hypervisorApi.inspectSdnDependencies(controllerId),
    enabled: requested && !!controllerId,
    retry: false, refetchOnWindowFocus: false, gcTime: 0,
  });
  const data = query.data?.data;
  const wrongController = data && data.controller_id !== controllerId;
  const visible = requested && !query.isFetching && !query.isError && !wrongController ? data : undefined;
  const collections = visible?.collections.filter(c => c.resource === resource && c.view === view) ?? [];
  const references = visible?.references.filter(r => r.source_resource === resource && r.view === view) ?? [];
  return <Card>
    <CardHeader><CardTitle>{t('SdnDependencies.title')}</CardTitle></CardHeader>
    <CardContent className="space-y-4">
      <p className="text-sm text-muted-foreground">{t('SdnDependencies.boundary')}</p>
      <Button variant="outline" disabled={!controllerId || query.isFetching} onClick={() => {
        if (requested) void query.refetch(); else setRequested(true);
      }}>{t(requested ? 'SdnDependencies.refresh' : 'SdnDependencies.inspect')}</Button>
      {requested && query.isFetching && <p role="status">{t('SdnInspection.refreshing')}</p>}
      {requested && (query.isError || wrongController) && <ErrorState message={t('SdnInspection.failed')} />}
      {visible && <>
        <p className="text-sm">{t('SdnInspection.observed', { time: new Date(visible.finished_at).toLocaleString() })}</p>
        <div className="flex flex-wrap gap-2">
          <Badge variant="outline">{t(`SdnInspection.pending.${visible.pending_state}`)}</Badge>
          <Badge variant="outline">{t('SdnDependencies.reads', { used: visible.requests_made, limit: visible.request_limit })}</Badge>
        </div>
        <p className="text-sm">{t('SdnDependencies.parents', { selected: visible.subnet_parents_selected, omitted: visible.subnet_parents_omitted_by_limit, limit: visible.subnet_parent_limit })}</p>
        {visible.response_limit_reached && <p role="alert" className="text-sm text-warning">{t('SdnDependencies.limited')}</p>}
        <p className="text-sm text-muted-foreground">{visible.unobserved_dependencies?.length ? t('SdnDependencies.unobserved', { resources: visible.unobserved_dependencies.map(name => t(`SdnDependencies.unobservedNames.${name}`)).join(', ') }) : t('SdnDependencies.unobservedFallback')}</p>
        <div className="grid gap-3 sm:grid-cols-2">
          <div><Label htmlFor={id + '-resource'}>{t('SdnDependencies.resource')}</Label>
            <select id={id + '-resource'} value={resource} onChange={event => setResource(event.target.value as Resource)} className="block w-full rounded-md border bg-background p-2 text-sm">
              {resources.map(name => <option key={name} value={name}>{t(`SdnDependencies.resources.${name}`)}</option>)}
            </select>
          </div>
          <div><Label htmlFor={id + '-view'}>{t('SdnDependencies.view')}</Label>
            <select id={id + '-view'} value={view} onChange={event => setView(event.target.value as View)} className="block w-full rounded-md border bg-background p-2 text-sm">
              {views.map(name => <option key={name} value={name}>{t(`SdnInspection.views.${name}`)}</option>)}
            </select>
          </div>
        </div>
        {collections.length === 0 && <p>{t('SdnDependencies.noCollection')}</p>}
        {collections.map((c, index) => <section key={`${c.parent_id ?? ''}-${index}`} className="space-y-2 rounded-md border p-3">
          {c.parent_id && <h4 className="font-medium">{t('SdnDependencies.parent', { name: c.parent_id })}</h4>}
          <Badge variant="outline">{c.status === 'not_observed' ? t('SdnDependencies.notObserved') : t(`SdnInspection.status.${c.status}`)}</Badge>
          {c.reason && <p className="text-sm">{t(`SdnDependencies.reasons.${c.reason}`)}</p>}
          {(c.resource === 'prefix-list-entries' || c.resource === 'route-map-entries') && <p className="text-sm text-muted-foreground">{t('SdnDependencies.policyBoundary')}</p>}
          {(c.resource === 'fabrics' || c.resource === 'fabric-nodes') && <p className="text-sm text-muted-foreground">{t('SdnDependencies.fabricBoundary')}</p>}
          {c.content_scope === 'identities_only' && <p className="text-sm text-muted-foreground">{t('SdnDependencies.identitiesOnly')}</p>}
          {c.status === 'available' && c.items != null && <>
            {c.items.length === 0 && <p>{t('SdnInspection.empty')}</p>}
            {c.items.slice(0, 50).map((row, rowIndex) => <DependencyRow key={rowIndex} row={row} nested={c.resource === 'prefix-list-entries' || c.resource === 'route-map-entries' || c.resource === 'fabric-nodes'} />)}
            {c.items.length > 50 && <p>{t('SdnDependencies.displayLimit', { limit: 50, total: c.items.length })}</p>}
            {c.omitted_fields > 0 && <p className="text-sm text-muted-foreground">{t('SdnInspection.omitted', { count: c.omitted_fields })}</p>}
          </>}
          <p className="text-xs text-muted-foreground">{new Date(c.observed_at).toLocaleString()}</p>
        </section>)}
        <div className="space-y-2">
          <h4 className="font-medium">{t('SdnDependencies.references')}</h4>
          <p className="text-sm text-muted-foreground">{t('SdnDependencies.referenceBoundary')}</p>
          {references.length === 0 && <p className="text-sm">{t('SdnDependencies.noReferences')}</p>}
          {references.slice(0, 100).map((ref, index) => <div key={index} className="rounded border p-2 text-sm">
            <p className="break-all">{ref.source_id} · {ref.field} → {ref.target_resource}/{ref.target_id}</p>
            <p>{t(`SdnDependencies.referenceStatus.${ref.status}`)} · {t(`SdnInspection.views.${ref.target_view}`)}</p>
          </div>)}
          {references.length > 100 && <p>{t('SdnDependencies.displayLimit', { limit: 100, total: references.length })}</p>}
        </div>
      </>}
    </CardContent>
  </Card>;
}


function DependencyRow({ row, nested }: { row: Record<string, unknown>; nested: boolean }) {
  const { t } = useTranslation('hypervisor');
  const shown = { ...row };
  const overlay = row.pending && typeof row.pending === 'object' && !Array.isArray(row.pending) ? row.pending as Record<string, unknown> : undefined;
  const limits: { field: string; total: number }[] = [];
  if (nested) {
    if (overlay) shown.pending = { ...overlay };
    for (const [prefix, object] of [['', shown], ['pending.', shown.pending]] as const) {
      if (!object || typeof object !== 'object' || Array.isArray(object)) continue;
      const fields = object as Record<string, unknown>;
      for (const field of ['entries', 'match', 'set', 'interfaces', 'peers']) {
        const value = fields[field];
        if (Array.isArray(value) && value.length > 50) {
          limits.push({ field: prefix + field, total: value.length });
          fields[field] = value.slice(0, 50);
        }
      }
    }
  }
  return <div className="space-y-1">
    {(row.details_status === 'unsupported_protocol' || overlay?.details_status === 'unsupported_protocol') && <p className="text-sm text-warning">{t('SdnDependencies.unsupportedFabricProtocol')}</p>}
    <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-muted p-2 text-xs">{JSON.stringify(shown, null, 2)}</pre>
    {limits.map(limit => <p key={limit.field} className="text-sm">{t('SdnDependencies.nestedDisplayLimit', { field: limit.field, total: limit.total, limit: 50 })}</p>)}
  </div>;
}
