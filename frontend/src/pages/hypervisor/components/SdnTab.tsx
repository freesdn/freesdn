// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Network, RefreshCw } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState } from '@/components/ui/empty-state';
import { hypervisorApi } from '@/lib/api';
import { SdnDependencies } from './SdnDependencies';
import { SdnAttachments } from './SdnAttachments';

export function SdnTab({ controllerId }: { controllerId: string }) {
  // Remount local node selection and results when the operator changes cluster.
  return <SdnInspectionPanel key={controllerId} controllerId={controllerId} />;
}

function SdnInspectionPanel({ controllerId }: { controllerId: string }) {
  const { t } = useTranslation('hypervisor');
  const [node, setNode] = useState('');
  const [requestedNode, setRequestedNode] = useState('');
  const snapshot = useQuery({
    queryKey: ['hypervisor', 'sdn', 'inspection', controllerId],
    queryFn: () => hypervisorApi.inspectSdn(controllerId),
    enabled: !!controllerId, retry: false, refetchOnWindowFocus: false,
  });
  const preview = useQuery({
    queryKey: ['hypervisor', 'sdn', 'dry-run', controllerId, requestedNode],
    queryFn: () => hypervisorApi.getSdnDryRun(controllerId, requestedNode),
    enabled: !!controllerId && !!requestedNode, retry: false, refetchOnWindowFocus: false,
    gcTime: 0,
  });
  const data = snapshot.data?.data;
  const dryRun = preview.data?.data;
  const validNode = /^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$/.test(node) && !node.includes('..');
  const showPreview = requestedNode !== '' && node === requestedNode;
  return <div className="space-y-4">
    <div className="flex items-center justify-between gap-2">
      <h3 className="flex items-center gap-2 font-semibold"><Network className="h-5 w-5" />{t('SdnInspection.title')}</h3>
      <Button variant="outline" disabled={!controllerId || snapshot.isFetching} onClick={() => void snapshot.refetch()}>
        <RefreshCw className="mr-2 h-4 w-4" />{t('SdnInspection.refresh')}
      </Button>
    </div>
    <div role="note" className="rounded-md border border-warning/40 bg-warning/10 p-3 text-sm space-y-2">
      <p className="font-medium">{t('SdnInspection.writeBoundary')}</p>
      <p>{t('SdnInspection.visibility')}</p>
      <p>{t('SdnInspection.recovery')}</p>
    </div>
    {snapshot.isPending && controllerId && <Skeleton className="h-32" />}
    {(snapshot.isError || (data && data.controller_id !== controllerId)) && <ErrorState message={t('SdnInspection.failed')} />}
    {!snapshot.isError && data?.controller_id === controllerId && <>
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Badge variant="outline">{t(`SdnInspection.pending.${data.pending_state}`)}</Badge>
        <span>{t('SdnInspection.observed', { time: new Date(data.finished_at).toLocaleString() })}</span>
        {snapshot.isFetching && <span>{t('SdnInspection.refreshing')}</span>}
      </div>
      <p className="text-sm text-muted-foreground">{t('SdnInspection.permissions', {
        status: t(`SdnInspection.status.${data.permissions_status}`),
        audit: data.audit_at_sdn == null ? t('SdnInspection.unknown') : String(data.audit_at_sdn),
        allocate: data.allocate_at_sdn == null ? t('SdnInspection.unknown') : String(data.allocate_at_sdn),
      })}</p>
      <p className="text-sm text-muted-foreground">{t('SdnInspection.unobserved', { resources: (data.unobserved_resources ?? []).join(', ') })}</p>
      {data.resources.map(resource => <section key={resource.resource} aria-label={t(`SdnInspection.resources.${resource.resource}`)} className="space-y-2">
        <h4 className="font-medium">{t(`SdnInspection.resources.${resource.resource}`)}</h4>
        <div className="grid gap-3 xl:grid-cols-3">
          {(['configured', 'running', 'pending'] as const).map(view => {
            const observation = resource[view];
            return <Card key={view}>
              <CardHeader className="pb-2"><CardTitle className="text-sm">{t(`SdnInspection.views.${view}`)}</CardTitle></CardHeader>
              <CardContent className="space-y-2 text-sm">
                <Badge variant="outline">{t(`SdnInspection.status.${observation.status}`)}</Badge>
                {observation.status === 'available' && observation.items != null && <>
                  {observation.items.length === 0 && <p>{t('SdnInspection.empty')}</p>}
                  {observation.items.map((row, index) => <pre key={index} className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded bg-muted p-2 text-xs">{JSON.stringify(row, null, 2)}</pre>)}
                  {observation.omitted_fields > 0 && <p className="text-muted-foreground">{t('SdnInspection.omitted', { count: observation.omitted_fields })}</p>}
                </>}
                <p className="text-xs text-muted-foreground">{new Date(observation.observed_at).toLocaleString()}</p>
              </CardContent>
            </Card>;
          })}
        </div>
      </section>)}
    </>}
    <SdnDependencies controllerId={controllerId} />
    <SdnAttachments controllerId={controllerId} />
    <Card>
      <CardHeader><CardTitle className="text-sm">{t('SdnInspection.dryRun')}</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm text-muted-foreground">{t('SdnInspection.diffBoundary')}</p>
        <Label htmlFor="sdn-preview-node">{t('SdnInspection.node')}</Label>
        <div className="flex gap-2">
          <Input id="sdn-preview-node" value={node} onChange={event => { setNode(event.target.value); setRequestedNode(''); }} placeholder="pve1" maxLength={63} />
          <Button variant="outline" disabled={!controllerId || !validNode || preview.isFetching} onClick={() => {
            if (requestedNode === node) void preview.refetch(); else setRequestedNode(node);
          }}>{t('SdnInspection.preview')}</Button>
        </div>
        {showPreview && preview.isFetching && <p>{t('SdnInspection.refreshing')}</p>}
        {showPreview && (preview.isError || (dryRun && (dryRun.controller_id !== controllerId || dryRun.node !== requestedNode))) && <ErrorState message={t('SdnInspection.failed')} />}
        {showPreview && !preview.isError && dryRun?.controller_id === controllerId && dryRun.node === requestedNode && <div className="space-y-2" role="status">
          <p>{requestedNode}: {t(`SdnInspection.status.${dryRun.status}`)}</p>
          {dryRun.status === 'available' && (['interfaces', 'frr'] as const).map(kind => {
            const diff = dryRun[kind];
            return diff && <p key={kind}>{t(`SdnInspection.${kind}`)}: {t(diff.changed ? 'SdnInspection.changed' : 'SdnInspection.unchanged')} ({t('SdnInspection.lines', { added: diff.added_lines, removed: diff.removed_lines })})</p>;
          })}
          <p className="text-xs text-muted-foreground">{t('SdnInspection.observed', { time: new Date(dryRun.observed_at).toLocaleString() })}</p>
        </div>}
      </CardContent>
    </Card>
  </div>;
}
