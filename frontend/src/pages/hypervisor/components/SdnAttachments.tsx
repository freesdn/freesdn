// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useId, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { hypervisorApi } from '@/lib/api';
import type { SdnAttachmentInspection } from '@/lib/api/hypervisor';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ErrorState } from '@/components/ui/empty-state';
import { Label } from '@/components/ui/label';

type Read = SdnAttachmentInspection['guests'][number];
const selectStyle = 'block w-full rounded-md border bg-background p-2 text-sm';

function ReadStatus({ read }: { read: Pick<Read, 'status' | 'reason' | 'observed_at' | 'omitted_fields'> }) {
  const { t } = useTranslation('hypervisor');
  return <div className="space-y-1 text-sm">
    <Badge variant="outline">{read.status === 'not_observed' ? t('SdnDependencies.notObserved') : t(`SdnInspection.status.${read.status}`)}</Badge>
    {read.reason && <p>{t(`SdnDependencies.reasons.${read.reason}`)}</p>}
    <p className="text-xs text-muted-foreground">{new Date(read.observed_at).toLocaleString()}</p>
    {!!read.omitted_fields && <p className="text-muted-foreground">{t('SdnInspection.omitted', { count: read.omitted_fields })}</p>}
  </div>;
}

export function SdnAttachments({ controllerId }: { controllerId: string }) {
  return <AttachmentPanel key={controllerId} controllerId={controllerId} />;
}

function AttachmentPanel({ controllerId }: { controllerId: string }) {
  const { t } = useTranslation('hypervisor');
  const id = useId();
  const [requested, setRequested] = useState(false);
  const [guestId, setGuestId] = useState('');
  const [node, setNode] = useState('');
  const [view, setView] = useState<Read['view']>('current');
  const query = useQuery({
    queryKey: ['hypervisor', 'sdn', 'attachments', controllerId],
    queryFn: () => hypervisorApi.inspectSdnAttachments(controllerId),
    enabled: requested && !!controllerId,
    retry: false, refetchOnWindowFocus: false, gcTime: 0,
  });
  const data = query.data?.data;
  const wrongController = data && data.controller_id !== controllerId;
  const visible = requested && !query.isFetching && !query.isError && !wrongController ? data : undefined;
  const guests = visible?.guests.filter(g => g.view === view) ?? [];
  const guest = guests.find(g => String(g.vmid) === guestId) ?? guests[0];
  const host = visible?.hosts.find(h => h.node === node) ?? visible?.hosts[0];
  return <Card>
    <CardHeader><CardTitle>{t('SdnAttachments.title')}</CardTitle></CardHeader>
    <CardContent className="space-y-4">
      <p className="text-sm text-muted-foreground">{t('SdnAttachments.boundary')}</p>
      <Button variant="outline" disabled={!controllerId || query.isFetching} onClick={() => {
        if (requested) void query.refetch(); else setRequested(true);
      }}>{t(requested ? 'SdnAttachments.refresh' : 'SdnAttachments.inspect')}</Button>
      {requested && query.isFetching && <p role="status">{t('SdnInspection.refreshing')}</p>}
      {requested && (query.isError || wrongController) && <ErrorState message={t('SdnInspection.failed')} />}
      {visible && <>
        <p className="text-sm">{t('SdnInspection.observed', { time: new Date(visible.finished_at).toLocaleString() })}</p>
        <Badge variant="outline">{t('SdnDependencies.reads', { used: visible.requests_made, limit: visible.request_limit })}</Badge>
        {visible.response_limit_reached && <p role="alert">{t('SdnDependencies.limited')}</p>}
        <div className="grid gap-3 sm:grid-cols-2">
          {(['guest_inventory', 'node_inventory'] as const).map(key => <section key={key} className="rounded border p-3">
            <h4 className="font-medium">{t(`SdnAttachments.${key}`)}</h4>
            <ReadStatus read={visible[key]} />
            {visible[key].status === 'available' && <p className="text-sm">{t('SdnAttachments.selection', { selected: visible[key].selected, total: visible[key].visible_count, omitted: visible[key].omitted_by_limit, limit: visible[key].selection_limit })}</p>}
          </section>)}
        </div>
        <p className="text-sm text-muted-foreground">{t('SdnAttachments.coverage')}</p>
        <div className="grid gap-3 sm:grid-cols-2">
          {visible.vnets.map(v => <section key={v.view} className="rounded border p-3">
            <h4 className="font-medium">{t('SdnAttachments.vnets', { view: t(`SdnInspection.views.${v.view}`) })}</h4>
            <ReadStatus read={v} />
            {v.status === 'available' && v.identities != null && <p className="text-sm">{t('SdnAttachments.visibleVnets', { count: v.identities.length })}</p>}
          </section>)}
        </div>
        <p className="text-sm text-muted-foreground">{t('SdnAttachments.guestBoundary')}</p>
        <div className="grid gap-3 sm:grid-cols-2">
          <div><Label htmlFor={id + '-guest'}>{t('SdnAttachments.guest')}</Label>
            <select id={id + '-guest'} className={selectStyle} value={guest?.vmid ?? ''} disabled={!guests.length} onChange={e => setGuestId(e.target.value)}>
              {!guests.length && <option value="">{t('SdnAttachments.noGuest')}</option>}
              {guests.map(g => <option key={g.vmid} value={g.vmid}>{g.guest_type} {g.vmid} · {g.node}</option>)}
            </select></div>
          <div><Label htmlFor={id + '-view'}>{t('SdnAttachments.view')}</Label>
            <select id={id + '-view'} className={selectStyle} value={view} onChange={e => setView(e.target.value as Read['view'])}>
              {(['current', 'pending_merged'] as const).map(v => <option key={v} value={v}>{t(`SdnAttachments.views.${v}`)}</option>)}
            </select></div>
        </div>
        {guest && <section className="space-y-2 rounded border p-3">
          <ReadStatus read={guest} />
          {guest.status === 'available' && guest.nics != null && <>
            {guest.nics.length === 0 && <p>{t('SdnAttachments.noNics')}</p>}
            {guest.nics.map(nic => <div key={nic.key} className="space-y-1 rounded bg-muted p-3 text-sm">
              <p className="font-medium break-all">{nic.key} → {nic.bridge ?? t('SdnAttachments.noBridge')}</p>
              {nic.tag != null && <p>{t('SdnAttachments.tag', { tag: nic.tag })}</p>}
              {nic.trunks != null && <p className="break-all">{t('SdnAttachments.trunks', { trunks: nic.trunks })}</p>}
              {(['link_down', 'firewall'] as const).map(key => nic[key] != null && <p key={key}>{t(`SdnAttachments.${key}`, { value: t(nic[key] ? 'SdnAttachments.yes' : 'SdnAttachments.no') })}</p>)}
              {(['configured_vnet', 'running_vnet', 'host_interface'] as const).map(key => <p key={key}>{t(`SdnAttachments.targets.${key}`)}: {t(`SdnAttachments.match.${nic[key] ?? 'not_observed'}`)}</p>)}
              {!!nic.omitted_options && <p className="text-muted-foreground">{t('SdnAttachments.omittedOptions', { count: nic.omitted_options })}</p>}
            </div>)}
          </>}
        </section>}
        <p className="text-sm text-muted-foreground">{t('SdnAttachments.hostBoundary')}</p>
        <div><Label htmlFor={id + '-node'}>{t('SdnAttachments.node')}</Label>
          <select id={id + '-node'} className={selectStyle} value={host?.node ?? ''} disabled={!visible.hosts.length} onChange={e => setNode(e.target.value)}>
            {!visible.hosts.length && <option value="">{t('SdnAttachments.noHost')}</option>}
            {visible.hosts.map(h => <option key={h.node} value={h.node}>{h.node}</option>)}
          </select></div>
        {host && <section className="space-y-2 rounded border p-3">
          <ReadStatus read={host} />
          {host.status === 'available' && host.interfaces != null && <>
            {host.interfaces.length === 0 && <p>{t('SdnInspection.empty')}</p>}
            {host.interfaces.slice(0, 50).map(iface => <div key={iface.iface} className="rounded bg-muted p-3 text-sm">
              <p className="font-medium break-all">{iface.iface} · {iface.interface_type}</p>
              {(['active', 'exists'] as const).map(key => iface[key] != null && <p key={key}>{t(`SdnAttachments.${key}`, { value: t(iface[key] ? 'SdnAttachments.yes' : 'SdnAttachments.no') })}</p>)}
              {(['bridge_ports', 'slaves', 'ovs_ports', 'ovs_bonds'] as const).map(key => iface[key] != null && <p key={key} className="break-all">{key}: {iface[key]?.join(', ') || t('SdnAttachments.noMembers')}</p>)}
              {iface.vlan_raw_device && <p className="break-all">vlan-raw-device: {iface.vlan_raw_device}</p>}
            </div>)}
            {host.interfaces.length > 50 && <p>{t('SdnDependencies.displayLimit', { limit: 50, total: host.interfaces.length })}</p>}
          </>}
        </section>}
      </>}
    </CardContent>
  </Card>;
}
