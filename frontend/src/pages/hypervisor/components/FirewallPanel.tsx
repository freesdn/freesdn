// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { hypervisorApi } from '@/lib/api';
import type { FirewallReviewIntent, FirewallTarget, FirewallRuleSettings } from '@/lib/api/hypervisor';
import { useUIStore } from '@/stores';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { PendingChangesDrawer } from '@/components/gateways/PendingChangesDrawer';
import { FirewallOperationDialog } from './dialogs/FirewallOperationDialog';

type Props = { controllerId: string; nodes?: { node: string }[]; guest?: { node: string; vm_type: string; vmid: number } };
export function FirewallPanel({ controllerId, nodes = [], guest }: Props) {
  const { t } = useTranslation('hypervisor');
  const readOnly = useUIStore((s) => s.readOnlyMode);
  const client = useQueryClient();
  const [scopeNode, setScopeNode] = useState('');
  const [intent, setIntent] = useState<{ controllerId: string; value: FirewallReviewIntent } | null>(null);
  const [trackedController, setTrackedController] = useState<string | null>(null);
  const [rule, setRule] = useState<FirewallRuleSettings>({ action: 'ACCEPT', type: 'in', enable: false });
  const invalidGuest = !!guest && guest.vm_type !== 'qemu' && guest.vm_type !== 'lxc';
  const target: FirewallTarget = guest
    ? { scope: 'guest', node: guest.node, vm_type: guest.vm_type as 'qemu' | 'lxc', vmid: guest.vmid }
    : scopeNode ? { scope: 'node', node: scopeNode } : { scope: 'cluster' };
  const query = useQuery({ queryKey: ['hypervisor', 'reviewed-firewall', controllerId, target], enabled: !!controllerId && !invalidGuest,
    queryFn: () => target.scope === 'guest'
      ? hypervisorApi.getGuestFirewallRules(controllerId, target.node!, target.vm_type!, target.vmid!)
      : target.scope === 'node' ? hypervisorApi.getNodeFirewallRules(controllerId, target.node!) : hypervisorApi.getClusterFirewallRules(controllerId),
  });
  const rules: { pos: number; type: string; action: string; enable: boolean | number; source?: string; dest?: string; dport?: string; comment?: string }[] = query.data?.data ?? [];
  const select = (value: Omit<FirewallReviewIntent, 'target'>) => setIntent({ controllerId, value: { target, ...value } });
  const blocked = readOnly || invalidGuest || query.isLoading || query.isError;
  return <div className="space-y-4">
    <p className="text-sm text-muted-foreground">{t('FirewallOps.warning')}</p>
    {!guest && <label className="flex gap-3 items-center">{t('FirewallOps.scope')}<select className="bg-background border rounded p-2" value={scopeNode} onChange={(e) => setScopeNode(e.target.value)}>
      <option value="">{t('FirewallOps.cluster')}</option>{nodes.map((n) => <option key={n.node} value={n.node}>{n.node}</option>)}
    </select></label>}
    <div className="flex flex-wrap gap-2">
      <Button variant="outline" disabled={invalidGuest} onClick={() => void query.refetch()}>{t('FirewallOps.refresh')}</Button>
      <Button variant="outline" onClick={() => setTrackedController(controllerId)}>{t('FirewallOps.pending')}</Button>
      <Button variant="outline" disabled={blocked} onClick={() => select({ action: 'options', options: { enable: true } })}>{t('FirewallOps.enable')}</Button>
      <Button variant="outline" disabled={blocked} onClick={() => select({ action: 'options', options: { enable: false } })}>{t('FirewallOps.disable')}</Button>
    </div>
    <div className="grid gap-2 sm:grid-cols-3">
      <label>{t('HypervisorPage.firewall.action')}<select className="block border rounded p-2 bg-background" value={rule.action} onChange={(e) => setRule({ ...rule, action: e.target.value })}>{['ACCEPT', 'DROP', 'REJECT'].map((v) => <option key={v}>{v}</option>)}</select></label>
      <label>{t('HypervisorPage.firewallDialog.direction')}<select className="block border rounded p-2 bg-background" value={rule.type ?? 'in'} onChange={(e) => setRule({ ...rule, type: e.target.value as 'in' | 'out' })}><option value="in">in</option><option value="out">out</option></select></label>
      <label className="flex gap-2 items-center"><input type="checkbox" checked={rule.enable ?? false} onChange={(e) => setRule({ ...rule, enable: e.target.checked })} />{t('HypervisorPage.backup.enabled')}</label>
      {(['source', 'dest', 'dport', 'proto', 'comment'] as const).map((key) => <label key={key}>{t(`FirewallOps.fields.${key}`)}<Input value={rule[key] ?? ''} onChange={(e) => setRule({ ...rule, [key]: e.target.value || null })} /></label>)}
      <Button disabled={blocked} onClick={() => select({ action: 'create', rule })}>{t('FirewallOps.add')}</Button>
    </div>
    {query.isLoading && <p role="status">{t('FirewallOps.loading')}</p>}
    {(query.isError || invalidGuest) && <p role="alert" className="text-destructive">{t('HypervisorPage.firewall.loadError')}</p>}
    {!invalidGuest && !query.isLoading && !query.isError && rules.length === 0 && <p>{t('HypervisorPage.firewall.emptyTitle')}</p>}
    {!invalidGuest && !query.isError && <div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr>
      <th>#</th><th>{t('HypervisorPage.firewallDialog.direction')}</th><th>{t('HypervisorPage.firewall.action')}</th><th>{t('FirewallOps.fields.source')}</th><th>{t('FirewallOps.fields.dest')}</th><th>{t('FirewallOps.fields.dport')}</th><th>{t('HypervisorPage.backup.enabled')}</th><th>{t('FirewallOps.fields.comment')}</th><th>{t('FirewallOps.actions')}</th>
    </tr></thead><tbody>{rules.map((row) => <tr key={row.pos} className="border-t">
      <td>{row.pos}</td><td>{row.type}</td><td>{row.action}</td><td>{row.source || '—'}</td><td>{row.dest || '—'}</td><td>{row.dport || '—'}</td><td>{row.enable === true || row.enable === 1 ? t('HypervisorPage.common.yes') : t('HypervisorPage.common.no')}</td><td>{row.comment || '—'}</td>
      <td><div className="flex gap-1">
        {(row.type === 'in' || row.type === 'out') && <Button size="sm" variant="outline" disabled={blocked} onClick={() => select({ action: 'update', pos: row.pos, rule: { action: row.action, type: row.type as 'in' | 'out', enable: !(row.enable === true || row.enable === 1) } })}>{t('FirewallOps.toggle')}</Button>}
        {row.pos > 0 && <Button size="sm" variant="outline" disabled={blocked} onClick={() => select({ action: 'move', pos: row.pos, moveto: 0 })}>{t('FirewallOps.first')}</Button>}
        <Button size="sm" variant="destructive" disabled={blocked} onClick={() => select({ action: 'delete', pos: row.pos })}>{t('FirewallOps.delete')}</Button></div></td>
    </tr>)}</tbody></table></div>}
    {intent && <FirewallOperationDialog controllerId={controllerId} originControllerId={intent.controllerId} currentTarget={target} intent={intent.value} onClose={() => setIntent(null)} onTracked={() => {
      setTrackedController(intent.controllerId); setIntent(null); void client.invalidateQueries({ queryKey: ['hypervisor', 'reviewed-firewall'] });
    }} />}
    {trackedController && <PendingChangesDrawer open onOpenChange={(open) => { if (!open) setTrackedController(null); }} vendor="proxmox" gatewayId={trackedController} gatewayName={trackedController} onApplied={() => void query.refetch()} />}
  </div>;
}
