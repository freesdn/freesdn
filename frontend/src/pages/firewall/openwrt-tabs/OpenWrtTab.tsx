// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * OpenWrt Gateway Tab
 * ====================
 *
 * Single consolidated tab rendered when ``gw.vendor === 'openwrt'``.
 * Wraps the 6 read endpoints (device-info / interfaces / firewall-rules /
 * port-forwards / dhcp-leases / arp-table) into an internal sub-tab
 * navigation so the operator gets the full surface without leaving
 * the gateway detail page.
 *
 * Writes will land in a follow-up commit, the backend adapter has
 * full CRUD but each write endpoint needs its own staged-change
 * registration in the apply pipeline (same pattern as MikroTik /
 * OPNsense / pfSense).
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Cpu, Network, ShieldCheck, ArrowLeftRight, Wifi, MemoryStick,
  RefreshCw, Server, AlertTriangle, CheckCircle2, XCircle,
  Plus, Trash2, BookmarkPlus,
} from 'lucide-react';
import { openwrtApi } from '@/lib/api/openwrt';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

type SubTab =
  | 'overview'
  | 'interfaces'
  | 'firewall'
  | 'port-forwards'
  | 'dhcp'
  | 'dhcp-static'
  | 'arp';

const SUB_TABS: { key: SubTab; labelKey: string; icon: typeof Cpu }[] = [
  { key: 'overview', labelKey: 'tabs.overview', icon: Cpu },
  { key: 'interfaces', labelKey: 'tabs.interfaces', icon: Network },
  { key: 'firewall', labelKey: 'tabs.firewall', icon: ShieldCheck },
  { key: 'port-forwards', labelKey: 'tabs.portForwards', icon: ArrowLeftRight },
  { key: 'dhcp', labelKey: 'tabs.dhcpLeases', icon: Wifi },
  { key: 'dhcp-static', labelKey: 'tabs.dhcpStatic', icon: BookmarkPlus },
  { key: 'arp', labelKey: 'tabs.arp', icon: MemoryStick },
];

function formatUptime(seconds?: number): string {
  if (!seconds) return '-';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function formatBytes(b?: number): string {
  if (!b) return '-';
  if (b >= 1e9) return `${(b / 1e9).toFixed(2)} GB`;
  if (b >= 1e6) return `${(b / 1e6).toFixed(1)} MB`;
  if (b >= 1e3) return `${(b / 1e3).toFixed(0)} KB`;
  return `${b} B`;
}

type RuleDraft = { name: string; src: string; target: string; proto: string; dest_port: string };
type PfDraft = { name: string; src: string; proto: string; src_dport: string; dest_ip: string; dest_port: string };
type HostDraft = { hostname: string; mac_address: string; ip_address: string };

const EMPTY_RULE: RuleDraft = { name: '', src: 'wan', target: 'ACCEPT', proto: 'tcp', dest_port: '' };
const EMPTY_PF: PfDraft = { name: '', src: 'wan', proto: 'tcp', src_dport: '', dest_ip: '', dest_port: '' };
const EMPTY_HOST: HostDraft = { hostname: '', mac_address: '', ip_address: '' };

export function OpenWrtTab({ controllerId }: { controllerId: string }) {
  const { t } = useTranslation('firewall');
  const [sub, setSub] = useState<SubTab>('overview');
  const { toast } = useToast();
  const qc = useQueryClient();

  // Write dialogs, keep the "draft" close to the dialog open state so a
  // canceled create doesn't leak typed values into the next open.
  const [ruleDialog, setRuleDialog] = useState<RuleDraft | null>(null);
  const [pfDialog, setPfDialog] = useState<PfDraft | null>(null);
  const [hostDialog, setHostDialog] = useState<HostDraft | null>(null);

  const stagedToast = (msg: string) =>
    toast({
      title: t('OpenWrtTab.toasts.staged.title'),
      description: t('OpenWrtTab.toasts.staged.description', { msg }),
    });

  const stageRule = useMutation({
    mutationFn: (input: {
      op: 'create' | 'delete';
      payload: Record<string, unknown>;
      targetId?: string;
    }) =>
      openwrtApi.stageFirewallRule(
        controllerId, input.op, input.payload, input.targetId,
      ),
    onSuccess: (_, vars) => {
      stagedToast(vars.op === 'delete' ? t('OpenWrtTab.staged.deleteRule') : t('OpenWrtTab.staged.newRule'));
      qc.invalidateQueries({ queryKey: ['openwrt-firewall', controllerId] });
      // Bump the pending-changes badge that lives in GatewayDetailPage.
      qc.invalidateQueries({ queryKey: ['pending-changes', 'openwrt', controllerId] });
    },
    onError: (err: any) =>
      toast({
        title: t('OpenWrtTab.toasts.stageFailed.title'),
        description: err?.response?.data?.detail || err?.message || t('OpenWrtTab.toasts.stageFailed.unknown'),
        variant: 'destructive',
      }),
  });

  const stagePf = useMutation({
    mutationFn: (input: {
      op: 'create' | 'delete';
      payload: Record<string, unknown>;
      targetId?: string;
    }) =>
      openwrtApi.stagePortForward(
        controllerId, input.op, input.payload, input.targetId,
      ),
    onSuccess: (_, vars) => {
      stagedToast(vars.op === 'delete' ? t('OpenWrtTab.staged.deletePortForward') : t('OpenWrtTab.staged.newPortForward'));
      qc.invalidateQueries({ queryKey: ['openwrt-port-forwards', controllerId] });
      qc.invalidateQueries({ queryKey: ['pending-changes', 'openwrt', controllerId] });
    },
    onError: (err: any) =>
      toast({
        title: t('OpenWrtTab.toasts.stageFailed.title'),
        description: err?.response?.data?.detail || err?.message || t('OpenWrtTab.toasts.stageFailed.unknown'),
        variant: 'destructive',
      }),
  });

  const stageHost = useMutation({
    mutationFn: (input: {
      op: 'create' | 'delete';
      payload: Record<string, unknown>;
      targetId?: string;
    }) =>
      openwrtApi.stageDhcpStaticHost(
        controllerId, input.op, input.payload, input.targetId,
      ),
    onSuccess: (_, vars) => {
      stagedToast(vars.op === 'delete' ? t('OpenWrtTab.staged.deleteStaticHost') : t('OpenWrtTab.staged.newStaticHost'));
      qc.invalidateQueries({ queryKey: ['openwrt-dhcp-static', controllerId] });
      qc.invalidateQueries({ queryKey: ['pending-changes', 'openwrt', controllerId] });
    },
    onError: (err: any) =>
      toast({
        title: t('OpenWrtTab.toasts.stageFailed.title'),
        description: err?.response?.data?.detail || err?.message || t('OpenWrtTab.toasts.stageFailed.unknown'),
        variant: 'destructive',
      }),
  });

  const deviceInfoQ = useQuery({
    queryKey: ['openwrt-device-info', controllerId],
    queryFn: () => openwrtApi.getDeviceInfo(controllerId),
    refetchInterval: 30_000,
    staleTime: 10_000,
  });
  const interfacesQ = useQuery({
    queryKey: ['openwrt-interfaces', controllerId],
    queryFn: () => openwrtApi.listInterfaces(controllerId),
    refetchInterval: 30_000,
    enabled: sub === 'overview' || sub === 'interfaces',
  });
  const firewallQ = useQuery({
    queryKey: ['openwrt-firewall', controllerId],
    queryFn: () => openwrtApi.listFirewallRules(controllerId),
    enabled: sub === 'firewall',
  });
  const pfQ = useQuery({
    queryKey: ['openwrt-port-forwards', controllerId],
    queryFn: () => openwrtApi.listPortForwards(controllerId),
    enabled: sub === 'port-forwards',
  });
  const dhcpQ = useQuery({
    queryKey: ['openwrt-dhcp', controllerId],
    queryFn: () => openwrtApi.listDhcpLeases(controllerId),
    refetchInterval: 30_000,
    enabled: sub === 'dhcp',
  });
  const arpQ = useQuery({
    queryKey: ['openwrt-arp', controllerId],
    queryFn: () => openwrtApi.listArpTable(controllerId),
    refetchInterval: 30_000,
    enabled: sub === 'arp',
  });
  const dhcpStaticQ = useQuery({
    queryKey: ['openwrt-dhcp-static', controllerId],
    queryFn: () => openwrtApi.listDhcpStaticMappings(controllerId),
    enabled: sub === 'dhcp-static',
  });

  const info = deviceInfoQ.data?.data?.info;
  const memTotal = info?.memory?.total;
  const memAvail = info?.memory?.available;
  const memUsedPct = memTotal && memAvail
    ? Math.round(((memTotal - memAvail) / memTotal) * 100)
    : null;

  // ── Sub-tab content renderers ────────────────────────────────────

  const overview = (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2">
            <Server className="h-4 w-4 text-primary" /> {t('OpenWrtTab.overview.system')}
          </CardTitle>
        </CardHeader>
        <CardContent noOffset className="px-4 pb-3 space-y-1.5 text-sm">
          <Row label={t('OpenWrtTab.overview.hostname')} value={info?.hostname} mono />
          <Row label={t('OpenWrtTab.overview.model')} value={info?.model} />
          <Row label={t('OpenWrtTab.overview.openwrtVersion')} value={info?.version} mono />
          <Row label={t('OpenWrtTab.overview.kernel')} value={info?.kernel} mono />
          <Row label={t('OpenWrtTab.overview.uptime')} value={formatUptime(info?.uptime)} />
          <Row label={t('OpenWrtTab.overview.load')} value={info?.load?.map(l => l.toFixed(2)).join(' / ')} mono />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2">
            <MemoryStick className="h-4 w-4 text-primary" /> {t('OpenWrtTab.overview.memory')}
          </CardTitle>
        </CardHeader>
        <CardContent noOffset className="px-4 pb-3 space-y-1.5 text-sm">
          <Row label={t('OpenWrtTab.overview.total')} value={formatBytes(memTotal)} />
          <Row label={t('OpenWrtTab.overview.available')} value={formatBytes(memAvail)} />
          <Row label={t('OpenWrtTab.overview.cached')} value={formatBytes(info?.memory?.cached)} />
          <Row label={t('OpenWrtTab.overview.buffered')} value={formatBytes(info?.memory?.buffered)} />
          {memUsedPct !== null && (
            <div className="pt-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">{t('OpenWrtTab.overview.used')}</span>
                <span className="font-mono">{memUsedPct}%</span>
              </div>
              <div className="h-1.5 w-full rounded-full bg-muted mt-1 overflow-hidden">
                <div className={cn(
                  'h-full rounded-full transition-all',
                  memUsedPct > 90 ? 'bg-destructive'
                    : memUsedPct > 70 ? 'bg-amber-500'
                    : 'bg-primary',
                )}
                style={{ width: `${memUsedPct}%` }} />
              </div>
            </div>
          )}
        </CardContent>
      </Card>
      <Card className="md:col-span-2">
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2">
            <Network className="h-4 w-4 text-primary" /> {t('OpenWrtTab.interfaces.title')}
            <span className="text-xs text-muted-foreground ml-1">
              {t('OpenWrtTab.interfaces.count', { n: interfacesQ.data?.data?.items?.length ?? 0 })}
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent noOffset className="px-4 pb-3">
          <InterfaceTable items={interfacesQ.data?.data?.items} isLoading={interfacesQ.isLoading} />
        </CardContent>
      </Card>
    </div>
  );

  const firewall = (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-sm flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-primary" /> {t('OpenWrtTab.firewall.title')}
          <span className="text-xs text-muted-foreground ml-1">
            {t('OpenWrtTab.firewall.count', { n: firewallQ.data?.data?.items?.length ?? 0 })}
          </span>
        </CardTitle>
        <Button size="sm" variant="outline" onClick={() => setRuleDialog({ ...EMPTY_RULE })}>
          <Plus className="h-3.5 w-3.5 mr-1" /> {t('OpenWrtTab.firewall.newRule')}
        </Button>
      </CardHeader>
      <CardContent noOffset className="px-0 pb-0">
        {firewallQ.isLoading ? (
          <div className="p-4 text-sm text-muted-foreground">{t('OpenWrtTab.common.loading')}</div>
        ) : (firewallQ.data?.data?.items?.length ?? 0) === 0 ? (
          <div className="p-4 text-sm text-muted-foreground">{t('OpenWrtTab.firewall.empty')}</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-muted/30 border-b">
              <tr className="text-left">
                <Th>{t('OpenWrtTab.firewall.col.name')}</Th><Th>{t('OpenWrtTab.firewall.col.srcDest')}</Th><Th>{t('OpenWrtTab.firewall.col.target')}</Th><Th>{t('OpenWrtTab.firewall.col.proto')}</Th><Th>{t('OpenWrtTab.firewall.col.status')}</Th><Th></Th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {(firewallQ.data?.data?.items || []).map((r, i) => (
                <tr key={i} className="hover:bg-muted/30">
                  <Td><span className="font-mono text-xs">{r.name || r.uci_name || '-'}</span></Td>
                  <Td><span className="text-xs">{(r.src as string) || '*'} → {(r.dest as string) || '*'}</span></Td>
                  <Td><Badge variant={r.target === 'ACCEPT' ? 'success' : r.target === 'REJECT' || r.target === 'DROP' ? 'destructive' : 'outline'} className="text-[10px]">{String(r.target || '-')}</Badge></Td>
                  <Td><span className="text-xs font-mono">{String(r.proto || 'any')}</span></Td>
                  <Td>{r.enabled === false ? <Badge variant="outline" className="text-[10px]">{t('OpenWrtTab.common.disabled')}</Badge> : <CheckCircle2 className="h-3.5 w-3.5 text-success inline" />}</Td>
                  <Td>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 w-7 p-0 text-destructive hover:text-destructive"
                      onClick={() => {
                        if (!window.confirm(t('OpenWrtTab.firewall.confirmDelete', { name: r.name || r.uci_name }))) return;
                        const targetId = (r.id as string) || (r.uci_name as string);
                        stageRule.mutate({ op: 'delete', payload: {}, targetId });
                      }}
                      disabled={stageRule.isPending}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </CardContent>
    </Card>
  );

  const portForwards = (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-sm flex items-center gap-2">
          <ArrowLeftRight className="h-4 w-4 text-primary" /> {t('OpenWrtTab.portForwards.title')}
          <span className="text-xs text-muted-foreground ml-1">
            {t('OpenWrtTab.portForwards.count', { n: pfQ.data?.data?.items?.length ?? 0 })}
          </span>
        </CardTitle>
        <Button size="sm" variant="outline" onClick={() => setPfDialog({ ...EMPTY_PF })}>
          <Plus className="h-3.5 w-3.5 mr-1" /> {t('OpenWrtTab.portForwards.newForward')}
        </Button>
      </CardHeader>
      <CardContent noOffset className="px-0 pb-0">
        {pfQ.isLoading ? (
          <div className="p-4 text-sm text-muted-foreground">{t('OpenWrtTab.common.loading')}</div>
        ) : (pfQ.data?.data?.items?.length ?? 0) === 0 ? (
          <div className="p-4 text-sm text-muted-foreground">{t('OpenWrtTab.portForwards.empty')}</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-muted/30 border-b">
              <tr className="text-left">
                <Th>{t('OpenWrtTab.portForwards.col.name')}</Th><Th>{t('OpenWrtTab.portForwards.col.external')}</Th><Th>{t('OpenWrtTab.portForwards.col.internal')}</Th><Th>{t('OpenWrtTab.portForwards.col.proto')}</Th><Th>{t('OpenWrtTab.portForwards.col.status')}</Th><Th></Th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {(pfQ.data?.data?.items || []).map((r, i) => (
                <tr key={i} className="hover:bg-muted/30">
                  <Td><span className="font-mono text-xs">{r.name || r.uci_name || '-'}</span></Td>
                  <Td><span className="text-xs font-mono">{String(r.interface || r.src || '*')}:{String(r.source_port || r.src_dport || '*')}</span></Td>
                  <Td><span className="text-xs font-mono">{String(r.target_ip || r.dest_ip || r.dest || '*')}:{String(r.target_port || r.dest_port || '*')}</span></Td>
                  <Td><span className="text-xs font-mono">{String(r.protocol || r.proto || 'any')}</span></Td>
                  <Td>{r.enabled === false ? <Badge variant="outline" className="text-[10px]">{t('OpenWrtTab.common.disabled')}</Badge> : <CheckCircle2 className="h-3.5 w-3.5 text-success inline" />}</Td>
                  <Td>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 w-7 p-0 text-destructive hover:text-destructive"
                      onClick={() => {
                        if (!window.confirm(t('OpenWrtTab.portForwards.confirmDelete', { name: r.name || r.uci_name }))) return;
                        const targetId = (r.id as string) || (r.uci_name as string);
                        stagePf.mutate({ op: 'delete', payload: {}, targetId });
                      }}
                      disabled={stagePf.isPending}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </CardContent>
    </Card>
  );

  const dhcp = (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm flex items-center gap-2">
          <Wifi className="h-4 w-4 text-primary" /> {t('OpenWrtTab.dhcp.title')}
          <span className="text-xs text-muted-foreground ml-1">
            {t('OpenWrtTab.dhcp.count', { n: dhcpQ.data?.data?.items?.length ?? 0 })}
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent noOffset className="px-0 pb-0">
        {dhcpQ.isLoading ? (
          <div className="p-4 text-sm text-muted-foreground">{t('OpenWrtTab.common.loading')}</div>
        ) : (dhcpQ.data?.data?.items?.length ?? 0) === 0 ? (
          <div className="p-4 text-sm text-muted-foreground">{t('OpenWrtTab.dhcp.empty')}</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-muted/30 border-b">
              <tr className="text-left"><Th>{t('OpenWrtTab.dhcp.col.hostname')}</Th><Th>{t('OpenWrtTab.dhcp.col.ipAddress')}</Th><Th>{t('OpenWrtTab.dhcp.col.mac')}</Th><Th>{t('OpenWrtTab.dhcp.col.expires')}</Th></tr>
            </thead>
            <tbody className="divide-y">
              {(dhcpQ.data?.data?.items || []).map((l, i) => (
                <tr key={i} className="hover:bg-muted/30">
                  <Td><span className="font-mono text-xs">{l.hostname || '-'}</span></Td>
                  <Td><span className="text-xs font-mono">{l.ip_address || '-'}</span></Td>
                  <Td><span className="text-xs font-mono">{l.mac_address || '-'}</span></Td>
                  <Td><span className="text-xs text-muted-foreground">{l.expires ? new Date(l.expires * 1000).toLocaleString() : '-'}</span></Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </CardContent>
    </Card>
  );

  const arp = (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm flex items-center gap-2">
          <MemoryStick className="h-4 w-4 text-primary" /> {t('OpenWrtTab.arp.title')}
          <span className="text-xs text-muted-foreground ml-1">
            {t('OpenWrtTab.arp.count', { n: arpQ.data?.data?.items?.length ?? 0 })}
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent noOffset className="px-0 pb-0">
        {arpQ.isLoading ? (
          <div className="p-4 text-sm text-muted-foreground">{t('OpenWrtTab.common.loading')}</div>
        ) : (arpQ.data?.data?.items?.length ?? 0) === 0 ? (
          <div className="p-4 text-sm text-muted-foreground">{t('OpenWrtTab.arp.empty')}</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-muted/30 border-b">
              <tr className="text-left"><Th>{t('OpenWrtTab.arp.col.ipAddress')}</Th><Th>{t('OpenWrtTab.arp.col.macAddress')}</Th><Th>{t('OpenWrtTab.arp.col.interface')}</Th></tr>
            </thead>
            <tbody className="divide-y">
              {(arpQ.data?.data?.items || []).map((e, i) => (
                <tr key={i} className="hover:bg-muted/30">
                  <Td><span className="text-xs font-mono">{(e.ip_address as string) || (e.ip as string) || '-'}</span></Td>
                  <Td><span className="text-xs font-mono">{(e.mac_address as string) || (e.mac as string) || '-'}</span></Td>
                  <Td><span className="text-xs font-mono">{(e.interface as string) || '-'}</span></Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </CardContent>
    </Card>
  );

  const dhcpStatic = (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-sm flex items-center gap-2">
          <BookmarkPlus className="h-4 w-4 text-primary" /> {t('OpenWrtTab.dhcpStatic.title')}
          <span className="text-xs text-muted-foreground ml-1">
            {t('OpenWrtTab.dhcpStatic.count', { n: dhcpStaticQ.data?.data?.items?.length ?? 0 })}
          </span>
        </CardTitle>
        <Button size="sm" variant="outline" onClick={() => setHostDialog({ ...EMPTY_HOST })}>
          <Plus className="h-3.5 w-3.5 mr-1" /> {t('OpenWrtTab.dhcpStatic.newReservation')}
        </Button>
      </CardHeader>
      <CardContent noOffset className="px-0 pb-0">
        {dhcpStaticQ.isLoading ? (
          <div className="p-4 text-sm text-muted-foreground">{t('OpenWrtTab.common.loading')}</div>
        ) : (dhcpStaticQ.data?.data?.items?.length ?? 0) === 0 ? (
          <div className="p-4 text-sm text-muted-foreground">
            {t('OpenWrtTab.dhcpStatic.emptyPrefix')} <strong>{t('OpenWrtTab.dhcpStatic.newReservation')}</strong> {t('OpenWrtTab.dhcpStatic.emptySuffix')}
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-muted/30 border-b">
              <tr className="text-left">
                <Th>{t('OpenWrtTab.dhcpStatic.col.hostname')}</Th><Th>{t('OpenWrtTab.dhcpStatic.col.macAddress')}</Th><Th>{t('OpenWrtTab.dhcpStatic.col.ipAddress')}</Th><Th></Th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {(dhcpStaticQ.data?.data?.items || []).map((h: any, i: number) => (
                <tr key={i} className="hover:bg-muted/30">
                  <Td><span className="font-mono text-xs">{h.hostname || '-'}</span></Td>
                  <Td><span className="text-xs font-mono">{h.mac_address || '-'}</span></Td>
                  <Td><span className="text-xs font-mono">{h.ip_address || '-'}</span></Td>
                  <Td>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 w-7 p-0 text-destructive hover:text-destructive"
                      onClick={() => {
                        if (!window.confirm(t('OpenWrtTab.dhcpStatic.confirmDelete', { name: h.hostname || h.mac_address }))) return;
                        const targetId = (h.id as string) || (h.uci_name as string);
                        stageHost.mutate({ op: 'delete', payload: {}, targetId });
                      }}
                      disabled={stageHost.isPending}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </CardContent>
    </Card>
  );

  const content = {
    'overview': overview,
    'interfaces': (
      <Card>
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2">
            <Network className="h-4 w-4 text-primary" /> {t('OpenWrtTab.interfaces.title')}
          </CardTitle>
        </CardHeader>
        <CardContent noOffset className="px-4 pb-3">
          <InterfaceTable items={interfacesQ.data?.data?.items} isLoading={interfacesQ.isLoading} />
        </CardContent>
      </Card>
    ),
    'firewall': firewall,
    'port-forwards': portForwards,
    'dhcp': dhcp,
    'dhcp-static': dhcpStatic,
    'arp': arp,
  }[sub];

  // Show "no creds saved" hint if the first read 502s with auth-related error
  const isAuthError = deviceInfoQ.isError && (
    String(deviceInfoQ.error || '').toLowerCase().includes('auth')
    || String((deviceInfoQ.error as any)?.response?.data?.detail || '').toLowerCase().includes('login')
  );

  return (
    <div className="space-y-4">
      {/* Sub-tab navigation */}
      <div className="flex items-center gap-1 border-b">
        {SUB_TABS.map((tab) => {
          const Icon = tab.icon;
          const active = sub === tab.key;
          return (
            <button
              key={tab.key}
              type="button"
              onClick={() => setSub(tab.key)}
              className={cn(
                'px-3 py-2 text-sm font-medium border-b-2 -mb-px transition-colors flex items-center gap-1.5',
                active
                  ? 'border-primary text-primary'
                  : 'border-transparent text-muted-foreground hover:text-foreground',
              )}
            >
              <Icon className="h-3.5 w-3.5" /> {t(`OpenWrtTab.${tab.labelKey}`)}
            </button>
          );
        })}
        <div className="ml-auto pb-1">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => { deviceInfoQ.refetch(); interfacesQ.refetch(); firewallQ.refetch(); pfQ.refetch(); dhcpQ.refetch(); dhcpStaticQ.refetch(); arpQ.refetch(); }}
          >
            <RefreshCw className="h-3.5 w-3.5 mr-1" /> {t('OpenWrtTab.actions.refresh')}
          </Button>
        </div>
      </div>

      {isAuthError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-3 flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-destructive" />
            <span className="text-sm">{t('OpenWrtTab.authError')}</span>
          </CardContent>
        </Card>
      )}

      {content}

      {/* ── Firewall rule create dialog ─────────────────────────────── */}
      <Dialog open={ruleDialog !== null} onOpenChange={(o) => !o && setRuleDialog(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('OpenWrtTab.ruleDialog.title')}</DialogTitle>
          </DialogHeader>
          {ruleDialog && (
            <div className="grid grid-cols-2 gap-3">
              <div className="col-span-2">
                <Label>{t('OpenWrtTab.ruleDialog.name')}</Label>
                <Input value={ruleDialog.name} onChange={(e) => setRuleDialog({ ...ruleDialog, name: e.target.value })} placeholder="Allow-SSH" />
              </div>
              <div>
                <Label>{t('OpenWrtTab.ruleDialog.zoneSrc')}</Label>
                <Input value={ruleDialog.src} onChange={(e) => setRuleDialog({ ...ruleDialog, src: e.target.value })} placeholder="wan" />
              </div>
              <div>
                <Label>{t('OpenWrtTab.ruleDialog.target')}</Label>
                <Input value={ruleDialog.target} onChange={(e) => setRuleDialog({ ...ruleDialog, target: e.target.value })} placeholder="ACCEPT | DROP | REJECT" />
              </div>
              <div>
                <Label>{t('OpenWrtTab.ruleDialog.protocol')}</Label>
                <Input value={ruleDialog.proto} onChange={(e) => setRuleDialog({ ...ruleDialog, proto: e.target.value })} placeholder="tcp | udp | icmp" />
              </div>
              <div>
                <Label>{t('OpenWrtTab.ruleDialog.destPort')}</Label>
                <Input value={ruleDialog.dest_port} onChange={(e) => setRuleDialog({ ...ruleDialog, dest_port: e.target.value })} placeholder="22" />
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="ghost" onClick={() => setRuleDialog(null)}>{t('OpenWrtTab.common.cancel')}</Button>
            <Button
              disabled={!ruleDialog || !ruleDialog.name || stageRule.isPending}
              onClick={() => {
                if (!ruleDialog) return;
                stageRule.mutate({
                  op: 'create',
                  payload: { ...ruleDialog, enabled: true },
                });
                setRuleDialog(null);
              }}
            >
              {t('OpenWrtTab.ruleDialog.submit')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Port forward create dialog ──────────────────────────────── */}
      <Dialog open={pfDialog !== null} onOpenChange={(o) => !o && setPfDialog(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('OpenWrtTab.pfDialog.title')}</DialogTitle>
          </DialogHeader>
          {pfDialog && (
            <div className="grid grid-cols-2 gap-3">
              <div className="col-span-2">
                <Label>{t('OpenWrtTab.pfDialog.name')}</Label>
                <Input value={pfDialog.name} onChange={(e) => setPfDialog({ ...pfDialog, name: e.target.value })} placeholder="Forward-SSH" />
              </div>
              <div>
                <Label>{t('OpenWrtTab.pfDialog.sourceZone')}</Label>
                <Input value={pfDialog.src} onChange={(e) => setPfDialog({ ...pfDialog, src: e.target.value })} placeholder="wan" />
              </div>
              <div>
                <Label>{t('OpenWrtTab.pfDialog.protocol')}</Label>
                <Input value={pfDialog.proto} onChange={(e) => setPfDialog({ ...pfDialog, proto: e.target.value })} placeholder="tcp" />
              </div>
              <div>
                <Label>{t('OpenWrtTab.pfDialog.externalPort')}</Label>
                <Input value={pfDialog.src_dport} onChange={(e) => setPfDialog({ ...pfDialog, src_dport: e.target.value })} placeholder="2222" />
              </div>
              <div>
                <Label>{t('OpenWrtTab.pfDialog.internalIp')}</Label>
                <Input value={pfDialog.dest_ip} onChange={(e) => setPfDialog({ ...pfDialog, dest_ip: e.target.value })} placeholder="192.168.1.150" />
              </div>
              <div className="col-span-2">
                <Label>{t('OpenWrtTab.pfDialog.internalPort')}</Label>
                <Input value={pfDialog.dest_port} onChange={(e) => setPfDialog({ ...pfDialog, dest_port: e.target.value })} placeholder="22" />
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="ghost" onClick={() => setPfDialog(null)}>{t('OpenWrtTab.common.cancel')}</Button>
            <Button
              disabled={!pfDialog || !pfDialog.name || stagePf.isPending}
              onClick={() => {
                if (!pfDialog) return;
                stagePf.mutate({
                  op: 'create',
                  payload: { ...pfDialog, enabled: true },
                });
                setPfDialog(null);
              }}
            >
              {t('OpenWrtTab.pfDialog.submit')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── DHCP static host create dialog ──────────────────────────── */}
      <Dialog open={hostDialog !== null} onOpenChange={(o) => !o && setHostDialog(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('OpenWrtTab.hostDialog.title')}</DialogTitle>
          </DialogHeader>
          {hostDialog && (
            <div className="grid grid-cols-2 gap-3">
              <div className="col-span-2">
                <Label>{t('OpenWrtTab.hostDialog.hostname')}</Label>
                <Input value={hostDialog.hostname} onChange={(e) => setHostDialog({ ...hostDialog, hostname: e.target.value })} placeholder="my-server" />
              </div>
              <div>
                <Label>{t('OpenWrtTab.hostDialog.macAddress')}</Label>
                <Input value={hostDialog.mac_address} onChange={(e) => setHostDialog({ ...hostDialog, mac_address: e.target.value })} placeholder="aa:bb:cc:dd:ee:ff" />
              </div>
              <div>
                <Label>{t('OpenWrtTab.hostDialog.ipAddress')}</Label>
                <Input value={hostDialog.ip_address} onChange={(e) => setHostDialog({ ...hostDialog, ip_address: e.target.value })} placeholder="192.168.1.150" />
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="ghost" onClick={() => setHostDialog(null)}>{t('OpenWrtTab.common.cancel')}</Button>
            <Button
              disabled={!hostDialog || !hostDialog.mac_address || !hostDialog.ip_address || stageHost.isPending}
              onClick={() => {
                if (!hostDialog) return;
                stageHost.mutate({
                  op: 'create',
                  payload: { ...hostDialog },
                });
                setHostDialog(null);
              }}
            >
              {t('OpenWrtTab.hostDialog.submit')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ── helpers ────────────────────────────────────────────────────────────

function Row({ label, value, mono }: { label: string; value?: string | null; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className={cn(mono && 'font-mono text-xs')}>{value ?? '-'}</span>
    </div>
  );
}

function Th({ children }: { children?: React.ReactNode }) {
  return <th className="px-3 py-2 text-xs font-medium text-muted-foreground">{children}</th>;
}
function Td({ children }: { children?: React.ReactNode }) {
  return <td className="px-3 py-2">{children}</td>;
}

function InterfaceTable({ items, isLoading }: { items?: any[]; isLoading?: boolean }) {
  const { t } = useTranslation('firewall');
  if (isLoading) return <div className="text-sm text-muted-foreground">{t('OpenWrtTab.common.loading')}</div>;
  if (!items || items.length === 0) {
    return <div className="text-sm text-muted-foreground">{t('OpenWrtTab.interfaces.empty')}</div>;
  }
  return (
    <table className="w-full text-sm">
      <thead className="border-b">
        <tr className="text-left">
          <Th>{t('OpenWrtTab.interfaces.col.interface')}</Th><Th>{t('OpenWrtTab.interfaces.col.device')}</Th><Th>{t('OpenWrtTab.interfaces.col.ipv4')}</Th><Th>{t('OpenWrtTab.interfaces.col.gateway')}</Th><Th>{t('OpenWrtTab.interfaces.col.state')}</Th>
        </tr>
      </thead>
      <tbody className="divide-y">
        {items.map((i, idx) => (
          <tr key={idx} className="hover:bg-muted/30">
            <Td><span className="font-mono text-xs">{i.name || '-'}</span></Td>
            <Td><span className="text-xs">{i.device || '-'}</span></Td>
            <Td><span className="text-xs font-mono">{(i.ipv4_address || i.ipv4) || '-'}{(i.ipv4_subnet ?? i.ipv4_mask) ? `/${i.ipv4_subnet ?? i.ipv4_mask}` : ''}</span></Td>
            <Td><span className="text-xs font-mono">{i.ipv4_gateway || i.gateway || '-'}</span></Td>
            <Td>{(i.status === 'up' || i.up === true) ? <CheckCircle2 className="h-3.5 w-3.5 text-success inline" /> : <XCircle className="h-3.5 w-3.5 text-muted-foreground inline" />}</Td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
