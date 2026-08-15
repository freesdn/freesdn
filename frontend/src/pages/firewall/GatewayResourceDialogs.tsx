// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Gateway Resource CRUD Dialogs
 *
 * Reusable create / edit / delete dialogs for every writable OPNsense resource
 * surfaced from the GatewayDetailPage. Follows existing codebase patterns:
 *   • useState-based form objects (not react-hook-form)
 *   • Radix Dialog components from @/components/ui/dialog
 *   • useMutation inside each dialog with toast + queryClient.invalidate
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { FormDialog } from '@/components/ui/form-dialog';
import { FormFieldArray } from '@/components/ui/form-field-array';
import { Loader2, Trash2, ListChecks } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import {
  gatewayApi,
  type GatewayRulePushRequest,
  type DNSOverrideRequest,
  type DNSDomainOverrideRequest,
  type DHCPStaticMappingRequest,
  type PortForwardRequest,
  type SourceNATRuleRequest,
  type AliasRequest,
  type WireGuardServerRequest,
  type WireGuardPeerRequest,
  type OpenVPNInstanceRequest,
  type StaticRouteRequest,
  type ShaperPipeRequest,
} from '@/lib/api';

// ═══════════════════════════════════════════════════════════════════════
// Shared helpers
// ═══════════════════════════════════════════════════════════════════════

interface BaseDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  gatewayId: string;
}

interface EditableDialogProps<T> extends BaseDialogProps {
  item?: T | null;
}

function useWriteMutation(
  gatewayId: string,
  mutationFn: () => Promise<any>,
  queryKeys: string[],
  successMsg: string,
  onClose: () => void,
) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  return useMutation({
    mutationFn,
    onSuccess: () => {
      queryKeys.forEach((k) =>
        queryClient.invalidateQueries({ queryKey: ['gateways', gatewayId, k] }),
      );
      toast({ title: t('GatewayResourceDialogs.toast.successTitle'), description: successMsg });
      onClose();
    },
    onError: (err: any) => {
      toast({
        title: t('GatewayResourceDialogs.toast.errorTitle'),
        description: err?.response?.data?.detail || err.message || t('GatewayResourceDialogs.toast.operationFailed'),
        variant: 'destructive',
      });
    },
  });
}

// ═══════════════════════════════════════════════════════════════════════
// 1. Delete Confirmation Dialog (generic)
// ═══════════════════════════════════════════════════════════════════════

export function DeleteResourceDialog({
  open,
  onOpenChange,
  gatewayId,
  resourceLabel,
  resourceName,
  deleteFn,
  queryKeys,
}: BaseDialogProps & {
  resourceLabel: string;
  resourceName: string;
  deleteFn: () => Promise<any>;
  queryKeys: string[];
}) {
  const { t } = useTranslation('firewall');
  const mutation = useWriteMutation(
    gatewayId,
    deleteFn,
    queryKeys,
    t('GatewayResourceDialogs.delete.successMsg', { resource: resourceLabel }),
    () => onOpenChange(false),
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('GatewayResourceDialogs.delete.title', { resource: resourceLabel })}</DialogTitle>
          <DialogDescription>
            {t('GatewayResourceDialogs.delete.confirmBefore')}<strong>{resourceName}</strong>{t('GatewayResourceDialogs.delete.confirmAfter')}
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('GatewayResourceDialogs.actions.cancel')}</Button>
          <Button variant="destructive" onClick={() => mutation.mutate()} disabled={mutation.isPending}>
            {mutation.isPending ? <><Loader2 className="h-4 w-4 animate-spin mr-1" /> {t('GatewayResourceDialogs.actions.deleting')}</> : t('GatewayResourceDialogs.actions.delete')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// 2. Firewall Rule · Push
// ═══════════════════════════════════════════════════════════════════════

const emptyRule: GatewayRulePushRequest = {
  action: 'allow',
  protocol: 'any',
  source: '',
  source_port: '',
  destination: '',
  destination_port: '',
  description: '',
  enabled: true,
  log: false,
  interface: '',
};

export function FirewallRuleFormDialog({ open, onOpenChange, gatewayId }: BaseDialogProps) {
  const { t } = useTranslation('firewall');
  const [form, setForm] = useState<GatewayRulePushRequest>({ ...emptyRule });
  const set = (k: keyof GatewayRulePushRequest, v: any) => setForm((p) => ({ ...p, [k]: v }));

  useEffect(() => { if (open) setForm({ ...emptyRule }); }, [open]);

  const mutation = useWriteMutation(
    gatewayId,
    () => gatewayApi.pushRule(gatewayId, form),
    ['firewall-rules'],
    t('GatewayResourceDialogs.rule.successMsg'),
    () => onOpenChange(false),
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{t('GatewayResourceDialogs.rule.title')}</DialogTitle>
          <DialogDescription>{t('GatewayResourceDialogs.rule.description')}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label>{t('GatewayResourceDialogs.fields.action')}</Label>
              <Select value={form.action} onValueChange={(v) => set('action', v as any)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="allow">{t('GatewayResourceDialogs.options.allow')}</SelectItem>
                  <SelectItem value="block">{t('GatewayResourceDialogs.options.block')}</SelectItem>
                  <SelectItem value="reject">{t('GatewayResourceDialogs.options.reject')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>{t('GatewayResourceDialogs.fields.protocol')}</Label>
              <Select value={form.protocol || 'any'} onValueChange={(v) => set('protocol', v)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="any">{t('GatewayResourceDialogs.options.any')}</SelectItem>
                  <SelectItem value="tcp">TCP</SelectItem>
                  <SelectItem value="udp">UDP</SelectItem>
                  <SelectItem value="tcp/udp">TCP/UDP</SelectItem>
                  <SelectItem value="icmp">ICMP</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div><Label>{t('GatewayResourceDialogs.fields.source')}</Label><Input placeholder={t('GatewayResourceDialogs.placeholders.any')} value={form.source || ''} onChange={(e) => set('source', e.target.value)} /></div>
            <div><Label>{t('GatewayResourceDialogs.fields.sourcePort')}</Label><Input placeholder={t('GatewayResourceDialogs.placeholders.any')} value={form.source_port || ''} onChange={(e) => set('source_port', e.target.value)} /></div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div><Label>{t('GatewayResourceDialogs.fields.destination')}</Label><Input placeholder={t('GatewayResourceDialogs.placeholders.any')} value={form.destination || ''} onChange={(e) => set('destination', e.target.value)} /></div>
            <div><Label>{t('GatewayResourceDialogs.fields.destinationPort')}</Label><Input placeholder={t('GatewayResourceDialogs.placeholders.any')} value={form.destination_port || ''} onChange={(e) => set('destination_port', e.target.value)} /></div>
          </div>
          <div><Label>{t('GatewayResourceDialogs.fields.interface')}</Label><Input placeholder={t('GatewayResourceDialogs.placeholders.interfaceList')} value={form.interface || ''} onChange={(e) => set('interface', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.description')}</Label><Input value={form.description || ''} onChange={(e) => set('description', e.target.value)} /></div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('GatewayResourceDialogs.actions.cancel')}</Button>
          <Button onClick={() => mutation.mutate()} disabled={mutation.isPending}>
            {mutation.isPending ? <><Loader2 className="h-4 w-4 animate-spin mr-1" /> {t('GatewayResourceDialogs.actions.pushing')}</> : t('GatewayResourceDialogs.actions.pushRule')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// 3. DNS Host Override · Create / Edit
// ═══════════════════════════════════════════════════════════════════════

const emptyDns: DNSOverrideRequest = { host: '', domain: '', ip: '', description: '', enabled: true };

export function DNSOverrideFormDialog({ open, onOpenChange, gatewayId, item }: EditableDialogProps<any>) {
  const { t } = useTranslation('firewall');
  const isEdit = !!item;
  const [form, setForm] = useState<DNSOverrideRequest>({ ...emptyDns });
  const set = (k: keyof DNSOverrideRequest, v: any) => setForm((p) => ({ ...p, [k]: v }));

  useEffect(() => {
    if (item) {
      setForm({ host: item.host || '', domain: item.domain || '', ip: item.ip || item.value || '', description: item.description || '', enabled: item.enabled !== false });
    } else if (open) { setForm({ ...emptyDns }); }
  }, [item, open]);

  const mutation = useWriteMutation(
    gatewayId,
    () => isEdit
      ? gatewayApi.updateDNSOverride(gatewayId, item.uuid || item.id, form)
      : gatewayApi.createDNSOverride(gatewayId, form),
    ['dns-overrides'],
    isEdit ? t('GatewayResourceDialogs.dnsOverride.updated') : t('GatewayResourceDialogs.dnsOverride.created'),
    () => onOpenChange(false),
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{isEdit ? t('GatewayResourceDialogs.dnsOverride.titleEdit') : t('GatewayResourceDialogs.dnsOverride.titleNew')}</DialogTitle>
          <DialogDescription>{t('GatewayResourceDialogs.dnsOverride.description')}</DialogDescription>
        </DialogHeader>
        <div className="space-y-3 py-2">
          <div><Label>{t('GatewayResourceDialogs.fields.hostname')}</Label><Input placeholder={t('GatewayResourceDialogs.placeholders.myserver')} value={form.host} onChange={(e) => set('host', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.domain')}</Label><Input placeholder="example.com" value={form.domain} onChange={(e) => set('domain', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.ipAddress')}</Label><Input placeholder="192.168.1.100" value={form.ip} onChange={(e) => set('ip', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.description')}</Label><Input value={form.description || ''} onChange={(e) => set('description', e.target.value)} /></div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('GatewayResourceDialogs.actions.cancel')}</Button>
          <Button onClick={() => mutation.mutate()} disabled={mutation.isPending || !form.host || !form.domain || !form.ip}>
            {mutation.isPending ? <><Loader2 className="h-4 w-4 animate-spin mr-1" /> {t('GatewayResourceDialogs.actions.saving')}</> : isEdit ? t('GatewayResourceDialogs.actions.update') : t('GatewayResourceDialogs.actions.create')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// 4. DNS Domain Override · Create / Edit
// ═══════════════════════════════════════════════════════════════════════

const emptyDnsDomain: DNSDomainOverrideRequest = { domain: '', server: '', port: 53, description: '', enabled: true };

export function DNSDomainOverrideFormDialog({ open, onOpenChange, gatewayId, item }: EditableDialogProps<any>) {
  const { t } = useTranslation('firewall');
  const isEdit = !!item;
  const [form, setForm] = useState<DNSDomainOverrideRequest>({ ...emptyDnsDomain });
  const set = (k: keyof DNSDomainOverrideRequest, v: any) => setForm((p) => ({ ...p, [k]: v }));

  useEffect(() => {
    if (item) {
      setForm({ domain: item.domain || '', server: item.server || '', port: item.port || 53, description: item.description || '', enabled: item.enabled !== false });
    } else if (open) { setForm({ ...emptyDnsDomain }); }
  }, [item, open]);

  const mutation = useWriteMutation(
    gatewayId,
    () => isEdit
      ? gatewayApi.updateDNSDomainOverride(gatewayId, item.uuid || item.id, form)
      : gatewayApi.createDNSDomainOverride(gatewayId, form),
    ['dns-domain-overrides'],
    isEdit ? t('GatewayResourceDialogs.dnsDomainOverride.updated') : t('GatewayResourceDialogs.dnsDomainOverride.created'),
    () => onOpenChange(false),
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{isEdit ? t('GatewayResourceDialogs.dnsDomainOverride.titleEdit') : t('GatewayResourceDialogs.dnsDomainOverride.titleNew')}</DialogTitle>
          <DialogDescription>{t('GatewayResourceDialogs.dnsDomainOverride.description')}</DialogDescription>
        </DialogHeader>
        <div className="space-y-3 py-2">
          <div><Label>{t('GatewayResourceDialogs.fields.domain')}</Label><Input placeholder="corp.example.com" value={form.domain} onChange={(e) => set('domain', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.dnsServer')}</Label><Input placeholder="10.0.0.1" value={form.server} onChange={(e) => set('server', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.port')}</Label><Input type="number" value={form.port || 53} onChange={(e) => set('port', parseInt(e.target.value) || 53)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.description')}</Label><Input value={form.description || ''} onChange={(e) => set('description', e.target.value)} /></div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('GatewayResourceDialogs.actions.cancel')}</Button>
          <Button onClick={() => mutation.mutate()} disabled={mutation.isPending || !form.domain || !form.server}>
            {mutation.isPending ? <><Loader2 className="h-4 w-4 animate-spin mr-1" /> {t('GatewayResourceDialogs.actions.saving')}</> : isEdit ? t('GatewayResourceDialogs.actions.update') : t('GatewayResourceDialogs.actions.create')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// 5. DHCP Static Mapping · Create / Edit
// ═══════════════════════════════════════════════════════════════════════

const emptyDhcpStatic: DHCPStaticMappingRequest = { mac: '', ipaddr: '', hostname: '', description: '', interface: 'lan' };

export function DHCPStaticMappingFormDialog({ open, onOpenChange, gatewayId, item }: EditableDialogProps<any>) {
  const { t } = useTranslation('firewall');
  const isEdit = !!item;
  const [form, setForm] = useState<DHCPStaticMappingRequest>({ ...emptyDhcpStatic });
  const set = (k: keyof DHCPStaticMappingRequest, v: any) => setForm((p) => ({ ...p, [k]: v }));

  useEffect(() => {
    if (item) {
      setForm({ mac: item.mac || '', ipaddr: item.ipaddr || item.ip || '', hostname: item.hostname || '', description: item.description || '', interface: item.interface || 'lan' });
    } else if (open) { setForm({ ...emptyDhcpStatic }); }
  }, [item, open]);

  const mutation = useWriteMutation(
    gatewayId,
    () => isEdit
      ? gatewayApi.updateDHCPStaticMapping(gatewayId, item.uuid || item.id, form)
      : gatewayApi.createDHCPStaticMapping(gatewayId, form),
    ['dhcp-static'],
    isEdit ? t('GatewayResourceDialogs.dhcpStatic.updated') : t('GatewayResourceDialogs.dhcpStatic.created'),
    () => onOpenChange(false),
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{isEdit ? t('GatewayResourceDialogs.dhcpStatic.titleEdit') : t('GatewayResourceDialogs.dhcpStatic.titleNew')}</DialogTitle>
          <DialogDescription>{t('GatewayResourceDialogs.dhcpStatic.description')}</DialogDescription>
        </DialogHeader>
        <div className="space-y-3 py-2">
          <div><Label>{t('GatewayResourceDialogs.fields.macAddress')}</Label><Input placeholder="00:11:22:33:44:55" value={form.mac} onChange={(e) => set('mac', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.ipAddress')}</Label><Input placeholder="192.168.1.150" value={form.ipaddr} onChange={(e) => set('ipaddr', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.hostname')}</Label><Input placeholder="my-server" value={form.hostname || ''} onChange={(e) => set('hostname', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.interface')}</Label><Input placeholder="lan" value={form.interface || ''} onChange={(e) => set('interface', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.description')}</Label><Input value={form.description || ''} onChange={(e) => set('description', e.target.value)} /></div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('GatewayResourceDialogs.actions.cancel')}</Button>
          <Button onClick={() => mutation.mutate()} disabled={mutation.isPending || !form.mac || !form.ipaddr}>
            {mutation.isPending ? <><Loader2 className="h-4 w-4 animate-spin mr-1" /> {t('GatewayResourceDialogs.actions.saving')}</> : isEdit ? t('GatewayResourceDialogs.actions.update') : t('GatewayResourceDialogs.actions.create')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// 6. Port Forward · Create / Edit
// ═══════════════════════════════════════════════════════════════════════

const emptyPortFwd: PortForwardRequest = {
  interface: 'wan', protocol: 'tcp', src_address: '', src_port: '', dst_address: '', dst_port: '', target_ip: '', target_port: '', description: '', enabled: true,
};

export function PortForwardFormDialog({ open, onOpenChange, gatewayId, item }: EditableDialogProps<any>) {
  const { t } = useTranslation('firewall');
  const isEdit = !!item;
  const [form, setForm] = useState<PortForwardRequest>({ ...emptyPortFwd });
  const set = (k: keyof PortForwardRequest, v: any) => setForm((p) => ({ ...p, [k]: v }));

  useEffect(() => {
    if (item) {
      setForm({
        interface: item.interface || 'wan', protocol: item.protocol || 'tcp',
        src_address: item.src_address || item.source || '', src_port: item.src_port || '',
        dst_address: item.dst_address || '', dst_port: item.dst_port || item.port || '',
        target_ip: item.target_ip || item.target || '', target_port: item.target_port || '',
        description: item.description || '', enabled: item.enabled !== false,
      });
    } else if (open) { setForm({ ...emptyPortFwd }); }
  }, [item, open]);

  const mutation = useWriteMutation(
    gatewayId,
    () => isEdit
      ? gatewayApi.updatePortForward(gatewayId, item.uuid || item.id, form)
      : gatewayApi.createPortForward(gatewayId, form),
    ['port-forwards'],
    isEdit ? t('GatewayResourceDialogs.portForward.updated') : t('GatewayResourceDialogs.portForward.created'),
    () => onOpenChange(false),
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{isEdit ? t('GatewayResourceDialogs.portForward.titleEdit') : t('GatewayResourceDialogs.portForward.titleNew')}</DialogTitle>
          <DialogDescription>{t('GatewayResourceDialogs.portForward.description')}</DialogDescription>
        </DialogHeader>
        <div className="space-y-3 py-2">
          <div className="grid grid-cols-2 gap-3">
            <div><Label>{t('GatewayResourceDialogs.fields.interface')}</Label><Input placeholder="wan" value={form.interface} onChange={(e) => set('interface', e.target.value)} /></div>
            <div>
              <Label>{t('GatewayResourceDialogs.fields.protocol')}</Label>
              <Select value={form.protocol} onValueChange={(v) => set('protocol', v)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="tcp">TCP</SelectItem>
                  <SelectItem value="udp">UDP</SelectItem>
                  <SelectItem value="tcp/udp">TCP/UDP</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div><Label>{t('GatewayResourceDialogs.fields.extPort')}</Label><Input placeholder="8080" value={form.dst_port} onChange={(e) => set('dst_port', e.target.value)} /></div>
            <div><Label>{t('GatewayResourceDialogs.fields.targetIp')}</Label><Input placeholder="192.168.1.150" value={form.target_ip} onChange={(e) => set('target_ip', e.target.value)} /></div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div><Label>{t('GatewayResourceDialogs.fields.targetPort')}</Label><Input placeholder="80" value={form.target_port} onChange={(e) => set('target_port', e.target.value)} /></div>
            <div><Label>{t('GatewayResourceDialogs.fields.srcAddressOpt')}</Label><Input placeholder={t('GatewayResourceDialogs.placeholders.any')} value={form.src_address || ''} onChange={(e) => set('src_address', e.target.value)} /></div>
          </div>
          <div><Label>{t('GatewayResourceDialogs.fields.description')}</Label><Input value={form.description || ''} onChange={(e) => set('description', e.target.value)} /></div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('GatewayResourceDialogs.actions.cancel')}</Button>
          <Button onClick={() => mutation.mutate()} disabled={mutation.isPending || !form.dst_port || !form.target_ip || !form.target_port}>
            {mutation.isPending ? <><Loader2 className="h-4 w-4 animate-spin mr-1" /> {t('GatewayResourceDialogs.actions.saving')}</> : isEdit ? t('GatewayResourceDialogs.actions.update') : t('GatewayResourceDialogs.actions.create')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// 7. Source NAT Rule · Create
// ═══════════════════════════════════════════════════════════════════════

const emptySNAT: SourceNATRuleRequest = {
  interface: 'wan', protocol: '', source_net: '', destination_net: '', target: '', description: '', enabled: true,
};

export function SourceNATFormDialog({ open, onOpenChange, gatewayId }: BaseDialogProps) {
  const { t } = useTranslation('firewall');
  const [form, setForm] = useState<SourceNATRuleRequest>({ ...emptySNAT });
  const set = (k: keyof SourceNATRuleRequest, v: any) => setForm((p) => ({ ...p, [k]: v }));

  useEffect(() => { if (open) setForm({ ...emptySNAT }); }, [open]);

  const mutation = useWriteMutation(
    gatewayId,
    () => gatewayApi.createSourceNATRule(gatewayId, form),
    ['nat-rules'],
    t('GatewayResourceDialogs.sourceNat.created'),
    () => onOpenChange(false),
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{t('GatewayResourceDialogs.sourceNat.title')}</DialogTitle>
          <DialogDescription>{t('GatewayResourceDialogs.sourceNat.description')}</DialogDescription>
        </DialogHeader>
        <div className="space-y-3 py-2">
          <div><Label>{t('GatewayResourceDialogs.fields.interface')}</Label><Input placeholder="wan" value={form.interface} onChange={(e) => set('interface', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.sourceNetwork')}</Label><Input placeholder="192.168.1.0/24" value={form.source_net || ''} onChange={(e) => set('source_net', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.destinationNetwork')}</Label><Input placeholder={t('GatewayResourceDialogs.placeholders.any')} value={form.destination_net || ''} onChange={(e) => set('destination_net', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.natTarget')}</Label><Input placeholder={t('GatewayResourceDialogs.placeholders.interfaceAddress')} value={form.target || ''} onChange={(e) => set('target', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.description')}</Label><Input value={form.description || ''} onChange={(e) => set('description', e.target.value)} /></div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('GatewayResourceDialogs.actions.cancel')}</Button>
          <Button onClick={() => mutation.mutate()} disabled={mutation.isPending || !form.interface}>
            {mutation.isPending ? <><Loader2 className="h-4 w-4 animate-spin mr-1" /> {t('GatewayResourceDialogs.actions.creating')}</> : t('GatewayResourceDialogs.actions.create')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// 8. Alias · Create / Edit (FormDialog + FormFieldArray for `content`)
// ═══════════════════════════════════════════════════════════════════════

const ALIAS_TYPES = ['host', 'network', 'port', 'url', 'geoip', 'mac', 'external'] as const;

const aliasSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  type: z.enum(ALIAS_TYPES),
  content: z
    .array(z.object({ value: z.string().min(1, 'Required') }))
    .min(1, 'At least one entry is required'),
  description: z.string(),
  enabled: z.boolean(),
});
type AliasFormValues = z.infer<typeof aliasSchema>;

const emptyAliasForm: AliasFormValues = {
  name: '',
  type: 'host',
  content: [{ value: '' }],
  description: '',
  enabled: true,
};

export function AliasFormDialog({ open, onOpenChange, gatewayId, item }: EditableDialogProps<any>) {
  const { t } = useTranslation('firewall');
  const isEdit = !!item;
  const queryClient = useQueryClient();
  const { toast } = useToast();

  // Build defaultValues from `item` (edit mode) or empty (create mode).
  // Content can arrive as either an array or a comma-separated string.
  const defaults: AliasFormValues = item
    ? {
        name: item.name || '',
        type: (ALIAS_TYPES as readonly string[]).includes(item.type) ? item.type : 'host',
        content: (() => {
          const c = Array.isArray(item.content)
            ? item.content
            : (item.content || '').split(',').map((s: string) => s.trim()).filter(Boolean);
          return c.length > 0
            ? c.map((v: string) => ({ value: v }))
            : [{ value: '' }];
        })(),
        description: item.description || '',
        enabled: item.enabled !== false,
      }
    : emptyAliasForm;

  return (
    <FormDialog<AliasFormValues>
      open={open}
      onOpenChange={onOpenChange}
      title={isEdit ? t('GatewayResourceDialogs.alias.titleEdit') : t('GatewayResourceDialogs.alias.titleNew')}
      description={t('GatewayResourceDialogs.alias.description')}
      schema={aliasSchema}
      defaultValues={defaults}
      submitLabel={isEdit ? t('GatewayResourceDialogs.actions.update') : t('GatewayResourceDialogs.actions.create')}
      contentClassName="max-w-md max-h-[85vh] overflow-y-auto"
      onSubmit={async (values) => {
        const payload: AliasRequest = {
          name: values.name,
          type: values.type,
          content: values.content.map((c) => c.value.trim()).filter(Boolean),
          description: values.description,
          enabled: values.enabled,
        };
        if (isEdit) {
          await gatewayApi.updateAlias(gatewayId, item.uuid || item.id, payload);
        } else {
          await gatewayApi.createAlias(gatewayId, payload);
        }
        queryClient.invalidateQueries({ queryKey: ['gateways', gatewayId, 'aliases'] });
        toast({ title: t('GatewayResourceDialogs.toast.successTitle'), description: isEdit ? t('GatewayResourceDialogs.alias.updated') : t('GatewayResourceDialogs.alias.created') });
        onOpenChange(false);
      }}
    >
      {(form) => (
        <>
          <FormField
            control={form.control}
            name="name"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('GatewayResourceDialogs.fields.name')}</FormLabel>
                <FormControl>
                  <Input placeholder="my_servers" disabled={isEdit} {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="type"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('GatewayResourceDialogs.fields.type')}</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    <SelectItem value="host">{t('GatewayResourceDialogs.aliasTypes.host')}</SelectItem>
                    <SelectItem value="network">{t('GatewayResourceDialogs.aliasTypes.network')}</SelectItem>
                    <SelectItem value="port">{t('GatewayResourceDialogs.aliasTypes.port')}</SelectItem>
                    <SelectItem value="url">{t('GatewayResourceDialogs.aliasTypes.url')}</SelectItem>
                    <SelectItem value="geoip">GeoIP</SelectItem>
                    <SelectItem value="mac">MAC</SelectItem>
                    <SelectItem value="external">{t('GatewayResourceDialogs.aliasTypes.external')}</SelectItem>
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormFieldArray<AliasFormValues, 'content'>
            control={form.control}
            name="content"
            defaultItem={{ value: '' }}
            addLabel={t('GatewayResourceDialogs.alias.addEntry')}
            label={t('GatewayResourceDialogs.alias.contentLabel')}
            description={t('GatewayResourceDialogs.alias.contentDescription')}
            minItems={1}
            emptyState={{
              icon: ListChecks,
              title: t('GatewayResourceDialogs.alias.emptyTitle'),
              description: t('GatewayResourceDialogs.alias.emptyDescription'),
            }}
          >
            {(_item, index, { remove, removeDisabled }) => (
              <div className="flex gap-2 items-start">
                <FormField
                  control={form.control}
                  name={`content.${index}.value` as const}
                  render={({ field }) => (
                    <FormItem className="flex-1">
                      <FormLabel className="sr-only">{t('GatewayResourceDialogs.alias.entryLabel', { index: index + 1 })}</FormLabel>
                      <FormControl>
                        <Input placeholder={t('GatewayResourceDialogs.placeholders.aliasEntry')} {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  onClick={() => remove()}
                  disabled={removeDisabled}
                  aria-label={t('GatewayResourceDialogs.alias.removeEntry', { index: index + 1 })}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
            )}
          </FormFieldArray>
          <FormField
            control={form.control}
            name="description"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('GatewayResourceDialogs.fields.description')}</FormLabel>
                <FormControl>
                  <Input {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </>
      )}
    </FormDialog>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// 9. WireGuard Server · Create
// ═══════════════════════════════════════════════════════════════════════

const emptyWGServer: WireGuardServerRequest = { name: '', listen_port: 51820, tunnel_address: [], enabled: true };

export function WireGuardServerFormDialog({ open, onOpenChange, gatewayId }: BaseDialogProps) {
  const { t } = useTranslation('firewall');
  const [form, setForm] = useState<WireGuardServerRequest>({ ...emptyWGServer });
  const [tunnelStr, setTunnelStr] = useState('');
  const set = (k: keyof WireGuardServerRequest, v: any) => setForm((p) => ({ ...p, [k]: v }));

  useEffect(() => { if (open) { setForm({ ...emptyWGServer }); setTunnelStr(''); } }, [open]);

  const mutation = useWriteMutation(
    gatewayId,
    () => gatewayApi.createWireGuardServer(gatewayId, { ...form, tunnel_address: tunnelStr.split(',').map((s) => s.trim()).filter(Boolean) }),
    ['wireguard'],
    t('GatewayResourceDialogs.wireGuardServer.created'),
    () => onOpenChange(false),
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{t('GatewayResourceDialogs.wireGuardServer.title')}</DialogTitle>
          <DialogDescription>{t('GatewayResourceDialogs.wireGuardServer.description')}</DialogDescription>
        </DialogHeader>
        <div className="space-y-3 py-2">
          <div><Label>{t('GatewayResourceDialogs.fields.name')}</Label><Input placeholder="wg0" value={form.name} onChange={(e) => set('name', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.listenPort')}</Label><Input type="number" value={form.listen_port} onChange={(e) => set('listen_port', parseInt(e.target.value) || 51820)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.tunnelAddresses')}</Label><Input placeholder="10.10.10.1/24" value={tunnelStr} onChange={(e) => setTunnelStr(e.target.value)} /></div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('GatewayResourceDialogs.actions.cancel')}</Button>
          <Button onClick={() => mutation.mutate()} disabled={mutation.isPending || !form.name || !tunnelStr.trim()}>
            {mutation.isPending ? <><Loader2 className="h-4 w-4 animate-spin mr-1" /> {t('GatewayResourceDialogs.actions.creating')}</> : t('GatewayResourceDialogs.actions.create')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// 10. WireGuard Peer · Create
// ═══════════════════════════════════════════════════════════════════════

const emptyWGPeer: WireGuardPeerRequest = { name: '', public_key: '', allowed_ips: [], endpoint: '', keepalive: 25, enabled: true };

export function WireGuardPeerFormDialog({ open, onOpenChange, gatewayId }: BaseDialogProps) {
  const { t } = useTranslation('firewall');
  const [form, setForm] = useState<WireGuardPeerRequest>({ ...emptyWGPeer });
  const [allowedStr, setAllowedStr] = useState('');
  const set = (k: keyof WireGuardPeerRequest, v: any) => setForm((p) => ({ ...p, [k]: v }));

  useEffect(() => { if (open) { setForm({ ...emptyWGPeer }); setAllowedStr(''); } }, [open]);

  const mutation = useWriteMutation(
    gatewayId,
    () => gatewayApi.createWireGuardPeer(gatewayId, { ...form, allowed_ips: allowedStr.split(',').map((s) => s.trim()).filter(Boolean) }),
    ['wireguard'],
    t('GatewayResourceDialogs.wireGuardPeer.created'),
    () => onOpenChange(false),
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{t('GatewayResourceDialogs.wireGuardPeer.title')}</DialogTitle>
          <DialogDescription>{t('GatewayResourceDialogs.wireGuardPeer.description')}</DialogDescription>
        </DialogHeader>
        <div className="space-y-3 py-2">
          <div><Label>{t('GatewayResourceDialogs.fields.name')}</Label><Input placeholder="peer-laptop" value={form.name} onChange={(e) => set('name', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.publicKey')}</Label><Input placeholder={t('GatewayResourceDialogs.placeholders.base64PublicKey')} value={form.public_key} onChange={(e) => set('public_key', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.allowedIps')}</Label><Input placeholder="10.10.10.2/32, 192.168.1.0/24" value={allowedStr} onChange={(e) => setAllowedStr(e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.endpointOptional')}</Label><Input placeholder="vpn.example.com:51820" value={form.endpoint || ''} onChange={(e) => set('endpoint', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.keepalive')}</Label><Input type="number" value={form.keepalive || 25} onChange={(e) => set('keepalive', parseInt(e.target.value) || 25)} /></div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('GatewayResourceDialogs.actions.cancel')}</Button>
          <Button onClick={() => mutation.mutate()} disabled={mutation.isPending || !form.name || !form.public_key || !allowedStr.trim()}>
            {mutation.isPending ? <><Loader2 className="h-4 w-4 animate-spin mr-1" /> {t('GatewayResourceDialogs.actions.creating')}</> : t('GatewayResourceDialogs.actions.create')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// 11. OpenVPN Instance · Create
// ═══════════════════════════════════════════════════════════════════════

const emptyOVPN: OpenVPNInstanceRequest = {
  description: '', role: 'server', protocol: 'udp', port: 1194, tunnel_network: '', local_network: '', remote_network: '', enabled: true,
};

export function OpenVPNInstanceFormDialog({ open, onOpenChange, gatewayId }: BaseDialogProps) {
  const { t } = useTranslation('firewall');
  const [form, setForm] = useState<OpenVPNInstanceRequest>({ ...emptyOVPN });
  const set = (k: keyof OpenVPNInstanceRequest, v: any) => setForm((p) => ({ ...p, [k]: v }));

  useEffect(() => { if (open) setForm({ ...emptyOVPN }); }, [open]);

  const mutation = useWriteMutation(
    gatewayId,
    () => gatewayApi.createOpenVPNInstance(gatewayId, form),
    ['openvpn'],
    t('GatewayResourceDialogs.openVpn.created'),
    () => onOpenChange(false),
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{t('GatewayResourceDialogs.openVpn.title')}</DialogTitle>
          <DialogDescription>{t('GatewayResourceDialogs.openVpn.description')}</DialogDescription>
        </DialogHeader>
        <div className="space-y-3 py-2">
          <div><Label>{t('GatewayResourceDialogs.fields.description')}</Label><Input placeholder={t('GatewayResourceDialogs.placeholders.officeVpn')} value={form.description} onChange={(e) => set('description', e.target.value)} /></div>
          <div>
            <Label>{t('GatewayResourceDialogs.fields.role')}</Label>
            <Select value={form.role} onValueChange={(v) => set('role', v)}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="server">{t('GatewayResourceDialogs.options.server')}</SelectItem>
                <SelectItem value="client">{t('GatewayResourceDialogs.options.client')}</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label>{t('GatewayResourceDialogs.fields.protocol')}</Label>
              <Select value={form.protocol || 'udp'} onValueChange={(v) => set('protocol', v)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="udp">UDP</SelectItem>
                  <SelectItem value="tcp">TCP</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div><Label>{t('GatewayResourceDialogs.fields.port')}</Label><Input type="number" value={form.port || 1194} onChange={(e) => set('port', parseInt(e.target.value) || 1194)} /></div>
          </div>
          <div><Label>{t('GatewayResourceDialogs.fields.tunnelNetwork')}</Label><Input placeholder="10.8.0.0/24" value={form.tunnel_network || ''} onChange={(e) => set('tunnel_network', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.localNetwork')}</Label><Input placeholder="192.168.1.0/24" value={form.local_network || ''} onChange={(e) => set('local_network', e.target.value)} /></div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('GatewayResourceDialogs.actions.cancel')}</Button>
          <Button onClick={() => mutation.mutate()} disabled={mutation.isPending || !form.description}>
            {mutation.isPending ? <><Loader2 className="h-4 w-4 animate-spin mr-1" /> {t('GatewayResourceDialogs.actions.creating')}</> : t('GatewayResourceDialogs.actions.create')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// 12. Static Route · Create
// ═══════════════════════════════════════════════════════════════════════

const emptyRoute: StaticRouteRequest = { network: '', gateway: '', description: '', disabled: false };

export function StaticRouteFormDialog({ open, onOpenChange, gatewayId }: BaseDialogProps) {
  const { t } = useTranslation('firewall');
  const [form, setForm] = useState<StaticRouteRequest>({ ...emptyRoute });
  const set = (k: keyof StaticRouteRequest, v: any) => setForm((p) => ({ ...p, [k]: v }));

  useEffect(() => { if (open) setForm({ ...emptyRoute }); }, [open]);

  const mutation = useWriteMutation(
    gatewayId,
    () => gatewayApi.createStaticRoute(gatewayId, form),
    ['static-routes', 'routing-table'],
    t('GatewayResourceDialogs.staticRoute.created'),
    () => onOpenChange(false),
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{t('GatewayResourceDialogs.staticRoute.title')}</DialogTitle>
          <DialogDescription>{t('GatewayResourceDialogs.staticRoute.description')}</DialogDescription>
        </DialogHeader>
        <div className="space-y-3 py-2">
          <div><Label>{t('GatewayResourceDialogs.fields.destinationNetwork')}</Label><Input placeholder="10.0.0.0/8" value={form.network} onChange={(e) => set('network', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.gateway')}</Label><Input placeholder="192.168.1.1" value={form.gateway} onChange={(e) => set('gateway', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.description')}</Label><Input value={form.description || ''} onChange={(e) => set('description', e.target.value)} /></div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('GatewayResourceDialogs.actions.cancel')}</Button>
          <Button onClick={() => mutation.mutate()} disabled={mutation.isPending || !form.network || !form.gateway}>
            {mutation.isPending ? <><Loader2 className="h-4 w-4 animate-spin mr-1" /> {t('GatewayResourceDialogs.actions.creating')}</> : t('GatewayResourceDialogs.actions.create')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// 13. Traffic Shaper Pipe · Create
// ═══════════════════════════════════════════════════════════════════════

const emptyPipe: ShaperPipeRequest = { description: '', bandwidth: 100, bandwidth_metric: 'Mbit', enabled: true };

export function ShaperPipeFormDialog({ open, onOpenChange, gatewayId }: BaseDialogProps) {
  const { t } = useTranslation('firewall');
  const [form, setForm] = useState<ShaperPipeRequest>({ ...emptyPipe });
  const set = (k: keyof ShaperPipeRequest, v: any) => setForm((p) => ({ ...p, [k]: v }));

  useEffect(() => { if (open) setForm({ ...emptyPipe }); }, [open]);

  const mutation = useWriteMutation(
    gatewayId,
    () => gatewayApi.createShaperPipe(gatewayId, form),
    ['shaper-pipes'],
    t('GatewayResourceDialogs.shaperPipe.created'),
    () => onOpenChange(false),
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{t('GatewayResourceDialogs.shaperPipe.title')}</DialogTitle>
          <DialogDescription>{t('GatewayResourceDialogs.shaperPipe.description')}</DialogDescription>
        </DialogHeader>
        <div className="space-y-3 py-2">
          <div><Label>{t('GatewayResourceDialogs.fields.description')}</Label><Input placeholder={t('GatewayResourceDialogs.placeholders.uploadLimit')} value={form.description} onChange={(e) => set('description', e.target.value)} /></div>
          <div className="grid grid-cols-2 gap-3">
            <div><Label>{t('GatewayResourceDialogs.fields.bandwidth')}</Label><Input type="number" value={form.bandwidth} onChange={(e) => set('bandwidth', parseInt(e.target.value) || 100)} /></div>
            <div>
              <Label>{t('GatewayResourceDialogs.fields.unit')}</Label>
              <Select value={form.bandwidth_metric} onValueChange={(v) => set('bandwidth_metric', v)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="Kbit">Kbit/s</SelectItem>
                  <SelectItem value="Mbit">Mbit/s</SelectItem>
                  <SelectItem value="Gbit">Gbit/s</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div><Label>{t('GatewayResourceDialogs.fields.mask')}</Label><Input placeholder="none / src-ip / dst-ip" value={form.mask || ''} onChange={(e) => set('mask', e.target.value)} /></div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('GatewayResourceDialogs.actions.cancel')}</Button>
          <Button onClick={() => mutation.mutate()} disabled={mutation.isPending || !form.description || !form.bandwidth}>
            {mutation.isPending ? <><Loader2 className="h-4 w-4 animate-spin mr-1" /> {t('GatewayResourceDialogs.actions.creating')}</> : t('GatewayResourceDialogs.actions.create')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// 14. IDS Settings · Edit
// ═══════════════════════════════════════════════════════════════════════

export function IDSSettingsFormDialog({
  open,
  onOpenChange,
  gatewayId,
  currentSettings,
}: BaseDialogProps & { currentSettings: any }) {
  const { t } = useTranslation('firewall');
  const [form, setForm] = useState({
    enabled: false,
    ips_mode: false,
    pattern_matcher: 'aho-corasick',
    interfaces: '',
  });
  const set = (k: string, v: any) => setForm((p) => ({ ...p, [k]: v }));

  useEffect(() => {
    if (currentSettings && open) {
      setForm({
        enabled: currentSettings.enabled ?? false,
        ips_mode: currentSettings.ips_mode ?? false,
        pattern_matcher: currentSettings.pattern_matcher || 'aho-corasick',
        interfaces: Array.isArray(currentSettings.interfaces)
          ? currentSettings.interfaces.join(', ')
          : currentSettings.interfaces || '',
      });
    }
  }, [currentSettings, open]);

  const mutation = useWriteMutation(
    gatewayId,
    () => gatewayApi.updateIDSSettings(gatewayId, {
      enabled: form.enabled,
      ips_mode: form.ips_mode,
      pattern_matcher: form.pattern_matcher,
      interfaces: form.interfaces.split(',').map((s) => s.trim()).filter(Boolean),
    }),
    ['ids-settings'],
    t('GatewayResourceDialogs.ids.updated'),
    () => onOpenChange(false),
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{t('GatewayResourceDialogs.ids.title')}</DialogTitle>
          <DialogDescription>{t('GatewayResourceDialogs.ids.description')}</DialogDescription>
        </DialogHeader>
        <div className="space-y-3 py-2">
          <div className="flex items-center justify-between">
            <Label>{t('GatewayResourceDialogs.fields.idsEnabled')}</Label>
            <Button variant={form.enabled ? 'default' : 'outline'} size="sm" onClick={() => set('enabled', !form.enabled)}>
              {form.enabled ? t('GatewayResourceDialogs.options.yes') : t('GatewayResourceDialogs.options.no')}
            </Button>
          </div>
          <div className="flex items-center justify-between">
            <Label>{t('GatewayResourceDialogs.fields.ipsMode')}</Label>
            <Button variant={form.ips_mode ? 'destructive' : 'outline'} size="sm" onClick={() => set('ips_mode', !form.ips_mode)}>
              {form.ips_mode ? t('GatewayResourceDialogs.options.active') : t('GatewayResourceDialogs.options.alertOnly')}
            </Button>
          </div>
          <div><Label>{t('GatewayResourceDialogs.fields.patternMatcher')}</Label><Input value={form.pattern_matcher} onChange={(e) => set('pattern_matcher', e.target.value)} /></div>
          <div><Label>{t('GatewayResourceDialogs.fields.interfacesCsv')}</Label><Input placeholder="lan, wan" value={form.interfaces} onChange={(e) => set('interfaces', e.target.value)} /></div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('GatewayResourceDialogs.actions.cancel')}</Button>
          <Button onClick={() => mutation.mutate()} disabled={mutation.isPending}>
            {mutation.isPending ? <><Loader2 className="h-4 w-4 animate-spin mr-1" /> {t('GatewayResourceDialogs.actions.saving')}</> : t('GatewayResourceDialogs.actions.update')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
