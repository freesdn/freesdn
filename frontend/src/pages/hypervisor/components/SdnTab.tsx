// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Hypervisor Module - SDN Tab
 * Shows Proxmox SDN zones, VNets, and controllers with create/delete/apply actions.
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import { DestructiveConfirmDialog } from '@/components/ui/destructive-confirm-dialog';
import { Network, Plus, Trash2, Play } from 'lucide-react';
import { hypervisorApi } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import type { CreateSdnZoneRequest, CreateSdnVnetRequest } from '@/lib/api';

interface SdnTabProps {
  controllerId: string;
}

interface SdnZone {
  zone?: string;
  type?: string;
  nodes?: string;
  mtu?: number;
  bridge?: string;
  state?: string;
  pending?: Record<string, unknown>;
}

interface SdnVnet {
  vnet?: string;
  zone?: string;
  tag?: number;
  alias?: string;
  vlanaware?: boolean;
  state?: string;
}

interface SdnController {
  controller?: string;
  type?: string;
  node?: string;
  state?: string;
}

const ZONE_TYPES = ['vlan', 'qinq', 'vxlan', 'evpn', 'simple'];

export function SdnTab({ controllerId }: SdnTabProps) {
  const { t } = useTranslation('hypervisor');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [zoneDialog, setZoneDialog] = useState(false);
  const [vnetDialog, setVnetDialog] = useState(false);
  // Typed-confirm targets (replace native confirm()).
  const [applyConfirmOpen, setApplyConfirmOpen] = useState(false);
  const [deleteZoneTarget, setDeleteZoneTarget] = useState<string | null>(null);
  const [deleteVnetTarget, setDeleteVnetTarget] = useState<string | null>(null);

  // Zone form state
  const [zoneName, setZoneName] = useState('');
  const [zoneType, setZoneType] = useState('vlan');
  const [zoneNodes, setZoneNodes] = useState('');
  const [zoneBridge, setZoneBridge] = useState('');
  const [zoneMtu, setZoneMtu] = useState('');

  // VNet form state
  const [vnetName, setVnetName] = useState('');
  const [vnetZone, setVnetZone] = useState('');
  const [vnetAlias, setVnetAlias] = useState('');
  const [vnetTag, setVnetTag] = useState('');
  const [vnetVlanaware, setVnetVlanaware] = useState(false);

  // Queries
  const { data: zonesResp, isLoading: zonesLoading, isError: zonesError } = useQuery({
    queryKey: ['hypervisor', 'sdn', 'zones', controllerId],
    queryFn: () => hypervisorApi.getSdnZones(controllerId),
    enabled: !!controllerId,
  });
  const zones: SdnZone[] = (zonesResp?.data as SdnZone[] | undefined) || [];

  const { data: vnetsResp, isLoading: vnetsLoading, isError: vnetsError } = useQuery({
    queryKey: ['hypervisor', 'sdn', 'vnets', controllerId],
    queryFn: () => hypervisorApi.getSdnVnets(controllerId),
    enabled: !!controllerId,
  });
  const vnets: SdnVnet[] = (vnetsResp?.data as SdnVnet[] | undefined) || [];

  const { data: ctrlsResp, isLoading: ctrlsLoading, isError: ctrlsError } = useQuery({
    queryKey: ['hypervisor', 'sdn', 'controllers', controllerId],
    queryFn: () => hypervisorApi.getSdnControllers(controllerId),
    enabled: !!controllerId,
  });
  const sdnControllers: SdnController[] = (ctrlsResp?.data as SdnController[] | undefined) || [];

  const isLoading = zonesLoading || vnetsLoading || ctrlsLoading;
  const hasError = zonesError || vnetsError || ctrlsError;

  // Mutations
  const applyMutation = useMutation({
    mutationFn: () => hypervisorApi.applySdn(controllerId),
    onSuccess: () => {
      toast({ title: t('SdnTab.toasts.sdnApplied.title'), description: t('SdnTab.toasts.sdnApplied.description') });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'sdn'] });
    },
    onError: () => {
      toast({ title: t('SdnTab.toasts.applyFailed.title'), description: t('SdnTab.toasts.applyFailed.description'), variant: 'destructive' });
    },
  });

  const createZoneMutation = useMutation({
    mutationFn: (data: CreateSdnZoneRequest) => hypervisorApi.createSdnZone(controllerId, data),
    onSuccess: () => {
      toast({ title: t('SdnTab.toasts.zoneCreated.title') });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'sdn', 'zones', controllerId] });
      setZoneDialog(false);
      resetZoneForm();
    },
    onError: () => {
      toast({ title: t('SdnTab.toasts.createFailed.title'), description: t('SdnTab.toasts.createZoneFailed.description'), variant: 'destructive' });
    },
  });

  const createVnetMutation = useMutation({
    mutationFn: (data: CreateSdnVnetRequest) => hypervisorApi.createSdnVnet(controllerId, data),
    onSuccess: () => {
      toast({ title: t('SdnTab.toasts.vnetCreated.title') });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'sdn', 'vnets', controllerId] });
      setVnetDialog(false);
      resetVnetForm();
    },
    onError: () => {
      toast({ title: t('SdnTab.toasts.createFailed.title'), description: t('SdnTab.toasts.createVnetFailed.description'), variant: 'destructive' });
    },
  });

  const deleteZoneMutation = useMutation({
    mutationFn: (zone: string) => hypervisorApi.deleteSdnZone(controllerId, zone),
    onSuccess: () => {
      toast({ title: t('SdnTab.toasts.zoneDeleted.title') });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'sdn', 'zones', controllerId] });
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      toast({ title: t('SdnTab.toasts.deleteFailed.title'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  const deleteVnetMutation = useMutation({
    mutationFn: (vnet: string) => hypervisorApi.deleteSdnVnet(controllerId, vnet),
    onSuccess: () => {
      toast({ title: t('SdnTab.toasts.vnetDeleted.title') });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'sdn', 'vnets', controllerId] });
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      toast({ title: t('SdnTab.toasts.deleteFailed.title'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  function resetZoneForm() {
    setZoneName('');
    setZoneType('vlan');
    setZoneNodes('');
    setZoneBridge('');
    setZoneMtu('');
  }

  function resetVnetForm() {
    setVnetName('');
    setVnetZone('');
    setVnetAlias('');
    setVnetTag('');
    setVnetVlanaware(false);
  }

  function handleCreateZone() {
    const data: CreateSdnZoneRequest = { zone: zoneName, type: zoneType };
    if (zoneNodes) data.nodes = zoneNodes;
    if (zoneBridge) data.bridge = zoneBridge;
    if (zoneMtu) data.mtu = parseInt(zoneMtu);
    createZoneMutation.mutate(data);
  }

  function handleCreateVnet() {
    const data: CreateSdnVnetRequest = { vnet: vnetName, zone: vnetZone };
    if (vnetAlias) data.alias = vnetAlias;
    if (vnetTag) data.tag = parseInt(vnetTag);
    if (vnetVlanaware) data.vlanaware = true;
    createVnetMutation.mutate(data);
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10" />
        <Skeleton className="h-64" />
        <Skeleton className="h-64" />
      </div>
    );
  }

  if (hasError) {
    return <ErrorState message={t('SdnTab.errorState.message')} />;
  }

  return (
    <div className="space-y-6">
      {/* Top bar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Network className="h-5 w-5 text-muted-foreground" />
          <h3 className="font-semibold">{t('SdnTab.heading')}</h3>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => setZoneDialog(true)}>
            <Plus className="h-3 w-3 mr-1" /> {t('SdnTab.actions.createZone')}
          </Button>
          <Button variant="outline" size="sm" onClick={() => setVnetDialog(true)}>
            <Plus className="h-3 w-3 mr-1" /> {t('SdnTab.actions.createVnet')}
          </Button>
          <Button size="sm" onClick={() => setApplyConfirmOpen(true)} disabled={applyMutation.isPending}>
            <Play className="h-3 w-3 mr-1" /> {t('SdnTab.actions.applySdn')}
          </Button>
        </div>
      </div>

      {/* Zones */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">{t('SdnTab.zones.title')}</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {zones.length === 0 ? (
            <div className="py-4">
              <EmptyState icon={Network} title={t('SdnTab.zones.empty.title')} description={t('SdnTab.zones.empty.description')} />
            </div>
          ) : (
            <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('SdnTab.zones.columns.zone')}</TableHead>
                  <TableHead>{t('SdnTab.zones.columns.type')}</TableHead>
                  <TableHead>{t('SdnTab.zones.columns.nodes')}</TableHead>
                  <TableHead>{t('SdnTab.zones.columns.mtu')}</TableHead>
                  <TableHead>{t('SdnTab.zones.columns.bridge')}</TableHead>
                  <TableHead>{t('SdnTab.zones.columns.state')}</TableHead>
                  <TableHead className="text-right">{t('SdnTab.zones.columns.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {zones.map((z) => (
                  <TableRow key={z.zone}>
                    <TableCell className="font-medium">{z.zone}</TableCell>
                    <TableCell><Badge variant="outline">{z.type}</Badge></TableCell>
                    <TableCell className="text-sm">{z.nodes || '--'}</TableCell>
                    <TableCell className="text-sm">{z.mtu || '--'}</TableCell>
                    <TableCell className="text-sm">{z.bridge || '--'}</TableCell>
                    <TableCell className="text-sm">{z.state || '--'}</TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => { if (z.zone) setDeleteZoneTarget(z.zone); }}
                        disabled={deleteZoneMutation.isPending}
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* VNets */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">{t('SdnTab.vnets.title')}</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {vnets.length === 0 ? (
            <div className="py-4">
              <EmptyState icon={Network} title={t('SdnTab.vnets.empty.title')} description={t('SdnTab.vnets.empty.description')} />
            </div>
          ) : (
            <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('SdnTab.vnets.columns.vnet')}</TableHead>
                  <TableHead>{t('SdnTab.vnets.columns.zone')}</TableHead>
                  <TableHead>{t('SdnTab.vnets.columns.tag')}</TableHead>
                  <TableHead>{t('SdnTab.vnets.columns.vlanAware')}</TableHead>
                  <TableHead>{t('SdnTab.vnets.columns.state')}</TableHead>
                  <TableHead className="text-right">{t('SdnTab.vnets.columns.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {vnets.map((v) => (
                  <TableRow key={v.vnet}>
                    <TableCell className="font-medium">{v.vnet}</TableCell>
                    <TableCell><Badge variant="outline">{v.zone}</Badge></TableCell>
                    <TableCell className="text-sm">{v.tag ?? '--'}</TableCell>
                    <TableCell className="text-sm">{v.vlanaware ? t('SdnTab.common.yes') : t('SdnTab.common.no')}</TableCell>
                    <TableCell className="text-sm">{v.state || '--'}</TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => { if (v.vnet) setDeleteVnetTarget(v.vnet); }}
                        disabled={deleteVnetMutation.isPending}
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* SDN Controllers */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">{t('SdnTab.controllers.title')}</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {sdnControllers.length === 0 ? (
            <div className="py-4">
              <EmptyState icon={Network} title={t('SdnTab.controllers.empty.title')} description={t('SdnTab.controllers.empty.description')} />
            </div>
          ) : (
            <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('SdnTab.controllers.columns.controller')}</TableHead>
                  <TableHead>{t('SdnTab.controllers.columns.type')}</TableHead>
                  <TableHead>{t('SdnTab.controllers.columns.node')}</TableHead>
                  <TableHead>{t('SdnTab.controllers.columns.state')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sdnControllers.map((c) => (
                  <TableRow key={c.controller}>
                    <TableCell className="font-medium">{c.controller}</TableCell>
                    <TableCell><Badge variant="outline">{c.type}</Badge></TableCell>
                    <TableCell className="text-sm">{c.node || '--'}</TableCell>
                    <TableCell className="text-sm">{c.state || '--'}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create Zone Dialog */}
      <Dialog open={zoneDialog} onOpenChange={(open) => { if (!open) { setZoneDialog(false); resetZoneForm(); } }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('SdnTab.zoneDialog.title')}</DialogTitle>
            <DialogDescription>{t('SdnTab.zoneDialog.description')}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="zone-name">{t('SdnTab.zoneDialog.fields.name')}</Label>
              <Input id="zone-name" value={zoneName} onChange={(e) => setZoneName(e.target.value)} placeholder="myzone" />
            </div>
            <div>
              <Label>{t('SdnTab.zoneDialog.fields.type')}</Label>
              <Select value={zoneType} onValueChange={setZoneType}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {ZONE_TYPES.map((t) => <SelectItem key={t} value={t}>{t}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="zone-nodes">{t('SdnTab.zoneDialog.fields.nodes')}</Label>
              <Input id="zone-nodes" value={zoneNodes} onChange={(e) => setZoneNodes(e.target.value)} placeholder="node1,node2" />
            </div>
            <div>
              <Label htmlFor="zone-bridge">{t('SdnTab.zoneDialog.fields.bridge')}</Label>
              <Input id="zone-bridge" value={zoneBridge} onChange={(e) => setZoneBridge(e.target.value)} placeholder="vmbr0" />
            </div>
            <div>
              <Label htmlFor="zone-mtu">{t('SdnTab.zoneDialog.fields.mtu')}</Label>
              <Input id="zone-mtu" type="number" value={zoneMtu} onChange={(e) => setZoneMtu(e.target.value)} placeholder="1500" />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setZoneDialog(false); resetZoneForm(); }}>{t('SdnTab.actions.cancel')}</Button>
            <Button disabled={!zoneName || createZoneMutation.isPending} onClick={handleCreateZone}>{t('SdnTab.actions.createZone')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Create VNet Dialog */}
      <Dialog open={vnetDialog} onOpenChange={(open) => { if (!open) { setVnetDialog(false); resetVnetForm(); } }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('SdnTab.vnetDialog.title')}</DialogTitle>
            <DialogDescription>{t('SdnTab.vnetDialog.description')}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="vnet-name">{t('SdnTab.vnetDialog.fields.name')}</Label>
              <Input id="vnet-name" value={vnetName} onChange={(e) => setVnetName(e.target.value)} placeholder="myvnet" />
            </div>
            <div>
              <Label>{t('SdnTab.vnetDialog.fields.zone')}</Label>
              <Select value={vnetZone} onValueChange={setVnetZone}>
                <SelectTrigger><SelectValue placeholder={t('SdnTab.vnetDialog.fields.zonePlaceholder')} /></SelectTrigger>
                <SelectContent>
                  {zones.filter((z): z is typeof z & { zone: string } => !!z.zone).map((z) => <SelectItem key={z.zone} value={z.zone}>{z.zone}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="vnet-alias">{t('SdnTab.vnetDialog.fields.alias')}</Label>
              <Input id="vnet-alias" value={vnetAlias} onChange={(e) => setVnetAlias(e.target.value)} />
            </div>
            <div>
              <Label htmlFor="vnet-tag">{t('SdnTab.vnetDialog.fields.tag')}</Label>
              <Input id="vnet-tag" type="number" value={vnetTag} onChange={(e) => setVnetTag(e.target.value)} />
            </div>
            <div className="flex items-center gap-2">
              <Checkbox id="vnet-vlanaware" checked={vnetVlanaware} onCheckedChange={(v) => setVnetVlanaware(!!v)} />
              <Label htmlFor="vnet-vlanaware" className="text-sm">{t('SdnTab.vnetDialog.fields.vlanAware')}</Label>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setVnetDialog(false); resetVnetForm(); }}>{t('SdnTab.actions.cancel')}</Button>
            <Button disabled={!vnetName || !vnetZone || createVnetMutation.isPending} onClick={handleCreateVnet}>{t('SdnTab.actions.createVnet')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Typed-confirm dialogs (replace native confirm()) */}
      <DestructiveConfirmDialog
        open={applyConfirmOpen}
        onOpenChange={setApplyConfirmOpen}
        title={t('SdnTab.actions.applySdn')}
        description={t('SdnTab.confirms.applySdn')}
        confirmationText="APPLY"
        confirmLabel={t('SdnTab.actions.applySdn')}
        isPending={applyMutation.isPending}
        onConfirm={() => {
          applyMutation.mutate();
          setApplyConfirmOpen(false);
        }}
      />
      <DestructiveConfirmDialog
        open={deleteZoneTarget !== null}
        onOpenChange={(o) => { if (!o) setDeleteZoneTarget(null); }}
        title={t('SdnTab.zones.columns.zone')}
        description={t('SdnTab.confirms.deleteZone', { zone: deleteZoneTarget ?? '' })}
        confirmationText={deleteZoneTarget ?? ''}
        confirmLabel={t('common:delete')}
        isPending={deleteZoneMutation.isPending}
        onConfirm={() => {
          if (deleteZoneTarget) deleteZoneMutation.mutate(deleteZoneTarget);
          setDeleteZoneTarget(null);
        }}
      />
      <DestructiveConfirmDialog
        open={deleteVnetTarget !== null}
        onOpenChange={(o) => { if (!o) setDeleteVnetTarget(null); }}
        title={t('SdnTab.vnets.columns.vnet')}
        description={t('SdnTab.confirms.deleteVnet', { vnet: deleteVnetTarget ?? '' })}
        confirmationText={deleteVnetTarget ?? ''}
        confirmLabel={t('common:delete')}
        isPending={deleteVnetMutation.isPending}
        onConfirm={() => {
          if (deleteVnetTarget) deleteVnetMutation.mutate(deleteVnetTarget);
          setDeleteVnetTarget(null);
        }}
      />
    </div>
  );
}
