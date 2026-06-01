// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Hypervisor Module - Templates Tab
 * Lists VM/CT templates with "Deploy from template" action.
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation } from '@tanstack/react-query';
import { FileBox, Server, Cpu, MemoryStick, HardDrive, Rocket, Loader2 } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import { hypervisorApi } from '@/lib/api';
import type { HypervisorTabProps } from './types';
import type { HypervisorVM } from '@/lib/api';

export function TemplatesTab({ controllerId, nodes, queryClient }: HypervisorTabProps) {
  const { t } = useTranslation('hypervisor');
  const { toast } = useToast();

  // Fetch all VMs + CTs to find templates
  const { data: allVmsResp, isLoading: vmsLoading, isError: vmsError } = useQuery({
    queryKey: ['hypervisor', 'templates', controllerId, 'qemu'],
    queryFn: () => hypervisorApi.getAllVMs(controllerId, 'qemu'),
    enabled: !!controllerId,
  });
  const { data: allCtsResp, isLoading: ctsLoading, isError: ctsError } = useQuery({
    queryKey: ['hypervisor', 'templates', controllerId, 'lxc'],
    queryFn: () => hypervisorApi.getAllVMs(controllerId, 'lxc'),
    enabled: !!controllerId,
  });

  const templates: HypervisorVM[] = [
    ...(allVmsResp?.data || []).filter((v) => v.template),
    ...(allCtsResp?.data || []).filter((v) => v.template),
  ];

  // Deploy dialog state
  const [deployFrom, setDeployFrom] = useState<HypervisorVM | null>(null);
  const [deployName, setDeployName] = useState('');
  const [deployNode, setDeployNode] = useState('');
  const [deployFull, setDeployFull] = useState(true);
  const [, setDeployStart] = useState(false);
  const [deployNewId, setDeployNewId] = useState('');

  // Fetch next VMID when deploy dialog opens
  const { data: nextIdResp } = useQuery({
    queryKey: ['hypervisor', 'nextid', controllerId],
    queryFn: () => hypervisorApi.getNextVMID(controllerId),
    enabled: !!deployFrom,
  });

  const cloneMutation = useMutation({
    mutationFn: () => {
      if (!deployFrom) throw new Error('No template selected');
      return hypervisorApi.cloneVM(controllerId, deployFrom.node, deployFrom.vm_type, deployFrom.vmid, {
        newid: parseInt(deployNewId) || (nextIdResp?.data?.vmid ?? 0),
        name: deployName || undefined,
        target: deployNode || undefined,
        full: deployFull,
      });
    },
    onSuccess: () => {
      toast({ title: t('TemplatesTab.toast.deployStarted.title'), description: t('TemplatesTab.toast.deployStarted.description', { name: deployFrom?.name }) });
      setDeployFrom(null);
      queryClient.invalidateQueries({ queryKey: ['hypervisor'] });
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      toast({ title: t('TemplatesTab.toast.deployFailed.title'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  const isLoading = vmsLoading || ctsLoading;
  const isError = vmsError || ctsError;

  if (isError) {
    return <ErrorState message={t('TemplatesTab.error.fetch')} />;
  }

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {[1, 2, 3].map((i) => <Skeleton key={i} className="h-40" />)}
      </div>
    );
  }

  if (templates.length === 0) {
    return (
      <EmptyState
        icon={FileBox}
        title={t('TemplatesTab.empty.title')}
        description={t('TemplatesTab.empty.description')}
      />
    );
  }

  return (
    <>
      <div className="grid gap-4 grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
        {templates.map((tpl) => (
          <Card key={`${tpl.node}-${tpl.vmid}`} className="group">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileBox className="h-4 w-4 text-muted-foreground" />
                  <CardTitle className="text-sm">{tpl.name || t('TemplatesTab.card.fallbackName', { vmid: tpl.vmid })}</CardTitle>
                </div>
                <Badge variant="outline" className="text-[10px]">
                  {tpl.vm_type === 'lxc' ? 'CT' : 'VM'} #{tpl.vmid}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 text-xs">
                <div className="flex items-center gap-1 text-muted-foreground">
                  <Server className="h-3 w-3" /> {tpl.node}
                </div>
                <div className="flex items-center gap-1 text-muted-foreground">
                  <Cpu className="h-3 w-3" /> {t('TemplatesTab.card.cores', { count: tpl.cpu_cores })}
                </div>
                <div className="flex items-center gap-1 text-muted-foreground">
                  <MemoryStick className="h-3 w-3" /> {t('TemplatesTab.card.memoryMb', { value: tpl.memory_mb })}
                </div>
              </div>
              {tpl.disk_gb > 0 && (
                <div className="flex items-center gap-1 text-xs text-muted-foreground">
                  <HardDrive className="h-3 w-3" /> {t('TemplatesTab.card.diskGb', { value: tpl.disk_gb.toFixed(1) })}
                </div>
              )}
              {tpl.tags.length > 0 && (
                <div className="flex gap-1 flex-wrap">
                  {tpl.tags.map((tag) => (
                    <Badge key={tag} variant="secondary" className="text-[10px] px-1">{tag}</Badge>
                  ))}
                </div>
              )}
              <Button
                size="sm"
                className="w-full"
                onClick={() => {
                  setDeployFrom(tpl);
                  setDeployName(`${tpl.name || 'vm'}-${Date.now().toString(36)}`);
                  setDeployNode(tpl.node);
                  setDeployFull(true);
                  setDeployStart(false);
                  setDeployNewId('');
                }}
              >
                <Rocket className="h-3.5 w-3.5 mr-1" /> {t('TemplatesTab.actions.deploy')}
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Deploy from Template Dialog */}
      <Dialog open={!!deployFrom} onOpenChange={(open) => { if (!open) setDeployFrom(null); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('TemplatesTab.dialog.title')}</DialogTitle>
            <DialogDescription>
              {t('TemplatesTab.dialog.description', {
                name: deployFrom?.name,
                vmid: deployFrom?.vmid,
                target: deployFrom?.vm_type === 'lxc'
                  ? t('TemplatesTab.dialog.targetContainer')
                  : t('TemplatesTab.dialog.targetVm'),
              })}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>{t('TemplatesTab.dialog.newVmid')}</Label>
              <Input
                type="number"
                value={deployNewId || (nextIdResp?.data?.vmid ?? '')}
                onChange={(e) => setDeployNewId(e.target.value)}
                placeholder={t('TemplatesTab.dialog.nextPlaceholder', { vmid: nextIdResp?.data?.vmid ?? '...' })}
                min={100}
              />
            </div>
            <div>
              <Label>{t('TemplatesTab.dialog.name')}</Label>
              <Input value={deployName} onChange={(e) => setDeployName(e.target.value)} />
            </div>
            <div>
              <Label>{t('TemplatesTab.dialog.targetNode')}</Label>
              <Select value={deployNode} onValueChange={setDeployNode}>
                <SelectTrigger><SelectValue placeholder={t('TemplatesTab.dialog.sameNode')} /></SelectTrigger>
                <SelectContent>
                  {nodes.filter((n) => n.status === 'online').map((n) => (
                    <SelectItem key={n.node} value={n.node}>{n.node}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center gap-2">
              <Checkbox id="deploy-full" checked={deployFull} onCheckedChange={(v) => setDeployFull(!!v)} />
              <Label htmlFor="deploy-full">{t('TemplatesTab.dialog.fullClone')}</Label>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeployFrom(null)}>{t('TemplatesTab.actions.cancel')}</Button>
            <Button onClick={() => cloneMutation.mutate()} disabled={cloneMutation.isPending}>
              {cloneMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {cloneMutation.isPending ? t('TemplatesTab.actions.deploying') : t('TemplatesTab.actions.deploy')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
