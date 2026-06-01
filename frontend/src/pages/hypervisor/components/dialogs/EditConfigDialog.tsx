// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Hypervisor Module - Edit VM/CT Configuration Dialog
 *
 * Built on the canonical FormDialog primitive (zod + react-hook-form).
 * The "General" tab carries the editable fields; "Disks", "Network",
 * and "Guest Agent" tabs are read-only views fetched alongside the config.
 *
 * The submit handler diffs the form values against the freshly-fetched
 * config and only sends fields that actually changed (preserves the
 * original "no-op when nothing changed" behavior).
 */
import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';
import { Cpu, Network, HardDrive, Info } from 'lucide-react';
import { FormDialog } from '@/components/ui/form-dialog';
import { FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Textarea } from '@/components/ui/textarea';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import { useToast } from '@/hooks/use-toast';
import { hypervisorApi } from '@/lib/api';
import type { HypervisorVM, GuestAgentInfo } from '@/lib/api';

interface EditConfigDialogProps {
  open: boolean;
  onClose: () => void;
  controllerId: string;
  vm: HypervisorVM | null;
}

function parseDisks(config: Record<string, unknown>): { key: string; value: string }[] {
  const diskPrefixes = ['scsi', 'virtio', 'ide', 'sata', 'efidisk', 'rootfs', 'mp'];
  return Object.entries(config)
    .filter(([k]) => diskPrefixes.some((p) => k.startsWith(p) && /\d/.test(k.replace(p, ''))))
    .map(([key, value]) => ({ key, value: String(value) }))
    .sort((a, b) => a.key.localeCompare(b.key));
}

function parseNetworks(config: Record<string, unknown>): { key: string; value: string }[] {
  return Object.entries(config)
    .filter(([k]) => /^net\d+$/.test(k))
    .map(([key, value]) => ({ key, value: String(value) }))
    .sort((a, b) => a.key.localeCompare(b.key));
}

const schema = z.object({
  cores: z.coerce.number().int().min(1).max(512),
  memory: z.coerce.number().int().min(16),
  balloon: z.coerce.number().int().min(0),
  description: z.string(),
  tags: z.string(),
  onboot: z.boolean(),
});
type EditConfigFormValues = z.infer<typeof schema>;

export function EditConfigDialog({ open, onClose, controllerId, vm }: EditConfigDialogProps) {
  const { t } = useTranslation('hypervisor');
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Fetch current config
  const { data: configResp, isLoading: configLoading } = useQuery({
    queryKey: ['hypervisor', 'config', controllerId, vm?.node, vm?.vm_type, vm?.vmid],
    queryFn: () => hypervisorApi.getVMConfig(controllerId, vm!.node, vm!.vm_type, vm!.vmid),
    enabled: open && !!vm,
  });
  const config = useMemo(
    () => (configResp?.data ?? {}) as Record<string, unknown>,
    [configResp],
  );

  // Guest agent info (only for running QEMU VMs)
  const { data: agentResp, isLoading: agentLoading } = useQuery({
    queryKey: ['hypervisor', 'agent', controllerId, vm?.node, vm?.vmid],
    queryFn: () => hypervisorApi.getGuestAgentInfo(controllerId, vm!.node, vm!.vmid),
    enabled: open && !!vm && vm.vm_type === 'qemu' && vm.status === 'running',
  });
  const agentInfo = agentResp?.data as GuestAgentInfo | undefined;

  // Defaults derived from the freshly-fetched config (re-keyed below to force
  // FormDialog to reset whenever the config payload arrives).
  const defaultValues = useMemo<EditConfigFormValues>(() => ({
    cores: Number(config.cores) || vm?.cpu_cores || 1,
    memory: Number(config.memory) || vm?.memory_mb || 512,
    balloon: Number(config.balloon) || 0,
    description: String(config.description || ''),
    tags: String(config.tags || ''),
    onboot: config.onboot === 1 || config.onboot === true,
  }), [config, vm]);

  const updateMutation = useMutation({
    mutationFn: (values: EditConfigFormValues) => {
      if (!vm) throw new Error('No VM');
      const payload: Record<string, unknown> = {};
      if (values.cores !== Number(config.cores)) payload.cores = values.cores;
      if (values.memory !== Number(config.memory)) payload.memory = values.memory;
      if (values.balloon !== Number(config.balloon)) payload.balloon = values.balloon;
      if (values.description !== String(config.description || '')) payload.description = values.description;
      if (values.tags !== String(config.tags || '')) payload.tags = values.tags;
      const configOnboot = config.onboot === 1 || config.onboot === true;
      if (values.onboot !== configOnboot) payload.onboot = values.onboot;
      if (Object.keys(payload).length === 0) throw new Error('No changes');
      return hypervisorApi.updateConfig(controllerId, vm.node, vm.vm_type, vm.vmid, payload);
    },
    onSuccess: () => {
      toast({ title: t('EditConfigDialog.toast.updated') });
      queryClient.invalidateQueries({ queryKey: ['hypervisor'] });
      onClose();
    },
    onError: (err: unknown) => {
      const e = err as { response?: { data?: { detail?: string } }; message?: string };
      const msg = e.message === 'No changes' ? t('EditConfigDialog.toast.noChanges') : (e?.response?.data?.detail || e.message);
      toast({ title: t('EditConfigDialog.toast.updateFailed'), description: msg, variant: 'destructive' });
    },
  });

  const disks = parseDisks(config);
  const networks = parseNetworks(config);
  const showAgentTab = vm?.vm_type === 'qemu' && vm.status === 'running';

  return (
    <FormDialog<EditConfigFormValues>
      // Force a re-mount when the config object identity changes so defaults
      // populate after the GET resolves.
      key={configResp ? 'loaded' : 'loading'}
      open={open}
      onOpenChange={(o) => { if (!o) onClose(); }}
      title={`${vm?.vm_type === 'lxc' ? t('EditConfigDialog.ct') : t('EditConfigDialog.vm')} ${vm?.vmid ?? ''} · ${vm?.name ?? ''}`}
      description={vm ? t('EditConfigDialog.dialogDescription', { node: vm.node }) : undefined}
      schema={schema}
      defaultValues={defaultValues}
      submitLabel={updateMutation.isPending ? t('EditConfigDialog.submit.saving') : t('EditConfigDialog.submit.save')}
      submitDisabled={configLoading}
      contentClassName="sm:max-w-2xl max-h-[85vh] overflow-hidden"
      onSubmit={async (values) => {
        await updateMutation.mutateAsync(values);
      }}
    >
      {(form) => {
        if (configLoading) return <Skeleton className="h-64" />;
        const memoryWatch = form.watch('memory');
        return (
          <Tabs defaultValue="general" className="flex-1 overflow-hidden">
            <TabsList className="w-full justify-start">
              <TabsTrigger value="general"><Cpu className="h-3.5 w-3.5 mr-1" />{t('EditConfigDialog.tabs.general')}</TabsTrigger>
              <TabsTrigger value="disks"><HardDrive className="h-3.5 w-3.5 mr-1" />{t('EditConfigDialog.tabs.disks', { count: disks.length })}</TabsTrigger>
              <TabsTrigger value="network"><Network className="h-3.5 w-3.5 mr-1" />{t('EditConfigDialog.tabs.network', { count: networks.length })}</TabsTrigger>
              {showAgentTab && (
                <TabsTrigger value="agent"><Info className="h-3.5 w-3.5 mr-1" />{t('EditConfigDialog.tabs.guestAgent')}</TabsTrigger>
              )}
            </TabsList>

            <div className="overflow-y-auto flex-1 max-h-[50vh] pr-1 mt-3">
              <TabsContent value="general" className="space-y-4 mt-0">
                <div className="grid grid-cols-2 gap-4">
                  <FormField
                    control={form.control}
                    name="cores"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>{t('EditConfigDialog.fields.cpuCores')}</FormLabel>
                        <FormControl>
                          <Input type="number" min={1} max={512} {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="memory"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>{t('EditConfigDialog.fields.memory')}</FormLabel>
                        <FormControl>
                          <Input type="number" min={16} step={256} {...field} />
                        </FormControl>
                        <FormDescription>{t('EditConfigDialog.fields.memoryGb', { gb: (Number(memoryWatch) / 1024).toFixed(1) })}</FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>
                {vm?.vm_type === 'qemu' && (
                  <FormField
                    control={form.control}
                    name="balloon"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>{t('EditConfigDialog.fields.balloon')}</FormLabel>
                        <FormControl>
                          <Input type="number" min={0} {...field} />
                        </FormControl>
                        <FormDescription>{t('EditConfigDialog.fields.balloonHelp')}</FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                )}
                <FormField
                  control={form.control}
                  name="tags"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t('EditConfigDialog.fields.tags')}</FormLabel>
                      <FormControl>
                        <Input placeholder="tag1;tag2;tag3" {...field} />
                      </FormControl>
                      <FormDescription>{t('EditConfigDialog.fields.tagsHelp')}</FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="description"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t('EditConfigDialog.fields.description')}</FormLabel>
                      <FormControl>
                        <Textarea rows={3} placeholder={t('EditConfigDialog.fields.descriptionPlaceholder')} {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="onboot"
                  render={({ field }) => (
                    <FormItem>
                      <label className="flex items-center gap-2 cursor-pointer">
                        <FormControl>
                          <Checkbox checked={field.value} onCheckedChange={(v) => field.onChange(!!v)} />
                        </FormControl>
                        <span className="text-sm">{t('EditConfigDialog.fields.startOnBoot')}</span>
                      </label>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </TabsContent>

              <TabsContent value="disks" className="mt-0">
                {disks.length === 0 ? (
                  <p className="text-sm text-muted-foreground py-4">{t('EditConfigDialog.disks.empty')}</p>
                ) : (
                  <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>{t('EditConfigDialog.disks.disk')}</TableHead>
                        <TableHead>{t('EditConfigDialog.disks.configuration')}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {disks.map((d) => (
                        <TableRow key={d.key}>
                          <TableCell className="font-mono text-xs font-medium">{d.key}</TableCell>
                          <TableCell className="text-xs text-muted-foreground break-all">{d.value}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                  </div>
                )}
              </TabsContent>

              <TabsContent value="network" className="mt-0">
                {networks.length === 0 ? (
                  <p className="text-sm text-muted-foreground py-4">{t('EditConfigDialog.network.empty')}</p>
                ) : (
                  <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>{t('EditConfigDialog.network.interface')}</TableHead>
                        <TableHead>{t('EditConfigDialog.network.configuration')}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {networks.map((n) => (
                        <TableRow key={n.key}>
                          <TableCell className="font-mono text-xs font-medium">{n.key}</TableCell>
                          <TableCell className="text-xs text-muted-foreground break-all">{n.value}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                  </div>
                )}
              </TabsContent>

              {showAgentTab && (
                <TabsContent value="agent" className="mt-0">
                  {agentLoading ? (
                    <Skeleton className="h-32" />
                  ) : !agentInfo || (agentInfo.interfaces?.length === 0 && !agentInfo.hostname) ? (
                    <p className="text-sm text-muted-foreground py-4">
                      {t('EditConfigDialog.agent.unavailable')}
                    </p>
                  ) : (
                    <div className="space-y-4">
                      {agentInfo.hostname && (
                        <div>
                          <Label className="text-xs text-muted-foreground">{t('EditConfigDialog.agent.hostname')}</Label>
                          <p className="text-sm font-medium">{agentInfo.hostname}</p>
                        </div>
                      )}
                      {agentInfo.os_type && (
                        <div>
                          <Label className="text-xs text-muted-foreground">{t('EditConfigDialog.agent.os')}</Label>
                          <p className="text-sm">{agentInfo.os_type} {agentInfo.os_version}</p>
                        </div>
                      )}
                      {agentInfo.interfaces && agentInfo.interfaces.length > 0 && (
                        <div className="overflow-x-auto">
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>{t('EditConfigDialog.agent.interface')}</TableHead>
                              <TableHead>{t('EditConfigDialog.agent.mac')}</TableHead>
                              <TableHead>{t('EditConfigDialog.agent.ipAddresses')}</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {agentInfo.interfaces.map((iface) => (
                              <TableRow key={iface.name}>
                                <TableCell className="font-mono text-xs">{iface.name}</TableCell>
                                <TableCell className="font-mono text-xs text-muted-foreground">{iface.mac_address}</TableCell>
                                <TableCell>
                                  <div className="flex flex-col gap-0.5">
                                    {iface.ip_addresses.map((ip) => (
                                      <Badge key={ip} variant="outline" className="text-[10px] font-mono w-fit">{ip}</Badge>
                                    ))}
                                  </div>
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                        </div>
                      )}
                    </div>
                  )}
                </TabsContent>
              )}
            </div>
          </Tabs>
        );
      }}
    </FormDialog>
  );
}
