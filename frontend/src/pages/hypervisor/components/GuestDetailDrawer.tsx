// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Hypervisor Module - Guest Detail Drawer
 * Slide-over panel showing VM/CT details when a row is clicked.
 * Includes overview, firewall rules, and config sections.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useState, useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Play,
  Power,
  RotateCcw,
  Shield,
  Settings,
  LayoutDashboard,
  Plus,
  Trash2,
  Loader2,
  Cloud,
  RefreshCw,
  Save,
} from 'lucide-react';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from '@/components/ui/sheet';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Skeleton } from '@/components/ui/skeleton';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { DestructiveConfirmDialog } from '@/components/ui/destructive-confirm-dialog';
import { useToast } from '@/hooks/use-toast';
import { hypervisorApi } from '@/lib/api';
import type { HypervisorVM, HypervisorFirewallRule } from '@/lib/api';
import { formatBytes, formatUptime } from './helpers';
import { statusBadge } from './StatusBadge';

interface GuestDetailDrawerProps {
  vm: HypervisorVM;
  controllerId: string;
  isOpen: boolean;
  onClose: () => void;
  onAction: (params: { node: string; vmType: string; vmid: number; action: string }) => void;
}

type Section = 'overview' | 'firewall' | 'config' | 'cloudinit';

export function GuestDetailDrawer({
  vm,
  controllerId,
  isOpen,
  onClose,
  onAction,
}: GuestDetailDrawerProps) {
  const { t } = useTranslation('hypervisor');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [activeSection, setActiveSection] = useState<Section>('overview');

  // ── Firewall rules ───────────────────────────────────────────────────
  const { data: fwResp, isLoading: fwLoading, isError: fwError } = useQuery({
    queryKey: ['hypervisor', 'guest-fw', controllerId, vm.node, vm.vm_type, vm.vmid],
    queryFn: () =>
      hypervisorApi.getGuestFirewallRules(controllerId, vm.node, vm.vm_type, vm.vmid),
    enabled: isOpen && activeSection === 'firewall',
  });
  const fwRules: HypervisorFirewallRule[] = fwResp?.data || [];

  // ── Config ───────────────────────────────────────────────────────────
  const { data: configResp, isLoading: configLoading, isError: configError } = useQuery({
    queryKey: ['hypervisor', 'guest-config', controllerId, vm.node, vm.vm_type, vm.vmid],
    queryFn: () =>
      hypervisorApi.getVMConfig(controllerId, vm.node, vm.vm_type, vm.vmid),
    enabled: isOpen && activeSection === 'config',
  });
  const config: Record<string, unknown> = configResp?.data || {};

  // ── Pending config ───────────────────────────────────────────────────
  const { data: pendingResp } = useQuery({
    queryKey: ['hypervisor', 'guest-pending', controllerId, vm.node, vm.vm_type, vm.vmid],
    queryFn: () =>
      vm.vm_type === 'qemu'
        ? hypervisorApi.getVmPendingConfig(controllerId, vm.node, vm.vmid)
        : hypervisorApi.getContainerPendingConfig(controllerId, vm.node, vm.vmid),
    enabled: isOpen && activeSection === 'config',
  });
  const pendingItems: Array<{ key: string; value: unknown; pending?: unknown }> =
    pendingResp?.data || [];

  // ── CloudInit ─────────────────────────────────────────────────────────
  const { data: ciResp, isLoading: ciLoading, isError: ciError } = useQuery({
    queryKey: ['hypervisor', 'cloudinit', controllerId, vm.node, vm.vmid],
    queryFn: () => hypervisorApi.getCloudInit(controllerId, vm.node, vm.vmid),
    enabled: isOpen && activeSection === 'cloudinit' && vm.vm_type !== 'lxc',
  });
   
  const ciData: Record<string, any> = useMemo(() => ciResp?.data || {}, [ciResp?.data]);

  const [ciUser, setCiUser] = useState('');
  const [ciPassword, setCiPassword] = useState('');
  const [ciSshKeys, setCiSshKeys] = useState('');
  const [ciIpConfig, setCiIpConfig] = useState('');
  const [ciNameserver, setCiNameserver] = useState('');
  const [ciSearchDomain, setCiSearchDomain] = useState('');

  // Populate CloudInit form when data arrives. Sensitive fields
  // (cipassword, sshkeys, ipconfig0, cloud-init can carry inline
  // credentials in any of these) are NEVER pre-filled. The backend
  // redacts them server-side anyway,
  // but rendering ``"***"`` in a password input is misleading, the
  // operator would think their password literally became "***" or
  // would submit "***" as the new value. Empty fields communicate
  // the actual contract: "leave blank to keep, type new to change".
  useEffect(() => {
    if (ciData && activeSection === 'cloudinit') {
      setCiUser(ciData.ciuser || '');
      // INTENTIONALLY blank, see comment above.
      setCiPassword('');
      setCiSshKeys('');
      // ipconfig0 is "ip=...,gw=...,password=..." on some images;
      // also blank by default. Operator can read the redacted server
      // value from the (Show current) hint instead.
      setCiIpConfig('');
      setCiNameserver(ciData.nameserver || '');
      setCiSearchDomain(ciData.searchdomain || '');
    }
  }, [ciData, activeSection]);

  const updateCiMutation = useMutation({
    mutationFn: () =>
      hypervisorApi.updateCloudInit(controllerId, vm.node, vm.vmid, {
        ciuser: ciUser || undefined,
        cipassword: ciPassword || undefined,
        sshkeys: ciSshKeys ? encodeURIComponent(ciSshKeys) : undefined,
        ipconfig0: ciIpConfig || undefined,
        nameserver: ciNameserver || undefined,
        searchdomain: ciSearchDomain || undefined,
      }),
    onSuccess: () => {
      toast({ title: t('GuestDetailDrawer.toasts.cloudInitSaved') });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'cloudinit'] });
    },
    onError: (err: any) => {
      toast({ title: t('GuestDetailDrawer.toasts.saveFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  const regenerateCiMutation = useMutation({
    mutationFn: () => hypervisorApi.regenerateCloudInit(controllerId, vm.node, vm.vmid),
    onSuccess: () => {
      toast({ title: t('GuestDetailDrawer.toasts.cloudInitRegenerated') });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'cloudinit'] });
    },
    onError: (err: any) => {
      toast({ title: t('GuestDetailDrawer.toasts.regenerateFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  // ── Firewall rule creation state ──────────────────────────────────────
  // Reset state when VM changes
  useEffect(() => {
    setActiveSection('overview');
    setShowAddRule(false);
    setDeleteRuleTarget(null);
    setRegenerateConfirmOpen(false);
    setCiUser('');
    setCiPassword('');
    setCiSshKeys('');
    setCiIpConfig('');
    setCiNameserver('');
    setCiSearchDomain('');
  }, [vm?.vmid]);

  const [showAddRule, setShowAddRule] = useState(false);
  // Typed-confirm targets for irreversible actions (replace native
  // confirm()).
  const [deleteRuleTarget, setDeleteRuleTarget] = useState<number | null>(null);
  const [regenerateConfirmOpen, setRegenerateConfirmOpen] = useState(false);
  const [newRuleAction, setNewRuleAction] = useState('ACCEPT');
  const [newRuleType, setNewRuleType] = useState('in');
  const [newRuleProto, setNewRuleProto] = useState('tcp');
  const [newRuleDport, setNewRuleDport] = useState('');
  const [newRuleSource, setNewRuleSource] = useState('');
  const [newRuleComment, setNewRuleComment] = useState('');

  const createRuleMutation = useMutation({
    mutationFn: () =>
      hypervisorApi.createGuestFirewallRule(controllerId, vm.node, vm.vm_type, vm.vmid, {
        action: newRuleAction,
        type: newRuleType,
        proto: newRuleProto || undefined,
        dport: newRuleDport || undefined,
        source: newRuleSource || undefined,
        comment: newRuleComment || undefined,
      }),
    onSuccess: () => {
      toast({ title: t('GuestDetailDrawer.toasts.ruleCreated') });
      setShowAddRule(false);
      setNewRuleDport('');
      setNewRuleSource('');
      setNewRuleComment('');
      queryClient.invalidateQueries({
        queryKey: ['hypervisor', 'guest-fw', controllerId, vm.node, vm.vm_type, vm.vmid],
      });
    },
    onError: (err: any) => {
      toast({
        title: t('GuestDetailDrawer.toasts.createRuleFailed'),
        description: err?.response?.data?.detail || err.message,
        variant: 'destructive',
      });
    },
  });

  const deleteRuleMutation = useMutation({
    mutationFn: (pos: number) =>
      hypervisorApi.deleteGuestFirewallRule(controllerId, vm.node, vm.vm_type, vm.vmid, pos),
    onSuccess: () => {
      toast({ title: t('GuestDetailDrawer.toasts.ruleDeleted') });
      queryClient.invalidateQueries({
        queryKey: ['hypervisor', 'guest-fw', controllerId, vm.node, vm.vm_type, vm.vmid],
      });
    },
    onError: (err: any) => {
      toast({
        title: t('GuestDetailDrawer.toasts.deleteRuleFailed'),
        description: err?.response?.data?.detail || err.message,
        variant: 'destructive',
      });
    },
  });

  // ── Config display helpers ────────────────────────────────────────────
  const pendingKeys = new Set(
    Array.isArray(pendingItems)
      ? pendingItems.filter((p: any) => p.pending !== undefined).map((p: any) => p.key)
      : []
  );

  const configEntries = Object.entries(config).filter(
    ([key]) => !['digest', 'description'].includes(key)
  );

  const sectionTabs: { key: Section; label: string; icon: typeof LayoutDashboard }[] = [
    { key: 'overview', label: t('GuestDetailDrawer.tabs.overview'), icon: LayoutDashboard },
    { key: 'firewall', label: t('GuestDetailDrawer.tabs.firewall'), icon: Shield },
    { key: 'config', label: t('GuestDetailDrawer.tabs.config'), icon: Settings },
    ...(vm.vm_type !== 'lxc'
      ? [{ key: 'cloudinit' as Section, label: t('GuestDetailDrawer.tabs.cloudInit'), icon: Cloud }]
      : []),
  ];

  return (
    <Sheet open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <SheetContent side="right" className="overflow-y-auto sm:max-w-xl">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2">
            {statusBadge(vm.status)}
            <span>{vm.name || t('GuestDetailDrawer.header.vmFallback', { vmid: vm.vmid })}</span>
            <Badge variant="outline">
              {vm.vm_type === 'lxc' ? t('GuestDetailDrawer.header.ct') : t('GuestDetailDrawer.header.vm')} {vm.vmid}
            </Badge>
          </SheetTitle>
          <SheetDescription>
            {t('GuestDetailDrawer.header.nodeUptime', { node: vm.node, uptime: formatUptime(vm.uptime) })}
            {vm.ip_address ? t('GuestDetailDrawer.header.ipSuffix', { ip: vm.ip_address }) : ''}
          </SheetDescription>
        </SheetHeader>

        {/* Quick action buttons */}
        <div className="flex gap-2 mt-4">
          {vm.status !== 'running' && (
            <Button
              size="sm"
              onClick={() =>
                onAction({ node: vm.node, vmType: vm.vm_type, vmid: vm.vmid, action: 'start' })
              }
            >
              <Play className="h-3 w-3 mr-1" /> {t('GuestDetailDrawer.actions.start')}
            </Button>
          )}
          {vm.status === 'running' && (
            <>
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  if (confirm(t('GuestDetailDrawer.confirms.shutdown', { kind: vm.vm_type === 'lxc' ? t('GuestDetailDrawer.header.ct') : t('GuestDetailDrawer.header.vm'), vmid: vm.vmid })))
                    onAction({
                      node: vm.node,
                      vmType: vm.vm_type,
                      vmid: vm.vmid,
                      action: 'shutdown',
                    });
                }}
              >
                <Power className="h-3 w-3 mr-1" /> {t('GuestDetailDrawer.actions.shutdown')}
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  if (confirm(t('GuestDetailDrawer.confirms.reboot', { kind: vm.vm_type === 'lxc' ? t('GuestDetailDrawer.header.ct') : t('GuestDetailDrawer.header.vm'), vmid: vm.vmid })))
                    onAction({
                      node: vm.node,
                      vmType: vm.vm_type,
                      vmid: vm.vmid,
                      action: 'reboot',
                    });
                }}
              >
                <RotateCcw className="h-3 w-3 mr-1" /> {t('GuestDetailDrawer.actions.reboot')}
              </Button>
            </>
          )}
        </div>

        {/* Section tabs */}
        <div className="flex gap-1 mt-4 border-b pb-0 overflow-x-auto">
          {sectionTabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.key}
                onClick={() => setActiveSection(tab.key)}
                className={`flex items-center gap-1.5 px-3 py-2 text-sm transition-colors border-b-2 -mb-px ${
                  activeSection === tab.key
                    ? 'border-primary text-primary font-medium'
                    : 'border-transparent text-muted-foreground hover:text-foreground'
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* ── Overview section ─────────────────────────────────────────────── */}
        {activeSection === 'overview' && (
          <div className="space-y-4 mt-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-xs text-muted-foreground">{t('GuestDetailDrawer.overview.cpu')}</p>
                <Progress value={vm.cpu_percent} className="h-2 mt-1" />
                <p className="text-sm mt-1">
                  {t('GuestDetailDrawer.overview.cpuValue', { percent: vm.cpu_percent.toFixed(1), cores: vm.cpu_cores })}
                </p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">{t('GuestDetailDrawer.overview.memory')}</p>
                <Progress value={vm.memory_percent} className="h-2 mt-1" />
                <p className="text-sm mt-1">
                  {t('GuestDetailDrawer.overview.memoryValue', { used: vm.memory_used_mb, total: vm.memory_mb })}
                </p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">{t('GuestDetailDrawer.overview.disk')}</p>
                <Progress value={vm.disk_percent} className="h-2 mt-1" />
                <p className="text-sm mt-1">
                  {t('GuestDetailDrawer.overview.diskValue', { used: vm.disk_used_gb.toFixed(1), total: vm.disk_gb.toFixed(1) })}
                </p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">{t('GuestDetailDrawer.overview.node')}</p>
                <p className="text-sm font-medium">{vm.node}</p>
                <p className="text-xs text-muted-foreground">
                  {t('GuestDetailDrawer.overview.uptime', { uptime: formatUptime(vm.uptime) })}
                </p>
              </div>
            </div>

            {(vm.net_in > 0 || vm.net_out > 0) && (
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-xs text-muted-foreground">{t('GuestDetailDrawer.overview.networkIn')}</p>
                  <p className="text-sm">{formatBytes(vm.net_in)}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">{t('GuestDetailDrawer.overview.networkOut')}</p>
                  <p className="text-sm">{formatBytes(vm.net_out)}</p>
                </div>
              </div>
            )}

            <div className="grid grid-cols-2 gap-4 pt-2 border-t">
              {vm.ip_address && (
                <div>
                  <p className="text-xs text-muted-foreground">{t('GuestDetailDrawer.overview.ipAddress')}</p>
                  <p className="text-sm font-mono">{vm.ip_address}</p>
                </div>
              )}
              {vm.os_type && (
                <div>
                  <p className="text-xs text-muted-foreground">{t('GuestDetailDrawer.overview.osType')}</p>
                  <p className="text-sm">{vm.os_type}</p>
                </div>
              )}
              {vm.ha_state && (
                <div>
                  <p className="text-xs text-muted-foreground">{t('GuestDetailDrawer.overview.haState')}</p>
                  <Badge variant="outline" className="text-xs">
                    {vm.ha_state}
                  </Badge>
                </div>
              )}
              {vm.lock && (
                <div>
                  <p className="text-xs text-muted-foreground">{t('GuestDetailDrawer.overview.lock')}</p>
                  <Badge variant="destructive" className="text-xs">
                    {vm.lock}
                  </Badge>
                </div>
              )}
              {vm.tags.length > 0 && (
                <div className="col-span-2">
                  <p className="text-xs text-muted-foreground mb-1">{t('GuestDetailDrawer.overview.tags')}</p>
                  <div className="flex gap-1 flex-wrap">
                    {vm.tags.map((tag) => (
                      <Badge key={tag} variant="outline" className="text-xs">
                        {tag}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── Firewall section ─────────────────────────────────────────────── */}
        {activeSection === 'firewall' && (
          <div className="space-y-4 mt-4">
            <div className="flex items-center justify-between">
              <h4 className="text-sm font-medium">{t('GuestDetailDrawer.firewall.heading')}</h4>
              <Button
                size="sm"
                variant="outline"
                onClick={() => setShowAddRule(!showAddRule)}
              >
                <Plus className="h-3 w-3 mr-1" />
                {showAddRule ? t('GuestDetailDrawer.firewall.cancel') : t('GuestDetailDrawer.firewall.addRule')}
              </Button>
            </div>

            {showAddRule && (
              <div className="border rounded-md p-3 space-y-3 bg-muted/30">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <Label className="text-xs">{t('GuestDetailDrawer.firewall.action')}</Label>
                    <Select value={newRuleAction} onValueChange={setNewRuleAction}>
                      <SelectTrigger className="h-8">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="ACCEPT">ACCEPT</SelectItem>
                        <SelectItem value="DROP">DROP</SelectItem>
                        <SelectItem value="REJECT">REJECT</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label className="text-xs">{t('GuestDetailDrawer.firewall.direction')}</Label>
                    <Select value={newRuleType} onValueChange={setNewRuleType}>
                      <SelectTrigger className="h-8">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="in">{t('GuestDetailDrawer.firewall.inbound')}</SelectItem>
                        <SelectItem value="out">{t('GuestDetailDrawer.firewall.outbound')}</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <Label className="text-xs">{t('GuestDetailDrawer.firewall.protocol')}</Label>
                    <Select value={newRuleProto} onValueChange={setNewRuleProto}>
                      <SelectTrigger className="h-8">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="tcp">TCP</SelectItem>
                        <SelectItem value="udp">UDP</SelectItem>
                        <SelectItem value="icmp">ICMP</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label className="text-xs">{t('GuestDetailDrawer.firewall.destPort')}</Label>
                    <Input
                      className="h-8"
                      value={newRuleDport}
                      onChange={(e) => setNewRuleDport(e.target.value)}
                      placeholder="80,443"
                    />
                  </div>
                </div>
                <div>
                  <Label className="text-xs">{t('GuestDetailDrawer.firewall.sourceOptional')}</Label>
                  <Input
                    className="h-8"
                    value={newRuleSource}
                    onChange={(e) => setNewRuleSource(e.target.value)}
                    placeholder="10.0.0.0/24"
                  />
                </div>
                <div>
                  <Label className="text-xs">{t('GuestDetailDrawer.firewall.commentOptional')}</Label>
                  <Input
                    className="h-8"
                    value={newRuleComment}
                    onChange={(e) => setNewRuleComment(e.target.value)}
                    placeholder={t('GuestDetailDrawer.firewall.commentPlaceholder')}
                  />
                </div>
                <Button
                  size="sm"
                  onClick={() => createRuleMutation.mutate()}
                  disabled={createRuleMutation.isPending}
                >
                  {createRuleMutation.isPending && (
                    <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                  )}
                  {t('GuestDetailDrawer.firewall.createRule')}
                </Button>
              </div>
            )}

            {fwError ? (
              <p className="text-sm text-destructive py-4">{t('GuestDetailDrawer.firewall.loadError')}</p>
            ) : fwLoading ? (
              <Skeleton className="h-32" />
            ) : fwRules.length === 0 ? (
              <p className="text-sm text-muted-foreground py-4">
                {t('GuestDetailDrawer.firewall.empty')}
              </p>
            ) : (
              <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>#</TableHead>
                    <TableHead>{t('GuestDetailDrawer.firewall.colDir')}</TableHead>
                    <TableHead>{t('GuestDetailDrawer.firewall.colAction')}</TableHead>
                    <TableHead>{t('GuestDetailDrawer.firewall.colProto')}</TableHead>
                    <TableHead>{t('GuestDetailDrawer.firewall.colSource')}</TableHead>
                    <TableHead>{t('GuestDetailDrawer.firewall.colDport')}</TableHead>
                    <TableHead>{t('GuestDetailDrawer.firewall.colComment')}</TableHead>
                    <TableHead className="w-[40px]" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {fwRules.map((rule) => (
                    <TableRow key={rule.pos}>
                      <TableCell className="font-mono text-xs">{rule.pos}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-[10px]">
                          {rule.type}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            rule.action === 'ACCEPT'
                              ? 'default'
                              : rule.action === 'DROP'
                                ? 'destructive'
                                : 'secondary'
                          }
                        >
                          {rule.action}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs">{rule.proto || '-'}</TableCell>
                      <TableCell className="text-xs font-mono">
                        {rule.source || '-'}
                      </TableCell>
                      <TableCell className="text-xs font-mono">
                        {rule.dport || '-'}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground max-w-[120px] truncate">
                        {rule.comment || '-'}
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-6 w-6 p-0 text-destructive"
                          disabled={deleteRuleMutation.isPending}
                          onClick={() => setDeleteRuleTarget(rule.pos)}
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
          </div>
        )}

        {/* ── Config section ───────────────────────────────────────────────── */}
        {activeSection === 'config' && (
          <div className="space-y-4 mt-4">
            <h4 className="text-sm font-medium">{t('GuestDetailDrawer.config.heading')}</h4>
            {configError ? (
              <p className="text-sm text-destructive py-4">{t('GuestDetailDrawer.config.loadError')}</p>
            ) : configLoading ? (
              <Skeleton className="h-48" />
            ) : configEntries.length === 0 ? (
              <p className="text-sm text-muted-foreground py-4">
                {t('GuestDetailDrawer.config.empty')}
              </p>
            ) : (
              <div className="border rounded-md overflow-hidden">
                <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[160px]">{t('GuestDetailDrawer.config.colKey')}</TableHead>
                      <TableHead>{t('GuestDetailDrawer.config.colValue')}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {configEntries.map(([key, value]) => (
                      <TableRow key={key}>
                        <TableCell className="font-mono text-xs font-medium">
                          {key}
                          {pendingKeys.has(key) && (
                            <Badge variant="outline" className="ml-1 text-[9px] text-amber-600">
                              {t('GuestDetailDrawer.config.pending')}
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground break-all max-w-[300px]">
                          {String(value)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Cloud-Init section ──────────────────────────────────────────── */}
        {activeSection === 'cloudinit' && vm.vm_type !== 'lxc' && (
          <div className="space-y-4 mt-4">
            <h4 className="text-sm font-medium">{t('GuestDetailDrawer.cloudInit.heading')}</h4>
            {ciError ? (
              <p className="text-sm text-destructive py-4">{t('GuestDetailDrawer.cloudInit.loadError')}</p>
            ) : ciLoading ? (
              <Skeleton className="h-48" />
            ) : (
              <div className="space-y-3">
                <div>
                  <Label className="text-xs">{t('GuestDetailDrawer.cloudInit.user')}</Label>
                  <Input
                    className="h-8"
                    value={ciUser}
                    onChange={(e) => setCiUser(e.target.value)}
                    placeholder="root"
                  />
                </div>
                <div>
                  <Label className="text-xs">{t('GuestDetailDrawer.cloudInit.password')}</Label>
                  <Input
                    className="h-8"
                    type="password"
                    value={ciPassword}
                    onChange={(e) => setCiPassword(e.target.value)}
                    placeholder={t('GuestDetailDrawer.cloudInit.passwordPlaceholder')}
                    autoComplete="new-password"
                  />
                </div>
                <div>
                  <Label className="text-xs">{t('GuestDetailDrawer.cloudInit.sshKeys')}</Label>
                  <Textarea
                    className="text-xs font-mono min-h-[80px]"
                    value={ciSshKeys}
                    onChange={(e) => setCiSshKeys(e.target.value)}
                    placeholder={t('GuestDetailDrawer.cloudInit.sshKeysPlaceholder')}
                  />
                </div>
                <div>
                  <Label className="text-xs">{t('GuestDetailDrawer.cloudInit.ipConfig')}</Label>
                  <Input
                    className="h-8 font-mono"
                    value={ciIpConfig}
                    onChange={(e) => setCiIpConfig(e.target.value)}
                    placeholder={t('GuestDetailDrawer.cloudInit.ipConfigPlaceholder')}
                  />
                </div>
                <div>
                  <Label className="text-xs">{t('GuestDetailDrawer.cloudInit.nameserver')}</Label>
                  <Input
                    className="h-8 font-mono"
                    value={ciNameserver}
                    onChange={(e) => setCiNameserver(e.target.value)}
                    placeholder="8.8.8.8"
                  />
                </div>
                <div>
                  <Label className="text-xs">{t('GuestDetailDrawer.cloudInit.searchDomain')}</Label>
                  <Input
                    className="h-8"
                    value={ciSearchDomain}
                    onChange={(e) => setCiSearchDomain(e.target.value)}
                    placeholder="example.com"
                  />
                </div>
                <div className="flex gap-2 pt-2">
                  <Button
                    size="sm"
                    onClick={() => updateCiMutation.mutate()}
                    disabled={updateCiMutation.isPending}
                  >
                    {updateCiMutation.isPending ? (
                      <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                    ) : (
                      <Save className="h-3 w-3 mr-1" />
                    )}
                    {t('GuestDetailDrawer.cloudInit.save')}
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => setRegenerateConfirmOpen(true)}
                    disabled={regenerateCiMutation.isPending}
                  >
                    {regenerateCiMutation.isPending ? (
                      <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                    ) : (
                      <RefreshCw className="h-3 w-3 mr-1" />
                    )}
                    {t('GuestDetailDrawer.cloudInit.regenerateDrive')}
                  </Button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Typed-confirm dialogs for irreversible actions (replace native confirm()) */}
        <DestructiveConfirmDialog
          open={deleteRuleTarget !== null}
          onOpenChange={(o) => { if (!o) setDeleteRuleTarget(null); }}
          title={t('GuestDetailDrawer.firewall.heading')}
          description={t('GuestDetailDrawer.confirms.deleteRule', { pos: deleteRuleTarget ?? '' })}
          confirmationText={deleteRuleTarget !== null ? String(deleteRuleTarget) : ''}
          confirmLabel={t('common:delete')}
          isPending={deleteRuleMutation.isPending}
          onConfirm={() => {
            if (deleteRuleTarget !== null) deleteRuleMutation.mutate(deleteRuleTarget);
            setDeleteRuleTarget(null);
          }}
        />
        <DestructiveConfirmDialog
          open={regenerateConfirmOpen}
          onOpenChange={setRegenerateConfirmOpen}
          title={t('GuestDetailDrawer.cloudInit.regenerateDrive')}
          description={t('GuestDetailDrawer.confirms.regenerate')}
          confirmationText="REGENERATE"
          confirmLabel={t('GuestDetailDrawer.cloudInit.regenerateDrive')}
          isPending={regenerateCiMutation.isPending}
          onConfirm={() => {
            regenerateCiMutation.mutate();
            setRegenerateConfirmOpen(false);
          }}
        />
      </SheetContent>
    </Sheet>
  );
}
