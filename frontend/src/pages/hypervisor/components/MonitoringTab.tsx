// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Hypervisor Module - Monitoring Tab
 * Real-time CPU/Memory/Network/Disk I/O charts using RRD data
 */
import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { useQuery } from '@tanstack/react-query';
import {
  XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Area, AreaChart,
} from 'recharts';
import { Cpu, MemoryStick, Network, HardDrive, Settings, ChevronDown, Info } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState } from '@/components/ui/empty-state';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import { hypervisorApi } from '@/lib/api';
import { formatBytes } from './helpers';
import type { HypervisorTabProps } from './types';
import type { HypervisorRRDPoint, HypervisorVM } from '@/lib/api';

const buildTimeframes = (t: TFunction) => [
  { value: 'hour', label: t('MonitoringTab.timeframes.hour') },
  { value: 'day', label: t('MonitoringTab.timeframes.day') },
  { value: 'week', label: t('MonitoringTab.timeframes.week') },
  { value: 'month', label: t('MonitoringTab.timeframes.month') },
];

function formatTime(ts: number): string {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function MetricChart({
  title,
  icon: Icon,
  data,
  lines,
  yFormatter,
}: {
  title: string;
  icon: typeof Cpu;
  data: HypervisorRRDPoint[];
  lines: { key: string; name: string; color: string }[];
  yFormatter?: (v: number) => string;
}) {
  const { t } = useTranslation('hypervisor');
  if (!data || data.length === 0) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center gap-2">
            <Icon className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-sm">{title}</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground py-8 text-center">{t('MonitoringTab.noData')}</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <Icon className="h-4 w-4 text-muted-foreground" />
          <CardTitle className="text-sm">{title}</CardTitle>
        </div>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={data} margin={{ top: 5, right: 5, left: 5, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
            <XAxis dataKey="time" tickFormatter={formatTime} tick={{ fontSize: 10 }} interval="preserveStartEnd" />
            <YAxis tick={{ fontSize: 10 }} tickFormatter={yFormatter} width={50} />
            <Tooltip
              labelFormatter={(v) => new Date((v as number) * 1000).toLocaleString()}
              formatter={(v, name) => [yFormatter ? yFormatter(Number(v)) : Number(v).toFixed(2), String(name)]}
              contentStyle={{ fontSize: 12 }}
            />
            {lines.map((line) => (
              <Area
                key={line.key}
                type="monotone"
                dataKey={line.key}
                name={line.name}
                stroke={line.color}
                fill={line.color}
                fillOpacity={0.1}
                strokeWidth={1.5}
                dot={false}
                connectNulls
              />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}

const DEFAULT_MAX_POINTS = 500;

interface AlertConfig {
  cpuThreshold: number;
  memoryThreshold: number;
  fireAfter: number;
  resolveAfter: number;
}

function loadAlertConfig(controllerId: string): AlertConfig {
  try {
    const raw = localStorage.getItem(`hypervisor-alert-config-${controllerId}`);
    if (raw) return JSON.parse(raw);
  } catch { /* ignore */ }
  return { cpuThreshold: 80, memoryThreshold: 85, fireAfter: 3, resolveAfter: 2 };
}

function saveAlertConfig(controllerId: string, config: AlertConfig) {
  localStorage.setItem(`hypervisor-alert-config-${controllerId}`, JSON.stringify(config));
}

export function MonitoringTab({ controllerId, nodes }: HypervisorTabProps) {
  const { t } = useTranslation('hypervisor');
  const TIMEFRAMES = buildTimeframes(t);
  const [timeframe, setTimeframe] = useState('hour');
  const [selectedNode, setSelectedNode] = useState('');
  useEffect(() => {
    if (!selectedNode && nodes.length > 0) {
      setSelectedNode(nodes[0].node);
    }
  }, [nodes, selectedNode]);
  const [selectedVM, setSelectedVM] = useState<{ node: string; vmid: number; vmType: string } | null>(null);

  // Alert hysteresis settings
  const [alertSettingsOpen, setAlertSettingsOpen] = useState(false);
  const [alertConfig, setAlertConfig] = useState<AlertConfig>(() => loadAlertConfig(controllerId));

  // Persist alert config on change
  useEffect(() => {
    saveAlertConfig(controllerId, alertConfig);
  }, [controllerId, alertConfig]);

  const activeNode = selectedNode || nodes[0]?.node || '';

  // Node RRD data
  const { data: nodeRrdResp, isLoading: nodeRrdLoading, isError: nodeRrdError } = useQuery({
    queryKey: ['hypervisor', 'rrd', 'node', controllerId, activeNode, timeframe],
    queryFn: () => hypervisorApi.getNodeRRD(controllerId, activeNode, timeframe, DEFAULT_MAX_POINTS),
    enabled: !!controllerId && !!activeNode && !selectedVM,
    refetchInterval: 30_000,
  });
  const nodeRrd = nodeRrdResp?.data || [];

  // VM RRD data
  const { data: vmRrdResp, isLoading: vmRrdLoading, isError: vmRrdError } = useQuery({
    queryKey: ['hypervisor', 'rrd', 'vm', controllerId, selectedVM?.node, selectedVM?.vmid, timeframe],
    queryFn: () => {
      if (selectedVM!.vmType === 'lxc') {
        return hypervisorApi.getContainerRRD(controllerId, selectedVM!.node, selectedVM!.vmid, timeframe, DEFAULT_MAX_POINTS);
      }
      return hypervisorApi.getVMRRD(controllerId, selectedVM!.node, selectedVM!.vmid, timeframe, DEFAULT_MAX_POINTS);
    },
    enabled: !!controllerId && !!selectedVM,
    refetchInterval: 30_000,
  });
  const vmRrd = vmRrdResp?.data || [];

  // VMs list for the selector, fetches ALL guest types (QEMU + LXC).
  // Distinct queryKey ('all') so it doesn't collide with the main page's
  // QEMU-only ['hypervisor', 'vms', controllerId] query; sharing that key
  // served the cached qemu-only list here and silently dropped every LXC
  // container from the VM/CT selector.
  const { data: vmsResp } = useQuery({
    queryKey: ['hypervisor', 'vms', controllerId, 'all'],
    queryFn: () => hypervisorApi.getAllVMs(controllerId),
    enabled: !!controllerId,
  });
  const allVMs: HypervisorVM[] = vmsResp?.data || [];

  const rrdData = selectedVM ? vmRrd : nodeRrd;
  const isLoading = selectedVM ? vmRrdLoading : nodeRrdLoading;
  const isError = selectedVM ? vmRrdError : nodeRrdError;

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="flex items-center gap-2">
          <Label className="text-sm">{t('MonitoringTab.controls.timeframe')}</Label>
          <Select value={timeframe} onValueChange={setTimeframe}>
            <SelectTrigger className="w-[140px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {TIMEFRAMES.map((tf) => (
                <SelectItem key={tf.value} value={tf.value}>{tf.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {nodes.length > 1 && !selectedVM && (
          <div className="flex items-center gap-2">
            <Label className="text-sm">{t('MonitoringTab.controls.node')}</Label>
            <Select value={activeNode} onValueChange={setSelectedNode}>
              <SelectTrigger className="w-[160px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {nodes.map((n) => (
                  <SelectItem key={n.node} value={n.node}>{n.node}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        )}

        <div className="flex items-center gap-2">
          <Label className="text-sm">{t('MonitoringTab.controls.vmCt')}</Label>
          <Select
            value={selectedVM ? `${selectedVM.node}:${selectedVM.vmType}:${selectedVM.vmid}` : 'none'}
            onValueChange={(v) => {
              if (v === 'none') {
                setSelectedVM(null);
              } else {
                const [node, vmType, vmid] = v.split(':');
                setSelectedVM({ node, vmType, vmid: parseInt(vmid) });
              }
            }}
          >
            <SelectTrigger className="w-[220px]">
              <SelectValue placeholder={t('MonitoringTab.controls.nodeMetricsPlaceholder')} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="none">{t('MonitoringTab.controls.nodeOption', { node: activeNode })}</SelectItem>
              {allVMs.filter((vm) => !vm.template).map((vm) => (
                <SelectItem key={`${vm.node}:${vm.vm_type}:${vm.vmid}`} value={`${vm.node}:${vm.vm_type}:${vm.vmid}`}>
                  {vm.vmid} · {vm.name} ({vm.vm_type === 'lxc' ? 'CT' : 'VM'})
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {isError ? (
        <ErrorState message={t('MonitoringTab.errorState')} />
      ) : isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[1, 2, 3, 4].map((i) => <Skeleton key={i} className="h-[250px]" />)}
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <MetricChart
            title={t('MonitoringTab.charts.cpu.title')}
            icon={Cpu}
            data={rrdData}
            lines={[
              { key: 'cpu', name: t('MonitoringTab.charts.cpu.cpu'), color: '#3b82f6' },
            ]}
            yFormatter={(v) => `${(v * 100).toFixed(0)}%`}
          />
          <MetricChart
            title={t('MonitoringTab.charts.memory.title')}
            icon={MemoryStick}
            data={rrdData}
            lines={[
              { key: 'mem', name: t('MonitoringTab.charts.memory.used'), color: '#8b5cf6' },
              { key: 'maxmem', name: t('MonitoringTab.charts.memory.total'), color: '#a5b4fc' },
            ]}
            yFormatter={(v) => formatBytes(v)}
          />
          <MetricChart
            title={t('MonitoringTab.charts.network.title')}
            icon={Network}
            data={rrdData}
            lines={[
              { key: 'netin', name: t('MonitoringTab.charts.network.in'), color: '#10b981' },
              { key: 'netout', name: t('MonitoringTab.charts.network.out'), color: '#f59e0b' },
            ]}
            yFormatter={(v) => formatBytes(v) + '/s'}
          />
          <MetricChart
            title={t('MonitoringTab.charts.disk.title')}
            icon={HardDrive}
            data={rrdData}
            lines={[
              { key: 'diskread', name: t('MonitoringTab.charts.disk.read'), color: '#06b6d4' },
              { key: 'diskwrite', name: t('MonitoringTab.charts.disk.write'), color: '#ef4444' },
            ]}
            yFormatter={(v) => formatBytes(v) + '/s'}
          />
        </div>
      )}

      {/* Alert Settings (Hysteresis) */}
      <Card>
        <CardHeader className="pb-2">
          <div
            className="flex items-center justify-between cursor-pointer"
            onClick={() => setAlertSettingsOpen(!alertSettingsOpen)}
          >
            <div className="flex items-center gap-2">
              <Settings className="h-4 w-4 text-muted-foreground" />
              <CardTitle className="text-sm">{t('MonitoringTab.alerts.title')}</CardTitle>
            </div>
            <ChevronDown className={`h-4 w-4 text-muted-foreground transition-transform ${alertSettingsOpen ? '' : '-rotate-90'}`} />
          </div>
        </CardHeader>
        {alertSettingsOpen && (
          <CardContent>
            <div className="grid grid-cols-2 gap-4 mb-3">
              <div>
                <Label className="text-xs">{t('MonitoringTab.alerts.cpuThreshold')}</Label>
                <Input
                  type="number"
                  min={1}
                  max={100}
                  value={alertConfig.cpuThreshold}
                  onChange={(e) => setAlertConfig((c) => ({ ...c, cpuThreshold: parseInt(e.target.value) || 80 }))}
                  className="h-8 text-sm"
                />
              </div>
              <div>
                <Label className="text-xs">{t('MonitoringTab.alerts.memoryThreshold')}</Label>
                <Input
                  type="number"
                  min={1}
                  max={100}
                  value={alertConfig.memoryThreshold}
                  onChange={(e) => setAlertConfig((c) => ({ ...c, memoryThreshold: parseInt(e.target.value) || 85 }))}
                  className="h-8 text-sm"
                />
              </div>
              <div>
                <Label className="text-xs">{t('MonitoringTab.alerts.fireAfter')}</Label>
                <Input
                  type="number"
                  min={1}
                  max={20}
                  value={alertConfig.fireAfter}
                  onChange={(e) => setAlertConfig((c) => ({ ...c, fireAfter: parseInt(e.target.value) || 3 }))}
                  className="h-8 text-sm"
                />
              </div>
              <div>
                <Label className="text-xs">{t('MonitoringTab.alerts.resolveAfter')}</Label>
                <Input
                  type="number"
                  min={1}
                  max={20}
                  value={alertConfig.resolveAfter}
                  onChange={(e) => setAlertConfig((c) => ({ ...c, resolveAfter: parseInt(e.target.value) || 2 }))}
                  className="h-8 text-sm"
                />
              </div>
            </div>
            <div className="flex items-start gap-2 text-xs text-muted-foreground">
              <Info className="h-3.5 w-3.5 mt-0.5 flex-shrink-0" />
              <p>
                {t('MonitoringTab.alerts.hysteresisInfo')}
              </p>
            </div>
          </CardContent>
        )}
      </Card>
    </div>
  );
}
