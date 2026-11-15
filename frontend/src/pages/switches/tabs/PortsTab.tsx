// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * PortsTab · front-panel port visualization + virtualized port table for the
 * switch detail view.
 *
 * Extracted from SwitchesPage as part of the monolith breakup. Owns the
 * search/selection UI-local state; the port table is the shared DataTable
 * (compact rows, right-aligned figures, the server's reason when the ports
 * fail to load). The parent owns the port-edit + apply-profile dialogs and
 * passes openers as callbacks, plus the four port-control mutations.
 */
import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ArrowUpFromLine,
  Copy,
  Diamond,
  Info,
  Link2,
  MoreVertical,
  Power,
  RefreshCw,
  Settings,
  ToggleLeft,
  ToggleRight,
  Zap,
  type LucideIcon,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { cn } from '@/lib/utils';
import { DisabledReason } from '@/components/ui/disabled-reason';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { SearchBar } from '@/components/ui/search-bar';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import {
  formatBytes,
  formatSpeed,
  getPoeClassLabel,
  getStatusColor,
  getUtilizationColor,
} from './_formatters';

// Local Port shape · matches the internal type used by SwitchesPage.
export interface PortsTabPort {
  id: string;
  port_index: number;
  port_name: string;
  port_type: string;
  enabled: boolean;
  link_status: string;
  link_speed?: number;
  vlan_mode: string;
  native_vlan: number;
  tagged_vlans: number[];
  voice_vlan?: number;
  poe_enabled: boolean;
  poe_status?: string;
  poe_power_draw?: number;
  poe_class?: number;
  neighbor_device?: string;
  neighbor_port?: string;
  sfp_vendor?: string;
  sfp_part_number?: string;
  sfp_type?: string;
  sfp_temperature?: number;
  sfp_tx_power?: number;
  sfp_rx_power?: number;
  sfp_wavelength?: number;
  tx_bytes: number;
  rx_bytes: number;
  tx_packets: number;
  rx_packets: number;
  tx_errors: number;
  rx_errors: number;
  tx_utilization: number;
  rx_utilization: number;
}

// Mutation handle interface · only the bits the tab actually reads.
export interface PortMutationHandle {
  isPending: boolean;
  mutate: (vars: { switchId: string; portIndex: number }) => void;
}

export interface PortToggleMutationHandle {
  isPending: boolean;
  mutate: (vars: { switchId: string; portIndex: number; enabled: boolean }) => void;
}

const getPortSpeedColor = (port: PortsTabPort) => {
  if (!port.enabled) return { border: 'border-muted-foreground', bg: 'bg-muted', label: 'Disabled' };
  if (port.link_status === 'down') return { border: 'border-muted-foreground/40', bg: 'bg-muted/50', label: 'Disconnected' };
  if (!port.link_speed) return { border: 'border-emerald-500', bg: 'bg-emerald-500/15 dark:bg-emerald-500/25', label: 'Connected' };
  if (port.link_speed >= 10000) return { border: 'border-purple-500', bg: 'bg-purple-500/15 dark:bg-purple-500/25', label: '10 Gbps' };
  if (port.link_speed >= 2500) return { border: 'border-blue-500', bg: 'bg-blue-500/15 dark:bg-blue-500/25', label: '2.5 Gbps' };
  if (port.link_speed >= 1000) return { border: 'border-green-500', bg: 'bg-green-500/15 dark:bg-green-500/25', label: '1000 Mbps' };
  return { border: 'border-orange-500', bg: 'bg-orange-500/15 dark:bg-orange-500/25', label: '10/100 Mbps' };
};

const portLegendItems = [
  { color: 'bg-orange-500', labelKey: 'legend.speed.fastEthernet' },
  { color: 'bg-green-500', labelKey: 'legend.speed.gigabit' },
  { color: 'bg-blue-500', labelKey: 'legend.speed.multiGig' },
  { color: 'bg-purple-500', labelKey: 'legend.speed.tenGig' },
  { color: 'bg-muted-foreground', labelKey: 'legend.speed.disabled' },
  { color: 'bg-muted-foreground/40', labelKey: 'legend.speed.disconnected' },
];

const portLegendIcons: { icon: LucideIcon; labelKey: string }[] = [
  { icon: Zap, labelKey: 'legend.icons.poeDelivering' },
  { icon: Link2, labelKey: 'legend.icons.lagMember' },
  { icon: Diamond, labelKey: 'legend.icons.sfp' },
  { icon: ArrowUpFromLine, labelKey: 'legend.icons.uplink' },
];

export interface PortsTabProps {
  ports: PortsTabPort[];
  selectedSwitchId: string | undefined;
  showPortControls: boolean;
  showPoeControls: boolean;
  portDisabledReason: string | undefined;
  portBounceMutation: PortMutationHandle;
  poeCycleMutation: PortMutationHandle;
  portToggleMutation: PortToggleMutationHandle;
  poeToggleMutation: PortToggleMutationHandle;
  onPortEdit: (port: PortsTabPort) => void;
  onApplyProfile: (selectedPortIds: string[]) => void;
  /** The ports are still loading (the table shows its skeleton). */
  isLoading?: boolean;
  /** The ports query failed: the table shows the server's reason. */
  error?: unknown;
  /** Retry the ports query. */
  onRetry?: () => void;
}

export function PortsTab({
  ports,
  selectedSwitchId,
  showPortControls,
  showPoeControls,
  portDisabledReason,
  portBounceMutation,
  poeCycleMutation,
  portToggleMutation,
  poeToggleMutation,
  onPortEdit,
  onApplyProfile,
  isLoading = false,
  error,
  onRetry,
}: PortsTabProps) {
  const { t } = useTranslation('switches');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedPorts, setSelectedPorts] = useState<string[]>([]);

  const filteredPorts = ports.filter((port) => {
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      return (
        port.port_name.toLowerCase().includes(query) ||
        (port.neighbor_device && port.neighbor_device.toLowerCase().includes(query))
      );
    }
    return true;
  });

  const trafficCell = (port: PortsTabPort, direction: 'tx' | 'rx') => {
    const bytes = direction === 'tx' ? port.tx_bytes : port.rx_bytes;
    const packets = direction === 'tx' ? port.tx_packets : port.rx_packets;
    const errors = direction === 'tx' ? port.tx_errors : port.rx_errors;
    const utilization = direction === 'tx' ? port.tx_utilization : port.rx_utilization;
    const arrow = direction === 'tx' ? '↑' : '↓';
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <div className="ml-auto cursor-default">
              {bytes > 0 ? (
                <div className="flex items-center justify-end gap-2 whitespace-nowrap">
                  <span className="text-xs tabular-nums">{arrow} {formatBytes(bytes)}</span>
                  {utilization > 0 && (
                    // A thin inline meter: the row stays one line per direction.
                    <span className="flex items-center gap-1">
                      <span className="h-1.5 w-6 rounded-full bg-muted overflow-hidden" aria-hidden="true">
                        <span
                          className={`block h-full rounded-full ${getUtilizationColor(utilization)}`}
                          style={{ width: `${Math.max(0, Math.min(utilization, 100))}%` }}
                        />
                      </span>
                      <span className="text-[10px] tabular-nums text-muted-foreground w-6 text-right">{utilization.toFixed(0)}%</span>
                    </span>
                  )}
                </div>
              ) : (
                <span className="text-muted-foreground text-xs">{arrow} 0</span>
              )}
            </div>
          </TooltipTrigger>
          <TooltipContent>
            <div className="text-xs space-y-1">
              <div>{t(`PortsTab.traffic.${direction}Bytes`)}: {formatBytes(bytes)}</div>
              <div>{t(`PortsTab.traffic.${direction}Packets`)}: {packets.toLocaleString()}</div>
              {errors > 0 && <div className="text-destructive">{t(`PortsTab.traffic.${direction}Errors`)}: {errors.toLocaleString()}</div>}
              {utilization > 0 && <div>{t('PortsTab.traffic.utilization')}: {utilization.toFixed(1)}%</div>}
            </div>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  };

  const portColumns: DataTableColumn<PortsTabPort>[] = [
    {
      id: 'port',
      header: t('PortsTab.table.port'),
      accessorFn: (port) => port.port_index,
      cell: (port) => (
        <div className="flex items-center gap-2 font-medium min-w-0">
          <div className={`h-2.5 w-2.5 shrink-0 rounded-sm ${getPortSpeedColor(port).border.replace('border-', 'bg-')}`} aria-hidden="true" />
          {/* One line per port: long port names (often the attached device)
              truncate, with the full name on hover. */}
          <span className="truncate max-w-[9rem]" title={port.port_name}>{port.port_name}</span>
          {port.port_type === 'sfp' && (
            <span className="text-[10px] font-semibold px-1 py-0.5 rounded bg-purple-500/10 text-purple-600 dark:text-purple-400 leading-none">SFP+</span>
          )}
        </div>
      ),
    },
    {
      id: 'status',
      header: t('PortsTab.table.status'),
      accessorFn: (port) => port.link_status,
      cell: (port) => (
        <div className="flex items-center gap-2 whitespace-nowrap">
          <div className={`h-2 w-2 rounded-full ${getStatusColor(port.link_status)}`} aria-hidden="true" />
          <span className="capitalize">{port.link_status}</span>
        </div>
      ),
    },
    {
      id: 'connection',
      header: t('PortsTab.table.connection'),
      accessorFn: (port) => port.neighbor_device ?? '',
      cell: (port) => port.neighbor_device ? (
        <div className="text-sm min-w-0">
          <div className="font-medium truncate max-w-[8rem]" title={port.neighbor_device}>{port.neighbor_device}</div>
          {port.neighbor_port && <div className="text-muted-foreground text-xs truncate max-w-[8rem]">{port.neighbor_port}</div>}
        </div>
      ) : (
        <span className="text-muted-foreground">-</span>
      ),
    },
    {
      id: 'speed',
      header: t('PortsTab.table.speed'),
      accessorFn: (port) => port.link_speed ?? 0,
      align: 'right',
      cell: (port) => (
        <span className={cn('whitespace-nowrap', port.link_speed && port.link_speed >= 1000 && 'font-medium')}>
          {formatSpeed(port.link_speed)}
        </span>
      ),
    },
    {
      id: 'type',
      header: t('PortsTab.table.type'),
      accessorFn: (port) => port.vlan_mode,
      sortable: false,
      cell: (port) => (
        <Badge variant="outline" className="text-xs capitalize">
          {port.vlan_mode === 'trunk' ? t('PortsTab.table.trunk') : t('PortsTab.table.access')}
        </Badge>
      ),
    },
    {
      id: 'vlan',
      header: 'VLAN',
      accessorFn: (port) => port.native_vlan,
      align: 'right',
      cell: (port) => (
        <div className="flex items-center justify-end gap-1">
          <Badge variant="outline" className="text-xs">{port.native_vlan}</Badge>
          {port.vlan_mode === 'trunk' && port.tagged_vlans.length > 0 && (
            <span className="text-xs text-muted-foreground">+{port.tagged_vlans.length}</span>
          )}
          {port.voice_vlan && (
            <Badge variant="secondary" className="text-xs">voice:{port.voice_vlan}</Badge>
          )}
        </div>
      ),
    },
    {
      id: 'poe',
      header: 'PoE',
      accessorFn: (port) => (port.poe_enabled ? port.poe_power_draw ?? 0 : -1),
      align: 'right',
      cell: (port) => port.poe_enabled ? (
        <div className="flex items-center justify-end gap-1.5">
          <Zap className={`h-4 w-4 ${port.poe_status === 'delivering' ? 'text-yellow-500 fill-yellow-500' : 'text-muted-foreground'}`} aria-hidden="true" />
          {port.poe_power_draw !== undefined && port.poe_power_draw > 0 ? (
            // The PoE class (802.3af/at/bt) is in the tooltip: as a badge it
            // pushed the actions column out of view at desktop width.
            <span className="text-sm font-medium whitespace-nowrap" title={getPoeClassLabel(port.poe_class) || undefined}>{port.poe_power_draw.toFixed(1)}W</span>
          ) : (
            <span className="text-xs text-muted-foreground">{t('PortsTab.poe.enabled')}</span>
          )}
        </div>
      ) : (
        <span className="text-xs text-muted-foreground">{t('PortsTab.poe.off')}</span>
      ),
    },
    {
      // Sent and received in one column (one line each), so the actions
      // column stays in view at desktop width.
      id: 'traffic',
      header: t('PortsTab.table.traffic'),
      accessorFn: (port) => port.tx_bytes + port.rx_bytes,
      align: 'right',
      cell: (port) => (
        <div className="space-y-0.5">
          {trafficCell(port, 'tx')}
          {trafficCell(port, 'rx')}
        </div>
      ),
    },
    {
      id: 'actions',
      header: <span className="sr-only">{t('PortsTab.table.actions')}</span>,
      sortable: false,
      cell: (port) => showPortControls ? (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" aria-label={t('PortsTab.actions.menuFor', { port: port.port_name })}>
              <MoreVertical className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => onPortEdit(port)}>
              <Settings className="mr-2 h-4 w-4" />
              {t('PortsTab.actions.configure')}
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => selectedSwitchId && portBounceMutation.mutate({ switchId: selectedSwitchId, portIndex: port.port_index })}
              disabled={portBounceMutation.isPending}
            >
              <RefreshCw className="mr-2 h-4 w-4" />
              {t('PortsTab.actions.bouncePort')}
            </DropdownMenuItem>
            {port.poe_enabled !== undefined && showPoeControls && (
              <DropdownMenuItem
                onClick={() => selectedSwitchId && poeCycleMutation.mutate({ switchId: selectedSwitchId, portIndex: port.port_index })}
                disabled={poeCycleMutation.isPending}
              >
                <Power className="mr-2 h-4 w-4" />
                {t('PortsTab.actions.poePowerCycle')}
              </DropdownMenuItem>
            )}
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={() => selectedSwitchId && portToggleMutation.mutate({ switchId: selectedSwitchId, portIndex: port.port_index, enabled: !port.enabled })}
              disabled={portToggleMutation.isPending}
            >
              {port.enabled ? (
                <>
                  <ToggleLeft className="mr-2 h-4 w-4" />
                  {t('PortsTab.actions.disable')}
                </>
              ) : (
                <>
                  <ToggleRight className="mr-2 h-4 w-4" />
                  {t('PortsTab.actions.enable')}
                </>
              )}
            </DropdownMenuItem>
            {/* PoE toggle only if PoE capable port and control is supported */}
            {port.poe_enabled !== undefined && showPoeControls && (
              <>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  onClick={() => selectedSwitchId && poeToggleMutation.mutate({ switchId: selectedSwitchId, portIndex: port.port_index, enabled: !port.poe_enabled })}
                  disabled={poeToggleMutation.isPending}
                >
                  <Zap className="mr-2 h-4 w-4" />
                  {port.poe_enabled ? t('PortsTab.actions.disablePoe') : t('PortsTab.actions.enablePoe')}
                </DropdownMenuItem>
              </>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      ) : (
        // A disabled button gets no pointer or focus events: the shared
        // wrapper carries the reason so it can actually be read.
        <DisabledReason reason={portDisabledReason || t('PortsTab.actions.controlNotSupported')}>
          <Button variant="ghost" size="icon" disabled aria-label={portDisabledReason || t('PortsTab.actions.controlNotSupported')}>
            <Info className="h-4 w-4 text-muted-foreground" />
          </Button>
        </DisabledReason>
      ),
    },
  ];

  return (
    <>
      {/* Toolbar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <SearchBar
            value={searchQuery}
            onChange={setSearchQuery}
            placeholder={t('PortsTab.toolbar.searchPlaceholder')}
            className="w-64"
          />
        </div>
        <div className="flex items-center gap-2">
          {selectedPorts.length > 0 && (
            <>
              <Button variant="outline" size="sm" onClick={() => onApplyProfile(selectedPorts)}>
                <Copy className="mr-2 h-4 w-4" />
                {t('PortsTab.toolbar.applyProfile', { count: selectedPorts.length })}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSelectedPorts([])}
              >
                {t('PortsTab.toolbar.clearSelection')}
              </Button>
            </>
          )}
        </div>
      </div>

      {/* Port Grid (front panel), once the ports are in */}
      {!isLoading && !error && (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">{t('PortsTab.portStatus.title')}</CardTitle>
          <CardDescription>{t('PortsTab.portStatus.description')}</CardDescription>
        </CardHeader>
        <CardContent>
          {/* Port visualization - Front panel style, 2 rows */}
          <div className="space-y-2 mb-4">
            {/* Row 1: Odd ports (1,3,5,...) */}
            <div className="flex gap-1.5 flex-wrap items-center">
              {filteredPorts.filter((p) => p.port_index % 2 === 1).map((port, i, arr) => {
                const sc = getPortSpeedColor(port);
                const prevPort = arr[i - 1];
                const showSfpDivider = port.port_type === 'sfp' && prevPort && prevPort.port_type !== 'sfp';
                return (
                  <React.Fragment key={port.id}>
                    {showSfpDivider && <div className="w-px h-8 bg-border mx-1" />}
                    <TooltipProvider>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <button
                            className={`
                              relative h-10 ${port.port_type === 'sfp' ? 'w-12' : 'w-10'} rounded border-2 flex items-center justify-center text-xs font-bold
                              transition-all hover:scale-110 hover:shadow-md
                              ${selectedPorts.includes(port.id) ? 'ring-2 ring-primary ring-offset-2' : ''}
                              ${sc.border} ${sc.bg}
                            `}
                            onClick={(e) => {
                              if (e.shiftKey) {
                                setSelectedPorts((prev) =>
                                  prev.includes(port.id) ? prev.filter((id) => id !== port.id) : [...prev, port.id],
                                );
                              } else { onPortEdit(port); }
                            }}
                          >
                            {port.port_index}
                            {port.poe_enabled && port.poe_status === 'delivering' && (
                              <Zap className="absolute -top-1 -right-1 h-3 w-3 text-yellow-500 fill-yellow-500" />
                            )}
                            {port.port_type === 'sfp' && (
                              <span className="absolute -bottom-1 left-1/2 -translate-x-1/2 text-[7px] font-semibold text-muted-foreground leading-none">SFP+</span>
                            )}
                          </button>
                        </TooltipTrigger>
                        <TooltipContent side="bottom" className="max-w-xs">
                          <div className="space-y-1">
                            <div className="font-medium">{port.port_name}{port.port_type === 'sfp' ? ' (SFP+)' : ''}</div>
                            <div className="text-xs">{t('PortsTab.tooltip.status')}: <span className="capitalize">{port.link_status}</span> {port.link_speed ? `• ${formatSpeed(port.link_speed)}` : ''}</div>
                            <div className="text-xs">VLAN: {port.native_vlan} ({port.vlan_mode})</div>
                            <div className="text-xs">PoE: {port.poe_enabled ? (port.poe_status === 'delivering' ? `${(port.poe_power_draw || 0).toFixed(1)}W` : t('PortsTab.tooltip.enabledIdle')) : t('PortsTab.tooltip.off')}{port.poe_status === 'delivering' && getPoeClassLabel(port.poe_class) ? ` (${getPoeClassLabel(port.poe_class)})` : ''}</div>
                            {port.neighbor_device && <div className="text-xs">→ {port.neighbor_device}{port.neighbor_port ? ` (${port.neighbor_port})` : ''}</div>}
                            {port.port_type === 'sfp' && (port.sfp_vendor || port.sfp_type) && (
                              <div className="text-xs border-t pt-1 mt-1 space-y-0.5">
                                {port.sfp_type && <div>{t('PortsTab.tooltip.module')}: {port.sfp_type}</div>}
                                {port.sfp_vendor && <div>{t('PortsTab.tooltip.vendor')}: {port.sfp_vendor}{port.sfp_part_number ? ` (${port.sfp_part_number})` : ''}</div>}
                                {port.sfp_wavelength && <div>{t('PortsTab.tooltip.wavelength')}: {port.sfp_wavelength}nm</div>}
                                {port.sfp_temperature != null && <div>{t('PortsTab.tooltip.temp')}: {port.sfp_temperature.toFixed(1)}°C</div>}
                                {(port.sfp_tx_power != null || port.sfp_rx_power != null) && (
                                  <div>{t('PortsTab.tooltip.power')}: {port.sfp_tx_power != null ? `TX ${port.sfp_tx_power.toFixed(1)}dBm` : ''}{port.sfp_tx_power != null && port.sfp_rx_power != null ? ' / ' : ''}{port.sfp_rx_power != null ? `RX ${port.sfp_rx_power.toFixed(1)}dBm` : ''}</div>
                                )}
                              </div>
                            )}
                          </div>
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  </React.Fragment>
                );
              })}
            </div>
            {/* Row 2: Even ports (2,4,6,...) */}
            <div className="flex gap-1.5 flex-wrap items-center">
              {filteredPorts.filter((p) => p.port_index % 2 === 0).map((port, i, arr) => {
                const sc = getPortSpeedColor(port);
                const prevPort = arr[i - 1];
                const showSfpDivider = port.port_type === 'sfp' && prevPort && prevPort.port_type !== 'sfp';
                return (
                  <React.Fragment key={port.id}>
                    {showSfpDivider && <div className="w-px h-8 bg-border mx-1" />}
                    <TooltipProvider>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <button
                            className={`
                              relative h-10 ${port.port_type === 'sfp' ? 'w-12' : 'w-10'} rounded border-2 flex items-center justify-center text-xs font-bold
                              transition-all hover:scale-110 hover:shadow-md
                              ${selectedPorts.includes(port.id) ? 'ring-2 ring-primary ring-offset-2' : ''}
                              ${sc.border} ${sc.bg}
                            `}
                            onClick={(e) => {
                              if (e.shiftKey) {
                                setSelectedPorts((prev) =>
                                  prev.includes(port.id) ? prev.filter((id) => id !== port.id) : [...prev, port.id],
                                );
                              } else { onPortEdit(port); }
                            }}
                          >
                            {port.port_index}
                            {port.poe_enabled && port.poe_status === 'delivering' && (
                              <Zap className="absolute -top-1 -right-1 h-3 w-3 text-yellow-500 fill-yellow-500" />
                            )}
                            {port.port_type === 'sfp' && (
                              <span className="absolute -bottom-1 left-1/2 -translate-x-1/2 text-[7px] font-semibold text-muted-foreground leading-none">SFP+</span>
                            )}
                          </button>
                        </TooltipTrigger>
                        <TooltipContent side="bottom" className="max-w-xs">
                          <div className="space-y-1">
                            <div className="font-medium">{port.port_name}{port.port_type === 'sfp' ? ' (SFP+)' : ''}</div>
                            <div className="text-xs">{t('PortsTab.tooltip.status')}: <span className="capitalize">{port.link_status}</span> {port.link_speed ? `• ${formatSpeed(port.link_speed)}` : ''}</div>
                            <div className="text-xs">VLAN: {port.native_vlan} ({port.vlan_mode})</div>
                            <div className="text-xs">PoE: {port.poe_enabled ? (port.poe_status === 'delivering' ? `${(port.poe_power_draw || 0).toFixed(1)}W` : t('PortsTab.tooltip.enabledIdle')) : t('PortsTab.tooltip.off')}{port.poe_status === 'delivering' && getPoeClassLabel(port.poe_class) ? ` (${getPoeClassLabel(port.poe_class)})` : ''}</div>
                            {port.neighbor_device && <div className="text-xs">→ {port.neighbor_device}{port.neighbor_port ? ` (${port.neighbor_port})` : ''}</div>}
                            {port.port_type === 'sfp' && (port.sfp_vendor || port.sfp_type) && (
                              <div className="text-xs border-t pt-1 mt-1 space-y-0.5">
                                {port.sfp_type && <div>{t('PortsTab.tooltip.module')}: {port.sfp_type}</div>}
                                {port.sfp_vendor && <div>{t('PortsTab.tooltip.vendor')}: {port.sfp_vendor}{port.sfp_part_number ? ` (${port.sfp_part_number})` : ''}</div>}
                                {port.sfp_wavelength && <div>{t('PortsTab.tooltip.wavelength')}: {port.sfp_wavelength}nm</div>}
                                {port.sfp_temperature != null && <div>{t('PortsTab.tooltip.temp')}: {port.sfp_temperature.toFixed(1)}°C</div>}
                                {(port.sfp_tx_power != null || port.sfp_rx_power != null) && (
                                  <div>{t('PortsTab.tooltip.power')}: {port.sfp_tx_power != null ? `TX ${port.sfp_tx_power.toFixed(1)}dBm` : ''}{port.sfp_tx_power != null && port.sfp_rx_power != null ? ' / ' : ''}{port.sfp_rx_power != null ? `RX ${port.sfp_rx_power.toFixed(1)}dBm` : ''}</div>
                                )}
                              </div>
                            )}
                          </div>
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  </React.Fragment>
                );
              })}
            </div>
          </div>

          {/* Legend */}
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 pt-3 border-t">
            {portLegendItems.map((item) => (
              <div key={item.labelKey} className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <span className={`inline-block h-3 w-3 rounded ${item.color}`} />
                {t(`PortsTab.${item.labelKey}`)}
              </div>
            ))}
            <div className="w-px h-4 bg-border mx-1" />
            {portLegendIcons.map((item) => {
              const Icon = item.icon;
              return (
                <div key={item.labelKey} className="flex items-center gap-1 text-xs text-muted-foreground">
                  <Icon className="h-3.5 w-3.5" aria-hidden="true" />
                  {t(`PortsTab.${item.labelKey}`)}
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>
      )}

      {/* Ports Table */}
      <DataTable<PortsTabPort>
        data={filteredPorts}
        columns={portColumns}
        isLoading={isLoading}
        error={error}
        onRetry={onRetry}
        searchable={false}
        density="compact"
        selectable
        selectedRows={ports.filter((port) => selectedPorts.includes(port.id))}
        onSelectionChange={(rows) => setSelectedPorts(rows.map((row) => row.id))}
        getRowLabel={(port) => port.port_name}
        itemName={t('PortsTab.table.itemName')}
        defaultPageSize={50}
        pageSizeOptions={[25, 50, 100]}
        skeletonRows={8}
      />
    </>
  );
}
