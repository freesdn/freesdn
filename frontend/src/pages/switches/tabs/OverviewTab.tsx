// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * OverviewTab · high-level switch dashboard: port status breakdown, PoE
 * analysis, traffic summary, device information, and LLDP neighbors.
 *
 * Extracted from SwitchesPage as part of the monolith breakup. Purely
 * presentational; the parent owns the LED mutation and passes it as a prop.
 */
import { Activity, ArrowLeftRight, Lightbulb, Zap } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { formatBytes, formatSpeed, getPoeClassLabel } from './_formatters';

// Local Port shape · matches the internal type used by SwitchesPage. Only the
// fields read by this tab are listed.
export interface OverviewTabPort {
  id: string;
  port_name: string;
  link_status: string;
  link_speed?: number;
  poe_enabled: boolean;
  poe_status?: string;
  poe_power_draw?: number;
  poe_class?: number;
  neighbor_device?: string;
  neighbor_port?: string;
  tx_bytes: number;
  rx_bytes: number;
}

export interface OverviewTabSwitch {
  id: string;
  model: string;
  model_version?: string;
  vendor: string;
  serial_number?: string;
  mac_address?: string;
  ip_address?: string;
  ipv6_address?: string;
  controller_connection_ip?: string;
  site_name: string;
  total_ports: number;
  poe_ports: number;
  sfp_ports: number;
  status: string;
  temperature?: number;
  fan_status?: string;
  ports_up: number;
  ports_down: number;
  ports_disabled: number;
  poe_budget: number;
  poe_used: number;
  firmware_version: string;
  hardware_version?: string;
  update_available: boolean;
  vlans_configured: number;
  connected_clients: number;
}

export interface OverviewTabProps {
  selectedSwitch: OverviewTabSwitch;
  ports: OverviewTabPort[];
  ledPending: boolean;
  onFlashLed: () => void;
}

export function OverviewTab({ selectedSwitch, ports, ledPending, onFlashLed }: OverviewTabProps) {
  const { t } = useTranslation('switches');
  return (
    <>
      {/* Row 1: Port Status Breakdown + PoE Analysis */}
      <div className="grid gap-4 lg:grid-cols-2">
        {/* Port Status Breakdown */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">{t('OverviewTab.portStatus.title')}</CardTitle>
            <CardDescription>{t('OverviewTab.portStatus.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {(() => {
                const total = selectedSwitch.total_ports || 1;
                const upPct = ((selectedSwitch.ports_up / total) * 100).toFixed(0);
                const downPct = ((selectedSwitch.ports_down / total) * 100).toFixed(0);
                const disabledPct = ((selectedSwitch.ports_disabled / total) * 100).toFixed(0);
                return (
                  <>
                    <div className="flex items-center justify-between text-sm">
                      <div className="flex items-center gap-2">
                        <span className="h-3 w-3 rounded-full bg-green-500" />
                        <span>{t('OverviewTab.portStatus.up')}</span>
                      </div>
                      <span className="font-medium">{selectedSwitch.ports_up} <span className="text-muted-foreground font-normal">({upPct}%)</span></span>
                    </div>
                    <Progress value={Number(upPct)} className="h-2 [&>div]:bg-green-500" />

                    <div className="flex items-center justify-between text-sm">
                      <div className="flex items-center gap-2">
                        <span className="h-3 w-3 rounded-full bg-orange-500" />
                        <span>{t('OverviewTab.portStatus.down')}</span>
                      </div>
                      <span className="font-medium">{selectedSwitch.ports_down} <span className="text-muted-foreground font-normal">({downPct}%)</span></span>
                    </div>
                    <Progress value={Number(downPct)} className="h-2 [&>div]:bg-orange-500" />

                    <div className="flex items-center justify-between text-sm">
                      <div className="flex items-center gap-2">
                        <span className="h-3 w-3 rounded-full bg-muted-foreground" />
                        <span>{t('OverviewTab.portStatus.disabled')}</span>
                      </div>
                      <span className="font-medium">{selectedSwitch.ports_disabled} <span className="text-muted-foreground font-normal">({disabledPct}%)</span></span>
                    </div>
                    <Progress value={Number(disabledPct)} className="h-2 [&>div]:bg-muted-foreground" />
                  </>
                );
              })()}
            </div>

            {/* Speed breakdown from actual port data */}
            {ports.length > 0 && (
              <div className="mt-4 pt-4 border-t">
                <p className="text-xs font-medium text-muted-foreground mb-2 uppercase tracking-wider">{t('OverviewTab.portStatus.linkSpeeds')}</p>
                <div className="grid grid-cols-2 gap-2">
                  {(() => {
                    const speeds: Record<string, { count: number; color: string }> = {
                      '10G': { count: 0, color: 'bg-purple-500' },
                      '2.5G': { count: 0, color: 'bg-blue-500' },
                      '1G': { count: 0, color: 'bg-green-500' },
                      '10/100M': { count: 0, color: 'bg-orange-500' },
                    };
                    ports.forEach((p) => {
                      if (p.link_status !== 'up' || !p.link_speed) return;
                      if (p.link_speed >= 10000) speeds['10G'].count++;
                      else if (p.link_speed >= 2500) speeds['2.5G'].count++;
                      else if (p.link_speed >= 1000) speeds['1G'].count++;
                      else speeds['10/100M'].count++;
                    });
                    return Object.entries(speeds)
                      .filter(([, v]) => v.count > 0)
                      .map(([label, v]) => (
                        <div key={label} className="flex items-center gap-2 text-sm">
                          <span className={`h-2.5 w-2.5 rounded-sm ${v.color}`} />
                          <span className="text-muted-foreground">{label}</span>
                          <span className="font-medium ml-auto">{v.count}</span>
                        </div>
                      ));
                  })()}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* PoE Analysis */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">{t('OverviewTab.poe.title')}</CardTitle>
            <CardDescription>{t('OverviewTab.poe.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {/* Main power gauge */}
              <div className="text-center">
                <div className="text-4xl font-bold tabular-nums">
                  {selectedSwitch.poe_used.toFixed(1)}<span className="text-lg font-normal text-muted-foreground">W</span>
                </div>
                <p className="text-sm text-muted-foreground mt-1">
                  {t('OverviewTab.poe.ofBudget', {
                    budget: selectedSwitch.poe_budget,
                    pct: selectedSwitch.poe_budget > 0 ? ((selectedSwitch.poe_used / selectedSwitch.poe_budget) * 100).toFixed(0) : 0,
                  })}
                </p>
                <Progress value={selectedSwitch.poe_budget > 0 ? (selectedSwitch.poe_used / selectedSwitch.poe_budget) * 100 : 0} className="mt-3 h-3" />
              </div>

              {/* PoE port breakdown from actual data */}
              {ports.length > 0 && (
                <div className="pt-3 border-t">
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 text-center">
                    {(() => {
                      const delivering = ports.filter((p) => p.poe_enabled && p.poe_status === 'delivering').length;
                      const enabled = ports.filter((p) => p.poe_enabled).length;
                      const total = ports.filter((p) => p.poe_enabled !== undefined).length;
                      return (
                        <>
                          <div>
                            <div className="text-2xl font-bold text-yellow-500">{delivering}</div>
                            <p className="text-xs text-muted-foreground">{t('OverviewTab.poe.delivering')}</p>
                          </div>
                          <div>
                            <div className="text-2xl font-bold text-blue-500">{enabled - delivering}</div>
                            <p className="text-xs text-muted-foreground">{t('OverviewTab.poe.idle')}</p>
                          </div>
                          <div>
                            <div className="text-2xl font-bold text-muted-foreground">{total - enabled}</div>
                            <p className="text-xs text-muted-foreground">{t('OverviewTab.poe.off')}</p>
                          </div>
                        </>
                      );
                    })()}
                  </div>
                </div>
              )}

              {/* Top PoE consumers */}
              {ports.length > 0 && (() => {
                const topPoe = ports
                  .filter((p) => p.poe_power_draw && p.poe_power_draw > 0)
                  .sort((a, b) => (b.poe_power_draw || 0) - (a.poe_power_draw || 0))
                  .slice(0, 5);
                if (topPoe.length === 0) return null;
                return (
                  <div className="pt-3 border-t">
                    <p className="text-xs font-medium text-muted-foreground mb-2 uppercase tracking-wider">{t('OverviewTab.poe.topConsumers')}</p>
                    <div className="space-y-2">
                      {topPoe.map((p) => (
                        <div key={p.id} className="flex items-center justify-between text-sm">
                          <div className="flex items-center gap-2">
                            <Zap className="h-3.5 w-3.5 text-yellow-500 fill-yellow-500" />
                            <span>{p.port_name}</span>
                            {getPoeClassLabel(p.poe_class) && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-yellow-500/10 text-yellow-600 font-medium">{getPoeClassLabel(p.poe_class)}</span>
                            )}
                            {p.neighbor_device && (
                              <span className="text-xs text-muted-foreground">({p.neighbor_device})</span>
                            )}
                          </div>
                          <span className="font-medium tabular-nums">{(p.poe_power_draw || 0).toFixed(1)}W</span>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })()}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Row 2: Traffic Overview + Connected Devices */}
      <div className="grid gap-4 lg:grid-cols-2">
        {/* Traffic Summary */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">{t('OverviewTab.traffic.title')}</CardTitle>
            <CardDescription>{t('OverviewTab.traffic.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            {ports.length > 0 ? (() => {
              const totalTx = ports.reduce((sum, p) => sum + (p.tx_bytes || 0), 0);
              const totalRx = ports.reduce((sum, p) => sum + (p.rx_bytes || 0), 0);
              const topTraffic = ports
                .filter((p) => p.link_status === 'up')
                .sort((a, b) => ((b.tx_bytes || 0) + (b.rx_bytes || 0)) - ((a.tx_bytes || 0) + (a.rx_bytes || 0)))
                .slice(0, 5);
              return (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="text-center p-3 rounded-lg bg-muted/50">
                      <div className="text-2xl font-bold text-blue-600">{'↑'} {formatBytes(totalTx)}</div>
                      <p className="text-xs text-muted-foreground mt-1">{t('OverviewTab.traffic.totalTx')}</p>
                    </div>
                    <div className="text-center p-3 rounded-lg bg-muted/50">
                      <div className="text-2xl font-bold text-green-600">{'↓'} {formatBytes(totalRx)}</div>
                      <p className="text-xs text-muted-foreground mt-1">{t('OverviewTab.traffic.totalRx')}</p>
                    </div>
                  </div>
                  {topTraffic.length > 0 && (
                    <div className="pt-3 border-t">
                      <p className="text-xs font-medium text-muted-foreground mb-2 uppercase tracking-wider">{t('OverviewTab.traffic.topPorts')}</p>
                      <div className="space-y-2">
                        {topTraffic.map((p) => (
                          <div key={p.id} className="flex items-center justify-between text-sm">
                            <div className="flex items-center gap-2">
                              <Activity className="h-3.5 w-3.5 text-muted-foreground" />
                              <span>{p.port_name}</span>
                              {p.neighbor_device && (
                                <span className="text-xs text-muted-foreground">({p.neighbor_device})</span>
                              )}
                            </div>
                            <span className="text-xs tabular-nums text-muted-foreground">
                              {'↑'}{formatBytes(p.tx_bytes)} {'↓'}{formatBytes(p.rx_bytes)}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            })() : (
              <p className="text-sm text-muted-foreground">{t('OverviewTab.traffic.noData')}</p>
            )}
          </CardContent>
        </Card>

        {/* Device Information */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">{t('OverviewTab.device.title')}</CardTitle>
            <CardDescription>{t('OverviewTab.device.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {[
                { label: t('OverviewTab.device.model'), value: selectedSwitch.model_version || selectedSwitch.model },
                { label: t('OverviewTab.device.vendor'), value: selectedSwitch.vendor },
                { label: t('OverviewTab.device.serialNumber'), value: selectedSwitch.serial_number },
                { label: t('OverviewTab.device.macAddress'), value: selectedSwitch.mac_address },
                { label: t('OverviewTab.device.ipAddress'), value: selectedSwitch.ip_address },
                { label: t('OverviewTab.device.ipv6Address'), value: selectedSwitch.ipv6_address },
                { label: t('OverviewTab.device.controllerIp'), value: selectedSwitch.controller_connection_ip },
                { label: t('OverviewTab.device.firmware'), value: selectedSwitch.firmware_version ? `v${selectedSwitch.firmware_version}` : undefined },
                { label: t('OverviewTab.device.hardwareVersion'), value: selectedSwitch.hardware_version },
                { label: t('OverviewTab.device.totalPorts'), value: `${selectedSwitch.total_ports} (${selectedSwitch.poe_ports} PoE, ${selectedSwitch.sfp_ports} SFP+)` },
                { label: t('OverviewTab.device.site'), value: selectedSwitch.site_name },
                { label: t('OverviewTab.device.vlans'), value: String(selectedSwitch.vlans_configured) },
                { label: t('OverviewTab.device.clients'), value: String(selectedSwitch.connected_clients) },
                { label: t('OverviewTab.device.fanStatus'), value: selectedSwitch.fan_status },
                { label: t('OverviewTab.device.status'), value: selectedSwitch.status },
              ].filter((row) => row.value).map((row) => (
                <div key={row.label} className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">{row.label}</span>
                  <span className="font-medium text-right">{row.value}</span>
                </div>
              ))}
              {selectedSwitch.temperature !== undefined && selectedSwitch.temperature > 0 && (
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">{t('OverviewTab.device.temperature')}</span>
                  <span className={`font-medium ${selectedSwitch.temperature > 60 ? 'text-red-500' : selectedSwitch.temperature > 45 ? 'text-yellow-500' : ''}`}>
                    {selectedSwitch.temperature}{'°'}C
                  </span>
                </div>
              )}
              {selectedSwitch.update_available && (
                <div className="mt-3 p-3 rounded-lg bg-blue-500/10 border border-blue-500/20">
                  <div className="flex items-center gap-2 text-sm text-blue-600 dark:text-blue-400">
                    <ArrowLeftRight className="h-4 w-4" />
                    <span className="font-medium">{t('OverviewTab.device.updateAvailable')}</span>
                  </div>
                </div>
              )}
              {/* LED Toggle */}
              <div className="mt-3 flex items-center justify-between">
                <div className="flex items-center gap-2 text-sm">
                  <Lightbulb className="h-4 w-4 text-muted-foreground" />
                  <span className="text-muted-foreground">{t('OverviewTab.device.locatorLed')}</span>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={ledPending}
                  onClick={onFlashLed}
                >
                  {ledPending ? t('OverviewTab.device.ledActivating') : t('OverviewTab.device.flashLed')}
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Row 3: LLDP Neighbors (connected devices) */}
      {ports.length > 0 && (() => {
        const neighbors = ports.filter((p) => p.neighbor_device);
        if (neighbors.length === 0) return null;
        return (
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">{t('OverviewTab.lldp.title')}</CardTitle>
              <CardDescription>{neighbors.length === 1 ? t('OverviewTab.lldp.discovered_one', { count: neighbors.length }) : t('OverviewTab.lldp.discovered_other', { count: neighbors.length })}</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('OverviewTab.lldp.localPort')}</TableHead>
                    <TableHead>{t('OverviewTab.lldp.neighbor')}</TableHead>
                    <TableHead>{t('OverviewTab.lldp.remotePort')}</TableHead>
                    <TableHead>{t('OverviewTab.lldp.speed')}</TableHead>
                    <TableHead>{t('OverviewTab.lldp.poe')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {neighbors.map((p) => (
                    <TableRow key={p.id}>
                      <TableCell className="font-medium">{p.port_name}</TableCell>
                      <TableCell>{p.neighbor_device}</TableCell>
                      <TableCell className="text-muted-foreground">{p.neighbor_port || '-'}</TableCell>
                      <TableCell>{formatSpeed(p.link_speed)}</TableCell>
                      <TableCell>
                        {p.poe_enabled && p.poe_power_draw && p.poe_power_draw > 0 ? (
                          <span className="flex items-center gap-1">
                            <Zap className="h-3.5 w-3.5 text-yellow-500 fill-yellow-500" />
                            {p.poe_power_draw.toFixed(1)}W
                            {getPoeClassLabel(p.poe_class) && (
                              <span className="text-[10px] px-1 py-0.5 rounded bg-yellow-500/10 text-yellow-600 font-medium">{getPoeClassLabel(p.poe_class)}</span>
                            )}
                          </span>
                        ) : '-'}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        );
      })()}
    </>
  );
}
