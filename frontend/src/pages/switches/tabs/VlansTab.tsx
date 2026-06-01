// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * VlansTab · VLAN list view + interactive VLAN-to-port matrix
 * (untagged/tagged/excluded toggle) for the switch detail view.
 *
 * Extracted from SwitchesPage as part of the monolith breakup. The parent
 * still owns ports/VLAN data + the bulk-assignment mutation; this component
 * owns only the matrix visibility toggle and the in-flight edits map.
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Grid3X3, RefreshCw } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';

// Local Port shape · matches the internal type used by SwitchesPage. Only the
// fields read by this tab are listed.
export interface VlansTabPort {
  port_index: number;
  port_name: string;
  native_vlan: number;
  tagged_vlans: number[];
}

export interface VlansTabSwitchVlan {
  id: string;
  vlan_id: number;
  name: string;
  description?: string;
  cidr?: string;
  dhcp_enabled?: boolean;
  untagged_ports: number;
  tagged_ports: number;
}

export interface VlansTabProps {
  ports: VlansTabPort[];
  switchVlans: VlansTabSwitchVlan[] | undefined;
  vlanAssignPending: boolean;
  onApply: (
    assignments: Array<{ port_index: number; native_vlan: number | null; tagged_vlans: number[] }>,
  ) => void;
}

export function VlansTab({ ports, switchVlans, vlanAssignPending, onApply }: VlansTabProps) {
  const { t } = useTranslation('switches');
  const [vlanEdits, setVlanEdits] = useState<Map<string, 'U' | 'T' | ''>>(new Map());
  const [showVlanMatrix, setShowVlanMatrix] = useState(false);

  return (
    <>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Button
            variant={showVlanMatrix ? 'default' : 'outline'}
            size="sm"
            onClick={() => setShowVlanMatrix(!showVlanMatrix)}
          >
            <Grid3X3 className="mr-2 h-4 w-4" />
            {showVlanMatrix ? t('VlansTab.view.matrix') : t('VlansTab.view.list')}
          </Button>
        </div>
        {showVlanMatrix && vlanEdits.size > 0 && (
          <div className="flex items-center gap-2">
            <Badge variant="secondary">{t('VlansTab.matrix.changes', { count: vlanEdits.size })}</Badge>
            <Button variant="outline" size="sm" onClick={() => setVlanEdits(new Map())}>
              {t('VlansTab.actions.discard')}
            </Button>
            <Button
              size="sm"
              disabled={vlanAssignPending}
              onClick={() => {
                // Compile edits into per-port assignments
                const portMap = new Map<number, { native: number | null; tagged: number[] }>();
                // Start with current state
                ports.forEach((p) => {
                  portMap.set(p.port_index, {
                    native: p.native_vlan,
                    tagged: [...(p.tagged_vlans || [])],
                  });
                });
                // Apply edits
                vlanEdits.forEach((value, key) => {
                  const [portIdx, vlanId] = key.split(':').map(Number);
                  const port = portMap.get(portIdx) || { native: null, tagged: [] };
                  if (value === 'U') {
                    port.native = vlanId;
                    port.tagged = port.tagged.filter((v) => v !== vlanId);
                  } else if (value === 'T') {
                    if (port.native === vlanId) port.native = null;
                    if (!port.tagged.includes(vlanId)) port.tagged.push(vlanId);
                  } else {
                    if (port.native === vlanId) port.native = null;
                    port.tagged = port.tagged.filter((v) => v !== vlanId);
                  }
                  portMap.set(portIdx, port);
                });
                // Build assignments for changed ports only
                const changedPorts = new Set(
                  Array.from(vlanEdits.keys()).map((k) => Number(k.split(':')[0])),
                );
                const assignments = Array.from(changedPorts).map((pi) => ({
                  port_index: pi,
                  native_vlan: portMap.get(pi)?.native ?? null,
                  tagged_vlans: portMap.get(pi)?.tagged ?? [],
                }));
                onApply(assignments);
                setVlanEdits(new Map());
              }}
            >
              {vlanAssignPending && <RefreshCw className="mr-2 h-4 w-4 animate-spin" />}
              {t('VlansTab.actions.applyChanges')}
            </Button>
          </div>
        )}
      </div>

      {!showVlanMatrix ? (
        /* VLAN list view */
        <Card>
          <CardHeader>
            <CardTitle>{t('VlansTab.list.title')}</CardTitle>
            <CardDescription>{t('VlansTab.list.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {switchVlans && switchVlans.length > 0 ? (
                switchVlans.map((vlan) => (
                  <div key={vlan.id} className="flex items-center justify-between p-3 rounded-lg border">
                    <div className="flex items-center gap-4">
                      <Badge variant="outline" className="text-lg px-3 py-1">
                        {vlan.vlan_id}
                      </Badge>
                      <div>
                        <div className="font-medium">{vlan.name}</div>
                        <div className="text-sm text-muted-foreground">
                          {t('VlansTab.list.portCounts', {
                            untagged: vlan.untagged_ports,
                            tagged: vlan.tagged_ports,
                          })}
                          {vlan.cidr && <span className="ml-2">{'•'} {vlan.cidr}</span>}
                        </div>
                        {vlan.description && (
                          <div className="text-xs text-muted-foreground">{vlan.description}</div>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {vlan.dhcp_enabled && (
                        <Badge variant="secondary" className="text-xs">{t('VlansTab.list.dhcp')}</Badge>
                      )}
                      <Button variant="outline" size="sm" onClick={() => setShowVlanMatrix(true)}>
                        {t('VlansTab.actions.viewPorts')}
                      </Button>
                    </div>
                  </div>
                ))
              ) : (
                (() => {
                  const vlanSet = new Map<number, { untagged: number; tagged: number }>();
                  ports.forEach((p) => {
                    if (!vlanSet.has(p.native_vlan)) vlanSet.set(p.native_vlan, { untagged: 0, tagged: 0 });
                    vlanSet.get(p.native_vlan)!.untagged++;
                    p.tagged_vlans.forEach((v) => {
                      if (!vlanSet.has(v)) vlanSet.set(v, { untagged: 0, tagged: 0 });
                      vlanSet.get(v)!.tagged++;
                    });
                  });
                  return Array.from(vlanSet.entries()).sort((a, b) => a[0] - b[0]).map(([vid, counts]) => (
                    <div key={vid} className="flex items-center justify-between p-3 rounded-lg border">
                      <div className="flex items-center gap-4">
                        <Badge variant="outline" className="text-lg px-3 py-1">{vid}</Badge>
                        <div>
                          <div className="font-medium">{vid === 1 ? t('VlansTab.list.default') : t('VlansTab.list.vlanName', { vid })}</div>
                          <div className="text-sm text-muted-foreground">
                            {t('VlansTab.list.portCounts', {
                              untagged: counts.untagged,
                              tagged: counts.tagged,
                            })}
                          </div>
                        </div>
                      </div>
                      <Button variant="outline" size="sm" onClick={() => setShowVlanMatrix(true)}>{t('VlansTab.actions.viewPorts')}</Button>
                    </div>
                  ));
                })()
              )}
            </div>
          </CardContent>
        </Card>
      ) : (
        /* VLAN-to-Port Matrix */
        <Card>
          <CardHeader>
            <CardTitle>{t('VlansTab.matrix.title')}</CardTitle>
            <CardDescription>
              {t('VlansTab.matrix.toggleHint')} <Badge variant="default" className="mx-1">U</Badge> {t('VlansTab.matrix.untagged')}
              <Badge variant="secondary" className="mx-1">T</Badge> {t('VlansTab.matrix.tagged')}
              <span className="mx-1 text-muted-foreground">{t('VlansTab.matrix.emptyExcluded')}</span>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b">
                    <th className="text-left p-2 sticky left-0 bg-background z-10 min-w-[120px]">{t('VlansTab.matrix.portColumn')}</th>
                    {(switchVlans || []).map((vlan) => (
                      <th key={vlan.vlan_id} className="p-2 text-center min-w-[60px]">
                        <div className="font-medium">{vlan.vlan_id}</div>
                        <div className="text-xs text-muted-foreground font-normal truncate max-w-[60px]">{vlan.name}</div>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {ports.map((port) => (
                    <tr key={port.port_index} className="border-b hover:bg-muted/50">
                      <td className="p-2 sticky left-0 bg-background z-10 font-medium">
                        {t('VlansTab.matrix.portRow', { index: port.port_index })}
                        {port.port_name && <span className="text-muted-foreground ml-1 text-xs">({port.port_name})</span>}
                      </td>
                      {(switchVlans || []).map((vlan) => {
                        const key = `${port.port_index}:${vlan.vlan_id}`;
                        // Determine current state (with edit override)
                        let state: 'U' | 'T' | '' = '';
                        if (port.native_vlan === vlan.vlan_id) state = 'U';
                        else if ((port.tagged_vlans || []).includes(vlan.vlan_id)) state = 'T';
                        // Apply edit if exists
                        if (vlanEdits.has(key)) state = vlanEdits.get(key)!;
                        const isEdited = vlanEdits.has(key);

                        return (
                          <td key={vlan.vlan_id} className="p-1 text-center">
                            <Button
                              variant="ghost"
                              size="sm"
                              className={`h-8 w-12 text-xs font-bold ${
                                state === 'U' ? 'bg-primary text-primary-foreground hover:bg-primary/80' :
                                state === 'T' ? 'bg-secondary text-secondary-foreground hover:bg-secondary/80' :
                                'hover:bg-muted'
                              } ${isEdited ? 'ring-2 ring-orange-400' : ''}`}
                              onClick={() => {
                                const next = state === '' ? 'U' : state === 'U' ? 'T' : '';
                                const newEdits = new Map(vlanEdits);
                                // Check if "next" is the original state
                                let original: 'U' | 'T' | '' = '';
                                if (port.native_vlan === vlan.vlan_id) original = 'U';
                                else if ((port.tagged_vlans || []).includes(vlan.vlan_id)) original = 'T';
                                if (next === original) {
                                  newEdits.delete(key);
                                } else {
                                  newEdits.set(key, next as 'U' | 'T' | '');
                                }
                                setVlanEdits(newEdits);
                              }}
                            >
                              {state || '-'}
                            </Button>
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </>
  );
}
