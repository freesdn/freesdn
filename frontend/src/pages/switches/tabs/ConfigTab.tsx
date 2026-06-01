// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * ConfigTab · STP/RSTP, IGMP snooping, port mirroring, QoS, DHCP snooping,
 * and ACL rules tables for the switch detail view.
 *
 * Extracted from SwitchesPage as part of the monolith breakup. Purely
 * presentational; receives all data via props from the parent's queries.
 */
import { Shield } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Badge } from '@/components/ui/badge';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import type {
  STPConfig,
  ACLRule,
  IGMPConfig,
  MirrorConfig,
  QoSConfig,
  DHCPSnoopingConfig,
} from '@/lib/api';

export interface ConfigTabProps {
  stpConfig: unknown;
  aclRules: unknown;
  igmpConfig: unknown;
  mirrorConfig: unknown;
  qosConfig: unknown;
  dhcpSnoopingConfig: unknown;
}

export function ConfigTab({
  stpConfig,
  aclRules,
  igmpConfig,
  mirrorConfig,
  qosConfig,
  dhcpSnoopingConfig,
}: ConfigTabProps) {
  const { t } = useTranslation('switches');
  return (
    <>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* STP Config */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">{t('ConfigTab.stp.title')}</CardTitle>
            <CardDescription>{t('ConfigTab.stp.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            {stpConfig ? (
              <div className="space-y-3">
                {[
                  { label: t('ConfigTab.stp.mode'), value: (stpConfig as STPConfig).mode?.toUpperCase() || 'RSTP' },
                  { label: t('ConfigTab.stp.priority'), value: String((stpConfig as STPConfig).priority ?? 32768) },
                  { label: t('ConfigTab.stp.helloTime'), value: `${(stpConfig as STPConfig).hello_time ?? 2}s` },
                  { label: t('ConfigTab.stp.forwardDelay'), value: `${(stpConfig as STPConfig).forward_delay ?? 15}s` },
                  { label: t('ConfigTab.stp.maxAge'), value: `${(stpConfig as STPConfig).max_age ?? 20}s` },
                  { label: t('ConfigTab.stp.rootBridge'), value: (stpConfig as STPConfig).root_bridge || 'N/A' },
                ].map((row) => (
                  <div key={row.label} className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">{row.label}</span>
                    <span className="font-medium">{row.value}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground py-4 text-center">{t('ConfigTab.stp.loading')}</p>
            )}
          </CardContent>
        </Card>

        {/* IGMP Snooping */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">{t('ConfigTab.igmp.title')}</CardTitle>
            <CardDescription>{t('ConfigTab.igmp.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            {igmpConfig ? (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">{t('ConfigTab.igmp.enabled')}</span>
                  <Badge variant={(igmpConfig as IGMPConfig).enabled ? 'default' : 'secondary'}>
                    {(igmpConfig as IGMPConfig).enabled ? t('ConfigTab.common.on') : t('ConfigTab.common.off')}
                  </Badge>
                </div>
                {[
                  { label: t('ConfigTab.igmp.version'), value: String((igmpConfig as IGMPConfig).version ?? 2) },
                  { label: t('ConfigTab.igmp.fastLeave'), value: (igmpConfig as IGMPConfig).fast_leave ? t('ConfigTab.common.enabled') : t('ConfigTab.common.disabled') },
                  { label: t('ConfigTab.igmp.querier'), value: (igmpConfig as IGMPConfig).querier ? t('ConfigTab.common.enabled') : t('ConfigTab.common.disabled') },
                  { label: t('ConfigTab.igmp.queryInterval'), value: `${(igmpConfig as IGMPConfig).query_interval ?? 125}s` },
                ].map((row) => (
                  <div key={row.label} className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">{row.label}</span>
                    <span className="font-medium">{row.value}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground py-4 text-center">{t('ConfigTab.igmp.loading')}</p>
            )}
          </CardContent>
        </Card>

        {/* Port Mirroring */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">{t('ConfigTab.mirror.title')}</CardTitle>
            <CardDescription>{t('ConfigTab.mirror.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            {mirrorConfig ? (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">{t('ConfigTab.common.status')}</span>
                  <Badge variant={(mirrorConfig as MirrorConfig).enabled ? 'default' : 'secondary'}>
                    {(mirrorConfig as MirrorConfig).enabled ? t('ConfigTab.common.active') : t('ConfigTab.common.inactive')}
                  </Badge>
                </div>
                {(mirrorConfig as MirrorConfig).destination_port !== undefined && (
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">{t('ConfigTab.mirror.destinationPort')}</span>
                    <span className="font-medium">{t('ConfigTab.mirror.portValue', { port: (mirrorConfig as MirrorConfig).destination_port })}</span>
                  </div>
                )}
                {(mirrorConfig as MirrorConfig).source_ports?.length ? (
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">{t('ConfigTab.mirror.sourcePorts')}</span>
                    <span className="font-medium">{(mirrorConfig as MirrorConfig).source_ports?.join(', ')}</span>
                  </div>
                ) : null}
                {(mirrorConfig as MirrorConfig).direction && (
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">{t('ConfigTab.common.direction')}</span>
                    <span className="font-medium capitalize">{(mirrorConfig as MirrorConfig).direction}</span>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground py-4 text-center">{t('ConfigTab.mirror.loading')}</p>
            )}
          </CardContent>
        </Card>

        {/* QoS Config */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">{t('ConfigTab.qos.title')}</CardTitle>
            <CardDescription>{t('ConfigTab.qos.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            {qosConfig ? (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">{t('ConfigTab.common.status')}</span>
                  <Badge variant={(qosConfig as QoSConfig).enabled ? 'default' : 'secondary'}>
                    {(qosConfig as QoSConfig).enabled ? t('ConfigTab.common.enabled') : t('ConfigTab.common.disabled')}
                  </Badge>
                </div>
                {(qosConfig as QoSConfig).mode && (
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">{t('ConfigTab.qos.mode')}</span>
                    <span className="font-medium capitalize">{(qosConfig as QoSConfig).mode?.replace(/_/g, ' ')}</span>
                  </div>
                )}
                {(qosConfig as QoSConfig).trust_mode && (
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">{t('ConfigTab.qos.trustMode')}</span>
                    <span className="font-medium capitalize">{(qosConfig as QoSConfig).trust_mode}</span>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground py-4 text-center">{t('ConfigTab.qos.loading')}</p>
            )}
          </CardContent>
        </Card>

        {/* DHCP Snooping */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">{t('ConfigTab.dhcp.title')}</CardTitle>
            <CardDescription>{t('ConfigTab.dhcp.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            {dhcpSnoopingConfig ? (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">{t('ConfigTab.common.status')}</span>
                  <Badge variant={(dhcpSnoopingConfig as DHCPSnoopingConfig).enabled ? 'default' : 'secondary'}>
                    {(dhcpSnoopingConfig as DHCPSnoopingConfig).enabled ? t('ConfigTab.common.enabled') : t('ConfigTab.common.disabled')}
                  </Badge>
                </div>
                {(dhcpSnoopingConfig as DHCPSnoopingConfig).verify_mac !== undefined && (
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">{t('ConfigTab.dhcp.verifyMac')}</span>
                    <span className="font-medium">{(dhcpSnoopingConfig as DHCPSnoopingConfig).verify_mac ? t('ConfigTab.common.yes') : t('ConfigTab.common.no')}</span>
                  </div>
                )}
                {(dhcpSnoopingConfig as DHCPSnoopingConfig).trusted_ports?.length ? (
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">{t('ConfigTab.dhcp.trustedPorts')}</span>
                    <span className="font-medium">{(dhcpSnoopingConfig as DHCPSnoopingConfig).trusted_ports?.join(', ')}</span>
                  </div>
                ) : null}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground py-4 text-center">{t('ConfigTab.dhcp.loading')}</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* ACL Rules Table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Shield className="h-4 w-4" />
            {t('ConfigTab.acl.title')}
          </CardTitle>
          <CardDescription>{t('ConfigTab.acl.rulesConfigured', { count: (aclRules as ACLRule[] | undefined)?.length || 0 })}</CardDescription>
        </CardHeader>
        <CardContent>
          {(aclRules as ACLRule[] | undefined)?.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>#</TableHead>
                  <TableHead>{t('ConfigTab.acl.columns.name')}</TableHead>
                  <TableHead>{t('ConfigTab.acl.columns.action')}</TableHead>
                  <TableHead>{t('ConfigTab.acl.columns.protocol')}</TableHead>
                  <TableHead>{t('ConfigTab.acl.columns.source')}</TableHead>
                  <TableHead>{t('ConfigTab.acl.columns.destination')}</TableHead>
                  <TableHead>{t('ConfigTab.acl.columns.direction')}</TableHead>
                  <TableHead>{t('ConfigTab.acl.columns.status')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(aclRules as ACLRule[]).map((rule, i) => (
                  <TableRow key={rule.id || i}>
                    <TableCell>{rule.index ?? i + 1}</TableCell>
                    <TableCell className="font-medium">{rule.name || '-'}</TableCell>
                    <TableCell>
                      <Badge variant={rule.action === 'permit' ? 'default' : 'destructive'} className="text-xs">
                        {rule.action || '-'}
                      </Badge>
                    </TableCell>
                    <TableCell>{rule.protocol || t('ConfigTab.acl.any')}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {rule.src_ip ? `${rule.src_ip}${rule.src_port ? `:${rule.src_port}` : ''}` : t('ConfigTab.acl.any')}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {rule.dst_ip ? `${rule.dst_ip}${rule.dst_port ? `:${rule.dst_port}` : ''}` : t('ConfigTab.acl.any')}
                    </TableCell>
                    <TableCell className="capitalize">{rule.direction || '-'}</TableCell>
                    <TableCell>
                      <Badge variant={rule.enabled ? 'default' : 'secondary'} className="text-xs">
                        {rule.enabled ? t('ConfigTab.common.active') : t('ConfigTab.common.disabled')}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="text-sm text-muted-foreground py-4 text-center">{t('ConfigTab.acl.empty')}</p>
          )}
        </CardContent>
      </Card>
    </>
  );
}
