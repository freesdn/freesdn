// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * GatewayVpnTab · WireGuard servers/peers + handshakes, OpenVPN instances +
 * sessions, IPsec tunnels + live status, Tailscale, and a raw VPN fallback panel.
 *
 * Extracted from GatewayDetailPage as part of the monolith breakup. Owns the
 * wgServerColumns, wgPeerColumns, and ipsecColumns definitions (only used here)
 * and receives all data plus the various add/delete/connect/apply callbacks
 * via props.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useTranslation } from 'react-i18next';
import {
  Activity,
  CheckCircle,
  Globe,
  Lock,
  Play,
  Plus,
  RefreshCw,
  Shield,
  Square,
  Trash2,
  XCircle,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { Skeleton } from '@/components/ui/skeleton';

export interface GatewayVpnTabProps {
  // WireGuard
  wgServers: any[];
  wgPeers: any[];
  wgLoading: boolean;
  wgHandshakesData: any;
  onAddWgServer: () => void;
  onAddWgPeer: () => void;
  onDeleteWgServer: (server: any, vid: string) => void;
  onDeleteWgPeer: (peer: any, vid: string) => void;
  // OpenVPN
  ovpnInstances: any[];
  ovpnSessions: any[];
  ovpnLoading: boolean;
  onAddOvpn: () => void;
  onDeleteOvpnInstance: (inst: any) => void;
  onKillOvpnSession: (session: any) => void;
  // IPsec
  ipsecPhase1: any[];
  ipsecPhase2: any[];
  ipsecLoading: boolean;
  ipsecStatusData: any;
  onApplyIpsec: () => void;
  onConnectIpsec: (vid: string) => void;
  onDisconnectIpsec: (vid: string) => void;
  // Tailscale
  tailscaleData: any;
  tailscaleLoading: boolean;
  // Raw VPN fallback
  vpn: any;
  vpnLoading: boolean;
}

export function GatewayVpnTab({
  wgServers,
  wgPeers,
  wgLoading,
  wgHandshakesData,
  onAddWgServer,
  onAddWgPeer,
  onDeleteWgServer,
  onDeleteWgPeer,
  ovpnInstances,
  ovpnSessions,
  ovpnLoading,
  onAddOvpn,
  onDeleteOvpnInstance,
  onKillOvpnSession,
  ipsecPhase1,
  ipsecPhase2,
  ipsecLoading,
  ipsecStatusData,
  onApplyIpsec,
  onConnectIpsec,
  onDisconnectIpsec,
  tailscaleData,
  tailscaleLoading,
  vpn,
  vpnLoading,
}: GatewayVpnTabProps) {
  const { t } = useTranslation('firewall');

  const wgServerColumns: DataTableColumn<any>[] = [
    { id: 'name', header: t('GatewayVpnTab.columns.name'), accessorFn: (r: any) => r.name || '-', sortable: true },
    { id: 'port', header: t('GatewayVpnTab.columns.port'), accessorFn: (r: any) => r.listen_port || r.port || '-' },
    { id: 'address', header: t('GatewayVpnTab.columns.tunnelAddress'), accessorFn: (r: any) => {
      const a = r.tunnel_address || r.tunneladdress;
      return Array.isArray(a) ? a.join(', ') : a || '-';
    }},
    { id: 'enabled', header: t('GatewayVpnTab.columns.enabled'), cell: (r: any) => {
      const enabled = r.enabled !== false && r.enabled !== '0';
      return enabled ? <CheckCircle className="h-4 w-4 text-green-600" /> : <XCircle className="h-4 w-4 text-muted-foreground" />;
    }},
    { id: 'actions', header: '', cell: (r: any) => {
      const vid = r.uuid || r.id;
      return vid ? (
        <Button variant="ghost" size="sm" onClick={() => onDeleteWgServer(r, vid)}><Trash2 className="h-3.5 w-3.5 text-destructive" /></Button>
      ) : null;
    }},
  ];

  const wgPeerColumns: DataTableColumn<any>[] = [
    { id: 'name', header: t('GatewayVpnTab.columns.name'), accessorFn: (r: any) => r.name || '-', sortable: true },
    { id: 'pubkey', header: t('GatewayVpnTab.columns.publicKey'), accessorFn: (r: any) => r.public_key?.slice(0, 16) + '...' || '-' },
    { id: 'allowed', header: t('GatewayVpnTab.columns.allowedIps'), accessorFn: (r: any) => {
      const a = r.allowed_ips || r.allowedips;
      return Array.isArray(a) ? a.join(', ') : a || '-';
    }},
    { id: 'endpoint', header: t('GatewayVpnTab.columns.endpoint'), accessorFn: (r: any) => r.endpoint || '-' },
    { id: 'keepalive', header: t('GatewayVpnTab.columns.keepalive'), accessorFn: (r: any) => r.keepalive ? `${r.keepalive}s` : '-' },
    { id: 'actions', header: '', cell: (r: any) => {
      const vid = r.uuid || r.id;
      return vid ? (
        <Button variant="ghost" size="sm" onClick={() => onDeleteWgPeer(r, vid)}><Trash2 className="h-3.5 w-3.5 text-destructive" /></Button>
      ) : null;
    }},
  ];

  const ipsecColumns: DataTableColumn<any>[] = [
    { id: 'description', header: t('GatewayVpnTab.columns.description'), accessorFn: (r: any) => r.description || r.descr || '-', sortable: true },
    { id: 'remote', header: t('GatewayVpnTab.columns.remote'), accessorFn: (r: any) => r.remote_gateway || r.remote || '-' },
    { id: 'ike', header: t('GatewayVpnTab.columns.ike'), accessorFn: (r: any) => r.ike_version || r.iketype || '-' },
    { id: 'protocol', header: t('GatewayVpnTab.columns.protocol'), accessorFn: (r: any) => r.protocol || '-' },
    { id: 'status', header: t('GatewayVpnTab.columns.status'), cell: (r: any) => {
      const connected = r.connected || r.status === 'connected' || r.status === 'established';
      return <Badge variant={connected ? 'default' : 'secondary'}>{connected ? t('GatewayVpnTab.status.connected') : t('GatewayVpnTab.status.disconnected')}</Badge>;
    }},
    { id: 'actions', header: '', cell: (r: any) => {
      const vid = r.uuid || r.id || r.ikeid;
      if (!vid) return null;
      const connected = r.connected || r.status === 'connected' || r.status === 'established';
      return connected ? (
        <Button variant="ghost" size="sm" onClick={() => onDisconnectIpsec(vid)}>
          <Square className="h-3.5 w-3.5 mr-1" /> {t('GatewayVpnTab.actions.disconnect')}
        </Button>
      ) : (
        <Button variant="ghost" size="sm" onClick={() => onConnectIpsec(vid)}>
          <Play className="h-3.5 w-3.5 mr-1" /> {t('GatewayVpnTab.actions.connect')}
        </Button>
      );
    }},
  ];

  return (
    <>
      {/* WireGuard */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2"><Lock className="h-4 w-4" /> {t('GatewayVpnTab.wireguard.title')}</CardTitle>
              <CardDescription>{t('GatewayVpnTab.wireguard.description')}</CardDescription>
            </div>
            <div className="flex gap-1">
              <Button size="sm" variant="outline" onClick={onAddWgServer}><Plus className="h-4 w-4 mr-1" /> {t('GatewayVpnTab.actions.server')}</Button>
              <Button size="sm" variant="outline" onClick={onAddWgPeer}><Plus className="h-4 w-4 mr-1" /> {t('GatewayVpnTab.actions.peer')}</Button>
            </div>
          </div>
        </CardHeader>
        {wgLoading ? (
          <CardContent><Skeleton className="h-24" /></CardContent>
        ) : (
          <>
            {wgServers.length > 0 && (
              <div className="px-4 pb-2">
                <p className="text-xs font-medium text-muted-foreground mb-1">{t('GatewayVpnTab.wireguard.servers')}</p>
                <DataTable embedded data={wgServers} columns={wgServerColumns} />
              </div>
            )}
            {wgPeers.length > 0 && (
              <div className="px-4 pb-4">
                <p className="text-xs font-medium text-muted-foreground mb-1">{t('GatewayVpnTab.wireguard.peers')}</p>
                <DataTable embedded data={wgPeers} columns={wgPeerColumns} />
              </div>
            )}
            {wgServers.length === 0 && wgPeers.length === 0 && (
              <CardContent noOffset><p className="text-sm text-muted-foreground py-4 text-center">{t('GatewayVpnTab.wireguard.empty')}</p></CardContent>
            )}
          </>
        )}
      </Card>

      {/* WireGuard Handshakes */}
      {wgHandshakesData?.data?.handshakes && (
        <Card className="border-border/50">
          <CardHeader className="pb-4">
            <CardTitle className="flex items-center gap-2"><Activity className="h-4 w-4" /> {t('GatewayVpnTab.handshakes.title')}</CardTitle>
            <CardDescription>{t('GatewayVpnTab.handshakes.description')}</CardDescription>
          </CardHeader>
          <DataTable
            embedded
            data={wgHandshakesData.data.handshakes}
            columns={[
              { id: 'peer', header: t('GatewayVpnTab.columns.peer'), accessorKey: 'peer' },
              { id: 'endpoint', header: t('GatewayVpnTab.columns.endpoint'), accessorKey: 'endpoint' },
              { id: 'last_handshake', header: t('GatewayVpnTab.columns.lastHandshake'), accessorKey: 'latest_handshake', cell: (r: any) => {
                const ts = r.latest_handshake;
                return <span className="text-sm">{ts ? new Date(ts * 1000).toLocaleString() : '-'}</span>;
              }},
              { id: 'transfer_rx', header: t('GatewayVpnTab.columns.transferRx'), accessorKey: 'transfer_rx' },
              { id: 'transfer_tx', header: t('GatewayVpnTab.columns.transferTx'), accessorKey: 'transfer_tx' },
            ] as DataTableColumn<any>[]}
          />
        </Card>
      )}

      {/* OpenVPN */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2"><Globe className="h-4 w-4" /> {t('GatewayVpnTab.openvpn.title')}</CardTitle>
              <CardDescription>{t('GatewayVpnTab.openvpn.summary', { instances: ovpnInstances.length, sessions: ovpnSessions.length })}</CardDescription>
            </div>
            <Button size="sm" variant="outline" onClick={onAddOvpn}><Plus className="h-4 w-4 mr-1" /> {t('GatewayVpnTab.actions.instance')}</Button>
          </div>
        </CardHeader>
        {ovpnLoading ? (
          <CardContent><Skeleton className="h-24" /></CardContent>
        ) : (
          <CardContent>
            {ovpnInstances.length > 0 ? (
              <div className="space-y-3">
                {ovpnInstances.map((inst: any, i: number) => (
                  <div key={i} className="p-3 rounded-lg border">
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-sm">{inst.description || inst.name || t('GatewayVpnTab.openvpn.instanceFallback', { index: i + 1 })}</span>
                      <Badge variant={inst.enabled !== false ? 'default' : 'secondary'}>
                        {inst.role || 'server'} · {inst.enabled !== false ? t('GatewayVpnTab.status.active') : t('GatewayVpnTab.status.disabled')}
                      </Badge>
                      {(inst.uuid || inst.id) && (
                        <Button variant="ghost" size="sm" className="ml-1" onClick={() => onDeleteOvpnInstance(inst)}>
                          <Trash2 className="h-3.5 w-3.5 text-destructive" />
                        </Button>
                      )}
                    </div>
                    {(inst.tunnel_network || inst.server) && <p className="text-xs text-muted-foreground mt-1">{t('GatewayVpnTab.openvpn.tunnel')}: {inst.tunnel_network || inst.server}</p>}
                    {inst.proto && <p className="text-xs text-muted-foreground">{t('GatewayVpnTab.openvpn.protocol')}: {inst['%proto'] || inst.proto} · {t('GatewayVpnTab.openvpn.port')}: {inst.port || '-'}</p>}
                    {inst.local && <p className="text-xs text-muted-foreground">{t('GatewayVpnTab.openvpn.local')}: {inst.local}</p>}
                  </div>
                ))}
                {ovpnSessions.length > 0 && (
                  <div className="mt-3 border-t pt-3">
                    <p className="text-xs font-medium text-muted-foreground mb-2">{t('GatewayVpnTab.openvpn.activeSessions')}</p>
                    {ovpnSessions.map((s: any, i: number) => (
                      <div key={i} className="flex items-center justify-between py-1.5 border-b last:border-0">
                        <div className="flex-1 min-w-0">
                          <span className="text-sm font-medium">{s.common_name || s.username || '-'}</span>
                          <span className="text-xs text-muted-foreground ml-2">{s.real_address || s.remote_ip || ''}</span>
                          {s.virtual_address && <span className="text-xs text-muted-foreground ml-2">VPN: {s.virtual_address}</span>}
                          {s.connected_since && <p className="text-xs text-muted-foreground">{t('GatewayVpnTab.openvpn.connected')}: {s.connected_since}{s.data_channel_cipher ? ` · ${s.data_channel_cipher}` : ''}</p>}
                          {(s.bytes_received || s.bytes_sent) && (
                            <p className="text-xs text-muted-foreground">
                              RX: {((Number(s.bytes_received) || 0) / 1048576).toFixed(1)} MB · TX: {((Number(s.bytes_sent) || 0) / 1048576).toFixed(1)} MB
                            </p>
                          )}
                        </div>
                        <Button variant="ghost" size="sm" onClick={() => onKillOvpnSession(s)}>
                          <XCircle className="h-3.5 w-3.5 mr-1" /> {t('GatewayVpnTab.actions.kill')}
                        </Button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground py-4 text-center">{t('GatewayVpnTab.openvpn.empty')}</p>
            )}
          </CardContent>
        )}
      </Card>

      {/* IPsec */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2"><Shield className="h-4 w-4" /> {t('GatewayVpnTab.ipsec.title')}</CardTitle>
              <CardDescription>{t('GatewayVpnTab.ipsec.description')}</CardDescription>
            </div>
            <div className="flex gap-1">
              {ipsecStatusData?.data?.status && (
                <Badge variant={ipsecStatusData.data.status.connected ? 'default' : 'secondary'} className="mr-2">
                  {ipsecStatusData.data.status.connected ? t('GatewayVpnTab.status.connected') : t('GatewayVpnTab.status.disconnected')}
                </Badge>
              )}
              <Button size="sm" variant="outline" onClick={onApplyIpsec}>
                <RefreshCw className="h-3.5 w-3.5 mr-1" /> {t('GatewayVpnTab.actions.applyChanges')}
              </Button>
            </div>
          </div>
        </CardHeader>
        {ipsecLoading ? (
          <CardContent><Skeleton className="h-24" /></CardContent>
        ) : ipsecPhase1.length > 0 || ipsecPhase2.length > 0 ? (
          <>
            {ipsecPhase1.length > 0 && (
              <div className="px-4 pb-2">
                <p className="text-xs font-medium text-muted-foreground mb-1">{t('GatewayVpnTab.ipsec.phase1')}</p>
                <DataTable embedded data={ipsecPhase1} columns={ipsecColumns} />
              </div>
            )}
            {ipsecPhase2.length > 0 && (
              <div className="px-4 pb-4">
                <p className="text-xs font-medium text-muted-foreground mb-1">{t('GatewayVpnTab.ipsec.phase2')}</p>
                <DataTable embedded data={ipsecPhase2} columns={ipsecColumns} />
              </div>
            )}
          </>
        ) : (
          <CardContent noOffset><p className="text-sm text-muted-foreground py-4 text-center">{t('GatewayVpnTab.ipsec.empty')}</p></CardContent>
        )}
      </Card>

      {/* IPsec Live Status */}
      {ipsecStatusData?.data?.status && (
        <Card className="border-border/50">
          <CardHeader className="pb-4">
            <CardTitle>{t('GatewayVpnTab.ipsecStatus.title')}</CardTitle>
            <CardDescription>{t('GatewayVpnTab.ipsecStatus.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              {Object.entries(ipsecStatusData.data.status).map(([key, val]) => (
                <div key={key}>
                  <dt className="text-muted-foreground capitalize">{key.replace(/_/g, ' ')}</dt>
                  <dd className="font-medium">{typeof val === 'boolean' ? (val ? t('GatewayVpnTab.common.yes') : t('GatewayVpnTab.common.no')) : String(val ?? '-')}</dd>
                </div>
              ))}
            </dl>
          </CardContent>
        </Card>
      )}

      {/* Tailscale VPN */}
      {(() => {
        const ts = tailscaleData?.data?.tailscale;
        if (!ts && !tailscaleLoading) return null;
        const settings = ts?.settings || {};
        return (
          <Card className="border-border/50">
            <CardHeader className="pb-4">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2"><Globe className="h-4 w-4" /> {t('GatewayVpnTab.tailscale.title')}</CardTitle>
                  <CardDescription>{t('GatewayVpnTab.tailscale.description')}</CardDescription>
                </div>
                <Badge variant={ts?.running ? 'default' : 'secondary'}>{ts?.running ? t('GatewayVpnTab.status.running') : t('GatewayVpnTab.status.stopped')}</Badge>
              </div>
            </CardHeader>
            {tailscaleLoading ? (
              <CardContent><Skeleton className="h-24" /></CardContent>
            ) : (
              <CardContent>
                <dl className="grid grid-cols-2 md:grid-cols-3 gap-x-6 gap-y-2 text-sm">
                  {[
                    [t('GatewayVpnTab.tailscale.enabled'), settings.enabled ? t('GatewayVpnTab.common.yes') : t('GatewayVpnTab.common.no')],
                    [t('GatewayVpnTab.tailscale.listenPort'), settings.listen_port || '-'],
                    [t('GatewayVpnTab.tailscale.acceptDns'), settings.accept_dns ? t('GatewayVpnTab.common.yes') : t('GatewayVpnTab.common.no')],
                    [t('GatewayVpnTab.tailscale.exitNode'), settings.advertise_exit_node ? t('GatewayVpnTab.tailscale.advertising') : t('GatewayVpnTab.common.no')],
                    [t('GatewayVpnTab.tailscale.subnetRoutes'), settings.accept_subnet_routes ? t('GatewayVpnTab.tailscale.accepting') : t('GatewayVpnTab.common.no')],
                    [t('GatewayVpnTab.tailscale.ssh'), settings.enable_ssh ? t('GatewayVpnTab.status.enabled') : t('GatewayVpnTab.status.disabled')],
                    [t('GatewayVpnTab.tailscale.snat'), settings.disable_snat ? t('GatewayVpnTab.status.disabled') : t('GatewayVpnTab.status.enabled')],
                  ].map(([label, val]) => (
                    <div key={label} className="flex justify-between">
                      <dt className="text-muted-foreground">{label}</dt>
                      <dd className="font-medium">{val}</dd>
                    </div>
                  ))}
                </dl>
                {settings.use_exit_node && settings.use_exit_node.length > 0 && (
                  <div className="mt-3 pt-3 border-t">
                    <p className="text-xs text-muted-foreground mb-1">{t('GatewayVpnTab.tailscale.exitNodePeers')}</p>
                    <div className="flex flex-wrap gap-1">
                      {settings.use_exit_node.map((n: string) => (
                        <Badge key={n} variant="outline" className="text-xs">{n}</Badge>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            )}
          </Card>
        );
      })()}

      {/* Legacy VPN raw data */}
      {vpn && !vpnLoading && (
        <Card className="border-border/50">
          <CardHeader className="pb-4">
            <CardTitle>{t('GatewayVpnTab.rawStatus.title')}</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="text-xs bg-muted p-4 rounded-lg overflow-auto max-h-[300px]">
              {JSON.stringify(redactVpnSecrets(vpn), null, 2)}
            </pre>
          </CardContent>
        </Card>
      )}
    </>
  );
}

// ─── Redaction ────────────────────────────────────────────────────────
// The VPN endpoint returns the controller's raw config blob which on
// pfSense / OPNsense / RouterOS includes WireGuard private keys, OpenVPN
// CA/TLS material, IPsec PSKs, and Tailscale auth tokens. Stringifying
// it into a visible <pre> exposes those to anyone with the operator's
// browser session (DevTools, screen-share, browser history cache, React
// DevTools props). Recurse the response and mask known secret-shaped
// fields by name.
const _VPN_SECRET_KEY_RE = /(?:^|[._-])(?:priv(?:ate)?[_-]?key|preshared(?:_?key)?|psk|secret|password|passphrase|auth[_-]?key|tls[_-]?key|ca[_-]?key|cert[_-]?key|node[_-]?key|auth[_-]?token|api[_-]?key|access[_-]?token|client[_-]?secret)$/i;

function redactVpnSecrets(value: unknown, depth = 0): unknown {
  if (depth > 12 || value == null) return value;
  if (Array.isArray(value)) {
    return value.map((v) => redactVpnSecrets(v, depth + 1));
  }
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (_VPN_SECRET_KEY_RE.test(k) && typeof v === 'string' && v.length > 0) {
        out[k] = '«redacted»';
      } else {
        out[k] = redactVpnSecrets(v, depth + 1);
      }
    }
    return out;
  }
  return value;
}
