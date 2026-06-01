// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Gateway Detail Page
 *
 * Comprehensive enterprise-grade dashboard for a single firewall/router gateway.
 * Tabs: Overview · Firewall Rules · NAT · VPN · Interfaces · DHCP · DNS ·
 *       Aliases · Routing · IDS · Shaper · Services · Backups · System ·
 *       Monitoring · Diagnostics · Logs · Sync Log  (18 tabs)
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { type MouseEvent, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Server,
  ArrowLeft,
  RefreshCw,
  Shield,
  Wifi,
  WifiOff,
  AlertCircle,
  Clock,
  Settings,
  Zap,
  Loader2,
  Power,
  AlertTriangle,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { StatsGrid } from '@/components/ui/stats-grid';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { type DataTableColumn } from '@/components/ui/data-table';
import { Skeleton } from '@/components/ui/skeleton';
import { PageHeader } from '@/components/layout';
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogCancel,
  AlertDialogAction,
} from '@/components/ui/alert-dialog';
import { useToast } from '@/hooks/use-toast';
import {
  gatewayApi,
  sitesApiV2,
  type GatewayConnection,
  type GatewayWriteResponse,
  type Site,
} from '@/lib/api';
import { cn } from '@/lib/utils';
import {
  DeleteResourceDialog,
  FirewallRuleFormDialog,
  DNSOverrideFormDialog,
  DNSDomainOverrideFormDialog,
  DHCPStaticMappingFormDialog,
  PortForwardFormDialog,
  SourceNATFormDialog,
  AliasFormDialog,
  WireGuardServerFormDialog,
  WireGuardPeerFormDialog,
  OpenVPNInstanceFormDialog,
  StaticRouteFormDialog,
  ShaperPipeFormDialog,
  IDSSettingsFormDialog,
} from './GatewayResourceDialogs';
import { GatewayAliasesTab } from './gateway-tabs/GatewayAliasesTab';
import { GatewayBackupsTab } from './gateway-tabs/GatewayBackupsTab';
import { GatewayDhcpTab } from './gateway-tabs/GatewayDhcpTab';
import { GatewayDiagnosticsTab } from './gateway-tabs/GatewayDiagnosticsTab';
import { GatewayDnsTab } from './gateway-tabs/GatewayDnsTab';
import { GatewayIdsTab } from './gateway-tabs/GatewayIdsTab';
import { GatewayInterfacesTab } from './gateway-tabs/GatewayInterfacesTab';
import { GatewayLogsTab } from './gateway-tabs/GatewayLogsTab';
import { GatewayMonitoringTab } from './gateway-tabs/GatewayMonitoringTab';
import { GatewayNatTab } from './gateway-tabs/GatewayNatTab';
import { GatewayOverviewTab } from './gateway-tabs/GatewayOverviewTab';
import { GatewayServicesTab } from './gateway-tabs/GatewayServicesTab';
import { GatewaySystemTab } from './gateway-tabs/GatewaySystemTab';
import { GatewayRoutingTab } from './gateway-tabs/GatewayRoutingTab';
import { GatewayRulesTab } from './gateway-tabs/GatewayRulesTab';
import { GatewayShaperTab } from './gateway-tabs/GatewayShaperTab';
import { GatewaySyncTab } from './gateway-tabs/GatewaySyncTab';
import { GatewayVpnTab } from './gateway-tabs/GatewayVpnTab';
import { vendorLabels } from './gateway-tabs/_formatters';
import {
  PendingChangesBadge,
  PendingChangesDrawer,
} from '@/components/gateways';
import { MikroTikSystemTab } from './mikrotik-tabs/MikroTikSystemTab';
import { MikroTikInterfacesTab } from './mikrotik-tabs/MikroTikInterfacesTab';
import { MikroTikIpTab } from './mikrotik-tabs/MikroTikIpTab';
import { MikroTikDhcpTab } from './mikrotik-tabs/MikroTikDhcpTab';
import { MikroTikFirewallTab } from './mikrotik-tabs/MikroTikFirewallTab';
import { MikroTikDnsTab } from './mikrotik-tabs/MikroTikDnsTab';
import { MikroTikVpnTab } from './mikrotik-tabs/MikroTikVpnTab';
import { MikroTikHotspotTab } from './mikrotik-tabs/MikroTikHotspotTab';
import { MikroTikQueuesTab } from './mikrotik-tabs/MikroTikQueuesTab';
import { MikroTikFirmwareTab } from './mikrotik-tabs/MikroTikFirmwareTab';
import { MikroTikBackupTab } from './mikrotik-tabs/MikroTikBackupTab';
import { MikroTikTopologyTab } from './mikrotik-tabs/MikroTikTopologyTab';
import { MikroTikSnmpTab } from './mikrotik-tabs/MikroTikSnmpTab';
import { OpenWrtTab } from './openwrt-tabs/OpenWrtTab';

// ─── Component ─────────────────────────────────────────────────────────

export default function GatewayDetailPage() {
  const { id, tab } = useParams<{ id: string; tab?: string }>();
  const navigate = useNavigate();
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();

  // Valid tab keys · URL param is validated against this set
  const VALID_TABS = new Set([
    'overview', 'rules', 'nat', 'vpn', 'interfaces', 'dhcp', 'dns',
    'aliases', 'routing', 'ids', 'shaper', 'services', 'backups',
    'system', 'monitoring', 'diagnostics', 'logs', 'sync',
  ]);
  // MikroTik renders a distinct tab set (9 tabs). The
  // pfSense-shaped queries below stay enabled-gated via `activeTab` so
  // they never fire for MikroTik (no MikroTik tab key matches any of
  // them), the queries become inert and the MikroTik tab branch
  // returns before the pfSense JSX is rendered. We use a custom key
  // for the VPN tab so it does not collide with the pfSense VPN tab
  // key (``vpn``), which would re-enable the pfSense queries.
  const MIKROTIK_TABS = new Set([
    'system', 'interfaces', 'ip', 'dhcp', 'firewall',
    'dns', 'mtk-vpn', 'hotspot', 'queues',
    // firmware lifecycle / backup / topology / SNMP CRUD
    'mtk-firmware', 'mtk-backup', 'mtk-topology', 'mtk-snmp',
  ]);
  const allValid = new Set<string>([...VALID_TABS, ...MIKROTIK_TABS]);
  const activeTab = tab && allValid.has(tab) ? tab : 'overview';
  const setActiveTab = useCallback(
    (value: string) => navigate(`/firewall/gateways/${id}/${value}`, { replace: true }),
    [id, navigate],
  );
  // Radix `onValueChange` only fires on the pointer-event branch
  // it manages internally; JS-synthesized `MouseEvent`s on a tab trigger
  // don't reliably reach that branch, so the URL never updates and the
  // automated test sees the tab "click" succeed without the content
  // swap. We attach an explicit click handler that calls `setActiveTab`
  // directly, real pointer clicks still go through `onValueChange`
  // (this becomes a deduplicated no-op because the URL is already
  // there) and synthesized clicks now have a deterministic path to the
  // navigate call. The pattern is applied to every `<TabsTrigger>` via
  // the helper below.
  const tabClick = useCallback(
    (value: string) => (event: MouseEvent<HTMLButtonElement>) => {
      // Honor preventDefault from a wrapping handler / shift-click etc.
      if (event.defaultPrevented) return;
      setActiveTab(value);
    },
    [setActiveTab],
  );
  const [showRebootDialog, setShowRebootDialog] = useState(false);
  // shared open/close state for the Pending Changes drawer.
  // The badge and the drawer are siblings that read/write the same
  // useState pair so the badge can also be a toggle button.
  const [pendingDrawerOpen, setPendingDrawerOpen] = useState(false);

  // ─── CRUD dialog state ──────────────────────────────────────────
  const [showRuleForm, setShowRuleForm] = useState(false);
  const [showDnsForm, setShowDnsForm] = useState(false);
  const [editingDns, setEditingDns] = useState<any>(null);
  const [showDnsDomainForm, setShowDnsDomainForm] = useState(false);
  const [editingDnsDomain, setEditingDnsDomain] = useState<any>(null);
  const [showDhcpStaticForm, setShowDhcpStaticForm] = useState(false);
  const [editingDhcpStatic, setEditingDhcpStatic] = useState<any>(null);
  const [showPortFwdForm, setShowPortFwdForm] = useState(false);
  const [editingPortFwd, setEditingPortFwd] = useState<any>(null);
  const [showSnatForm, setShowSnatForm] = useState(false);
  const [showAliasForm, setShowAliasForm] = useState(false);
  const [editingAlias, setEditingAlias] = useState<any>(null);
  const [showWgServerForm, setShowWgServerForm] = useState(false);
  const [showWgPeerForm, setShowWgPeerForm] = useState(false);
  const [showOvpnForm, setShowOvpnForm] = useState(false);
  const [showRouteForm, setShowRouteForm] = useState(false);
  const [showPipeForm, setShowPipeForm] = useState(false);
  const [showIdsSettings, setShowIdsSettings] = useState(false);
  const [deleteDialog, setDeleteDialog] = useState<{
    open: boolean; label: string; name: string; fn: () => Promise<any>; keys: string[];
  }>({ open: false, label: '', name: '', fn: async () => {}, keys: [] });
  const openDelete = (label: string, name: string, fn: () => Promise<any>, keys: string[]) =>
    setDeleteDialog({ open: true, label, name, fn, keys });

  // ─── Gateway data ─────────────────────────────────────────────────

  const { data: gwData, isLoading: gwLoading, isError: gwError } = useQuery({
    queryKey: ['gateways', id],
    queryFn: () => gatewayApi.getById(id!),
    enabled: !!id,
    refetchInterval: 30_000,
  });

  const gw: GatewayConnection | undefined = gwData?.data;

  // ─── Sites (for site name display) ────────────────────────────────

  const { data: sitesData } = useQuery({
    queryKey: ['sites-list'],
    queryFn: async () => (await sitesApiV2.list({ page_size: 200 })).data,
    staleTime: 60_000,
  });
  const sites: Site[] = sitesData?.items ?? [];
  const siteName = gw?.site_id ? sites.find((s) => s.id === gw.site_id)?.name : undefined;

  // ─── Live data queries (loaded per-tab) ───────────────────────────

  const { data: statusData, isError: statusError } = useQuery({
    queryKey: ['gateways', id, 'status'],
    queryFn: () => gatewayApi.getStatus(id!),
    enabled: !!id && activeTab === 'overview',
    refetchInterval: 30_000,
  });

  const { data: deviceSummaryData } = useQuery({
    queryKey: ['gateways', id, 'device-summary'],
    queryFn: () => gatewayApi.getDeviceSummary(id!),
    enabled: !!id && activeTab === 'overview',
    refetchInterval: 60_000,
  });

  const { data: rulesData, isLoading: rulesLoading, isError: rulesError } = useQuery({
    queryKey: ['gateways', id, 'firewall-rules'],
    queryFn: () => gatewayApi.getFirewallRules(id!),
    enabled: !!id && activeTab === 'rules',
  });

  const { data: natData, isLoading: natLoading, isError: natError } = useQuery({
    queryKey: ['gateways', id, 'nat-rules'],
    queryFn: () => gatewayApi.getNATRules(id!),
    enabled: !!id && activeTab === 'nat',
  });

  const { data: portFwdData, isLoading: portFwdLoading } = useQuery({
    queryKey: ['gateways', id, 'port-forwards'],
    queryFn: () => gatewayApi.getPortForwards(id!),
    enabled: !!id && activeTab === 'nat',
  });

  const { data: vpnData, isLoading: vpnLoading, isError: vpnError } = useQuery({
    queryKey: ['gateways', id, 'vpn'],
    queryFn: () => gatewayApi.getVPN(id!),
    enabled: !!id && activeTab === 'vpn',
  });

  const { data: wireguardData, isLoading: wgLoading, isError: wgError } = useQuery({
    queryKey: ['gateways', id, 'wireguard'],
    queryFn: () => gatewayApi.getWireGuard(id!),
    enabled: !!id && activeTab === 'vpn',
  });

  const { data: openvpnData, isLoading: ovpnLoading } = useQuery({
    queryKey: ['gateways', id, 'openvpn'],
    queryFn: () => gatewayApi.getOpenVPN(id!),
    enabled: !!id && activeTab === 'vpn',
  });

  const { data: ipsecData, isLoading: ipsecLoading } = useQuery({
    queryKey: ['gateways', id, 'ipsec'],
    queryFn: () => gatewayApi.getIPsec(id!),
    enabled: !!id && activeTab === 'vpn',
  });

  const { data: interfacesData, isLoading: interfacesLoading, isError: interfacesError } = useQuery({
    queryKey: ['gateways', id, 'interfaces'],
    queryFn: () => gatewayApi.getInterfaces(id!),
    enabled: !!id && activeTab === 'interfaces',
  });

  const { data: dhcpData, isLoading: dhcpLoading, isError: dhcpError } = useQuery({
    queryKey: ['gateways', id, 'dhcp'],
    queryFn: () => gatewayApi.getDHCP(id!),
    enabled: !!id && activeTab === 'dhcp',
  });

  const { data: dhcpStaticData, isLoading: dhcpStaticLoading } = useQuery({
    queryKey: ['gateways', id, 'dhcp-static'],
    queryFn: () => gatewayApi.getDHCPStaticMappings(id!),
    enabled: !!id && activeTab === 'dhcp',
  });

  const { data: dnsOverridesData, isLoading: dnsOvLoading, isError: dnsOvError } = useQuery({
    queryKey: ['gateways', id, 'dns-overrides'],
    queryFn: () => gatewayApi.getDNSOverrides(id!),
    enabled: !!id && activeTab === 'dns',
  });

  const { data: dnsDomainData, isLoading: dnsDomLoading } = useQuery({
    queryKey: ['gateways', id, 'dns-domain-overrides'],
    queryFn: () => gatewayApi.getDNSDomainOverrides(id!),
    enabled: !!id && activeTab === 'dns',
  });

  const { data: aliasesData, isLoading: aliasesLoading, isError: aliasesError } = useQuery({
    queryKey: ['gateways', id, 'aliases'],
    queryFn: () => gatewayApi.getAliases(id!),
    enabled: !!id && activeTab === 'aliases',
  });

  const { data: staticRoutesData, isLoading: routesLoading, isError: routesError } = useQuery({
    queryKey: ['gateways', id, 'static-routes'],
    queryFn: () => gatewayApi.getStaticRoutes(id!),
    enabled: !!id && activeTab === 'routing',
  });

  const { data: routingTableData, isLoading: rtLoading } = useQuery({
    queryKey: ['gateways', id, 'routing-table'],
    queryFn: () => gatewayApi.getRoutingTable(id!),
    enabled: !!id && activeTab === 'routing',
  });

  const { data: arpData, isLoading: arpLoading } = useQuery({
    queryKey: ['gateways', id, 'arp'],
    queryFn: () => gatewayApi.getARPTable(id!),
    enabled: !!id && activeTab === 'routing',
  });

  const { data: idsSettingsData } = useQuery({
    queryKey: ['gateways', id, 'ids-settings'],
    queryFn: () => gatewayApi.getIDSSettings(id!),
    enabled: !!id && activeTab === 'ids',
  });

  const { data: idsAlertsData, isLoading: idsAlertsLoading, isError: idsAlertsError } = useQuery({
    queryKey: ['gateways', id, 'ids-alerts'],
    queryFn: () => gatewayApi.getIDSAlerts(id!, { limit: 500 }),
    enabled: !!id && activeTab === 'ids',
  });

  const { data: shaperPipesData, isLoading: shaperLoading } = useQuery({
    queryKey: ['gateways', id, 'shaper-pipes'],
    queryFn: () => gatewayApi.getShaperPipes(id!),
    enabled: !!id && activeTab === 'shaper',
  });

  const { data: shaperQueuesData } = useQuery({
    queryKey: ['gateways', id, 'shaper-queues'],
    queryFn: () => gatewayApi.getShaperQueues(id!),
    enabled: !!id && activeTab === 'shaper',
  });

  const { data: shaperRulesData } = useQuery({
    queryKey: ['gateways', id, 'shaper-rules'],
    queryFn: () => gatewayApi.getShaperRules(id!),
    enabled: !!id && activeTab === 'shaper',
  });

  const { data: servicesData, isLoading: servicesLoading, isError: servicesError } = useQuery({
    queryKey: ['gateways', id, 'services'],
    queryFn: () => gatewayApi.getServices(id!),
    enabled: !!id && activeTab === 'services',
  });

  const { data: backupsData, isLoading: backupsLoading, isError: backupsErrorFlag } = useQuery({
    queryKey: ['gateways', id, 'backups'],
    queryFn: () => gatewayApi.getBackups(id!),
    enabled: !!id && activeTab === 'backups',
  });

  const { data: firmwareData } = useQuery({
    queryKey: ['gateways', id, 'firmware'],
    queryFn: () => gatewayApi.getFirmware(id!),
    enabled: !!id && activeTab === 'overview',
  });

  const { data: healthData } = useQuery({
    queryKey: ['gateways', id, 'health'],
    queryFn: () => gatewayApi.getGatewayHealth(id!),
    enabled: !!id && activeTab === 'overview',
    refetchInterval: 30_000,
  });

  const { data: sysLogData, isLoading: sysLogLoading } = useQuery({
    queryKey: ['gateways', id, 'logs-system'],
    queryFn: () => gatewayApi.getSystemLog(id!, { limit: 200 }),
    enabled: !!id && activeTab === 'logs',
  });

  const { data: fwLogData, isLoading: fwLogLoading } = useQuery({
    queryKey: ['gateways', id, 'logs-firewall'],
    queryFn: () => gatewayApi.getFirewallLog(id!, { limit: 200 }),
    enabled: !!id && activeTab === 'logs',
  });

  const { data: syncLogsData, isLoading: syncLogsLoading } = useQuery({
    queryKey: ['gateways', id, 'sync-logs'],
    queryFn: () => gatewayApi.getSyncLogs(id!, { limit: 50 }),
    enabled: !!id && activeTab === 'sync',
  });

  // ─── Enterprise queries ───────────────────────────────────────────

  const { data: ndpData, isLoading: ndpLoading } = useQuery({
    queryKey: ['gateways', id, 'ndp'],
    queryFn: () => gatewayApi.getNDPTable(id!),
    enabled: !!id && activeTab === 'interfaces',
  });

  const { data: vipData, isLoading: vipLoading } = useQuery({
    queryKey: ['gateways', id, 'vips'],
    queryFn: () => gatewayApi.getVIPStatus(id!),
    enabled: !!id && activeTab === 'interfaces',
  });

  const { data: wgHandshakesData } = useQuery({
    queryKey: ['gateways', id, 'wg-handshakes'],
    queryFn: () => gatewayApi.getWireGuardHandshakes(id!),
    enabled: !!id && activeTab === 'vpn',
  });

  const { data: _ovpnSessionsData } = useQuery({
    queryKey: ['gateways', id, 'ovpn-sessions'],
    queryFn: () => gatewayApi.getOpenVPNSessions(id!),
    enabled: !!id && activeTab === 'vpn',
  });

  const { data: ipsecStatusData } = useQuery({
    queryKey: ['gateways', id, 'ipsec-status'],
    queryFn: () => gatewayApi.getIPsecStatus(id!),
    enabled: !!id && activeTab === 'vpn',
  });

  const { data: unboundStatusData } = useQuery({
    queryKey: ['gateways', id, 'unbound-status'],
    queryFn: () => gatewayApi.getUnboundStatus(id!),
    enabled: !!id && activeTab === 'dns',
  });

  const { data: tailscaleData, isLoading: tailscaleLoading } = useQuery({
    queryKey: ['gateways', id, 'tailscale'],
    queryFn: () => gatewayApi.getTailscaleStatus(id!),
    enabled: !!id && activeTab === 'vpn',
  });

  const { data: vlanDevicesData, isLoading: vlanDevicesLoading } = useQuery({
    queryKey: ['gateways', id, 'vlan-devices'],
    queryFn: () => gatewayApi.getVLANDevices(id!),
    enabled: !!id && activeTab === 'interfaces',
  });

  const { data: laggDevicesData, isLoading: laggDevicesLoading } = useQuery({
    queryKey: ['gateways', id, 'lagg-devices'],
    queryFn: () => gatewayApi.getLAGGDevices(id!),
    enabled: !!id && activeTab === 'interfaces',
  });

  const { data: virtualIpsData, isLoading: virtualIpsLoading } = useQuery({
    queryKey: ['gateways', id, 'virtual-ips'],
    queryFn: () => gatewayApi.getVirtualIPs(id!),
    enabled: !!id && activeTab === 'interfaces',
  });

  // ─── HAProxy (Load Balancer) ────────────────────────────────────────
  const { data: haproxyData, isLoading: haproxyLoading } = useQuery({
    queryKey: ['gateways', id, 'haproxy'],
    queryFn: () => gatewayApi.getHAProxyStatus(id!),
    enabled: !!id && activeTab === 'services',
  });

  // ─── Certificate Management ─────────────────────────────────────────
  const { data: trustData, isLoading: trustLoading } = useQuery({
    queryKey: ['gateways', id, 'trust-overview'],
    queryFn: () => gatewayApi.getTrustOverview(id!),
    enabled: !!id && activeTab === 'system',
  });

  // ─── ACME / Let's Encrypt ──────────────────────────────────────────
  const { data: acmeData, isLoading: acmeLoading } = useQuery({
    queryKey: ['gateways', id, 'acme-overview'],
    queryFn: () => gatewayApi.getACMEOverview(id!),
    enabled: !!id && activeTab === 'system',
  });

  // ─── Syslog Forwarding ─────────────────────────────────────────────
  const { data: syslogData, isLoading: syslogLoading } = useQuery({
    queryKey: ['gateways', id, 'syslog'],
    queryFn: () => gatewayApi.getSyslogDestinations(id!),
    enabled: !!id && activeTab === 'system',
  });

  // ─── Dynamic DNS ───────────────────────────────────────────────────
  const { data: dyndnsData, isLoading: dyndnsLoading } = useQuery({
    queryKey: ['gateways', id, 'dyndns'],
    queryFn: () => gatewayApi.getDynDNSAccounts(id!),
    enabled: !!id && activeTab === 'dns',
  });

  // ─── Captive Portal ───────────────────────────────────────────────
  const { data: captivePortalData, isLoading: captivePortalLoading } = useQuery({
    queryKey: ['gateways', id, 'captive-portal'],
    queryFn: () => gatewayApi.getCaptivePortalZones(id!),
    enabled: !!id && activeTab === 'services',
  });

  // ─── HA / Config Sync ─────────────────────────────────────────────
  const { data: haStatusData, isLoading: haStatusLoading } = useQuery({
    queryKey: ['gateways', id, 'ha-status'],
    queryFn: () => gatewayApi.getHAStatus(id!),
    enabled: !!id && activeTab === 'system',
  });

  // ─── Kea DHCP ─────────────────────────────────────────────────────
  const { data: keaSubnetsData, isLoading: keaSubnetsLoading } = useQuery({
    queryKey: ['gateways', id, 'kea-dhcpv4-subnets'],
    queryFn: () => gatewayApi.getKeaDHCPv4Subnets(id!),
    enabled: !!id && activeTab === 'dhcp',
  });

  const { data: keaLeasesData, isLoading: keaLeasesLoading, isError: keaLeasesError } = useQuery({
    queryKey: ['gateways', id, 'kea-dhcpv4-leases'],
    queryFn: () => gatewayApi.getKeaDHCPv4Leases(id!),
    enabled: !!id && activeTab === 'dhcp',
  });

  const { data: idsRulesetsData } = useQuery({
    queryKey: ['gateways', id, 'ids-rulesets'],
    queryFn: () => gatewayApi.getIDSRulesets(id!),
    enabled: !!id && activeTab === 'ids',
  });

  const { data: idsRulesData, isLoading: idsRulesLoading } = useQuery({
    queryKey: ['gateways', id, 'ids-rules'],
    queryFn: () => gatewayApi.getIDSRules(id!),
    enabled: !!id && activeTab === 'ids',
  });

  const { data: idsStatusData } = useQuery({
    queryKey: ['gateways', id, 'ids-status'],
    queryFn: () => gatewayApi.getIDSStatus(id!),
    enabled: !!id && activeTab === 'ids',
  });

  const { data: packagesData, isLoading: packagesLoading } = useQuery({
    queryKey: ['gateways', id, 'packages'],
    queryFn: () => gatewayApi.getInstalledPackages(id!),
    enabled: !!id && activeTab === 'system',
  });

  const { data: pluginsData } = useQuery({
    queryKey: ['gateways', id, 'plugins'],
    queryFn: () => gatewayApi.getInstalledPlugins(id!),
    enabled: !!id && activeTab === 'system',
  });

  const { data: cronData, isLoading: cronLoading } = useQuery({
    queryKey: ['gateways', id, 'cron-jobs'],
    queryFn: () => gatewayApi.getCronJobs(id!),
    enabled: !!id && activeTab === 'system',
  });

  const { data: connectionsData, isLoading: connectionsLoading } = useQuery({
    queryKey: ['gateways', id, 'connections'],
    queryFn: () => gatewayApi.getConnections(id!),
    enabled: !!id && activeTab === 'diagnostics',
  });

  // Monitoring queries (temperature/disk/traffic/pfInfo) moved into
  // GatewayMonitoringTab · that tab owns its own data fetching.

  // ─── 1:1 NAT ─────────────────────────────────────────────────────
  const { data: oneToOneNatData, isLoading: oneToOneNatLoading } = useQuery({
    queryKey: ['gateways', id, 'onetoone-nat'],
    queryFn: () => gatewayApi.getOneToOneNatRules(id!),
    enabled: !!id && activeTab === 'nat',
  });

  // ─── Bridges ──────────────────────────────────────────────────────
  const { data: bridgesData, isLoading: bridgesLoading } = useQuery({
    queryKey: ['gateways', id, 'bridges'],
    queryFn: () => gatewayApi.getBridges(id!),
    enabled: !!id && activeTab === 'interfaces',
  });

  // ─── DHCP Relay ───────────────────────────────────────────────────
  const { data: dhcpRelayData, isLoading: dhcpRelayLoading } = useQuery({
    queryKey: ['gateways', id, 'dhcp-relay'],
    queryFn: () => gatewayApi.getDhcpRelay(id!),
    enabled: !!id && activeTab === 'dhcp',
  });

  // ─── Web Proxy / Squid ────────────────────────────────────────────
  const { data: proxyData, isLoading: proxyLoading } = useQuery({
    queryKey: ['gateways', id, 'proxy'],
    queryFn: () => gatewayApi.getProxySettings(id!),
    enabled: !!id && activeTab === 'services',
  });
  const { data: proxyBlacklistsData, isLoading: proxyBlacklistsLoading } = useQuery({
    queryKey: ['gateways', id, 'proxy-blacklists'],
    queryFn: () => gatewayApi.getProxyBlacklists(id!),
    enabled: !!id && activeTab === 'services',
  });

  // ─── CrowdSec ────────────────────────────────────────────────────
  const { data: crowdsecData, isLoading: crowdsecLoading } = useQuery({
    queryKey: ['gateways', id, 'crowdsec'],
    queryFn: () => gatewayApi.getCrowdSecStatus(id!),
    enabled: !!id && activeTab === 'ids',
  });

  // Telegraf/Monit/NetFlow/HealthCheck queries moved into GatewayMonitoringTab.

  // ─── Cross-cutting: Config Diff ───────────────────────────────────
  const { data: configDiffData, isLoading: configDiffLoading } = useQuery({
    queryKey: ['gateways', id, 'config-diff'],
    queryFn: () => gatewayApi.getConfigDiff(id!),
    enabled: !!id && activeTab === 'backups',
  });

  // ─── Cross-cutting: Certificate Expiry ────────────────────────────
  const { data: certExpiryData, isLoading: certExpiryLoading } = useQuery({
    queryKey: ['gateways', id, 'cert-expiry'],
    queryFn: () => gatewayApi.getCertificateExpiry(id!, 30),
    enabled: !!id && activeTab === 'system',
  });

  // ─── Mutations ────────────────────────────────────────────────────

  const testMutation = useMutation({
    mutationFn: () => gatewayApi.testExisting(id!),
    onSuccess: (res) => {
      const r = res.data;
      if (r.success) {
        toast({ title: t('GatewayDetailPage.toasts.connectionOk'), description: `${r.hostname || gw?.host} · ${r.version || ''} (${r.latency_ms}ms)` });
      } else {
        toast({ title: t('GatewayDetailPage.toasts.connectionFailed'), description: r.message, variant: 'destructive' });
      }
      queryClient.invalidateQueries({ queryKey: ['gateways', id] });
    },
    onError: (err: any) => {
      toast({ title: t('GatewayDetailPage.toasts.error'), description: err?.response?.data?.detail || t('GatewayDetailPage.toasts.testFailed'), variant: 'destructive' });
    },
  });

  const syncMutation = useMutation({
    mutationFn: () => gatewayApi.triggerSync(id!, true),
    onSuccess: () => {
      toast({ title: t('GatewayDetailPage.toasts.syncTriggered'), description: t('GatewayDetailPage.toasts.syncTriggeredDesc') });
      queryClient.invalidateQueries({ queryKey: ['gateways', id] });
    },
    onError: (err: any) => {
      toast({ title: t('GatewayDetailPage.toasts.syncFailed'), description: err?.response?.data?.detail || t('GatewayDetailPage.toasts.syncFailedDesc'), variant: 'destructive' });
    },
  });

  // Generic write helper with toast + invalidation
  const writeOp = (
    mutationFn: () => Promise<any>,
    successMsg: string,
    invalidateKeys: string[],
  ) => {
    mutationFn()
      .then((res) => {
        const r: GatewayWriteResponse = res.data;
        if (r.success) {
          toast({ title: successMsg, description: r.message });
        } else {
          toast({ title: t('GatewayDetailPage.toasts.operationFailed'), description: r.message, variant: 'destructive' });
        }
        invalidateKeys.forEach((k) =>
          queryClient.invalidateQueries({ queryKey: ['gateways', id, k] }),
        );
      })
      .catch((err: any) => {
        toast({ title: t('GatewayDetailPage.toasts.error'), description: err?.response?.data?.detail || t('GatewayDetailPage.toasts.requestFailed'), variant: 'destructive' });
      });
  };

  const serviceControlMutation = useMutation({
    mutationFn: ({ serviceName, action }: { serviceName: string; action: 'start' | 'stop' | 'restart' }) =>
      gatewayApi.controlService(id!, serviceName, { action }),
    onSuccess: (res) => {
      const r: GatewayWriteResponse = res.data;
      toast({ title: r.success ? t('GatewayDetailPage.toasts.serviceUpdated') : t('GatewayDetailPage.toasts.failed'), description: r.message, variant: r.success ? 'default' : 'destructive' });
      queryClient.invalidateQueries({ queryKey: ['gateways', id, 'services'] });
    },
    onError: (err: any) => {
      toast({ title: t('GatewayDetailPage.toasts.error'), description: err?.response?.data?.detail || t('GatewayDetailPage.toasts.serviceControlFailed'), variant: 'destructive' });
    },
  });

  const backupMutation = useMutation({
    mutationFn: () => gatewayApi.createBackup(id!),
    onSuccess: () => {
      toast({ title: t('GatewayDetailPage.toasts.backupCreated') });
      queryClient.invalidateQueries({ queryKey: ['gateways', id, 'backups'] });
    },
    onError: (err: any) => {
      toast({ title: t('GatewayDetailPage.toasts.backupFailed'), description: err?.response?.data?.detail || t('GatewayDetailPage.toasts.error'), variant: 'destructive' });
    },
  });

  const rebootMutation = useMutation({
    mutationFn: () => gatewayApi.rebootGateway(id!),
    onSuccess: () => {
      toast({ title: t('GatewayDetailPage.toasts.rebootInitiated'), description: t('GatewayDetailPage.toasts.rebootInitiatedDesc') });
      setShowRebootDialog(false);
    },
    onError: (err: any) => {
      toast({ title: t('GatewayDetailPage.toasts.rebootFailed'), description: err?.response?.data?.detail || t('GatewayDetailPage.toasts.error'), variant: 'destructive' });
    },
  });

  // Diagnostic mutations (host is supplied by GatewayDiagnosticsTab via mutate())
  // Toast helper, surface diagnostic failures the same shape as
  // serviceControlMutation so the user sees the exception name + a
  // truncated detail instead of the request silently disappearing.
  const diagnosticErrorToast = (label: string) => (err: any) => {
    const name = err?.name || err?.constructor?.name || 'Error';
    const raw = err?.response?.data?.detail || err?.message || t('GatewayDetailPage.toasts.requestFailed');
    const detail = typeof raw === 'string' ? raw : JSON.stringify(raw);
    const truncated = detail.length > 100 ? `${detail.slice(0, 100)}…` : detail;
    toast({ title: t('GatewayDetailPage.toasts.diagnosticFailed', { label }), description: `${name}: ${truncated}`, variant: 'destructive' });
  };
  const pingMutation = useMutation({
    mutationFn: (host: string) => gatewayApi.runPing(id!, { host, count: 4 }),
    onError: diagnosticErrorToast(t('GatewayDetailPage.diagnostics.ping')),
  });
  const traceMutation = useMutation({
    mutationFn: (host: string) => gatewayApi.runTraceroute(id!, { host }),
    onError: diagnosticErrorToast(t('GatewayDetailPage.diagnostics.traceroute')),
  });
  const dnsLookupMutation = useMutation({
    mutationFn: (host: string) => gatewayApi.runDNSLookup(id!, { hostname: host }),
    onError: diagnosticErrorToast(t('GatewayDetailPage.diagnostics.dnsLookup')),
  });

  // Aggregate isError across the most-used live queries on each tab. When
  // any of them fails we surface a single banner above the tabs so empty
  // tables don't silently hide a failed read.
  const hasQueryError =
    gwError || statusError || rulesError || interfacesError || servicesError ||
    natError || vpnError || wgError || dhcpError || keaLeasesError ||
    dnsOvError || aliasesError || routesError || idsAlertsError || backupsErrorFlag;

  // ─── Loading state ────────────────────────────────────────────────

  if (gwLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-12 w-1/3" />
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-28" />)}
        </div>
        <Skeleton className="h-[400px]" />
      </div>
    );
  }

  if (!gw) {
    return (
      <div className="text-center py-20 space-y-4">
        <AlertCircle className="h-16 w-16 mx-auto text-muted-foreground" />
        <h2 className="text-xl font-semibold">{t('GatewayDetailPage.notFound.title')}</h2>
        <Button variant="outline" onClick={() => navigate('/firewall/gateways')}>
          <ArrowLeft className="h-4 w-4 mr-2" /> {t('GatewayDetailPage.notFound.back')}
        </Button>
      </div>
    );
  }

  // ─── MikroTik render path ─────────────────────────────────────────
  // RouterOS uses a completely different domain layout (no pfSense
  // aliases / IDS / shaper / OpenVPN / etc), so we render a slim
  // 5-tab UI here and return before the pfSense JSX below.
  if (gw.vendor === 'mikrotik') {
    const mtkVendorLabel = vendorLabels[gw.vendor] || gw.vendor;
    const mtkActiveTab = MIKROTIK_TABS.has(activeTab) ? activeTab : 'system';
    return (
      <div className="space-y-6">
        <PageHeader
          icon={Server}
          title={gw.name}
          subtitle={`${t('GatewayDetailPage.header.subtitle', { vendor: mtkVendorLabel, host: gw.host, port: gw.port })}${siteName ? ` · ${siteName}` : ''}`}
          actions={
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={() => navigate('/firewall/gateways')}>
                <ArrowLeft className="h-4 w-4 mr-2" /> {t('GatewayDetailPage.actions.back')}
              </Button>
              <PendingChangesBadge
                vendor={gw.vendor}
                gatewayId={id!}
                open={pendingDrawerOpen}
                onOpenChange={setPendingDrawerOpen}
              />
              <Button
                variant="outline"
                size="sm"
                onClick={() => syncMutation.mutate()}
                disabled={syncMutation.isPending}
              >
                {syncMutation.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <RefreshCw className="h-4 w-4 mr-1" />
                )}
                {t('GatewayDetailPage.actions.sync')}
              </Button>
            </div>
          }
        />
        <PendingChangesDrawer
          open={pendingDrawerOpen}
          onOpenChange={setPendingDrawerOpen}
          vendor={gw.vendor}
          gatewayId={id!}
          gatewayName={gw.name}
        />

        <StatsGrid
          columns={4}
          stats={[
            {
              title: t('GatewayDetailPage.stats.status'),
              value:
                gw.is_online === true
                  ? t('GatewayDetailPage.stats.online')
                  : gw.is_online === false
                    ? t('GatewayDetailPage.stats.offline')
                    : t('GatewayDetailPage.stats.unknown'),
              icon: gw.is_online ? Wifi : WifiOff,
              variant:
                gw.is_online === true
                  ? 'success'
                  : gw.is_online === false
                    ? 'destructive'
                    : 'default',
            },
            {
              title: t('GatewayDetailPage.stats.version'),
              value: gw.detected_version || '-',
              icon: Settings,
              variant: 'primary',
              description: gw.detected_hostname || undefined,
            },
            {
              title: t('GatewayDetailPage.stats.lastSync'),
              value: gw.last_sync_at
                ? new Date(gw.last_sync_at).toLocaleDateString()
                : t('GatewayDetailPage.stats.never'),
              icon: Clock,
              variant: gw.sync_status === 'failed' ? 'destructive' : 'primary',
              description: gw.sync_status,
            },
            {
              title: t('GatewayDetailPage.stats.capabilities'),
              value: gw.capabilities?.length ?? 0,
              icon: Shield,
              variant: 'primary',
              description: gw.capabilities?.slice(0, 3).join(', ') || t('GatewayDetailPage.stats.noneDetected'),
            },
          ]}
        />

        <Tabs value={mtkActiveTab} onValueChange={setActiveTab}>
          <TabsList>
            <TabsTrigger value="system" data-testid="tab-system" onClick={tabClick('system')}>{t('GatewayDetailPage.tabs.system')}</TabsTrigger>
            <TabsTrigger value="interfaces" data-testid="tab-interfaces" onClick={tabClick('interfaces')}>{t('GatewayDetailPage.tabs.interfaces')}</TabsTrigger>
            <TabsTrigger value="ip" data-testid="tab-ip" onClick={tabClick('ip')}>{t('GatewayDetailPage.tabs.ip')}</TabsTrigger>
            <TabsTrigger value="dhcp" data-testid="tab-dhcp" onClick={tabClick('dhcp')}>{t('GatewayDetailPage.tabs.dhcp')}</TabsTrigger>
            <TabsTrigger value="firewall" data-testid="tab-firewall" onClick={tabClick('firewall')}>{t('GatewayDetailPage.tabs.firewall')}</TabsTrigger>
            <TabsTrigger value="dns" data-testid="tab-dns" onClick={tabClick('dns')}>{t('GatewayDetailPage.tabs.dns')}</TabsTrigger>
            <TabsTrigger value="mtk-vpn" data-testid="tab-mtk-vpn" onClick={tabClick('mtk-vpn')}>{t('GatewayDetailPage.tabs.vpn')}</TabsTrigger>
            <TabsTrigger value="hotspot" data-testid="tab-hotspot" onClick={tabClick('hotspot')}>{t('GatewayDetailPage.tabs.hotspot')}</TabsTrigger>
            <TabsTrigger value="queues" data-testid="tab-queues" onClick={tabClick('queues')}>{t('GatewayDetailPage.tabs.queues')}</TabsTrigger>
            <TabsTrigger value="mtk-firmware" data-testid="tab-mtk-firmware" onClick={tabClick('mtk-firmware')}>{t('GatewayDetailPage.tabs.firmware')}</TabsTrigger>
            <TabsTrigger value="mtk-backup" data-testid="tab-mtk-backup" onClick={tabClick('mtk-backup')}>{t('GatewayDetailPage.tabs.backup')}</TabsTrigger>
            <TabsTrigger value="mtk-topology" data-testid="tab-mtk-topology" onClick={tabClick('mtk-topology')}>{t('GatewayDetailPage.tabs.topology')}</TabsTrigger>
            <TabsTrigger value="mtk-snmp" data-testid="tab-mtk-snmp" onClick={tabClick('mtk-snmp')}>{t('GatewayDetailPage.tabs.snmp')}</TabsTrigger>
          </TabsList>

          <TabsContent value="system" className="mt-6">
            <MikroTikSystemTab
              controllerId={id!}
              isActive={mtkActiveTab === 'system'}
              gatewayName={gw.name}
            />
          </TabsContent>
          <TabsContent value="interfaces" className="mt-6">
            <MikroTikInterfacesTab
              controllerId={id!}
              isActive={mtkActiveTab === 'interfaces'}
              gatewayName={gw.name}
            />
          </TabsContent>
          <TabsContent value="ip" className="mt-6">
            <MikroTikIpTab
              controllerId={id!}
              isActive={mtkActiveTab === 'ip'}
              gatewayName={gw.name}
            />
          </TabsContent>
          <TabsContent value="dhcp" className="mt-6">
            <MikroTikDhcpTab
              controllerId={id!}
              isActive={mtkActiveTab === 'dhcp'}
              gatewayName={gw.name}
            />
          </TabsContent>
          <TabsContent value="firewall" className="mt-6">
            <MikroTikFirewallTab
              controllerId={id!}
              isActive={mtkActiveTab === 'firewall'}
              gatewayName={gw.name}
            />
          </TabsContent>
          <TabsContent value="dns" className="mt-6">
            <MikroTikDnsTab
              controllerId={id!}
              isActive={mtkActiveTab === 'dns'}
              gatewayName={gw.name}
            />
          </TabsContent>
          <TabsContent value="mtk-vpn" className="mt-6">
            <MikroTikVpnTab
              controllerId={id!}
              isActive={mtkActiveTab === 'mtk-vpn'}
              gatewayName={gw.name}
            />
          </TabsContent>
          <TabsContent value="hotspot" className="mt-6">
            <MikroTikHotspotTab
              controllerId={id!}
              isActive={mtkActiveTab === 'hotspot'}
              gatewayName={gw.name}
            />
          </TabsContent>
          <TabsContent value="queues" className="mt-6">
            <MikroTikQueuesTab
              controllerId={id!}
              isActive={mtkActiveTab === 'queues'}
              gatewayName={gw.name}
            />
          </TabsContent>
          <TabsContent value="mtk-firmware" className="mt-6">
            <MikroTikFirmwareTab
              controllerId={id!}
              isActive={mtkActiveTab === 'mtk-firmware'}
            />
          </TabsContent>
          <TabsContent value="mtk-backup" className="mt-6">
            <MikroTikBackupTab
              controllerId={id!}
              isActive={mtkActiveTab === 'mtk-backup'}
            />
          </TabsContent>
          <TabsContent value="mtk-topology" className="mt-6">
            <MikroTikTopologyTab
              controllerId={id!}
              isActive={mtkActiveTab === 'mtk-topology'}
            />
          </TabsContent>
          <TabsContent value="mtk-snmp" className="mt-6">
            <MikroTikSnmpTab
              controllerId={id!}
              isActive={mtkActiveTab === 'mtk-snmp'}
            />
          </TabsContent>
        </Tabs>
      </div>
    );
  }

  // ─── OpenWrt render path ──────────────────────────────────────────
  // OpenWrt uses ubus/UCI rather than the pfSense domain model, so
  // we render a dedicated tab here (with its own internal sub-tabs
  // for Overview / Interfaces / Firewall / Port Forwards / DHCP /
  // ARP) and return before the pfSense JSX below.
  if (gw.vendor === 'openwrt') {
    const owrtVendorLabel = vendorLabels[gw.vendor] || gw.vendor;
    return (
      <div className="space-y-6">
        <PageHeader
          icon={Server}
          title={gw.name}
          subtitle={`${t('GatewayDetailPage.header.subtitle', { vendor: owrtVendorLabel, host: gw.host, port: gw.port })}${siteName ? ` · ${siteName}` : ''}`}
          actions={
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={() => navigate('/firewall/gateways')}>
                <ArrowLeft className="h-4 w-4 mr-2" /> {t('GatewayDetailPage.actions.back')}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => syncMutation.mutate()}
                disabled={syncMutation.isPending}
              >
                {syncMutation.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <RefreshCw className="h-4 w-4 mr-1" />
                )}
                {t('GatewayDetailPage.actions.sync')}
              </Button>
            </div>
          }
        />

        <StatsGrid
          columns={4}
          stats={[
            {
              title: t('GatewayDetailPage.stats.status'),
              value:
                gw.is_online === true
                  ? t('GatewayDetailPage.stats.online')
                  : gw.is_online === false
                    ? t('GatewayDetailPage.stats.offline')
                    : t('GatewayDetailPage.stats.unknown'),
              icon: gw.is_online ? Wifi : WifiOff,
              variant:
                gw.is_online === true
                  ? 'success'
                  : gw.is_online === false
                    ? 'destructive'
                    : 'default',
            },
            {
              title: t('GatewayDetailPage.stats.version'),
              value: gw.detected_version || '-',
              icon: Settings,
              variant: 'primary',
              description: gw.detected_hostname || undefined,
            },
            {
              title: t('GatewayDetailPage.stats.lastSync'),
              value: gw.last_sync_at
                ? new Date(gw.last_sync_at).toLocaleDateString()
                : t('GatewayDetailPage.stats.never'),
              icon: Clock,
              variant: gw.sync_status === 'failed' ? 'destructive' : 'primary',
              description: gw.sync_status,
            },
            {
              title: t('GatewayDetailPage.stats.capabilities'),
              value: gw.capabilities?.length ?? 0,
              icon: Shield,
              variant: 'primary',
              description: gw.capabilities?.slice(0, 3).join(', ') || t('GatewayDetailPage.stats.noneDetected'),
            },
          ]}
        />

        <OpenWrtTab controllerId={id!} />
      </div>
    );
  }

  const vendorLabel = vendorLabels[gw.vendor] || gw.vendor;
  const liveStatus = statusData?.data;
  const deviceSummary = deviceSummaryData?.data?.summary ?? {};
  const firmware = firmwareData?.data?.firmware ?? {};
  const gwHealth = healthData?.data?.gateways ?? [];
  const rules = rulesData?.data?.rules ?? [];
  const natRules = natData?.data?.rules ?? [];
  const portForwards = portFwdData?.data?.port_forwards ?? [];
  const vpn = vpnData?.data;
  const wgServers = wireguardData?.data?.servers ?? [];
  const wgPeers = wireguardData?.data?.peers ?? [];
  const ovpnInstances = openvpnData?.data?.instances ?? [];
  const ovpnSessions = openvpnData?.data?.sessions ?? [];
  const ipsecPhase1 = ipsecData?.data?.phase1 ?? [];
  const ipsecPhase2 = ipsecData?.data?.phase2 ?? [];
  const interfaces = interfacesData?.data?.interfaces ?? [];
  const dhcpLeases = dhcpData?.data?.leases ?? [];
  const dhcpStatic = dhcpStaticData?.data?.static_mappings ?? [];
  const dnsOverrides = dnsOverridesData?.data?.overrides ?? [];
  const dnsDomainOverrides = dnsDomainData?.data?.domain_overrides ?? [];
  const aliases = aliasesData?.data?.aliases ?? [];
  const staticRoutes = staticRoutesData?.data?.routes ?? [];
  const routingTable = routingTableData?.data?.routing_table ?? [];
  const arpEntries = arpData?.data?.arp_entries ?? [];
  const idsSettings = idsSettingsData?.data ?? {};
  const idsAlerts = idsAlertsData?.data?.alerts ?? [];
  const shaperPipes = shaperPipesData?.data?.pipes ?? [];
  const shaperQueues = shaperQueuesData?.data?.queues ?? [];
  const shaperRules = shaperRulesData?.data?.rules ?? [];
  const services = servicesData?.data?.services ?? [];
  const backups = backupsData?.data?.backups ?? [];
  const sysLogs = sysLogData?.data?.logs ?? [];
  const fwLogs = fwLogData?.data?.logs ?? [];
  const syncLogs = syncLogsData?.data ?? [];

  // ─── Column definitions ───────────────────────────────────────────

  const syncLogColumns: DataTableColumn<any>[] = [
    { id: 'started', header: t('GatewayDetailPage.syncLogColumns.started'), accessorKey: 'started_at', sortable: true, cell: (r: any) => (
      <span className="text-sm">{new Date(r.started_at).toLocaleString()}</span>
    )},
    { id: 'status', header: t('GatewayDetailPage.syncLogColumns.status'), cell: (r: any) => (
      <Badge variant={r.status === 'success' ? 'default' : r.status === 'failed' ? 'destructive' : 'secondary'}>
        {r.status}
      </Badge>
    )},
    { id: 'duration', header: t('GatewayDetailPage.syncLogColumns.duration'), cell: (r: any) => (
      <span className="text-sm">{r.duration_ms ? `${r.duration_ms}ms` : '-'}</span>
    )},
    { id: 'synced', header: t('GatewayDetailPage.syncLogColumns.itemsSynced'), accessorKey: 'items_synced' },
    { id: 'failed', header: t('GatewayDetailPage.syncLogColumns.failed'), accessorKey: 'items_failed', cell: (r: any) => (
      <span className={cn('text-sm', r.items_failed > 0 && 'text-destructive font-medium')}>{r.items_failed}</span>
    )},
    { id: 'error', header: t('GatewayDetailPage.syncLogColumns.error'), accessorKey: 'error', cell: (r: any) => (
      <span className="text-xs text-muted-foreground truncate max-w-[200px] block">{r.error || '-'}</span>
    )},
  ];

  // ─── Deep integration columns ─────────────────────────────────────

  const logColumns: DataTableColumn<any>[] = [
    { id: 'timestamp', header: t('GatewayDetailPage.logColumns.time'), accessorFn: (r: any) => r.timestamp || r.date || r.__timestamp__ || '-', sortable: true, cell: (r: any) => (
      <span className="text-xs font-mono">{r.timestamp || r.date || '-'}</span>
    )},
    { id: 'process', header: t('GatewayDetailPage.logColumns.process'), accessorFn: (r: any) => r.process_name || r.process || r.facility || '-' },
    { id: 'message', header: t('GatewayDetailPage.logColumns.message'), accessorFn: (r: any) => r.line || r.message || r.msg || '-', cell: (r: any) => (
      <span className="text-xs font-mono max-w-[600px] truncate block">{r.line || r.message || r.msg || '-'}</span>
    )},
  ];

  // ─── Render ───────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        icon={Server}
        title={gw.name}
        subtitle={`${t('GatewayDetailPage.header.subtitle', { vendor: vendorLabel, host: gw.host, port: gw.port })}${siteName ? ` · ${siteName}` : ''}`}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => navigate('/firewall/gateways')}>
              <ArrowLeft className="h-4 w-4 mr-2" /> {t('GatewayDetailPage.actions.back')}
            </Button>
            <PendingChangesBadge
              vendor={gw.vendor}
              gatewayId={id!}
              open={pendingDrawerOpen}
              onOpenChange={setPendingDrawerOpen}
            />
            <Button
              variant="outline"
              size="sm"
              onClick={() => testMutation.mutate()}
              disabled={testMutation.isPending}
            >
              {testMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Zap className="h-4 w-4 mr-1" />}
              {t('GatewayDetailPage.actions.test')}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => syncMutation.mutate()}
              disabled={syncMutation.isPending}
            >
              {syncMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4 mr-1" />}
              {t('GatewayDetailPage.actions.sync')}
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={() => setShowRebootDialog(true)}
            >
              <Power className="h-4 w-4 mr-1" /> {t('GatewayDetailPage.actions.reboot')}
            </Button>
          </div>
        }
      />
      <PendingChangesDrawer
        open={pendingDrawerOpen}
        onOpenChange={setPendingDrawerOpen}
        vendor={gw.vendor}
        gatewayId={id!}
        gatewayName={gw.name}
      />

      {hasQueryError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('GatewayDetailPage.errors.partialLoad')}</span>
          </CardContent>
        </Card>
      )}

      {/* Quick stats */}
      <StatsGrid
        columns={4}
        stats={[
          {
            title: t('GatewayDetailPage.stats.status'),
            value: gw.is_online === true ? t('GatewayDetailPage.stats.online') : gw.is_online === false ? t('GatewayDetailPage.stats.offline') : t('GatewayDetailPage.stats.unknown'),
            icon: gw.is_online ? Wifi : WifiOff,
            variant: gw.is_online === true ? 'success' : gw.is_online === false ? 'destructive' : 'default',
          },
          {
            title: t('GatewayDetailPage.stats.version'),
            value: gw.detected_version || firmware.current_version || deviceSummary.version || '-',
            icon: Settings,
            variant: 'primary',
            description: gw.detected_hostname || deviceSummary.hostname || undefined,
          },
          {
            title: t('GatewayDetailPage.stats.lastSync'),
            value: gw.last_sync_at ? new Date(gw.last_sync_at).toLocaleDateString() : t('GatewayDetailPage.stats.never'),
            icon: Clock,
            variant: gw.sync_status === 'failed' ? 'destructive' : 'primary',
            description: gw.sync_status,
          },
          {
            title: t('GatewayDetailPage.stats.capabilities'),
            value: gw.capabilities?.length ?? 0,
            icon: Shield,
            variant: 'primary',
            description: gw.capabilities?.slice(0, 3).join(', ') || t('GatewayDetailPage.stats.noneDetected'),
          },
        ]}
      />

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview" data-testid="tab-overview" onClick={tabClick('overview')}>{t('GatewayDetailPage.tabs.overview')}</TabsTrigger>
          <TabsTrigger value="rules" data-testid="tab-rules" onClick={tabClick('rules')}>{t('GatewayDetailPage.tabs.firewallRules')}</TabsTrigger>
          <TabsTrigger value="nat" data-testid="tab-nat" onClick={tabClick('nat')}>{t('GatewayDetailPage.tabs.natPortFwd')}</TabsTrigger>
          <TabsTrigger value="vpn" data-testid="tab-vpn" onClick={tabClick('vpn')}>{t('GatewayDetailPage.tabs.vpn')}</TabsTrigger>
          <TabsTrigger value="interfaces" data-testid="tab-interfaces" onClick={tabClick('interfaces')}>{t('GatewayDetailPage.tabs.interfaces')}</TabsTrigger>
          <TabsTrigger value="dhcp" data-testid="tab-dhcp" onClick={tabClick('dhcp')}>{t('GatewayDetailPage.tabs.dhcp')}</TabsTrigger>
          <TabsTrigger value="dns" data-testid="tab-dns" onClick={tabClick('dns')}>{t('GatewayDetailPage.tabs.dns')}</TabsTrigger>
          <TabsTrigger value="aliases" data-testid="tab-aliases" onClick={tabClick('aliases')}>{t('GatewayDetailPage.tabs.aliases')}</TabsTrigger>
          <TabsTrigger value="routing" data-testid="tab-routing" onClick={tabClick('routing')}>{t('GatewayDetailPage.tabs.routingArp')}</TabsTrigger>
          <TabsTrigger value="ids" data-testid="tab-ids" onClick={tabClick('ids')}>{t('GatewayDetailPage.tabs.idsIps')}</TabsTrigger>
          <TabsTrigger value="shaper" data-testid="tab-shaper" onClick={tabClick('shaper')}>{t('GatewayDetailPage.tabs.trafficShaper')}</TabsTrigger>
          <TabsTrigger value="services" data-testid="tab-services" onClick={tabClick('services')}>{t('GatewayDetailPage.tabs.services')}</TabsTrigger>
          <TabsTrigger value="backups" data-testid="tab-backups" onClick={tabClick('backups')}>{t('GatewayDetailPage.tabs.backups')}</TabsTrigger>
          <TabsTrigger value="system" data-testid="tab-system" onClick={tabClick('system')}>{t('GatewayDetailPage.tabs.system')}</TabsTrigger>
          <TabsTrigger value="monitoring" data-testid="tab-monitoring" onClick={tabClick('monitoring')}>{t('GatewayDetailPage.tabs.monitoring')}</TabsTrigger>
          <TabsTrigger value="diagnostics" data-testid="tab-diagnostics" onClick={tabClick('diagnostics')}>{t('GatewayDetailPage.tabs.diagnostics')}</TabsTrigger>
          <TabsTrigger value="logs" data-testid="tab-logs" onClick={tabClick('logs')}>{t('GatewayDetailPage.tabs.logs')}</TabsTrigger>
          <TabsTrigger value="sync" data-testid="tab-sync" onClick={tabClick('sync')}>{t('GatewayDetailPage.tabs.syncLog')}</TabsTrigger>
        </TabsList>

        {/* ─── Overview Tab ─────────────────────────────────────────── */}
        <TabsContent value="overview" className="mt-6 space-y-6">
          <GatewayOverviewTab
            gw={gw}
            vendorLabel={vendorLabel}
            deviceSummary={deviceSummary}
            firmware={firmware}
            gwHealth={gwHealth}
            liveStatus={liveStatus}
          />
        </TabsContent>

        {/* ─── Firewall Rules Tab ───────────────────────────────────── */}
        <TabsContent value="rules" className="mt-6">
          <GatewayRulesTab
            rules={rules}
            rulesLoading={rulesLoading}
            vendorLabel={vendorLabel}
            onAddRule={() => setShowRuleForm(true)}
            onDeleteRule={(r, vid) => openDelete(t('GatewayDetailPage.resources.firewallRule'), r.description || vid, () => gatewayApi.deleteVendorRule(id!, vid), ['firewall-rules'])}
          />
        </TabsContent>

        {/* ─── NAT / Port Forwards Tab ──────────────────────────────── */}
        <TabsContent value="nat" className="mt-6 space-y-6">
          <GatewayNatTab
            natRules={natRules}
            natLoading={natLoading}
            portForwards={portForwards}
            portFwdLoading={portFwdLoading}
            oneToOneNatData={oneToOneNatData}
            oneToOneNatLoading={oneToOneNatLoading}
            onAddSourceNat={() => setShowSnatForm(true)}
            onAddPortForward={() => { setEditingPortFwd(null); setShowPortFwdForm(true); }}
            onEditPortForward={(r) => { setEditingPortFwd(r); setShowPortFwdForm(true); }}
            onDeleteNatRule={(r, vid) => openDelete(t('GatewayDetailPage.resources.natRule'), r.description || vid, () => gatewayApi.deleteSourceNATRule(id!, vid), ['nat-rules'])}
            onDeletePortForward={(r, vid) => openDelete(t('GatewayDetailPage.resources.portForward'), r.description || vid, () => gatewayApi.deletePortForward(id!, vid), ['port-forwards'])}
          />
        </TabsContent>

        {/* ─── VPN Tab (WireGuard + OpenVPN + IPsec) ────────────────── */}
        <TabsContent value="vpn" className="mt-6 space-y-6">
          <GatewayVpnTab
            wgServers={wgServers}
            wgPeers={wgPeers}
            wgLoading={wgLoading}
            wgHandshakesData={wgHandshakesData}
            onAddWgServer={() => setShowWgServerForm(true)}
            onAddWgPeer={() => setShowWgPeerForm(true)}
            onDeleteWgServer={(r, vid) => openDelete(t('GatewayDetailPage.resources.wireguardServer'), r.name || vid, () => gatewayApi.deleteWireGuardServer(id!, vid), ['wireguard'])}
            onDeleteWgPeer={(r, vid) => openDelete(t('GatewayDetailPage.resources.wireguardPeer'), r.name || vid, () => gatewayApi.deleteWireGuardPeer(id!, vid), ['wireguard'])}
            ovpnInstances={ovpnInstances}
            ovpnSessions={ovpnSessions}
            ovpnLoading={ovpnLoading}
            onAddOvpn={() => setShowOvpnForm(true)}
            onDeleteOvpnInstance={(inst) => openDelete(t('GatewayDetailPage.resources.openvpnInstance'), inst.description || inst.name || '', () => gatewayApi.deleteOpenVPNInstance(id!, inst.uuid || inst.id), ['openvpn'])}
            onKillOvpnSession={(s) => writeOp(() => gatewayApi.killOpenVPNSession(id!, s.id || s.common_name), t('GatewayDetailPage.success.sessionKilled'), ['openvpn'])}
            ipsecPhase1={ipsecPhase1}
            ipsecPhase2={ipsecPhase2}
            ipsecLoading={ipsecLoading}
            ipsecStatusData={ipsecStatusData}
            onApplyIpsec={() => writeOp(() => gatewayApi.applyIPsecChanges(id!), t('GatewayDetailPage.success.ipsecApplied'), ['ipsec', 'ipsec-status'])}
            onConnectIpsec={(vid) => writeOp(() => gatewayApi.connectIPsecTunnel(id!, vid), t('GatewayDetailPage.success.tunnelConnected'), ['ipsec'])}
            onDisconnectIpsec={(vid) => writeOp(() => gatewayApi.disconnectIPsecTunnel(id!, vid), t('GatewayDetailPage.success.tunnelDisconnected'), ['ipsec'])}
            tailscaleData={tailscaleData}
            tailscaleLoading={tailscaleLoading}
            vpn={vpn}
            vpnLoading={vpnLoading}
          />
        </TabsContent>

        {/* ─── Interfaces Tab ───────────────────────────────────────── */}
        <TabsContent value="interfaces" className="mt-6 space-y-6">
          <GatewayInterfacesTab
            interfaces={interfaces}
            interfacesLoading={interfacesLoading}
            vlanDevicesData={vlanDevicesData}
            vlanDevicesLoading={vlanDevicesLoading}
            laggDevicesData={laggDevicesData}
            laggDevicesLoading={laggDevicesLoading}
            virtualIpsData={virtualIpsData}
            virtualIpsLoading={virtualIpsLoading}
            vipData={vipData}
            vipLoading={vipLoading}
            ndpData={ndpData}
            ndpLoading={ndpLoading}
            bridgesData={bridgesData}
            bridgesLoading={bridgesLoading}
            onFlushArp={() => writeOp(() => gatewayApi.flushARPTable(id!), t('GatewayDetailPage.success.arpFlushed'), ['arp'])}
          />
        </TabsContent>

        {/* ─── DHCP Tab ─────────────────────────────────────────────── */}
        <TabsContent value="dhcp" className="mt-6 space-y-6">
          <GatewayDhcpTab
            dhcpLeases={dhcpLeases}
            dhcpLoading={dhcpLoading}
            dhcpStatic={dhcpStatic}
            dhcpStaticLoading={dhcpStaticLoading}
            keaSubnetsData={keaSubnetsData}
            keaSubnetsLoading={keaSubnetsLoading}
            keaLeasesData={keaLeasesData}
            keaLeasesLoading={keaLeasesLoading}
            dhcpRelayData={dhcpRelayData}
            dhcpRelayLoading={dhcpRelayLoading}
            onAddStatic={() => { setEditingDhcpStatic(null); setShowDhcpStaticForm(true); }}
            onEditStatic={(r) => { setEditingDhcpStatic(r); setShowDhcpStaticForm(true); }}
            onDeleteStatic={(r, vid) => openDelete(t('GatewayDetailPage.resources.staticMapping'), `${r.mac} → ${r.ipaddr || r.ip}`, () => gatewayApi.deleteDHCPStaticMapping(id!, vid), ['dhcp-static'])}
          />
        </TabsContent>

        {/* ─── DNS Tab ──────────────────────────────────────────────── */}
        <TabsContent value="dns" className="mt-6 space-y-6">
          <GatewayDnsTab
            unboundStatusData={unboundStatusData}
            dnsOverrides={dnsOverrides}
            dnsOvLoading={dnsOvLoading}
            dnsDomainOverrides={dnsDomainOverrides}
            dnsDomLoading={dnsDomLoading}
            dyndnsData={dyndnsData}
            dyndnsLoading={dyndnsLoading}
            onAddOverride={() => { setEditingDns(null); setShowDnsForm(true); }}
            onEditOverride={(r) => { setEditingDns(r); setShowDnsForm(true); }}
            onDeleteOverride={(r, vid) => openDelete(t('GatewayDetailPage.resources.dnsOverride'), `${r.host}.${r.domain}`, () => gatewayApi.deleteDNSOverride(id!, vid), ['dns-overrides'])}
            onAddDomain={() => { setEditingDnsDomain(null); setShowDnsDomainForm(true); }}
            onEditDomain={(r) => { setEditingDnsDomain(r); setShowDnsDomainForm(true); }}
            onDeleteDomain={(r, vid) => openDelete(t('GatewayDetailPage.resources.domainOverride'), r.domain, () => gatewayApi.deleteDNSDomainOverride(id!, vid), ['dns-domain-overrides'])}
          />
        </TabsContent>

        {/* ─── Aliases Tab ──────────────────────────────────────────── */}
        <TabsContent value="aliases" className="mt-6">
          <GatewayAliasesTab
            aliases={aliases}
            aliasesLoading={aliasesLoading}
            onAddAlias={() => { setEditingAlias(null); setShowAliasForm(true); }}
            onEditAlias={(r) => { setEditingAlias(r); setShowAliasForm(true); }}
            onDeleteAlias={(r, vid) => openDelete(t('GatewayDetailPage.resources.alias'), r.name, () => gatewayApi.deleteAlias(id!, vid), ['aliases'])}
          />
        </TabsContent>

        {/* ─── Routing / ARP Tab ────────────────────────────────────── */}
        <TabsContent value="routing" className="mt-6 space-y-6">
          <GatewayRoutingTab
            staticRoutes={staticRoutes}
            routesLoading={routesLoading}
            routingTable={routingTable}
            rtLoading={rtLoading}
            arpEntries={arpEntries}
            arpLoading={arpLoading}
            onAddRoute={() => setShowRouteForm(true)}
            onDeleteRoute={(r, vid) => openDelete(t('GatewayDetailPage.resources.staticRoute'), r.network, () => gatewayApi.deleteStaticRoute(id!, vid), ['static-routes', 'routing-table'])}
          />
        </TabsContent>

        {/* ─── IDS / IPS Tab ────────────────────────────────────────── */}
        <TabsContent value="ids" className="mt-6 space-y-6">
          <GatewayIdsTab
            idsStatusData={idsStatusData}
            idsSettings={idsSettings}
            idsAlerts={idsAlerts}
            idsAlertsLoading={idsAlertsLoading}
            idsRulesetsData={idsRulesetsData}
            idsRulesData={idsRulesData}
            idsRulesLoading={idsRulesLoading}
            crowdsecData={crowdsecData}
            crowdsecLoading={crowdsecLoading}
            onControl={(action) => {
              const msgMap: Record<string, string> = {
                start: t('GatewayDetailPage.success.idsStarted'),
                stop: t('GatewayDetailPage.success.idsStopped'),
                restart: t('GatewayDetailPage.success.idsRestarted'),
                'update-rules': t('GatewayDetailPage.success.idsRulesUpdated'),
              };
              const keys = action === 'update-rules' ? ['ids-rulesets', 'ids-rules'] : ['ids-status'];
              writeOp(() => gatewayApi.controlIDS(id!, { action }), msgMap[action], keys);
            }}
            onEditSettings={() => setShowIdsSettings(true)}
            onClearAlerts={() => writeOp(() => gatewayApi.dropIDSAlertLog(id!), t('GatewayDetailPage.success.alertLogCleared'), ['ids-alerts'])}
            onToggleRule={(sid) => writeOp(() => gatewayApi.toggleIDSRule(id!, sid), t('GatewayDetailPage.success.ruleToggled'), ['ids-rules'])}
          />
        </TabsContent>

        {/* ─── Traffic Shaper Tab ───────────────────────────────────── */}
        <TabsContent value="shaper" className="mt-6 space-y-6">
          <GatewayShaperTab
            shaperPipes={shaperPipes}
            shaperLoading={shaperLoading}
            shaperQueues={shaperQueues}
            shaperRules={shaperRules}
            onAddPipe={() => setShowPipeForm(true)}
            onDeletePipe={(r, vid) => openDelete(t('GatewayDetailPage.resources.shaperPipe'), r.description || vid, () => gatewayApi.deleteShaperPipe(id!, vid), ['shaper-pipes'])}
            onAddQueue={() => writeOp(() => gatewayApi.createShaperQueue(id!, { description: 'New Queue', weight: 100, enabled: true }), t('GatewayDetailPage.success.queueCreated'), ['shaper-queues'])}
            onDeleteQueue={(r, vid) => openDelete(t('GatewayDetailPage.resources.queue'), r.description || vid, () => gatewayApi.deleteShaperQueue(id!, vid), ['shaper-queues'])}
            onAddRule={() => writeOp(() => gatewayApi.createShaperRule(id!, { description: 'New Rule', sequence: 1, enabled: true }), t('GatewayDetailPage.success.ruleCreated'), ['shaper-rules'])}
            onDeleteRule={(r, vid) => openDelete(t('GatewayDetailPage.resources.rule'), r.description || vid, () => gatewayApi.deleteShaperRule(id!, vid), ['shaper-rules'])}
          />
        </TabsContent>

        {/* ─── Services Tab · extracted to GatewayServicesTab ─── */}
        <TabsContent value="services" className="mt-6 space-y-6">
          <GatewayServicesTab
            vendorLabel={vendorLabel}
            haproxyData={haproxyData}
            haproxyLoading={haproxyLoading}
            captivePortalData={captivePortalData}
            captivePortalLoading={captivePortalLoading}
            services={services}
            servicesLoading={servicesLoading}
            onServiceAction={(serviceName, action) =>
              serviceControlMutation.mutate({ serviceName, action })
            }
            serviceActionPending={serviceControlMutation.isPending}
            proxyData={proxyData}
            proxyLoading={proxyLoading}
            proxyBlacklistsData={proxyBlacklistsData}
            proxyBlacklistsLoading={proxyBlacklistsLoading}
          />
        </TabsContent>

        {/* ─── Backups Tab ──────────────────────────────────────────── */}
        <TabsContent value="backups" className="mt-6 space-y-6">
          <GatewayBackupsTab
            backups={backups}
            backupsLoading={backupsLoading}
            onCreateBackup={() => backupMutation.mutate()}
            isCreating={backupMutation.isPending}
            onRevertBackup={(filename) => writeOp(() => gatewayApi.revertBackup(id!, filename), t('GatewayDetailPage.success.backupReverted'), ['backups'])}
            onDeleteBackup={(filename) => openDelete(t('GatewayDetailPage.resources.backup'), filename || '', () => gatewayApi.deleteBackup(id!, filename), ['backups'])}
            onDownloadConfig={() => writeOp(() => gatewayApi.downloadConfig(id!), t('GatewayDetailPage.success.configDownloaded'), [])}
            configDiffData={configDiffData}
            configDiffLoading={configDiffLoading}
          />
        </TabsContent>

        {/* ─── Diagnostics Tab ──────────────────────────────────────── */}
        <TabsContent value="diagnostics" className="mt-6 space-y-6">
          <GatewayDiagnosticsTab
            ping={pingMutation}
            traceroute={traceMutation}
            dnsLookup={dnsLookupMutation}
            connectionsData={connectionsData}
            connectionsLoading={connectionsLoading}
          />
        </TabsContent>

        {/* ─── Logs Tab ─────────────────────────────────────────────── */}
        <TabsContent value="logs" className="mt-6">
          <GatewayLogsTab
            fwLogs={fwLogs}
            fwLogLoading={fwLogLoading}
            sysLogs={sysLogs}
            sysLogLoading={sysLogLoading}
            logColumns={logColumns}
          />
        </TabsContent>

        {/* ─── Sync Log Tab ─────────────────────────────────────────── */}
        <TabsContent value="sync" className="mt-6">
          <GatewaySyncTab
            syncLogs={syncLogs}
            syncLogsLoading={syncLogsLoading}
            syncLogColumns={syncLogColumns}
            onSync={() => syncMutation.mutate()}
            isSyncing={syncMutation.isPending}
          />
        </TabsContent>

        {/* ─── System Tab · extracted to GatewaySystemTab ─── */}
        <TabsContent value="system" className="mt-6 space-y-6">
          <GatewaySystemTab
            packagesData={packagesData}
            packagesLoading={packagesLoading}
            pluginsData={pluginsData}
            cronData={cronData}
            cronLoading={cronLoading}
            trustData={trustData}
            trustLoading={trustLoading}
            acmeData={acmeData}
            acmeLoading={acmeLoading}
            syslogData={syslogData}
            syslogLoading={syslogLoading}
            haStatusData={haStatusData}
            haStatusLoading={haStatusLoading}
            certExpiryData={certExpiryData}
            certExpiryLoading={certExpiryLoading}
            onCheckUpdates={() => writeOp(() => gatewayApi.firmwareCheck(id!), t('GatewayDetailPage.success.firmwareCheckComplete'), ['firmware'])}
            onDownloadConfig={() => writeOp(() => gatewayApi.downloadConfig(id!), t('GatewayDetailPage.success.configDownloaded'), [])}
            onHaltGateway={() => writeOp(() => gatewayApi.haltGateway(id!), t('GatewayDetailPage.success.gatewayHalted'), [])}
          />
        </TabsContent>

        {/* ─── Monitoring Tab · extracted to GatewayMonitoringTab ─── */}
        <TabsContent value="monitoring" className="mt-6 space-y-6">
          <GatewayMonitoringTab gatewayId={id || ''} isActive={activeTab === 'monitoring'} />
        </TabsContent>

      </Tabs>

      {/* Reboot Confirmation Dialog */}
      <AlertDialog open={showRebootDialog} onOpenChange={setShowRebootDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('GatewayDetailPage.rebootDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('GatewayDetailPage.rebootDialog.intro')} <strong>{gw.name}</strong> {t('GatewayDetailPage.rebootDialog.target', { vendor: vendorLabel, host: gw.host })}
              {' '}{t('GatewayDetailPage.rebootDialog.warning')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('GatewayDetailPage.actions.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => rebootMutation.mutate()}
              disabled={rebootMutation.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {rebootMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Power className="h-4 w-4 mr-2" />}
              {t('GatewayDetailPage.actions.rebootNow')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ─── CRUD Dialogs ────────────────────────────────────────────── */}
      <DeleteResourceDialog
        open={deleteDialog.open}
        onOpenChange={(o) => setDeleteDialog((p) => ({ ...p, open: o }))}
        gatewayId={id!}
        resourceLabel={deleteDialog.label}
        resourceName={deleteDialog.name}
        deleteFn={deleteDialog.fn}
        queryKeys={deleteDialog.keys}
      />
      <FirewallRuleFormDialog open={showRuleForm} onOpenChange={setShowRuleForm} gatewayId={id!} />
      <DNSOverrideFormDialog open={showDnsForm} onOpenChange={setShowDnsForm} gatewayId={id!} item={editingDns} />
      <DNSDomainOverrideFormDialog open={showDnsDomainForm} onOpenChange={setShowDnsDomainForm} gatewayId={id!} item={editingDnsDomain} />
      <DHCPStaticMappingFormDialog open={showDhcpStaticForm} onOpenChange={setShowDhcpStaticForm} gatewayId={id!} item={editingDhcpStatic} />
      <PortForwardFormDialog open={showPortFwdForm} onOpenChange={setShowPortFwdForm} gatewayId={id!} item={editingPortFwd} />
      <SourceNATFormDialog open={showSnatForm} onOpenChange={setShowSnatForm} gatewayId={id!} />
      <AliasFormDialog open={showAliasForm} onOpenChange={setShowAliasForm} gatewayId={id!} item={editingAlias} />
      <WireGuardServerFormDialog open={showWgServerForm} onOpenChange={setShowWgServerForm} gatewayId={id!} />
      <WireGuardPeerFormDialog open={showWgPeerForm} onOpenChange={setShowWgPeerForm} gatewayId={id!} />
      <OpenVPNInstanceFormDialog open={showOvpnForm} onOpenChange={setShowOvpnForm} gatewayId={id!} />
      <StaticRouteFormDialog open={showRouteForm} onOpenChange={setShowRouteForm} gatewayId={id!} />
      <ShaperPipeFormDialog open={showPipeForm} onOpenChange={setShowPipeForm} gatewayId={id!} />
      <IDSSettingsFormDialog open={showIdsSettings} onOpenChange={setShowIdsSettings} gatewayId={id!} currentSettings={idsSettings} />
    </div>
  );
}
