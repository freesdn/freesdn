/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useState, useMemo, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import {
  Network,
  Settings,
  RefreshCw,
  MoreVertical,
  Plus,
  Zap,
  Link2,
  ChevronRight,
  ChevronDown,
  Activity,
  Layers,
  Copy,
  Eye,
  AlertTriangle,
  Shield,
  Globe,
  FileText,
  Users,
  History,
  ArrowLeft,
} from 'lucide-react';
import { PageHeader } from '@/components/layout';
import { ErrorState } from '@/components/ui/empty-state';
import { Download } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Textarea } from '@/components/ui/textarea';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';
import { switchesApi, deviceControlApi, configApi } from '@/lib/api';
import type {
  SwitchPort as ApiSwitchPort,
  StaticRoute,
  MACTableEntry, LLDPNeighbor,
  SwitchEvent, SwitchClient,
  SwitchPortProfile,
} from '@/lib/api';
import { StatsGrid } from '@/components/ui/stats-grid';
import { EmptyState } from '@/components/ui/empty-state';
import { useDeviceCapabilities, useToast } from '@/hooks';
import { SwitchClientsTab } from './tabs/SwitchClientsTab';
import { ProfilesTab } from './tabs/ProfilesTab';
import { LagsTab } from './tabs/LagsTab';
import { LogsTab } from './tabs/LogsTab';
import { ConfigHistoryTab } from './tabs/ConfigHistoryTab';
import { DiagnosticsTab } from './tabs/DiagnosticsTab';
import { NetworkTab } from './tabs/NetworkTab';
import { AdvancedTab } from './tabs/AdvancedTab';
import { OverviewTab } from './tabs/OverviewTab';
import { PortsTab } from './tabs/PortsTab';
import { VlansTab } from './tabs/VlansTab';
import { ConfigTab } from './tabs/ConfigTab';

// Types
interface SwitchDevice {
  id: string;
  name: string;
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
  uptime: number;
  cpu_usage: number;
  memory_usage: number;
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

interface Port {
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
  stp_state?: string;
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

interface LAG {
  id: string;
  name: string;
  lag_id: number;
  mode: string;
  member_ports: number[];
  status: string;
  active_ports: number;
  aggregate_speed: number;
}

// Note: SwitchDevice, Port, PortProfile, LAG interfaces retained for component typing
// API response types are mapped to these internal types

// Helper functions retained for use in summary cards + switch list view
const formatUptime = (seconds?: number) => {
  if (seconds == null) return '-';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
};

const getStatusColor = (status: string) => {
  switch (status) {
    case 'up':
    case 'online':
    case 'forwarding':
    case 'delivering':
      return 'bg-success';
    case 'down':
    case 'searching':
      return 'bg-warning';
    case 'disabled':
    case 'blocking':
      return 'bg-muted-foreground';
    case 'fault':
    case 'offline':
      return 'bg-destructive';
    default:
      return 'bg-muted-foreground';
  }
};


export default function SwitchesPage() {
  const { t } = useTranslation('switches');
  const queryClient = useQueryClient();
  const { deviceId: deviceIdFromUrl, tab: tabFromUrl } = useParams<{ deviceId?: string; tab?: string }>();
  const navigate = useNavigate();
  const [selectedSwitch, setSelectedSwitch] = useState<SwitchDevice | null>(null);
  const [activeTab, setActiveTab] = useState(tabFromUrl || 'overview');
  const [expandedSwitches, setExpandedSwitches] = useState<string[]>([]);
  // Diff range is keyed by version UUIDs (not version_numbers).
  // The backend ``/enterprise/config-versions/{a}/diff/{b}`` endpoint
  // takes UUIDs; tracking numbers here would force a per-click round-
  // trip to resolve them. Display labels still use ``version_number``.
  const [diffVersions, setDiffVersions] = useState<{ a: string; b: string; aLabel: number; bLabel: number } | null>(null);

  const selectSwitch = useCallback((sw: SwitchDevice | null) => {
    setSelectedSwitch(sw);
    if (sw) {
      navigate(`/switches/${sw.id}/${activeTab}`, { replace: true });
    } else {
      navigate('/switches', { replace: true });
      setActiveTab('overview');
    }
  }, [navigate, activeTab]);

  const switchTab = useCallback((tab: string) => {
    setActiveTab(tab);
    if (selectedSwitch) {
      navigate(`/switches/${selectedSwitch.id}/${tab}`, { replace: true });
    }
  }, [selectedSwitch, navigate]);

  // Dialogs
  const [portDialogOpen, setPortDialogOpen] = useState(false);
  const [applyProfileDialogOpen, setApplyProfileDialogOpen] = useState(false);
  // Selected port IDs are owned by PortsTab; copied up here when the user
  // clicks "Apply Profile" so the apply-profile dialog (parent-owned) knows
  // which ports to target.
  const [selectedPortIdsForProfile, setSelectedPortIdsForProfile] = useState<string[]>([]);
  // Which profile the user picked in the apply-profile dialog.
  const [applyProfileId, setApplyProfileId] = useState<string>('');
  const [lagDialogOpen, setLagDialogOpen] = useState(false);
  const [editingLag, setEditingLag] = useState<LAG | null>(null);
  const [lagDeleteConfirm, setLagDeleteConfirm] = useState<LAG | null>(null);
  const [lagForm, setLagForm] = useState({
    name: '',
    mode: 'lacp' as 'lacp' | 'static',
    member_ports: [] as number[],
    lacp_mode: 'active' as 'active' | 'passive',
    lacp_timeout: 'long' as 'long' | 'short',
  });
  const [selectedPort, setSelectedPort] = useState<Port | null>(null);

  // Port profile create/edit dialog
  type ProfileForm = {
    name: string;
    description: string;
    profile_type: string;
    native_vlan: string;
    tagged_vlans: string;
    voice_vlan: string;
    poe_enabled: boolean;
    stp_enabled: boolean;
  };
  const emptyProfileForm: ProfileForm = {
    name: '',
    description: '',
    profile_type: 'custom',
    native_vlan: '',
    tagged_vlans: '',
    voice_vlan: '',
    poe_enabled: false,
    stp_enabled: false,
  };
  const [profileDialogOpen, setProfileDialogOpen] = useState(false);
  const [editingProfileId, setEditingProfileId] = useState<string | null>(null);
  const [profileForm, setProfileForm] = useState<ProfileForm>(emptyProfileForm);
  const [profileDeleteConfirm, setProfileDeleteConfirm] = useState<SwitchPortProfile | null>(null);

  // Site context
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // Fetch switches from API
  const {
    data: switches,
    isLoading: switchesLoading,
    isError: switchesError,
    refetch: _refetchSwitches,
  } = useQuery({
    queryKey: ['switches', { siteId: selectedSiteId }],
    queryFn: async () => {
      const response = await switchesApi.listSwitches({ ...(selectedSiteId ? { site_id: selectedSiteId } : {}), per_page: 200 });
      return response.data.items;
    },
    staleTime: 30000,
  });

  // Resolve /:deviceId from URL once switch list loads
  useEffect(() => {
    if (!switches || !deviceIdFromUrl) return;
    if (selectedSwitch?.id === deviceIdFromUrl) return;
    const match = switches.find((sw: SwitchDevice) => sw.id === deviceIdFromUrl);
    if (match) {
      setSelectedSwitch(match);
    }
  }, [switches, deviceIdFromUrl, selectedSwitch?.id]);

  // Sync active tab from URL
  useEffect(() => {
    if (tabFromUrl && tabFromUrl !== activeTab) {
      setActiveTab(tabFromUrl);
    }
  }, [tabFromUrl, activeTab]);

  // Fetch ports for selected switch
  const {
    data: portsData,
    isLoading: portsLoading,
    isError: portsError,
    refetch: _refetchPorts,
  } = useQuery({
    queryKey: ['switch-ports', selectedSwitch?.id],
    queryFn: async () => {
      if (!selectedSwitch) return [];
      const response = await switchesApi.listPorts(selectedSwitch.id);
      return response.data;
    },
    enabled: !!selectedSwitch,
    staleTime: 15000,
  });

  // Fetch VLANs for selected switch
  const { data: switchVlans, isLoading: switchVlansLoading, isError: switchVlansError } = useQuery({
    queryKey: ['switch-vlans', selectedSwitch?.id],
    queryFn: async () => {
      if (!selectedSwitch) return [];
      const r = await switchesApi.getVlans(selectedSwitch.id);
      return r.data;
    },
    enabled: !!selectedSwitch,
    staleTime: 30000,
  });

  // Fetch port profiles
  const {
    data: profiles,
    isLoading: profilesLoading,
  } = useQuery({
    queryKey: ['port-profiles'],
    queryFn: async () => {
      const response = await switchesApi.listProfiles();
      return response.data;
    },
    staleTime: 60000,
  });

  // Fetch LAGs for selected switch
  const {
    data: lags,
    isLoading: lagsLoading,
  } = useQuery({
    queryKey: ['switch-lags', selectedSwitch?.id],
    queryFn: async (): Promise<LAG[]> => {
      if (!selectedSwitch) return [];
      const response = await switchesApi.listLAGs(selectedSwitch.id);
      return response.data;
    },
    enabled: !!selectedSwitch,
    staleTime: 30000,
  });

  // Network tab queries (lazy-loaded)
  const { data: stpConfig, isError: stpError } = useQuery({
    queryKey: ['switch-stp', selectedSwitch?.id],
    queryFn: async () => {
      if (!selectedSwitch) return null;
      const r = await switchesApi.getStpConfig(selectedSwitch.id);
      return r.data;
    },
    enabled: !!selectedSwitch && activeTab === 'config',
    staleTime: 30000,
  });

  const { data: aclRules, isError: aclError } = useQuery({
    queryKey: ['switch-acl', selectedSwitch?.id],
    queryFn: async () => {
      if (!selectedSwitch) return [];
      const r = await switchesApi.getAclRules(selectedSwitch.id);
      return r.data;
    },
    enabled: !!selectedSwitch && activeTab === 'config',
    staleTime: 30000,
  });

  const { data: igmpConfig, isError: igmpError } = useQuery({
    queryKey: ['switch-igmp', selectedSwitch?.id],
    queryFn: async () => {
      if (!selectedSwitch) return null;
      const r = await switchesApi.getIgmpConfig(selectedSwitch.id);
      return r.data;
    },
    enabled: !!selectedSwitch && activeTab === 'config',
    staleTime: 30000,
  });

  const { data: mirrorConfig, isError: mirrorError } = useQuery({
    queryKey: ['switch-mirror', selectedSwitch?.id],
    queryFn: async () => {
      if (!selectedSwitch) return null;
      const r = await switchesApi.getMirrorConfig(selectedSwitch.id);
      return r.data;
    },
    enabled: !!selectedSwitch && activeTab === 'config',
    staleTime: 30000,
  });

  const { data: qosConfig, isError: qosError } = useQuery({
    queryKey: ['switch-qos', selectedSwitch?.id],
    queryFn: async () => {
      if (!selectedSwitch) return null;
      const r = await switchesApi.getQosConfig(selectedSwitch.id);
      return r.data;
    },
    enabled: !!selectedSwitch && activeTab === 'config',
    staleTime: 30000,
  });

  const { data: dhcpSnoopingConfig, isError: dhcpSnoopingError } = useQuery({
    queryKey: ['switch-dhcp-snooping', selectedSwitch?.id],
    queryFn: async () => {
      if (!selectedSwitch) return null;
      const r = await switchesApi.getDhcpSnoopingConfig(selectedSwitch.id);
      return r.data;
    },
    enabled: !!selectedSwitch && activeTab === 'config',
    staleTime: 30000,
  });

  const { data: staticRoutes, isError: staticRoutesError } = useQuery({
    queryKey: ['switch-routes', selectedSwitch?.id],
    queryFn: async () => {
      if (!selectedSwitch) return [];
      const r = await switchesApi.getStaticRoutes(selectedSwitch.id);
      return r.data;
    },
    enabled: !!selectedSwitch && activeTab === 'network',
    staleTime: 30000,
  });

  const { data: dhcpConfig, isError: dhcpError } = useQuery({
    queryKey: ['switch-dhcp', selectedSwitch?.id],
    queryFn: async () => {
      if (!selectedSwitch) return null;
      const r = await switchesApi.getDhcpConfig(selectedSwitch.id);
      return r.data;
    },
    enabled: !!selectedSwitch && activeTab === 'network',
    staleTime: 30000,
  });

  const { data: lldpNeighbors, isError: lldpError } = useQuery({
    queryKey: ['switch-lldp', selectedSwitch?.id],
    queryFn: async () => {
      if (!selectedSwitch) return [];
      const r = await switchesApi.getLldpNeighbors(selectedSwitch.id);
      return r.data;
    },
    enabled: !!selectedSwitch && activeTab === 'network',
    staleTime: 30000,
  });

  const { data: macTable, isError: macTableError } = useQuery({
    queryKey: ['switch-mac-table', selectedSwitch?.id],
    queryFn: async () => {
      if (!selectedSwitch) return [];
      const r = await switchesApi.getMacTable(selectedSwitch.id);
      return r.data;
    },
    enabled: !!selectedSwitch && activeTab === 'network',
    staleTime: 30000,
  });

  const { data: switchEvents } = useQuery({
    queryKey: ['switch-events', selectedSwitch?.id],
    queryFn: async () => {
      if (!selectedSwitch) return [];
      const r = await switchesApi.getEvents(selectedSwitch.id);
      return r.data;
    },
    enabled: !!selectedSwitch && activeTab === 'logs',
    staleTime: 15000,
  });

  const { data: switchAlerts } = useQuery({
    queryKey: ['switch-alerts', selectedSwitch?.id],
    queryFn: async () => {
      if (!selectedSwitch) return [];
      const r = await switchesApi.getAlerts(selectedSwitch.id);
      return r.data;
    },
    enabled: !!selectedSwitch && activeTab === 'logs',
    staleTime: 15000,
  });

  const { data: switchClients, isLoading: isClientsLoading, isError: isClientsError } = useQuery({
    queryKey: ['switch-clients', selectedSwitch?.id],
    queryFn: async () => {
      if (!selectedSwitch) return [];
      const r = await switchesApi.getClients(selectedSwitch.id);
      return r.data;
    },
    enabled: !!selectedSwitch && activeTab === 'clients',
    staleTime: 15000,
  });

  // Aggregate error flags for the Config and Network tabs. If any of the
  // per-feature queries fail, surface a single ErrorState (with retry) for
  // that tab, mirroring the isClientsError pattern.
  const configError = stpError || aclError || igmpError || mirrorError || qosError || dhcpSnoopingError;
  const networkError = staticRoutesError || dhcpError || lldpError || macTableError;

  // Config history queries (lazy-loaded)
  const { data: configVersions, isLoading: configVersionsLoading } = useQuery({
    queryKey: ['config-versions', selectedSwitch?.id],
    queryFn: async () => {
      if (!selectedSwitch) return null;
      const response = await configApi.getVersions(selectedSwitch.id);
      return response.data;
    },
    enabled: !!selectedSwitch && activeTab === 'config-history',
    staleTime: 30000,
  });

  const { data: configDiff, isLoading: diffLoading } = useQuery({
    queryKey: ['config-diff', selectedSwitch?.id, diffVersions?.a, diffVersions?.b],
    queryFn: async () => {
      if (!selectedSwitch || !diffVersions) return null;
      // compareVersions now takes version UUIDs (a, b), the
      // human-readable labels (aLabel/bLabel) stay client-side for
      // the heading.
      const response = await configApi.compareVersions(selectedSwitch.id, diffVersions.a, diffVersions.b);
      return response.data;
    },
    enabled: !!selectedSwitch && !!diffVersions,
  });

  // Capability check for selected switch
  const {
    canPoeControl,
    canPortControl,
    getDisabledReason,
    isLoading: _capsLoading,
  } = useDeviceCapabilities(selectedSwitch?.id);

  // Determine which controls should be shown based on capabilities
  const showPoeControls = !selectedSwitch || canPoeControl;
  const showPortControls = !selectedSwitch || canPortControl;
  const poeDisabledReason = selectedSwitch ? getDisabledReason('port.poe_control') : undefined;
  const portDisabledReason = selectedSwitch ? getDisabledReason('port.admin_control') : undefined;

  const { toast } = useToast();

  // LED toggle mutation
  const refreshMutation = useMutation({
    mutationFn: (switchId: string) => switchesApi.refreshSwitch(switchId),
    onSuccess: (resp) => {
      if (selectedSwitch) {
        queryClient.invalidateQueries({ queryKey: ['switches'] });
        queryClient.invalidateQueries({ queryKey: ['switch', selectedSwitch.id] });
        queryClient.invalidateQueries({ queryKey: ['switch-ports', selectedSwitch.id] });
        queryClient.invalidateQueries({ queryKey: ['switch-mac-table', selectedSwitch.id] });
      }
      const d = resp.data;
      toast({
        title: t('SwitchesPage.toast.switchRefreshed'),
        description: t('SwitchesPage.toast.switchRefreshedDesc', { clients: d.connected_clients, entries: d.mac_table_entries }),
      });
    },
    onError: () => {
      toast({ title: t('SwitchesPage.toast.switchRefreshFailed'), variant: 'destructive' });
    },
  });

  const ledMutation = useMutation({
    mutationFn: ({ deviceId, setting }: { deviceId: string; setting: number }) =>
      deviceControlApi.setLed(deviceId, setting),
    onSuccess: () => {
      toast({ title: t('SwitchesPage.toast.ledUpdated') });
    },
    onError: () => {
      toast({ title: t('SwitchesPage.toast.ledUpdateFailed'), variant: 'destructive' });
    },
  });

  // PoE cycle mutation
  const poeCycleMutation = useMutation({
    mutationFn: ({ switchId, portIndex }: { switchId: string; portIndex: number }) =>
      switchesApi.cyclePoe(switchId, portIndex),
    onSuccess: () => {
      toast({ title: t('SwitchesPage.toast.poeCycleInitiated') });
      if (selectedSwitch) {
        queryClient.invalidateQueries({ queryKey: ['switch-ports', selectedSwitch.id] });
      }
    },
    onError: () => {
      toast({ title: t('SwitchesPage.toast.poeCycleFailed'), variant: 'destructive' });
    },
  });

  // Port bounce mutation (disable → wait → re-enable with recovery)
  const portBounceMutation = useMutation({
    mutationFn: async ({ switchId, portIndex }: { switchId: string; portIndex: number }) => {
      await switchesApi.togglePort(switchId, portIndex, false);
      await new Promise(resolve => setTimeout(resolve, 2000));
      try {
        await switchesApi.togglePort(switchId, portIndex, true);
      } catch (_reEnableError) {
        // Port is disabled · attempt one retry before giving up
        await new Promise(resolve => setTimeout(resolve, 1000));
        await switchesApi.togglePort(switchId, portIndex, true);
      }
    },
    onSuccess: () => {
      toast({ title: t('SwitchesPage.toast.portBounced') });
      if (selectedSwitch) {
        queryClient.invalidateQueries({ queryKey: ['switch-ports', selectedSwitch.id] });
      }
    },
    onError: () => {
      toast({ title: t('SwitchesPage.toast.portBounceFailed'), variant: 'destructive' });
      if (selectedSwitch) {
        queryClient.invalidateQueries({ queryKey: ['switch-ports', selectedSwitch.id] });
      }
    },
  });

  // Port enable/disable mutation
  const portToggleMutation = useMutation({
    mutationFn: ({ switchId, portIndex, enabled }: { switchId: string; portIndex: number; enabled: boolean }) =>
      switchesApi.togglePort(switchId, portIndex, enabled),
    onSuccess: (_data, variables) => {
      toast({ title: variables.enabled ? t('SwitchesPage.toast.portEnabled') : t('SwitchesPage.toast.portDisabled') });
      if (selectedSwitch) {
        queryClient.invalidateQueries({ queryKey: ['switch-ports', selectedSwitch.id] });
      }
    },
    onError: (_err, variables) => {
      toast({ title: variables.enabled ? t('SwitchesPage.toast.portEnableFailed') : t('SwitchesPage.toast.portDisableFailed'), variant: 'destructive' });
    },
  });

  // PoE enable/disable mutation
  const poeToggleMutation = useMutation({
    mutationFn: ({ switchId, portIndex, enabled }: { switchId: string; portIndex: number; enabled: boolean }) =>
      switchesApi.togglePoe(switchId, portIndex, enabled),
    onSuccess: (_data, variables) => {
      toast({ title: variables.enabled ? t('SwitchesPage.toast.poeEnabled') : t('SwitchesPage.toast.poeDisabled') });
      if (selectedSwitch) {
        queryClient.invalidateQueries({ queryKey: ['switch-ports', selectedSwitch.id] });
      }
    },
    onError: (_err, variables) => {
      toast({ title: variables.enabled ? t('SwitchesPage.toast.poeEnableFailed') : t('SwitchesPage.toast.poeDisableFailed'), variant: 'destructive' });
    },
  });

  // LAG mutations
  const lagCreateMutation = useMutation({
    mutationFn: (data: typeof lagForm) =>
      switchesApi.createLAG(selectedSwitch!.id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['switch-lags', selectedSwitch?.id] });
      setLagDialogOpen(false);
      setLagForm({ name: '', mode: 'lacp', member_ports: [], lacp_mode: 'active', lacp_timeout: 'long' });
      toast({ title: t('SwitchesPage.toast.lagCreated') });
    },
    onError: (err: any) => toast({ title: err?.response?.data?.detail || t('SwitchesPage.toast.lagCreateFailed'), variant: 'destructive' }),
  });

  const lagUpdateMutation = useMutation({
    mutationFn: ({ lagId, data }: { lagId: number; data: Partial<typeof lagForm> }) =>
      switchesApi.updateLAG(selectedSwitch!.id, lagId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['switch-lags', selectedSwitch?.id] });
      setEditingLag(null);
      toast({ title: t('SwitchesPage.toast.lagUpdated') });
    },
    onError: (err: any) => toast({ title: err?.response?.data?.detail || t('SwitchesPage.toast.lagUpdateFailed'), variant: 'destructive' }),
  });

  const lagDeleteMutation = useMutation({
    mutationFn: (lagId: number) => switchesApi.deleteLAG(selectedSwitch!.id, lagId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['switch-lags', selectedSwitch?.id] });
      setLagDeleteConfirm(null);
      toast({ title: t('SwitchesPage.toast.lagDeleted') });
    },
    onError: (err: any) => toast({ title: err?.response?.data?.detail || t('SwitchesPage.toast.lagDeleteFailed'), variant: 'destructive' }),
  });

  // Port profile create/edit/duplicate/delete (DB-backed /switches/profiles).
  const profileFormToPayload = (form: ProfileForm): Partial<SwitchPortProfile> => {
    const parseVlan = (v: string): number | undefined => {
      const n = parseInt(v.trim(), 10);
      return Number.isFinite(n) ? n : undefined;
    };
    const tagged = form.tagged_vlans
      .split(',')
      .map((s) => parseInt(s.trim(), 10))
      .filter((n) => Number.isFinite(n));
    return {
      name: form.name.trim(),
      description: form.description.trim() || undefined,
      profile_type: form.profile_type,
      ...(selectedSiteId ? { site_id: selectedSiteId } : {}),
      native_vlan: parseVlan(form.native_vlan) ?? null,
      tagged_vlans: tagged.length ? tagged : null,
      voice_vlan: parseVlan(form.voice_vlan) ?? null,
      poe_enabled: form.poe_enabled,
      stp_enabled: form.stp_enabled,
    };
  };

  const profileCreateMutation = useMutation({
    mutationFn: (form: ProfileForm) => switchesApi.createProfile(profileFormToPayload(form)),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['port-profiles'] });
      setProfileDialogOpen(false);
      setProfileForm(emptyProfileForm);
      toast({ title: t('ProfilesTab.actions.createProfile') });
    },
    onError: (err: any) =>
      toast({ title: err?.response?.data?.detail || err?.response?.data?.error?.message || t('common:error', { ns: 'common' }), variant: 'destructive' }),
  });

  const profileUpdateMutation = useMutation({
    mutationFn: ({ id, form }: { id: string; form: ProfileForm }) =>
      switchesApi.updateProfile(id, profileFormToPayload(form)),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['port-profiles'] });
      setProfileDialogOpen(false);
      setEditingProfileId(null);
      setProfileForm(emptyProfileForm);
      toast({ title: t('common:save', { ns: 'common' }) });
    },
    onError: (err: any) =>
      toast({ title: err?.response?.data?.detail || err?.response?.data?.error?.message || t('common:error', { ns: 'common' }), variant: 'destructive' }),
  });

  const profileDeleteMutation = useMutation({
    mutationFn: (id: string) => switchesApi.deleteProfile(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['port-profiles'] });
      setProfileDeleteConfirm(null);
      toast({ title: t('common:delete', { ns: 'common' }) });
    },
    onError: (err: any) =>
      toast({ title: err?.response?.data?.detail || err?.response?.data?.error?.message || t('common:error', { ns: 'common' }), variant: 'destructive' }),
  });

  // Apply a DB-backed profile to the ports the user selected in PortsTab.
  const applyProfileMutation = useMutation({
    mutationFn: ({ profileId, portIds }: { profileId: string; portIds: string[] }) =>
      switchesApi.applyProfile(selectedSwitch!.id, { profile_id: profileId, port_ids: portIds }),
    onSuccess: (res: any) => {
      queryClient.invalidateQueries({ queryKey: ['switch-ports', selectedSwitch?.id] });
      queryClient.invalidateQueries({ queryKey: ['port-profiles'] });
      setApplyProfileDialogOpen(false);
      setApplyProfileId('');
      setSelectedPortIdsForProfile([]);
      toast({ title: t('SwitchesPage.toast.profileApplied', { count: res?.data?.ports_updated ?? selectedPortIdsForProfile.length }) });
    },
    onError: (err: any) =>
      toast({ title: err?.response?.data?.detail || err?.response?.data?.error?.message || t('common:error', { ns: 'common' }), variant: 'destructive' }),
  });

  const openCreateProfile = () => {
    setEditingProfileId(null);
    setProfileForm(emptyProfileForm);
    setProfileDialogOpen(true);
  };

  const profileToForm = (p: SwitchPortProfile): ProfileForm => ({
    name: p.name,
    description: p.description || '',
    profile_type: p.profile_type || 'custom',
    native_vlan: p.native_vlan != null ? String(p.native_vlan) : '',
    tagged_vlans: (p.tagged_vlans || []).join(', '),
    voice_vlan: p.voice_vlan != null ? String(p.voice_vlan) : '',
    poe_enabled: !!p.poe_enabled,
    stp_enabled: !!p.stp_enabled,
  });

  const openEditProfile = (p: SwitchPortProfile) => {
    setEditingProfileId(p.id);
    setProfileForm(profileToForm(p));
    setProfileDialogOpen(true);
  };

  const openDuplicateProfile = (p: SwitchPortProfile) => {
    setEditingProfileId(null);
    setProfileForm({ ...profileToForm(p), name: `${p.name} (copy)` });
    setProfileDialogOpen(true);
  };

  const submitProfile = () => {
    if (!profileForm.name.trim()) return;
    if (editingProfileId) {
      profileUpdateMutation.mutate({ id: editingProfileId, form: profileForm });
    } else {
      profileCreateMutation.mutate(profileForm);
    }
  };

  // VLAN port assignment mutation
  const vlanAssignMutation = useMutation({
    mutationFn: (assignments: Array<{ port_index: number; native_vlan: number | null; tagged_vlans: number[] }>) =>
      switchesApi.bulkVlanAssignment(selectedSwitch!.id, { assignments }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['switch-vlans', selectedSwitch?.id] });
      queryClient.invalidateQueries({ queryKey: ['switch-ports', selectedSwitch?.id] });
      toast({ title: t('SwitchesPage.toast.vlanAssignmentsUpdated') });
    },
    onError: (err: any) => toast({ title: err?.response?.data?.detail || t('SwitchesPage.toast.vlanAssignmentsFailed'), variant: 'destructive' }),
  });

  // Port form state
  const [portForm, setPortForm] = useState({
    name: '',
    description: '',
    enabled: true,
    vlan_mode: 'access',
    native_vlan: 1,
    tagged_vlans: [] as number[],
    poe_enabled: true,
    poe_mode: 'auto',
    poe_limit: 30,
    flow_control: false,
    mtu: 1500,
    stp_enabled: true,
    // STP protocol mode, must match backend StpConfig.mode Literal: rstp | stp | mstp.
    stp_mode: 'rstp',
    security_enabled: false,
    mac_limit: 3,
    storm_control_enabled: false,
    storm_broadcast_rate: 500,
    storm_multicast_rate: 500,
    storm_unknown_unicast_rate: 500,
    rate_limit_enabled: false,
    rate_limit_ingress: 0,
    rate_limit_egress: 0,
    isolation_enabled: false,
  });

  // Map API ports to internal Port type
  const ports: Port[] = useMemo(() => {
    if (!portsData) return [];
    return portsData.map((p: ApiSwitchPort) => ({
      id: p.id,
      port_index: p.port_index,
      port_name: p.name,
      port_type: p.port_type,
      enabled: p.enabled,
      link_status: p.status?.link_status || 'down',
      link_speed: p.status?.link_speed,
      vlan_mode: p.vlan_config?.mode || 'access',
      native_vlan: p.vlan_config?.native_vlan || 1,
      tagged_vlans: p.vlan_config?.tagged_vlans || [],
      poe_enabled: p.poe_config?.enabled || false,
      poe_status: p.status?.poe_status,
      poe_power_draw: p.status?.poe_power_draw,
      poe_class: p.status?.poe_class,
      stp_state: p.status?.stp_state,
      neighbor_device: p.status?.neighbor_device,
      neighbor_port: p.status?.neighbor_port,
      sfp_vendor: (p.status as any)?.sfp_vendor,
      sfp_part_number: (p.status as any)?.sfp_part_number,
      sfp_type: (p.status as any)?.sfp_type,
      sfp_temperature: (p.status as any)?.sfp_temperature,
      sfp_tx_power: (p.status as any)?.sfp_tx_power,
      sfp_rx_power: (p.status as any)?.sfp_rx_power,
      sfp_wavelength: (p.status as any)?.sfp_wavelength,
      tx_bytes: p.status?.tx_bytes || 0,
      rx_bytes: p.status?.rx_bytes || 0,
      tx_packets: p.status?.tx_packets || 0,
      rx_packets: p.status?.rx_packets || 0,
      tx_errors: p.status?.tx_errors || 0,
      rx_errors: p.status?.rx_errors || 0,
      tx_utilization: p.status?.tx_utilization || 0,
      rx_utilization: p.status?.rx_utilization || 0,
    }));
  }, [portsData]);

  // Client-side CSV export of the currently-loaded switch list.
  const handleExportSwitches = () => {
    if (!switches || switches.length === 0) {
      toast({ title: t('SwitchesPage.empty.title'), variant: 'destructive' });
      return;
    }
    const columns: Array<keyof SwitchDevice> = [
      'name', 'vendor', 'model', 'serial_number', 'ip_address', 'mac_address',
      'site_name', 'status', 'total_ports', 'ports_up', 'ports_down',
      'poe_used', 'poe_budget', 'firmware_version', 'connected_clients',
    ];
    const escape = (v: unknown) => {
      const s = v == null ? '' : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const header = columns.join(',');
    const rows = switches.map((sw) => columns.map((c) => escape((sw as SwitchDevice)[c])).join(','));
    const csv = [header, ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `switches-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const toggleSwitchExpand = (switchId: string) => {
    setExpandedSwitches(prev =>
      prev.includes(switchId)
        ? prev.filter(id => id !== switchId)
        : [...prev, switchId]
    );
  };

  const handlePortEdit = (port: Port) => {
    setSelectedPort(port);
    setPortForm({
      name: port.port_name,
      description: '',
      enabled: port.enabled,
      vlan_mode: port.vlan_mode,
      native_vlan: port.native_vlan,
      tagged_vlans: port.tagged_vlans,
      poe_enabled: port.poe_enabled,
      poe_mode: 'auto',
      poe_limit: 30,
      flow_control: false,
      mtu: 1500,
      stp_enabled: true,
      stp_mode: 'rstp',
      security_enabled: false,
      mac_limit: 3,
      storm_control_enabled: false,
      storm_broadcast_rate: 500,
      storm_multicast_rate: 500,
      storm_unknown_unicast_rate: 500,
      rate_limit_enabled: false,
      rate_limit_ingress: 0,
      rate_limit_egress: 0,
      isolation_enabled: false,
    });
    setPortDialogOpen(true);
  };

  const handlePortSave = async () => {
    if (!selectedSwitch || !selectedPort) return;
    try {
      // Save main port config
      await switchesApi.updatePort(selectedSwitch.id, selectedPort.port_index, {
        name: portForm.name || undefined,
        enabled: portForm.enabled,
        vlan_config: {
          mode: portForm.vlan_mode,
          native_vlan: portForm.native_vlan,
          tagged_vlans: portForm.tagged_vlans,
        },
        poe_config: {
          enabled: portForm.poe_enabled,
          mode: portForm.poe_mode,
          power_limit: portForm.poe_limit,
        },
        stp_config: {
          enabled: portForm.stp_enabled,
          mode: portForm.stp_mode,
          bpdu_filter: false,
          bpdu_guard: false,
        },
        flow_control: portForm.flow_control,
        mtu: portForm.mtu,
        // Only send mac_limit when port security is actually on. The dialog
        // hides the field when the toggle is off but kept sending its value,
        // and the backend applied it regardless.
        security_config: {
          enabled: portForm.security_enabled,
          ...(portForm.security_enabled ? { mac_limit: portForm.mac_limit } : {}),
        },
      });

      // Apply per-port settings via dedicated endpoints (fire-and-forget, best-effort)
      const portIdx = selectedPort.port_index;
      const sid = selectedSwitch.id;

      await Promise.allSettled([
        switchesApi.setPortFlowControl(sid, portIdx, portForm.flow_control),
        portForm.isolation_enabled !== false
          ? switchesApi.setPortIsolation(sid, portIdx, portForm.isolation_enabled)
          : Promise.resolve(),
        portForm.rate_limit_enabled
          ? switchesApi.setPortBandwidth(sid, portIdx, {
              bandwidth_ctrl_type: 1,
              ingress_rate: portForm.rate_limit_ingress || undefined,
              egress_rate: portForm.rate_limit_egress || undefined,
            })
          : switchesApi.setPortBandwidth(sid, portIdx, { bandwidth_ctrl_type: 0 }),
        portForm.storm_control_enabled
          ? switchesApi.setPortStormControl(sid, portIdx, {
              broadcast_enabled: true,
              broadcast_rate: portForm.storm_broadcast_rate,
              multicast_enabled: true,
              multicast_rate: portForm.storm_multicast_rate,
              unknown_unicast_enabled: true,
              unknown_unicast_rate: portForm.storm_unknown_unicast_rate,
            })
          : switchesApi.setPortStormControl(sid, portIdx, {
              broadcast_enabled: false,
              multicast_enabled: false,
              unknown_unicast_enabled: false,
            }),
      ]);

      queryClient.invalidateQueries({ queryKey: ['switch-ports', selectedSwitch.id] });
      toast({ title: t('SwitchesPage.toast.portConfigSaved') });
      setPortDialogOpen(false);
    } catch (error) {
      console.error('Failed to save port configuration:', error);
      toast({ title: t('SwitchesPage.toast.portConfigSaveFailed'), variant: 'destructive' });
    }
  };

  // Switch detail view
  if (selectedSwitch) {
    return (
      <div className="space-y-6">
          {/* Header */}
          <PageHeader
            icon={Network}
            title={selectedSwitch.name}
            description={`${selectedSwitch.vendor} ${selectedSwitch.model} • ${selectedSwitch.site_name}`}
            breadcrumbs={
              <button
                type="button"
                onClick={() => selectSwitch(null)}
                className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
              >
                <ArrowLeft className="h-3.5 w-3.5" />
                {t('SwitchesPage.actions.back')}
              </button>
            }
            actions={
              <>
                <Badge variant={selectedSwitch.status === 'online' ? 'default' : 'destructive'}>
                  {selectedSwitch.status}
                </Badge>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={refreshMutation.isPending}
                  onClick={() => refreshMutation.mutate(selectedSwitch.id)}
                >
                  <RefreshCw className={`mr-2 h-4 w-4 ${refreshMutation.isPending ? 'animate-spin' : ''}`} />
                  {refreshMutation.isPending ? t('SwitchesPage.actions.refreshing') : t('SwitchesPage.actions.refresh')}
                </Button>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="outline" size="sm">
                      <MoreVertical className="h-4 w-4" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem onClick={() => switchTab('config')}>
                      <Settings className="mr-2 h-4 w-4" />
                      {t('SwitchesPage.menu.configureStp')}
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => switchTab('network')}>
                      <Eye className="mr-2 h-4 w-4" />
                      {t('SwitchesPage.menu.viewMacTable')}
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => switchTab('config')}>
                      <Activity className="mr-2 h-4 w-4" />
                      {t('SwitchesPage.menu.portMirroring')}
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </>
            }
          />

        {/* Capability Warning Banner */}
        {selectedSwitch && (!showPortControls || !showPoeControls) && (
          <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-4 dark:border-yellow-800 dark:bg-yellow-900/20">
            <div className="flex items-start gap-3">
              <AlertTriangle className="h-5 w-5 text-yellow-600 dark:text-yellow-500 mt-0.5" />
              <div>
                <h4 className="font-medium text-yellow-800 dark:text-yellow-200">
                  {t('SwitchesPage.capabilities.limitedTitle')}
                </h4>
                <p className="text-sm text-yellow-700 dark:text-yellow-300 mt-1">
                  {!showPortControls && (
                    <span className="block">
                      <strong>{t('SwitchesPage.capabilities.portControlLabel')}</strong> {portDisabledReason || t('SwitchesPage.capabilities.portNotSupported')}
                    </span>
                  )}
                  {!showPoeControls && (
                    <span className="block">
                      <strong>{t('SwitchesPage.capabilities.poeControlLabel')}</strong> {poeDisabledReason || t('SwitchesPage.capabilities.poeNotSupported')}
                    </span>
                  )}
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Summary Cards */}
        <div className="grid gap-4 md:grid-cols-5">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">{t('SwitchesPage.summary.ports')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-2">
                <span className="text-2xl font-bold text-green-600">{selectedSwitch.ports_up}</span>
                <span className="text-muted-foreground">/ {selectedSwitch.total_ports}</span>
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                {t('SwitchesPage.summary.portsDownDisabled', { down: selectedSwitch.ports_down, disabled: selectedSwitch.ports_disabled })}
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">{t('SwitchesPage.summary.poePower')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{selectedSwitch.poe_used.toFixed(1)}W</div>
              <Progress
                value={selectedSwitch.poe_budget > 0 ? (selectedSwitch.poe_used / selectedSwitch.poe_budget) * 100 : 0}
                className="mt-1 h-2"
              />
              <p className="text-xs text-muted-foreground mt-1">
                {t('SwitchesPage.summary.ofBudget', { budget: selectedSwitch.poe_budget })}
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">{t('SwitchesPage.summary.cpu')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{selectedSwitch.cpu_usage}%</div>
              <Progress value={selectedSwitch.cpu_usage} className="mt-1 h-2" />
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">{t('SwitchesPage.summary.memory')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{selectedSwitch.memory_usage}%</div>
              <Progress value={selectedSwitch.memory_usage} className="mt-1 h-2" />
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">{t('SwitchesPage.summary.uptime')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{formatUptime(selectedSwitch.uptime)}</div>
              <p className="text-xs text-muted-foreground mt-1">
                v{selectedSwitch.firmware_version}
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={switchTab}>
          <TabsList>
            <TabsTrigger value="overview">
              <Eye className="mr-2 h-4 w-4" />
              {t('SwitchesPage.tabs.overview')}
            </TabsTrigger>
            <TabsTrigger value="ports">
              <Network className="mr-2 h-4 w-4" />
              {t('SwitchesPage.tabs.ports')}
            </TabsTrigger>
            <TabsTrigger value="vlans">
              <Layers className="mr-2 h-4 w-4" />
              {t('SwitchesPage.tabs.vlans')}
            </TabsTrigger>
            <TabsTrigger value="lags">
              <Link2 className="mr-2 h-4 w-4" />
              {t('SwitchesPage.tabs.lags')}
            </TabsTrigger>
            <TabsTrigger value="profiles">
              <Copy className="mr-2 h-4 w-4" />
              {t('SwitchesPage.tabs.profiles')}
            </TabsTrigger>
            <TabsTrigger value="network">
              <Globe className="mr-2 h-4 w-4" />
              {t('SwitchesPage.tabs.network')}
            </TabsTrigger>
            <TabsTrigger value="config">
              <Shield className="mr-2 h-4 w-4" />
              {t('SwitchesPage.tabs.config')}
            </TabsTrigger>
            <TabsTrigger value="config-history">
              <History className="mr-2 h-4 w-4" />
              {t('SwitchesPage.tabs.configHistory')}
            </TabsTrigger>
            <TabsTrigger value="logs">
              <FileText className="mr-2 h-4 w-4" />
              {t('SwitchesPage.tabs.logs')}
            </TabsTrigger>
            <TabsTrigger value="clients">
              <Users className="mr-2 h-4 w-4" />
              {t('SwitchesPage.tabs.clients')}
            </TabsTrigger>
            <TabsTrigger value="diagnostics">
              <Activity className="mr-2 h-4 w-4" />
              {t('SwitchesPage.tabs.diagnostics')}
            </TabsTrigger>
            <TabsTrigger value="advanced">
              <Settings className="mr-2 h-4 w-4" />
              {t('SwitchesPage.tabs.advanced')}
            </TabsTrigger>
          </TabsList>

          {/* ═══ Overview Tab ═══ */}
          <TabsContent value="overview" className="space-y-4">
            <OverviewTab
              selectedSwitch={selectedSwitch}
              ports={ports}
              ledPending={ledMutation.isPending}
              onFlashLed={() => ledMutation.mutate({ deviceId: selectedSwitch.id, setting: 1 })}
            />
          </TabsContent>

          {/* ═══ Ports Tab ═══ */}
          <TabsContent value="ports" className="space-y-4">
            {portsError ? (
              <ErrorState
                message={t('SwitchesPage.errorState.message')}
                onRetry={() => queryClient.invalidateQueries({ queryKey: ['switch-ports', selectedSwitch?.id] })}
              />
            ) : portsLoading ? (
              <div className="flex items-center justify-center py-12">
                <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            ) : (
              <PortsTab
                ports={ports}
                selectedSwitchId={selectedSwitch?.id}
                showPortControls={showPortControls}
                showPoeControls={showPoeControls}
                portDisabledReason={portDisabledReason}
                portBounceMutation={portBounceMutation}
                poeCycleMutation={poeCycleMutation}
                portToggleMutation={portToggleMutation}
                poeToggleMutation={poeToggleMutation}
                onPortEdit={handlePortEdit}
                onApplyProfile={(selected) => {
                  setSelectedPortIdsForProfile(selected);
                  setApplyProfileDialogOpen(true);
                }}
              />
            )}
          </TabsContent>

          {/* ═══ VLANs Tab ═══ */}
          <TabsContent value="vlans" className="space-y-4">
            {portsError || switchVlansError ? (
              <ErrorState
                message={t('SwitchesPage.errorState.message')}
                onRetry={() => {
                  queryClient.invalidateQueries({ queryKey: ['switch-vlans', selectedSwitch?.id] });
                  queryClient.invalidateQueries({ queryKey: ['switch-ports', selectedSwitch?.id] });
                }}
              />
            ) : portsLoading || switchVlansLoading ? (
              <div className="flex items-center justify-center py-12">
                <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            ) : (
              <VlansTab
                ports={ports}
                switchVlans={switchVlans}
                vlanAssignPending={vlanAssignMutation.isPending}
                onApply={(assignments) => vlanAssignMutation.mutate(assignments)}
              />
            )}
          </TabsContent>

          {/* ═══ LAGs Tab ═══ */}
          <TabsContent value="lags" className="space-y-4">
            <LagsTab
              lags={lags}
              lagsLoading={lagsLoading}
              onCreate={() => {
                setLagForm({ name: '', mode: 'lacp', member_ports: [], lacp_mode: 'active', lacp_timeout: 'long' });
                setLagDialogOpen(true);
              }}
              onEdit={(lag) => {
                setEditingLag(lag);
                setLagForm({
                  name: lag.name,
                  mode: lag.mode as 'lacp' | 'static',
                  member_ports: lag.member_ports,
                  lacp_mode: 'active',
                  lacp_timeout: 'long',
                });
              }}
              onDelete={(lag) => setLagDeleteConfirm(lag)}
            />
          </TabsContent>

          {/* ═══ Profiles Tab ═══ */}
          <TabsContent value="profiles" className="space-y-4">
            <ProfilesTab
              profiles={profiles}
              profilesLoading={profilesLoading}
              onCreate={openCreateProfile}
              onEdit={openEditProfile}
              onDuplicate={openDuplicateProfile}
              onDelete={setProfileDeleteConfirm}
            />
          </TabsContent>

          {/* ═══ Network Tab ═══ */}
          <TabsContent value="network" className="space-y-4">
            {networkError ? (
              <ErrorState
                message={t('SwitchesPage.errorState.message')}
                onRetry={() => {
                  queryClient.invalidateQueries({ queryKey: ['switch-routes', selectedSwitch?.id] });
                  queryClient.invalidateQueries({ queryKey: ['switch-dhcp', selectedSwitch?.id] });
                  queryClient.invalidateQueries({ queryKey: ['switch-lldp', selectedSwitch?.id] });
                  queryClient.invalidateQueries({ queryKey: ['switch-mac-table', selectedSwitch?.id] });
                }}
              />
            ) : (
              <NetworkTab
                lldpNeighbors={lldpNeighbors as LLDPNeighbor[] | undefined}
                staticRoutes={staticRoutes as StaticRoute[] | undefined}
                dhcpConfig={dhcpConfig}
                macTable={macTable as MACTableEntry[] | undefined}
              />
            )}
          </TabsContent>

          {/* ═══ Config Tab ═══ */}
          <TabsContent value="config" className="space-y-4">
            {configError ? (
              <ErrorState
                message={t('SwitchesPage.errorState.message')}
                onRetry={() => {
                  queryClient.invalidateQueries({ queryKey: ['switch-stp', selectedSwitch?.id] });
                  queryClient.invalidateQueries({ queryKey: ['switch-acl', selectedSwitch?.id] });
                  queryClient.invalidateQueries({ queryKey: ['switch-igmp', selectedSwitch?.id] });
                  queryClient.invalidateQueries({ queryKey: ['switch-mirror', selectedSwitch?.id] });
                  queryClient.invalidateQueries({ queryKey: ['switch-qos', selectedSwitch?.id] });
                  queryClient.invalidateQueries({ queryKey: ['switch-dhcp-snooping', selectedSwitch?.id] });
                }}
              />
            ) : (
              <ConfigTab
                stpConfig={stpConfig}
                aclRules={aclRules}
                igmpConfig={igmpConfig}
                mirrorConfig={mirrorConfig}
                qosConfig={qosConfig}
                dhcpSnoopingConfig={dhcpSnoopingConfig}
              />
            )}
          </TabsContent>

          {/* ═══ Config History Tab ═══ */}
          <TabsContent value="config-history" className="space-y-4">
            <ConfigHistoryTab
              configVersions={configVersions}
              configVersionsLoading={configVersionsLoading}
              configDiff={configDiff}
              diffLoading={diffLoading}
              diffVersions={diffVersions}
              onSelectDiff={setDiffVersions}
            />
          </TabsContent>

          {/* ═══ Logs Tab ═══ */}
          <TabsContent value="logs" className="space-y-4">
            <LogsTab
              switchAlerts={switchAlerts as SwitchEvent[] | undefined}
              switchEvents={switchEvents as SwitchEvent[] | undefined}
            />
          </TabsContent>

          {/* ═══ Clients Tab ═══ */}
          <TabsContent value="clients" className="space-y-4">
            {isClientsError ? (
              <Card>
                <CardContent noOffset className="py-12">
                  <EmptyState
                    icon={AlertTriangle}
                    title={t('SwitchesPage.clients.loadFailedTitle')}
                    description={t('SwitchesPage.clients.loadFailedDesc')}
                    variant="default"
                    action={{ label: t('SwitchesPage.actions.retry'), onClick: () => queryClient.invalidateQueries({ queryKey: ['switch-clients', selectedSwitch?.id] }) }}
                  />
                </CardContent>
              </Card>
            ) : (
              <SwitchClientsTab
                clients={(switchClients as SwitchClient[] | undefined) || []}
                isLoading={isClientsLoading}
              />
            )}
          </TabsContent>

          {/* ═══ Diagnostics Tab ═══ */}
          <TabsContent value="diagnostics" className="space-y-4">
            <DiagnosticsTab
              selectedSwitchId={selectedSwitch?.id}
              totalPorts={selectedSwitch?.total_ports}
              toast={toast}
            />
          </TabsContent>

          {/* ═══ Advanced Tab ═══ */}
          <TabsContent value="advanced" className="space-y-4">
            <AdvancedTab selectedSwitchId={selectedSwitch?.id} toast={toast} />
          </TabsContent>
        </Tabs>

        {/* Port Configuration Dialog */}
        <Dialog open={portDialogOpen} onOpenChange={setPortDialogOpen}>
          <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>{t('SwitchesPage.portDialog.title', { name: selectedPort?.port_name })}</DialogTitle>
              <DialogDescription>
                {t('SwitchesPage.portDialog.description')}
              </DialogDescription>
            </DialogHeader>

            <Tabs defaultValue="general" className="w-full">
              <TabsList className="grid w-full grid-cols-4">
                <TabsTrigger value="general">{t('SwitchesPage.portDialog.tabs.general')}</TabsTrigger>
                <TabsTrigger value="vlan">{t('SwitchesPage.portDialog.tabs.vlan')}</TabsTrigger>
                <TabsTrigger value="poe">{t('SwitchesPage.portDialog.tabs.poe')}</TabsTrigger>
                <TabsTrigger value="security">{t('SwitchesPage.portDialog.tabs.security')}</TabsTrigger>
              </TabsList>

              <TabsContent value="general" className="space-y-4">
                <div className="space-y-2">
                  <Label>{t('SwitchesPage.portDialog.portName')}</Label>
                  <Input
                    value={portForm.name}
                    onChange={(e) => setPortForm({ ...portForm, name: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>{t('SwitchesPage.portDialog.descriptionLabel')}</Label>
                  <Textarea
                    value={portForm.description}
                    onChange={(e) => setPortForm({ ...portForm, description: e.target.value })}
                    placeholder={t('SwitchesPage.portDialog.descriptionPlaceholder')}
                    rows={2}
                  />
                </div>
                <div className="flex items-center justify-between">
                  <Label>{t('SwitchesPage.portDialog.portEnabled')}</Label>
                  <Switch
                    checked={portForm.enabled}
                    onCheckedChange={(checked) => setPortForm({ ...portForm, enabled: checked })}
                  />
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <Label>{t('SwitchesPage.portDialog.flowControl')}</Label>
                    <p className="text-xs text-muted-foreground">{t('SwitchesPage.portDialog.flowControlHint')}</p>
                  </div>
                  <Switch
                    checked={portForm.flow_control}
                    onCheckedChange={(checked) => setPortForm({ ...portForm, flow_control: checked })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>MTU</Label>
                  <Input
                    type="number"
                    min={1500}
                    max={9216}
                    value={portForm.mtu}
                    onChange={(e) => setPortForm({ ...portForm, mtu: Number(e.target.value) })}
                  />
                  <p className="text-xs text-muted-foreground">{t('SwitchesPage.portDialog.mtuHint')}</p>
                </div>
              </TabsContent>

              <TabsContent value="vlan" className="space-y-4">
                <div className="space-y-2">
                  <Label>{t('SwitchesPage.portDialog.vlanMode')}</Label>
                  <Select
                    value={portForm.vlan_mode}
                    onValueChange={(v) => setPortForm({ ...portForm, vlan_mode: v })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="access">{t('SwitchesPage.portDialog.vlanModeAccess')}</SelectItem>
                      <SelectItem value="trunk">{t('SwitchesPage.portDialog.vlanModeTrunk')}</SelectItem>
                      <SelectItem value="hybrid">{t('SwitchesPage.portDialog.vlanModeHybrid')}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label>{t('SwitchesPage.portDialog.nativeVlan')}</Label>
                  <Input
                    type="number"
                    min={1}
                    max={4094}
                    value={portForm.native_vlan}
                    onChange={(e) => setPortForm({ ...portForm, native_vlan: Number(e.target.value) })}
                  />
                </div>

                {portForm.vlan_mode !== 'access' && (
                  <div className="space-y-2">
                    <Label>{t('SwitchesPage.portDialog.taggedVlans')}</Label>
                    <Input
                      placeholder={t('SwitchesPage.portDialog.taggedVlansPlaceholder')}
                      value={portForm.tagged_vlans.join(', ')}
                      onChange={(e) => {
                        const vlans = e.target.value
                          .split(',')
                          .map(v => parseInt(v.trim()))
                          .filter(v => !isNaN(v) && v >= 1 && v <= 4094);
                        setPortForm({ ...portForm, tagged_vlans: vlans });
                      }}
                    />
                  </div>
                )}

              </TabsContent>

              <TabsContent value="poe" className="space-y-4">
                <div className="flex items-center justify-between">
                  <Label>{t('SwitchesPage.portDialog.poeEnabled')}</Label>
                  <Switch
                    checked={portForm.poe_enabled}
                    onCheckedChange={(checked) => setPortForm({ ...portForm, poe_enabled: checked })}
                  />
                </div>

                {portForm.poe_enabled && (
                  <>
                    <div className="space-y-2">
                      <Label>{t('SwitchesPage.portDialog.poeMode')}</Label>
                      <Select
                        value={portForm.poe_mode}
                        onValueChange={(v) => setPortForm({ ...portForm, poe_mode: v })}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {/* Values must match backend PoeConfig.mode Literal: auto | manual | fixed.
                              Wattage is controlled separately via the Power Limit field below. */}
                          <SelectItem value="auto">{t('SwitchesPage.portDialog.poeModeAuto')}</SelectItem>
                          <SelectItem value="manual">{t('SwitchesPage.portDialog.poeModeManual')}</SelectItem>
                          <SelectItem value="fixed">{t('SwitchesPage.portDialog.poeModeFixed')}</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="space-y-2">
                      <Label>{t('SwitchesPage.portDialog.powerLimit')}</Label>
                      <Input
                        type="number"
                        min={1}
                        max={100}
                        value={portForm.poe_limit}
                        onChange={(e) => setPortForm({ ...portForm, poe_limit: Number(e.target.value) })}
                      />
                    </div>

                  </>
                )}
              </TabsContent>

              <TabsContent value="security" className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <Label>{t('SwitchesPage.portDialog.portSecurity')}</Label>
                    <p className="text-xs text-muted-foreground">{t('SwitchesPage.portDialog.portSecurityHint')}</p>
                  </div>
                  <Switch
                    checked={portForm.security_enabled}
                    onCheckedChange={(checked) => setPortForm({ ...portForm, security_enabled: checked })}
                  />
                </div>

                {portForm.security_enabled && (
                  <div className="space-y-2">
                    <Label>{t('SwitchesPage.portDialog.macAddressLimit')}</Label>
                    <Input
                      type="number"
                      min={1}
                      max={1024}
                      value={portForm.mac_limit}
                      onChange={(e) => setPortForm({ ...portForm, mac_limit: Number(e.target.value) })}
                    />
                  </div>
                )}

                <div className="flex items-center justify-between">
                  <div>
                    <Label>{t('SwitchesPage.portDialog.rateLimiting')}</Label>
                    <p className="text-xs text-muted-foreground">{t('SwitchesPage.portDialog.rateLimitingHint')}</p>
                  </div>
                  <Switch
                    checked={portForm.rate_limit_enabled}
                    onCheckedChange={(checked) => setPortForm({ ...portForm, rate_limit_enabled: checked })}
                  />
                </div>
                {portForm.rate_limit_enabled && (
                  <div className="grid grid-cols-2 gap-3 pl-2">
                    <div className="space-y-1">
                      <Label className="text-xs">{t('SwitchesPage.portDialog.ingress')}</Label>
                      <Input
                        type="number"
                        min={0}
                        max={10000000}
                        value={portForm.rate_limit_ingress}
                        onChange={(e) => setPortForm({ ...portForm, rate_limit_ingress: Number(e.target.value) })}
                      />
                    </div>
                    <div className="space-y-1">
                      <Label className="text-xs">{t('SwitchesPage.portDialog.egress')}</Label>
                      <Input
                        type="number"
                        min={0}
                        max={10000000}
                        value={portForm.rate_limit_egress}
                        onChange={(e) => setPortForm({ ...portForm, rate_limit_egress: Number(e.target.value) })}
                      />
                    </div>
                  </div>
                )}

                <div className="flex items-center justify-between">
                  <div>
                    <Label>{t('SwitchesPage.portDialog.stormControl')}</Label>
                    <p className="text-xs text-muted-foreground">{t('SwitchesPage.portDialog.stormControlHint')}</p>
                  </div>
                  <Switch
                    checked={portForm.storm_control_enabled}
                    onCheckedChange={(checked) => setPortForm({ ...portForm, storm_control_enabled: checked })}
                  />
                </div>
                {portForm.storm_control_enabled && (
                  <div className="space-y-2 pl-2">
                    <div className="space-y-1">
                      <Label className="text-xs">{t('SwitchesPage.portDialog.broadcastThreshold')}</Label>
                      <Input
                        type="number"
                        min={0}
                        value={portForm.storm_broadcast_rate}
                        onChange={(e) => setPortForm({ ...portForm, storm_broadcast_rate: Number(e.target.value) })}
                      />
                    </div>
                    <div className="space-y-1">
                      <Label className="text-xs">{t('SwitchesPage.portDialog.multicastThreshold')}</Label>
                      <Input
                        type="number"
                        min={0}
                        value={portForm.storm_multicast_rate}
                        onChange={(e) => setPortForm({ ...portForm, storm_multicast_rate: Number(e.target.value) })}
                      />
                    </div>
                    <div className="space-y-1">
                      <Label className="text-xs">{t('SwitchesPage.portDialog.unknownUnicastThreshold')}</Label>
                      <Input
                        type="number"
                        min={0}
                        value={portForm.storm_unknown_unicast_rate}
                        onChange={(e) => setPortForm({ ...portForm, storm_unknown_unicast_rate: Number(e.target.value) })}
                      />
                    </div>
                  </div>
                )}

                <div className="flex items-center justify-between">
                  <div>
                    <Label>{t('SwitchesPage.portDialog.portIsolation')}</Label>
                    <p className="text-xs text-muted-foreground">{t('SwitchesPage.portDialog.portIsolationHint')}</p>
                  </div>
                  <Switch
                    checked={portForm.isolation_enabled}
                    onCheckedChange={(checked) => setPortForm({ ...portForm, isolation_enabled: checked })}
                  />
                </div>
              </TabsContent>
            </Tabs>

            <DialogFooter>
              <Button variant="outline" onClick={() => setPortDialogOpen(false)}>
                {t('SwitchesPage.actions.cancel')}
              </Button>
              <Button onClick={handlePortSave}>{t('SwitchesPage.actions.saveChanges')}</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* LAG Create/Edit Dialog */}
        <Dialog open={lagDialogOpen || !!editingLag} onOpenChange={(open) => {
          if (!open) { setLagDialogOpen(false); setEditingLag(null); }
        }}>
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle>{editingLag ? t('SwitchesPage.lagDialog.editTitle') : t('SwitchesPage.lagDialog.createTitle')}</DialogTitle>
              <DialogDescription>
                {editingLag ? t('SwitchesPage.lagDialog.editDescription') : t('SwitchesPage.lagDialog.createDescription')}
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label>{t('SwitchesPage.lagDialog.name')}</Label>
                <Input
                  value={lagForm.name}
                  onChange={(e) => setLagForm(f => ({ ...f, name: e.target.value }))}
                  placeholder={t('SwitchesPage.lagDialog.namePlaceholder')}
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>{t('SwitchesPage.lagDialog.mode')}</Label>
                  <Select value={lagForm.mode} onValueChange={(v) => setLagForm(f => ({ ...f, mode: v as 'lacp' | 'static' }))}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="lacp">LACP (802.3ad)</SelectItem>
                      <SelectItem value="static">{t('SwitchesPage.lagDialog.modeStatic')}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                {lagForm.mode === 'lacp' && (
                  <div className="space-y-2">
                    <Label>{t('SwitchesPage.lagDialog.lacpMode')}</Label>
                    <Select value={lagForm.lacp_mode} onValueChange={(v) => setLagForm(f => ({ ...f, lacp_mode: v as 'active' | 'passive' }))}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="active">{t('SwitchesPage.lagDialog.lacpActive')}</SelectItem>
                        <SelectItem value="passive">{t('SwitchesPage.lagDialog.lacpPassive')}</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                )}
              </div>
              <div className="space-y-2">
                <Label>{t('SwitchesPage.lagDialog.memberPorts')}</Label>
                <div className="grid grid-cols-4 md:grid-cols-8 gap-1">
                  {ports.map((port) => (
                    <Button
                      key={port.port_index}
                      variant={lagForm.member_ports.includes(port.port_index) ? "default" : "outline"}
                      size="sm"
                      className="h-8 w-full text-xs"
                      onClick={() => setLagForm(f => ({
                        ...f,
                        member_ports: f.member_ports.includes(port.port_index)
                          ? f.member_ports.filter(p => p !== port.port_index)
                          : [...f.member_ports, port.port_index].sort((a, b) => a - b),
                      }))}
                    >
                      {port.port_index}
                    </Button>
                  ))}
                </div>
                <p className="text-xs text-muted-foreground">
                  {t('SwitchesPage.lagDialog.selected', { ports: lagForm.member_ports.length > 0 ? lagForm.member_ports.join(', ') : t('SwitchesPage.lagDialog.none') })}
                </p>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => { setLagDialogOpen(false); setEditingLag(null); }}>
                {t('SwitchesPage.actions.cancel')}
              </Button>
              <Button
                disabled={!lagForm.name || lagForm.member_ports.length < 2 || lagCreateMutation.isPending || lagUpdateMutation.isPending}
                onClick={() => {
                  if (editingLag) {
                    lagUpdateMutation.mutate({ lagId: editingLag.lag_id, data: lagForm });
                  } else {
                    lagCreateMutation.mutate(lagForm);
                  }
                }}
              >
                {(lagCreateMutation.isPending || lagUpdateMutation.isPending) && (
                  <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                )}
                {editingLag ? t('SwitchesPage.actions.update') : t('SwitchesPage.actions.create')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* LAG Delete Confirmation */}
        <Dialog open={!!lagDeleteConfirm} onOpenChange={(open) => { if (!open) setLagDeleteConfirm(null); }}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{t('SwitchesPage.lagDelete.title')}</DialogTitle>
              <DialogDescription>
                {t('SwitchesPage.lagDelete.description', { name: lagDeleteConfirm?.name })}
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="outline" onClick={() => setLagDeleteConfirm(null)}>{t('SwitchesPage.actions.cancel')}</Button>
              <Button
                variant="destructive"
                disabled={lagDeleteMutation.isPending}
                onClick={() => lagDeleteConfirm && lagDeleteMutation.mutate(lagDeleteConfirm.lag_id)}
              >
                {lagDeleteMutation.isPending && <RefreshCw className="mr-2 h-4 w-4 animate-spin" />}
                {t('SwitchesPage.actions.delete')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Port Profile Create/Edit Dialog */}
        <Dialog open={profileDialogOpen} onOpenChange={(open) => {
          if (!open) { setProfileDialogOpen(false); setEditingProfileId(null); }
        }}>
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle>
                {editingProfileId ? t('ProfilesTab.actions.edit') : t('ProfilesTab.actions.createProfile')}
              </DialogTitle>
              <DialogDescription>{t('ProfilesTab.empty.description')}</DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label>{t('SwitchesPage.lagDialog.name')}</Label>
                <Input
                  value={profileForm.name}
                  onChange={(e) => setProfileForm(f => ({ ...f, name: e.target.value }))}
                  placeholder={t('SwitchesPage.lagDialog.namePlaceholder')}
                />
              </div>
              <div className="space-y-2">
                <Label>{t('SwitchesPage.portDialog.descriptionLabel')}</Label>
                <Textarea
                  value={profileForm.description}
                  onChange={(e) => setProfileForm(f => ({ ...f, description: e.target.value }))}
                  placeholder={t('SwitchesPage.portDialog.descriptionPlaceholder')}
                />
              </div>
              <div className="space-y-2">
                <Label>{t('ProfilesTab.fields.profileType')}</Label>
                <Select value={profileForm.profile_type} onValueChange={(v) => setProfileForm(f => ({ ...f, profile_type: v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="custom">custom</SelectItem>
                    <SelectItem value="ap">ap</SelectItem>
                    <SelectItem value="camera">camera</SelectItem>
                    <SelectItem value="voip">voip</SelectItem>
                    <SelectItem value="printer">printer</SelectItem>
                    <SelectItem value="iot">iot</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>{t('SwitchesPage.portDialog.nativeVlan')}</Label>
                  <Input
                    type="number"
                    value={profileForm.native_vlan}
                    onChange={(e) => setProfileForm(f => ({ ...f, native_vlan: e.target.value }))}
                    placeholder={t('SwitchesPage.portDialog.optional')}
                  />
                </div>
                <div className="space-y-2">
                  <Label>{t('SwitchesPage.portDialog.voiceVlan')}</Label>
                  <Input
                    type="number"
                    value={profileForm.voice_vlan}
                    onChange={(e) => setProfileForm(f => ({ ...f, voice_vlan: e.target.value }))}
                    placeholder={t('SwitchesPage.portDialog.optional')}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label>{t('SwitchesPage.portDialog.taggedVlans')}</Label>
                <Input
                  value={profileForm.tagged_vlans}
                  onChange={(e) => setProfileForm(f => ({ ...f, tagged_vlans: e.target.value }))}
                  placeholder={t('SwitchesPage.portDialog.taggedVlansPlaceholder')}
                />
              </div>
              <div className="flex items-center justify-between">
                <Label>{t('SwitchesPage.portDialog.poeEnabled')}</Label>
                <Switch
                  checked={profileForm.poe_enabled}
                  onCheckedChange={(v) => setProfileForm(f => ({ ...f, poe_enabled: v }))}
                />
              </div>
              <div className="flex items-center justify-between">
                <Label>STP</Label>
                <Switch
                  checked={profileForm.stp_enabled}
                  onCheckedChange={(v) => setProfileForm(f => ({ ...f, stp_enabled: v }))}
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => { setProfileDialogOpen(false); setEditingProfileId(null); }}>
                {t('SwitchesPage.actions.cancel')}
              </Button>
              <Button
                disabled={!profileForm.name.trim() || profileCreateMutation.isPending || profileUpdateMutation.isPending}
                onClick={submitProfile}
              >
                {(profileCreateMutation.isPending || profileUpdateMutation.isPending) && (
                  <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                )}
                {editingProfileId ? t('SwitchesPage.actions.update') : t('SwitchesPage.actions.create')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Apply Profile to selected ports */}
        <Dialog open={applyProfileDialogOpen} onOpenChange={(open) => {
          if (!open) { setApplyProfileDialogOpen(false); setApplyProfileId(''); }
        }}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{t('SwitchesPage.applyProfile.title')}</DialogTitle>
              <DialogDescription>
                {t('SwitchesPage.applyProfile.description', { count: selectedPortIdsForProfile.length })}
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label>{t('SwitchesPage.applyProfile.profileLabel')}</Label>
                <Select value={applyProfileId} onValueChange={setApplyProfileId}>
                  <SelectTrigger>
                    <SelectValue placeholder={t('SwitchesPage.applyProfile.profilePlaceholder')} />
                  </SelectTrigger>
                  <SelectContent>
                    {(profiles || []).map((p) => (
                      <SelectItem key={p.id} value={p.id}>{p.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {(!profiles || profiles.length === 0) && (
                  <p className="text-xs text-muted-foreground">{t('SwitchesPage.applyProfile.noProfiles')}</p>
                )}
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => { setApplyProfileDialogOpen(false); setApplyProfileId(''); }}>
                {t('SwitchesPage.actions.cancel')}
              </Button>
              <Button
                disabled={!applyProfileId || selectedPortIdsForProfile.length === 0 || applyProfileMutation.isPending}
                onClick={() => applyProfileMutation.mutate({ profileId: applyProfileId, portIds: selectedPortIdsForProfile })}
              >
                {applyProfileMutation.isPending && <RefreshCw className="mr-2 h-4 w-4 animate-spin" />}
                {t('SwitchesPage.applyProfile.apply')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Port Profile Delete Confirmation */}
        <Dialog open={!!profileDeleteConfirm} onOpenChange={(open) => { if (!open) setProfileDeleteConfirm(null); }}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{t('ProfilesTab.actions.delete')}</DialogTitle>
              <DialogDescription>
                {t('SwitchesPage.lagDelete.description', { name: profileDeleteConfirm?.name })}
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="outline" onClick={() => setProfileDeleteConfirm(null)}>{t('SwitchesPage.actions.cancel')}</Button>
              <Button
                variant="destructive"
                disabled={profileDeleteMutation.isPending}
                onClick={() => profileDeleteConfirm && profileDeleteMutation.mutate(profileDeleteConfirm.id)}
              >
                {profileDeleteMutation.isPending && <RefreshCw className="mr-2 h-4 w-4 animate-spin" />}
                {t('SwitchesPage.actions.delete')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    );
  }

  // Switch list view
  return (
    <div className="space-y-6">
        {/* Header */}
        <PageHeader
          title={t('SwitchesPage.header.title')}
          description={t('SwitchesPage.header.description')}
          icon={Network}
          onRefresh={() => _refetchSwitches()}
          refreshing={switchesLoading}
          secondaryActions={[{ label: t('SwitchesPage.actions.export'), icon: Download, onClick: handleExportSwitches }]}
          primaryAction={{
            label: t('SwitchesPage.actions.addSwitch'),
            icon: Plus,
            onClick: () => navigate('/discovery'),
          }}
        />

      {/* Error State */}
      {switchesError && (
        <ErrorState
          message={t('SwitchesPage.errorState.message')}
          onRetry={() => _refetchSwitches()}
        />
      )}

      {/* Summary */}
      {!switchesError && switches && (
        <StatsGrid
          columns={4}
          isLoading={switchesLoading}
          stats={[
            {
              title: t('SwitchesPage.stats.totalSwitches'),
              value: switches.length,
              icon: Network,
              variant: 'primary',
              description: t('SwitchesPage.stats.onlineCount', { count: switches.filter((s) => s.status === 'online').length }),
            },
            {
              title: t('SwitchesPage.stats.activePorts'),
              value: `${switches.reduce((sum, s) => sum + s.ports_up, 0)} / ${switches.reduce((sum, s) => sum + s.total_ports, 0)}`,
              icon: Activity,
              variant: 'info',
              description: t('SwitchesPage.stats.portsUpTotal'),
            },
            {
              title: t('SwitchesPage.stats.poePower'),
              value: `${switches.reduce((sum, s) => sum + s.poe_used, 0).toFixed(1)}W`,
              icon: Zap,
              variant: 'warning',
              description: t('SwitchesPage.stats.ofBudget', { budget: switches.reduce((sum, s) => sum + s.poe_budget, 0) }),
            },
            {
              title: t('SwitchesPage.stats.portProfiles'),
              value: profiles?.length || 0,
              icon: Copy,
              variant: 'default',
              description: t('SwitchesPage.stats.portsUsing', { count: profiles?.reduce((sum, p) => sum + p.ports_using, 0) || 0 }),
            },
          ]}
        />
      )}

      {/* Empty State */}
      {!switchesLoading && (!switches || switches.length === 0) && (
        <EmptyState
          icon={Network}
          title={t('SwitchesPage.empty.title')}
          description={t('SwitchesPage.empty.description')}
          variant="card"
        />
      )}

      {/* Switch List */}
      {switches && switches.length > 0 && (
      <div className="space-y-4">
        {switches.map((sw) => (
          <Card key={sw.id} className="overflow-hidden">
            <Collapsible
              open={expandedSwitches.includes(sw.id)}
              onOpenChange={() => toggleSwitchExpand(sw.id)}
            >
              <CollapsibleTrigger asChild>
                <CardHeader className="cursor-pointer hover:bg-muted/50">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      {expandedSwitches.includes(sw.id) ? (
                        <ChevronDown className="h-5 w-5" />
                      ) : (
                        <ChevronRight className="h-5 w-5" />
                      )}
                      <Network className="h-8 w-8 text-muted-foreground" />
                      <div>
                        <CardTitle className="text-xl">{sw.name}</CardTitle>
                        <CardDescription>
                          {sw.vendor} {sw.model} • {sw.site_name}
                        </CardDescription>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        <div className="flex items-center gap-2">
                          <div className={`h-2 w-2 rounded-full ${getStatusColor(sw.status)}`} />
                          <span className="capitalize">{sw.status}</span>
                        </div>
                        <div className="text-sm text-muted-foreground">
                          {t('SwitchesPage.list.portsUp', { up: sw.ports_up, total: sw.total_ports })}
                        </div>
                      </div>
                      <Button
                        variant="outline"
                        onClick={(e) => {
                          e.stopPropagation();
                          selectSwitch(sw);
                        }}
                      >
                        {t('SwitchesPage.actions.manage')}
                      </Button>
                    </div>
                  </div>
                </CardHeader>
              </CollapsibleTrigger>

              <CollapsibleContent>
                <CardContent className="pt-0">
                  <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 py-4 border-t">
                    <div>
                      <span className="text-sm text-muted-foreground">{t('SwitchesPage.list.uptime')}</span>
                      <div className="font-medium">{formatUptime(sw.uptime)}</div>
                    </div>
                    <div>
                      <span className="text-sm text-muted-foreground">{t('SwitchesPage.list.cpu')}</span>
                      <div className="font-medium">{sw.cpu_usage}%</div>
                    </div>
                    <div>
                      <span className="text-sm text-muted-foreground">{t('SwitchesPage.list.memory')}</span>
                      <div className="font-medium">{sw.memory_usage}%</div>
                    </div>
                    <div>
                      <span className="text-sm text-muted-foreground">{t('SwitchesPage.list.poe')}</span>
                      <div className="font-medium">{sw.poe_used.toFixed(1)}W / {sw.poe_budget}W</div>
                    </div>
                    <div>
                      <span className="text-sm text-muted-foreground">{t('SwitchesPage.list.firmware')}</span>
                      <div className="flex items-center gap-1">
                        <span className="font-medium">v{sw.firmware_version}</span>
                        {sw.update_available && (
                          <Badge variant="secondary" className="text-xs">{t('SwitchesPage.list.update')}</Badge>
                        )}
                      </div>
                    </div>
                    <div>
                      <span className="text-sm text-muted-foreground">{t('SwitchesPage.list.vlans')}</span>
                      <div className="font-medium">{sw.vlans_configured}</div>
                    </div>
                  </div>

                  {/* Mini port visualization */}
                  <div className="pt-4 border-t">
                    <div className="text-sm text-muted-foreground mb-2">{t('SwitchesPage.list.portStatus')}</div>
                    <div className="flex gap-1 flex-wrap">
                      {/* Up ports (green) */}
                      {Array.from({ length: sw.ports_up }, (_, i) => (
                        <div
                          key={`up-${i}`}
                          className="h-4 w-4 rounded bg-success"
                          title={t('SwitchesPage.list.portUp')}
                        />
                      ))}
                      {/* Down ports (yellow) */}
                      {Array.from({ length: sw.ports_down }, (_, i) => (
                        <div
                          key={`down-${i}`}
                          className="h-4 w-4 rounded bg-warning"
                          title={t('SwitchesPage.list.portDown')}
                        />
                      ))}
                      {/* Disabled ports (gray) */}
                      {Array.from({ length: sw.ports_disabled }, (_, i) => (
                        <div
                          key={`disabled-${i}`}
                          className="h-4 w-4 rounded bg-muted-foreground"
                          title={t('SwitchesPage.list.portDisabled')}
                        />
                      ))}
                    </div>
                  </div>
                </CardContent>
              </CollapsibleContent>
            </Collapsible>
          </Card>
        ))}
      </div>
      )}
    </div>
  );
}
