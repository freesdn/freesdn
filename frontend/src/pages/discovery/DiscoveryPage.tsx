// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Discovery Page
 * =============================
 *
 * Complete device discovery interface with:
 * - Network subnet scanning (target-based, 4-phase async pipeline)
 * - Controller-based discovery (via adapters)
 * - Agent-based deep scanning (L2/L3 OS-level probes)
 * - Live scan progress with phases
 * - Discovered device cards with fingerprinting
 * - Driver matching & device adoption (3-step wizard)
 * - Bulk adopt selected devices
 * - Scan history panel
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Radar,
  RefreshCw,
  Server,
  CheckCircle,
  Clock,
  AlertTriangle,
  Loader2,
  Play,
  Square,
  Network,
  Globe,
  Fingerprint,
  Zap,
  Settings,
  Grid3X3,
  List,
  Bot,
  CheckSquare,
  X,
  Search,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Input } from '@/components/ui/input';
import { SearchBar } from '@/components/ui/search-bar';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import {
  controllersApi,
  sitesApi,
  discoveryApi,
  agentsApi,
  type ScanRequest,
  type ScanProgress as ScanProgressType,
  type DiscoveredDevice as ApiDiscoveredDevice,
  type ScanResults,
  type Driver,
  type AgentSummary,
  getApiErrorMessage,
} from '@/lib/api';
import { useWebSocket } from '@/hooks/useWebSocket';
import { useWebSocketStore } from '@/stores';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';
import { PageHeader } from '@/components/layout';
import { EmptyState } from '@/components/ui/empty-state';
import { useSiteStore } from '@/stores/siteStore';

// Sub-components
import {
  ScanWizard,
  ScanProgress,
  DiscoveredDeviceCard,
  AdoptDeviceDialog,
  DeviceDetailsDialog,
  DiscoveryStats,
  ScanHistoryPanel,
} from '@/components/discovery';
import type { DiscoveredDevice } from '@/components/discovery/DiscoveredDeviceCard';
import { AgentDiscoveriesTab } from '@/components/discovery/AgentDiscoveriesTab';
import { TopologyDiscoveryTab } from '@/components/discovery/TopologyDiscoveryTab';

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

interface ControllerItem {
  id: string;
  name: string;
  type: string;
  host: string;
  status: string;
  site_id: string;
  site_name?: string;
  last_sync: string | null;
}

interface SiteItem {
  id: string;
  name: string;
  subnets?: Array<{ cidr: string; name?: string }>;
}

type DiscoveryTab = 'network' | 'controllers' | 'agent' | 'discovered' | 'topology';

const VENDOR_COLORS: Record<string, string> = {
  'tp-link': 'bg-teal-500/10 text-teal-500 border-teal-500/20',
  hikvision: 'bg-red-500/10 text-red-500 border-red-500/20',
  mikrotik: 'bg-sky-500/10 text-sky-500 border-sky-500/20',
  ubiquiti: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
  cisco: 'bg-indigo-500/10 text-indigo-500 border-indigo-500/20',
  dahua: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
  fortinet: 'bg-red-600/10 text-red-600 border-red-600/20',
  grandstream: 'bg-purple-500/10 text-purple-500 border-purple-500/20',
  netgate: 'bg-blue-600/10 text-blue-600 border-blue-600/20',
  deciso: 'bg-orange-600/10 text-orange-600 border-orange-600/20',
};

// ─────────────────────────────────────────────────────────────────────
// Helpers: convert API device shape → component device shape
// ─────────────────────────────────────────────────────────────────────

function toComponentDevice(d: ApiDiscoveredDevice): DiscoveredDevice {
  return {
    ip: d.ip_address,
    mac: d.mac_address,
    hostname: d.hostname,
    vendor: d.vendor,
    device_type: d.device_type,
    open_ports: d.open_ports,
    confidence: d.vendor_confidence ?? d.device_type_confidence,
    driver_match: d.driver_match
      ? {
          driver_id: d.driver_match.driver_id,
          driver_name: d.driver_match.driver_name,
          confidence: Math.round(d.driver_match.confidence * 100),
          reasons: d.driver_match.match_reasons,
          is_manageable: d.is_manageable,
        }
      : undefined,
    is_adopted: d.adopted,
    status: d.adopted ? 'adopted' : d.driver_match ? 'matched' : 'new',
    fingerprint: (d as any).fingerprint_data as Record<string, unknown> | undefined,
  };
}

// ─────────────────────────────────────────────────────────────────────
// Main Page Component
// ─────────────────────────────────────────────────────────────────────

export default function DiscoveryPage() {
  const { t } = useTranslation('discovery');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // Active tab · URL-driven
  const navigate = useNavigate();
  const { tab: urlTab } = useParams<{ tab?: string }>();
  const DISCOVERY_TABS = ['network', 'controllers', 'agent', 'discovered', 'topology'] as const;
  const activeTab: DiscoveryTab = DISCOVERY_TABS.includes(urlTab as any) ? (urlTab as DiscoveryTab) : 'network';
  const setActiveTab = (v: DiscoveryTab) => navigate(v === 'network' ? '/discovery' : `/discovery/${v}`, { replace: true });

  // ── Network Scan State ──
  const [scanTargets, setScanTargets] = useState('');
  const [scanPorts] = useState('22,23,80,443,554,8080,8443');
  const [probeServices, setProbeServices] = useState(true);
  const [resolveHostnames, setResolveHostnames] = useState(true);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [scanProgress, setScanProgress] = useState<ScanProgressType | null>(null);
  const [scanResults, setScanResults] = useState<ScanResults | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const progressPollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Cleanup interval on unmount to prevent memory leaks
  useEffect(() => {
    return () => {
      if (progressPollRef.current) {
        clearInterval(progressPollRef.current);
        progressPollRef.current = null;
      }
    };
  }, []);

  // ── Controller Discovery State ──
  const [selectedController, setSelectedController] = useState<string>('all');
  const [controllerDiscoveryStatus, setControllerDiscoveryStatus] = useState<
    'idle' | 'running' | 'completed' | 'failed'
  >('idle');
  const [controllerProgressMsg, setControllerProgressMsg] = useState('');
  const [controllerStats, setControllerStats] = useState<{
    totalDevices: number;
    newDevices: number;
    updatedDevices: number;
    failedControllers: number;
  } | null>(null);

  // ── Wizard / View State ──
  const [wizardOpen, setWizardOpen] = useState(false);
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [searchQuery, setSearchQuery] = useState('');
  const [controllerSearch, setControllerSearch] = useState('');

  // ── Device Dialogs ──
  const [selectedDevice, setSelectedDevice] = useState<DiscoveredDevice | null>(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [adoptOpen, setAdoptOpen] = useState(false);
  const [adoptDevice, setAdoptDevice] = useState<DiscoveredDevice | null>(null);

  // ── Bulk selection ──
  const [selectionMode, setSelectionMode] = useState(false);
  const [selectedDevices, setSelectedDevices] = useState<Set<string>>(new Set());

  // ── Agent scan state ──
  const [agentScanTarget, setAgentScanTarget] = useState('');
  const [agentTaskId, setAgentTaskId] = useState<string | null>(null);
  const [selectedAgentId, setSelectedAgentId] = useState<string>('');

  // ── Stats (accumulated) ──
  const [totalScans, setTotalScans] = useState(0);

  // ── Data fetching ──
  const { data: sitesData, isError: isErrorSites } = useQuery({
    queryKey: ['sites', { siteId: selectedSiteId }],
    queryFn: async () => {
      const response = await sitesApi.getAll();
      return response.data;
    },
  });
  const sites: SiteItem[] = useMemo(() => sitesData?.items ?? [], [sitesData?.items]);

  const {
    data: controllersData,
    isLoading: controllersLoading,
    isError: isErrorControllers,
    refetch: refetchControllers,
  } = useQuery({
    queryKey: ['controllers', { siteId: selectedSiteId }],
    queryFn: async () => {
      const response = await controllersApi.getAll(selectedSiteId ?? undefined);
      return response.data;
    },
  });
  const controllers: ControllerItem[] = controllersData?.items || [];

  const { data: driversData, isError: isErrorDrivers } = useQuery({
    queryKey: ['discovery-drivers', { siteId: selectedSiteId }],
    queryFn: async () => {
      const response = await discoveryApi.listDrivers();
      return response.data;
    },
  });
  const drivers: Driver[] = Array.isArray(driversData) ? driversData : [];

  // Online agents for the Agent Scan tab. The /discovery/agent-scan endpoint
  // requires a real, online RemoteAgent UUID (it 422s on a missing/unknown id
  // and 400s if the agent isn't online), so we list online agents, scoped to
  // the selected site when one is active, and let the operator pick one.
  const { data: agentsData, isLoading: agentsLoading } = useQuery({
    queryKey: ['discovery-online-agents', { siteId: selectedSiteId }],
    queryFn: async () => {
      const params: { status: string; per_page: number; site_id?: string } = {
        status: 'online',
        per_page: 200,
      };
      if (selectedSiteId) params.site_id = selectedSiteId;
      const response = await agentsApi.list(params);
      return response.data;
    },
    refetchInterval: 30000,
  });
  const onlineAgents: AgentSummary[] = useMemo(() => agentsData?.items ?? [], [agentsData?.items]);

  // Keep the selected agent valid: clear the selection if the chosen agent
  // drops offline / out of the (possibly site-filtered) list.
  useEffect(() => {
    if (selectedAgentId && !onlineAgents.some((a) => a.id === selectedAgentId)) {
      setSelectedAgentId('');
    }
  }, [onlineAgents, selectedAgentId]);

  // ── WebSocket for real-time updates ──
  const wsStatus = useWebSocketStore((s) => s.connectionStatus);
  useWebSocket({
    enabled: true,
    // Page-scoped secondary socket: only needs discovery progress. Scope the
    // subscription to discovery.* and suppress global window-event dispatches so
    // it doesn't double-fire camera/vpn/pbx toasts the App-wide socket already
    // handles.
    subscriptions: ['discovery.*', 'device.*', 'controller.*'],
    dispatchWindowEvents: false,
    onMessage: (msg: any) => {
      // The production WS forwarder wraps every bus event as
      // {type:'event', event:{event_type, payload, ...}} (websocket.py
      // register_event_bus_forwarder + Event.to_dict). Unwrap that envelope
      // before branching, the old flat {event_type, data} read never matched,
      // so the whole controller-discovery realtime layer was dead.
      const inner = msg?.type === 'event' ? msg.event : msg;
      const eventType: string = inner?.event_type ?? inner?.type ?? '';
      const payload = inner?.payload ?? {};

      if (eventType === 'discovery.started') {
        setControllerDiscoveryStatus('running');
        setControllerProgressMsg(
          t('DiscoveryPage.ws.discovering', {
            target: payload?.controller_name || t('DiscoveryPage.ws.devices'),
          }),
        );
      } else if (eventType === 'discovery.progress') {
        setControllerProgressMsg(payload?.message || t('DiscoveryPage.ws.inProgress'));
      } else if (eventType === 'discovery.completed') {
        setControllerDiscoveryStatus('completed');
        // Backend stats use snake_case per-controller keys (DiscoveryService
        // ._process_devices → {total, new, updated, ...}); map them to the
        // camelCase the cards render. failedControllers isn't carried on a
        // per-controller completed event, so default it to 0.
        const s = payload?.stats ?? {};
        setControllerStats({
          totalDevices: s.total ?? 0,
          newDevices: s.new ?? 0,
          updatedDevices: s.updated ?? 0,
          failedControllers: s.failed_controllers ?? 0,
        });
        setControllerProgressMsg('');
        queryClient.invalidateQueries({ queryKey: ['controllers'] });
        queryClient.invalidateQueries({ queryKey: ['devices'] });
      } else if (eventType === 'discovery.failed') {
        setControllerDiscoveryStatus('failed');
        setControllerProgressMsg(payload?.error || t('DiscoveryPage.ws.discoveryFailed'));
      } else if (eventType === 'discovery.scan_progress') {
        const d = payload;
        if (d?.scan_id && d.scan_id === activeScanId) {
          setScanProgress((prev: any) => ({
            ...prev,
            scan_id: d.scan_id,
            status: d.status,
            current_phase: d.phase,
            progress: d.progress_pct ?? prev?.progress ?? 0,
            discovered_hosts: d.discovered,
            total_hosts: d.total,
            hosts_scanned: prev?.hosts_scanned ?? 0,
            devices_found: d.discovered,
            devices_identified: prev?.devices_identified ?? 0,
          }));
        }
      }
    },
  });

  // ── Progress polling for network scans ──
  const startProgressPolling = useCallback(
    (scanId: string) => {
      if (progressPollRef.current) clearInterval(progressPollRef.current);
      progressPollRef.current = setInterval(async () => {
        try {
          const res = await discoveryApi.getScanProgress(scanId);
          const p = res.data;
          setScanProgress(p);

          if (p.status === 'completed' || p.status === 'failed' || p.status === 'cancelled') {
            clearInterval(progressPollRef.current!);
            progressPollRef.current = null;
            setIsScanning(false);

            const resultsRes = await discoveryApi.getScanResults(scanId);
            setScanResults(resultsRes.data);

            if (p.status === 'completed') {
              setTotalScans((prev) => prev + 1);
              toast({
                title: t('DiscoveryPage.toast.scanComplete.title'),
                description: t('DiscoveryPage.toast.scanComplete.description', {
                  count: resultsRes.data.total_discovered,
                }),
              });
            }
          }
        } catch {
          // Scan may not be ready yet, continue polling
        }
      }, 1500);
    },
    [toast, t],
  );

  useEffect(() => {
    return () => {
      if (progressPollRef.current) clearInterval(progressPollRef.current);
    };
  }, []);

  // ── Mutations ──
  const startScanMutation = useMutation({
    mutationFn: async (request: ScanRequest) => {
      const response = await discoveryApi.startScan(request);
      return response.data;
    },
    onSuccess: (data) => {
      setActiveScanId(data.scan_id);
      setIsScanning(true);
      setScanResults(null);
      startProgressPolling(data.scan_id);
      toast({ title: t('DiscoveryPage.toast.scanStarted.title'), description: data.message });
    },
    onError: (err: any) => {
      toast({
        title: t('DiscoveryPage.toast.scanFailed.title'),
        description: err.response?.data?.detail || t('DiscoveryPage.toast.scanFailed.description'),
        variant: 'destructive',
      });
    },
  });

  const cancelScanMutation = useMutation({
    mutationFn: async () => {
      if (!activeScanId) return;
      await discoveryApi.cancelScan(activeScanId);
    },
    onSuccess: () => {
      setIsScanning(false);
      if (progressPollRef.current) clearInterval(progressPollRef.current);
      toast({ title: t('DiscoveryPage.toast.scanCancelled.title') });
    },
    onError: (err: any) => {
      toast({
        title: t('DiscoveryPage.toast.cancelFailed.title'),
        description: err.response?.data?.detail || t('DiscoveryPage.toast.cancelFailed.description'),
        variant: 'destructive',
      });
    },
  });

  const discoverControllerMutation = useMutation({
    mutationFn: async (controllerId: string) => {
      const response = await discoveryApi.discoverController(controllerId, { sync: false });
      return response.data;
    },
    onSuccess: () => setControllerDiscoveryStatus('running'),
    onError: (error: any) => {
      setControllerDiscoveryStatus('failed');
      setControllerProgressMsg(getApiErrorMessage(error, t('DiscoveryPage.errors.startDiscovery')));
    },
  });

  const discoverAllMutation = useMutation({
    mutationFn: async () => {
      const response = await discoveryApi.discoverAll();
      return response.data;
    },
    onSuccess: () => setControllerDiscoveryStatus('running'),
    onError: (error: any) => {
      setControllerDiscoveryStatus('failed');
      setControllerProgressMsg(getApiErrorMessage(error, t('DiscoveryPage.errors.startDiscovery')));
    },
  });

  const agentScanMutation = useMutation({
    mutationFn: async (data: { agentId: string; targets: string[] }) => {
      const response = await discoveryApi.startAgentScan({
        agent_id: data.agentId,
        targets: data.targets,
        scan_type: 'deep',
      });
      return response.data;
    },
    onSuccess: (data) => {
      setAgentTaskId(data.task_id);
      toast({
        title: t('DiscoveryPage.toast.agentScanStarted.title'),
        description: t('DiscoveryPage.toast.agentScanStarted.description'),
      });
    },
    onError: (err: any) => {
      toast({
        title: t('DiscoveryPage.toast.agentScanFailed.title'),
        description:
          err.response?.data?.detail || t('DiscoveryPage.toast.agentScanFailed.description'),
        variant: 'destructive',
      });
    },
  });

  // ── Poll the dispatched agent scan to completion ──
  // The /discovery/agent-scan/{task_id} endpoint returns {status, progress,
  // result, error_message}. Mirror RunScanDialog: poll every 1.5s while the
  // AgentTask is non-terminal, stop on a terminal status. On terminal we clear
  // the in-progress UI, toast success/failure, and invalidate the device list
  // (discovered hosts land in inventory via the agent report path).
  const AGENT_TERMINAL_STATUSES = new Set(['completed', 'failed', 'cancelled']);
  const { data: agentScanTask } = useQuery({
    queryKey: ['discovery', 'agent-scan', agentTaskId],
    queryFn: async () => {
      const res = await discoveryApi.getAgentScanStatus(agentTaskId!);
      return res.data;
    },
    enabled: !!agentTaskId,
    refetchInterval: (query) => {
      const data = query.state.data as { status?: string } | undefined;
      if (data && AGENT_TERMINAL_STATUSES.has(data.status ?? '')) return false;
      return 1500;
    },
  });

  // Fire once when the agent scan reaches a terminal state: clear the spinner,
  // surface success/failure, and refresh the inventory lists.
  useEffect(() => {
    if (!agentScanTask || !AGENT_TERMINAL_STATUSES.has(agentScanTask.status)) return;
    if (agentScanTask.status === 'completed') {
      toast({
        title: t('DiscoveryPage.toast.agentScanComplete.title'),
        description: t('DiscoveryPage.toast.agentScanComplete.description'),
      });
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      queryClient.invalidateQueries({ queryKey: ['discovered-hosts'] });
    } else {
      toast({
        title: t('DiscoveryPage.toast.agentScanFailed.title'),
        description:
          (agentScanTask as { error_message?: string }).error_message ||
          t('DiscoveryPage.toast.agentScanFailed.description'),
        variant: agentScanTask.status === 'failed' ? 'destructive' : undefined,
      });
    }
    setAgentTaskId(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agentScanTask?.status]);

  const bulkAdoptMutation = useMutation({
    mutationFn: async (devices: DiscoveredDevice[]) => {
      // driver_id is omitted intentionally, backend auto-matches per host
      // and falls back to "generic" for hosts without a confident vendor
      // adapter match (mirrors AgentDiscoveriesTab). Do not invent
      // client-side driver ids like 'generic-snmp' (not a registry id).
      const requests = devices.map((d) => ({
        ip_address: d.ip,
        name: d.hostname || d.ip,
        mac_address: d.mac,
        site_id: selectedSiteId ?? sites[0]?.id ?? '',
        device_type: d.device_type || 'unknown',
      }));
      const res = await discoveryApi.bulkAdoptDevices(requests);
      return res.data;
    },
    onSuccess: (data) => {
      toast({
        title: t('DiscoveryPage.toast.bulkAdoptComplete.title'),
        description: t('DiscoveryPage.toast.bulkAdoptComplete.description', {
          succeeded: data.succeeded,
          failed: data.failed,
        }),
      });
      setSelectionMode(false);
      setSelectedDevices(new Set());
      queryClient.invalidateQueries({ queryKey: ['devices'] });
    },
    onError: (err: any) => {
      toast({
        title: t('DiscoveryPage.toast.bulkAdoptFailed.title'),
        description:
          err.response?.data?.detail || t('DiscoveryPage.toast.bulkAdoptFailed.description'),
        variant: 'destructive',
      });
    },
  });

  // ── Handlers ──
  const handleQuickScan = useCallback(() => {
    const targets = scanTargets
      .split(/[,\n]+/)
      .map((t: string) => t.trim())
      .filter(Boolean);

    if (targets.length === 0) {
      toast({
        title: t('DiscoveryPage.toast.noTargets.title'),
        description: t('DiscoveryPage.toast.noTargets.description'),
        variant: 'destructive',
      });
      return;
    }

    const ports = scanPorts
      .split(',')
      .map((p: string) => parseInt(p.trim(), 10))
      .filter((p: number) => !isNaN(p) && p > 0 && p < 65536);

    startScanMutation.mutate({
      targets,
      tcp_ports: ports.length > 0 ? ports : undefined,
      scan_methods: ['tcp_connect', 'mdns', 'ssdp'],
      // Backend ScanOptionsSchema field names (the FE toggles were dropped
      // before because they used keys the server ignores).
      options: {
        probe_services: probeServices,
        resolve_hostnames: resolveHostnames,
      },
    });
  }, [scanTargets, scanPorts, probeServices, resolveHostnames, startScanMutation, toast, t]);

  const handleWizardScan = useCallback(
    (request: ScanRequest) => {
      startScanMutation.mutate(request);
      setWizardOpen(false);
    },
    [startScanMutation],
  );

  // Controller-type wizard scans don't hit /discovery/scan (no IP targets).
  // They trigger adapter-based discovery on a registered controller and the
  // live status surfaces on the Controllers tab, so route there.
  const handleWizardControllerScan = useCallback(
    (controllerId: string) => {
      setControllerStats(null);
      discoverControllerMutation.mutate(controllerId);
      setWizardOpen(false);
      // Route to the Controllers tab so live discovery status is visible
      // (setActiveTab is unmemoized; navigate is stable from react-router).
      navigate('/discovery/controllers', { replace: true });
    },
    [discoverControllerMutation, navigate],
  );

  const handleControllerDiscover = useCallback(() => {
    setControllerStats(null);
    if (selectedController !== 'all') {
      discoverControllerMutation.mutate(selectedController);
    } else {
      discoverAllMutation.mutate();
    }
  }, [selectedController, discoverControllerMutation, discoverAllMutation]);

  const handleFillFromSite = useCallback(
    (siteId: string) => {
      const site = sites.find((s) => s.id === siteId);
      if (site?.subnets?.length) {
        setScanTargets(site.subnets.map((s) => s.cidr).join('\n'));
      }
    },
    [sites],
  );

  // ── Device actions ──
  const handleViewDetails = useCallback((device: DiscoveredDevice) => {
    setSelectedDevice(device);
    setDetailsOpen(true);
  }, []);

  const handleAdoptClick = useCallback((device: DiscoveredDevice) => {
    setAdoptDevice(device);
    setAdoptOpen(true);
  }, []);

  const handleSelectionChange = useCallback((device: DiscoveredDevice, checked: boolean) => {
    setSelectedDevices((prev) => {
      const next = new Set(prev);
      if (checked) next.add(device.ip);
      else next.delete(device.ip);
      return next;
    });
  }, []);

  // ── Computed: convert API devices to component devices, filter ──
  const componentDevices: DiscoveredDevice[] = (scanResults?.devices || []).map(toComponentDevice);

  const handleBulkAdopt = useCallback(() => {
    const devices = componentDevices.filter((d) => selectedDevices.has(d.ip));
    if (devices.length > 0) bulkAdoptMutation.mutate(devices);
  }, [selectedDevices, bulkAdoptMutation, componentDevices]);

  const filteredDevices = componentDevices.filter((d) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      d.ip?.toLowerCase().includes(q) ||
      d.hostname?.toLowerCase().includes(q) ||
      d.vendor?.toLowerCase().includes(q) ||
      d.device_type?.toLowerCase().includes(q) ||
      d.mac?.toLowerCase().includes(q)
    );
  });

  // Stats
  const stats = {
    totalScans: totalScans,
    devicesFound: scanResults?.total_discovered ?? 0,
    adopted: componentDevices.filter((d) => d.is_adopted).length,
    activeScans: isScanning ? 1 : 0,
    pending: componentDevices.filter((d) => d.status === 'new').length,
    failed: 0,
  };

  // Reset controller status
  useEffect(() => {
    if (controllerDiscoveryStatus === 'completed' || controllerDiscoveryStatus === 'failed') {
      const timer = setTimeout(() => setControllerDiscoveryStatus('idle'), 5000);
      return () => clearTimeout(timer);
    }
  }, [controllerDiscoveryStatus]);

  const filteredControllers = controllers.filter((c) => {
    if (!controllerSearch) return true;
    const q = controllerSearch.toLowerCase();
    return (
      c.name.toLowerCase().includes(q) ||
      c.host.toLowerCase().includes(q) ||
      c.type.toLowerCase().includes(q)
    );
  });

  const hasQueryError = isErrorSites || isErrorControllers || isErrorDrivers;

  // ─────────────────────────────────────────────────────────────────
  // Render
  // ─────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        icon={Radar}
        title={t('DiscoveryPage.header.title')}
        subtitle={t('DiscoveryPage.header.subtitle')}
        onRefresh={() => refetchControllers()}
        refreshing={controllersLoading}
        actions={
          <div className="flex items-center gap-3">
            <div
              className={cn(
                'w-2 h-2 rounded-full',
                wsStatus === 'online' ? 'bg-emerald-500' : 'bg-muted-foreground',
              )}
            />
            <span className="text-sm text-muted-foreground">
              {wsStatus === 'online'
                ? t('DiscoveryPage.status.live')
                : t('DiscoveryPage.status.connecting')}
            </span>
          </div>
        }
      />

      {hasQueryError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('DiscoveryPage.errors.partialLoad')}</span>
          </CardContent>
        </Card>
      )}

      {/* Discovery Stats */}
      <DiscoveryStats
        totalScans={stats.totalScans}
        devicesFound={stats.devicesFound}
        devicesAdopted={stats.adopted}
        activeScans={stats.activeScans}
        pendingDevices={stats.pending}
        failedScans={stats.failed}
      />

      {/* Tabs: Network Scan / Controller Discovery / Agent Scan */}
      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as DiscoveryTab)}>
        <TabsList>
          <TabsTrigger value="network" className="gap-2">
            <Network className="h-4 w-4" />
            {t('DiscoveryPage.tabs.network')}
          </TabsTrigger>
          <TabsTrigger value="controllers" className="gap-2">
            <Server className="h-4 w-4" />
            {t('DiscoveryPage.tabs.controllers')}
          </TabsTrigger>
          <TabsTrigger value="agent" className="gap-2">
            <Bot className="h-4 w-4" />
            {t('DiscoveryPage.tabs.agent')}
          </TabsTrigger>
          <TabsTrigger value="discovered" className="gap-2">
            <Network className="h-4 w-4" />
            {t('DiscoveryPage.tabs.discovered')}
          </TabsTrigger>
          <TabsTrigger value="topology" className="gap-2">
            <Network className="h-4 w-4" />
            {t('DiscoveryPage.tabs.topology')}
          </TabsTrigger>
        </TabsList>

        {/* ═══════════════════════════════════════════════════════════ */}
        {/* NETWORK SCAN TAB */}
        {/* ═══════════════════════════════════════════════════════════ */}
        <TabsContent value="network" className="space-y-6 mt-6">
          {/* Quick scan bar OR Wizard */}
          {wizardOpen ? (
            <ScanWizard
              sites={sites}
              controllers={controllers}
              onStartScan={handleWizardScan}
              onStartControllerScan={handleWizardControllerScan}
              onCancel={() => setWizardOpen(false)}
              isLoading={startScanMutation.isPending || discoverControllerMutation.isPending}
            />
          ) : (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="h-5 w-5 text-amber-500" />
                  {t('DiscoveryPage.networkScan.title')}
                </CardTitle>
                <CardDescription>
                  {t('DiscoveryPage.networkScan.description')}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex flex-col sm:flex-row gap-3">
                  <div className="flex-1">
                    <Input
                      placeholder={t('DiscoveryPage.networkScan.targetsPlaceholder')}
                      value={scanTargets}
                      onChange={(e) => setScanTargets(e.target.value)}
                      disabled={isScanning}
                    />
                  </div>

                  {sites.length > 0 && (
                    <Select onValueChange={handleFillFromSite}>
                      <SelectTrigger className="w-48">
                        <SelectValue placeholder={t('DiscoveryPage.networkScan.fillFromSite')} />
                      </SelectTrigger>
                      <SelectContent>
                        {sites.map((site) => (
                          <SelectItem key={site.id} value={site.id}>
                            {site.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  )}

                  {!isScanning ? (
                    <Button
                      onClick={handleQuickScan}
                      className="gap-2"
                      disabled={startScanMutation.isPending}
                    >
                      {startScanMutation.isPending ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <Play className="h-4 w-4" />
                      )}
                      {t('DiscoveryPage.networkScan.scan')}
                    </Button>
                  ) : (
                    <Button
                      variant="destructive"
                      onClick={() => cancelScanMutation.mutate()}
                      className="gap-2"
                    >
                      <Square className="h-4 w-4" />
                      {t('DiscoveryPage.networkScan.cancel')}
                    </Button>
                  )}

                  <Button
                    variant="outline"
                    onClick={() => setWizardOpen(true)}
                    className="gap-2"
                  >
                    <Settings className="h-4 w-4" />
                    {t('DiscoveryPage.networkScan.wizard')}
                  </Button>
                </div>

                <div className="flex items-center gap-6 text-sm">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <Checkbox
                      checked={probeServices}
                      onCheckedChange={(v) => setProbeServices(!!v)}
                    />
                    {t('DiscoveryPage.networkScan.probeServices')}
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <Checkbox
                      checked={resolveHostnames}
                      onCheckedChange={(v) => setResolveHostnames(!!v)}
                    />
                    {t('DiscoveryPage.networkScan.resolveHostnames')}
                  </label>
                  <span className="text-muted-foreground">
                    {t('DiscoveryPage.networkScan.ports')}{' '}
                    <code className="text-xs bg-muted px-1 py-0.5 rounded">{scanPorts}</code>
                  </span>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Live scan progress */}
          {isScanning && scanProgress && (
            <ScanProgress
              progress={{
                scan_id: activeScanId || '',
                status: scanProgress.status,
                progress: scanProgress.progress ?? scanProgress.phase_progress ?? 0,
                hosts_scanned: scanProgress.hosts_scanned ?? scanProgress.scanned_hosts ?? 0,
                devices_found: scanProgress.devices_found ?? scanProgress.discovered_hosts ?? 0,
                devices_identified: scanProgress.devices_identified ?? 0,
                current_activity: scanProgress.current_phase || t('DiscoveryPage.scanProgress.scanning'),
                current_phase: scanProgress.current_phase,
                errors: scanProgress.errors,
              }}
              onCancel={() => cancelScanMutation.mutate()}
              onViewResults={() => {}}
            />
          )}

          {/* Scan Results */}
          {scanResults && (
            <div className="space-y-4">
              {/* Results summary bar */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <Card>
                  <CardContent noOffset>
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm text-muted-foreground">{t('DiscoveryPage.results.discovered')}</p>
                        <p className="text-2xl font-bold">{scanResults.total_discovered}</p>
                      </div>
                      <Server className="h-8 w-8 text-muted-foreground" />
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent noOffset>
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm text-muted-foreground">{t('DiscoveryPage.results.manageable')}</p>
                        <p className="text-2xl font-bold text-emerald-500">
                          {scanResults.total_manageable ?? scanResults.manageable_count ?? 0}
                        </p>
                      </div>
                      <CheckCircle className="h-8 w-8 text-emerald-500" />
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent noOffset>
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm text-muted-foreground">{t('DiscoveryPage.results.status')}</p>
                        <p className="text-lg font-semibold capitalize">{scanResults.status}</p>
                      </div>
                      <Clock className="h-8 w-8 text-blue-500" />
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent noOffset>
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm text-muted-foreground">{t('DiscoveryPage.results.duration')}</p>
                        <p className="text-2xl font-bold">
                          {(() => {
                            const secs = scanResults.elapsed_seconds ?? scanResults.duration_seconds;
                            return secs ? `${Math.round(secs)}s` : '-';
                          })()}
                        </p>
                      </div>
                      <Zap className="h-8 w-8 text-amber-500" />
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Device results with toolbar */}
              <Card>
                <CardHeader className="pb-4">
                  <div className="flex items-center justify-between flex-wrap gap-3">
                    <CardTitle>
                      {t('DiscoveryPage.results.devicesTitle', { count: filteredDevices.length })}
                    </CardTitle>
                    <div className="flex items-center gap-2">
                      {/* Search */}
                      <SearchBar
                        value={searchQuery}
                        onChange={setSearchQuery}
                        placeholder={t('DiscoveryPage.results.searchPlaceholder')}
                        className="w-56"
                      />

                      {/* Selection mode toggle */}
                      <Button
                        size="sm"
                        variant={selectionMode ? 'default' : 'outline'}
                        onClick={() => {
                          setSelectionMode(!selectionMode);
                          setSelectedDevices(new Set());
                        }}
                        className="gap-1.5"
                      >
                        <CheckSquare className="h-4 w-4" />
                        {t('DiscoveryPage.results.select')}
                      </Button>

                      {/* View mode */}
                      <div className="flex border rounded-md">
                        <Button
                          size="icon"
                          variant={viewMode === 'grid' ? 'default' : 'ghost'}
                          className="h-9 w-9 rounded-r-none"
                          onClick={() => setViewMode('grid')}
                        >
                          <Grid3X3 className="h-4 w-4" />
                        </Button>
                        <Button
                          size="icon"
                          variant={viewMode === 'list' ? 'default' : 'ghost'}
                          className="h-9 w-9 rounded-l-none"
                          onClick={() => setViewMode('list')}
                        >
                          <List className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  </div>
                </CardHeader>

                {/* Bulk action bar */}
                {selectionMode && selectedDevices.size > 0 && (
                  <div className="mx-6 mb-4 p-3 rounded-lg bg-primary/5 border border-primary/20 flex items-center justify-between">
                    <span className="text-sm font-medium">
                      {selectedDevices.size === 1
                        ? t('DiscoveryPage.results.selectedOne', { count: selectedDevices.size })
                        : t('DiscoveryPage.results.selectedOther', { count: selectedDevices.size })}
                    </span>
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        onClick={handleBulkAdopt}
                        disabled={bulkAdoptMutation.isPending}
                        className="gap-1.5"
                      >
                        {bulkAdoptMutation.isPending ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <CheckCircle className="h-3.5 w-3.5" />
                        )}
                        {t('DiscoveryPage.results.bulkAdopt')}
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => {
                          setSelectedDevices(new Set());
                          setSelectionMode(false);
                        }}
                      >
                        <X className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>
                )}

                <CardContent noOffset>
                  {filteredDevices.length === 0 ? (
                    <EmptyState
                      icon={Search}
                      title={t('DiscoveryPage.results.emptyTitle')}
                      description={t('DiscoveryPage.results.emptyDescription')}
                      variant="compact"
                    />
                  ) : (
                    <div
                      className={cn(
                        'gap-4',
                        viewMode === 'grid'
                          ? 'grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3'
                          : 'flex flex-col',
                      )}
                    >
                      {filteredDevices.map((device, idx) => (
                        <DiscoveredDeviceCard
                          key={`${device.ip}-${idx}`}
                          device={device}
                          onViewDetails={handleViewDetails}
                          onAdopt={handleAdoptClick}
                          selectionMode={selectionMode}
                          selected={selectedDevices.has(device.ip)}
                          onSelectionChange={handleSelectionChange}
                        />
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          )}

          {/* Empty state */}
          {!isScanning && !scanResults && !wizardOpen && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2">
                <Card className="border-dashed">
                  <CardContent noOffset className="py-12 text-center">
                    <Network className="h-12 w-12 mx-auto text-muted-foreground/50 mb-4" />
                    <h3 className="text-lg font-medium mb-2">{t('DiscoveryPage.ready.title')}</h3>
                    <p className="text-muted-foreground mb-4 max-w-md mx-auto">
                      {t('DiscoveryPage.ready.description')}
                    </p>
                    <div className="flex gap-2 justify-center">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setScanTargets('192.168.1.0/24')}
                      >
                        192.168.1.0/24
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setScanTargets('10.0.0.0/24')}
                      >
                        10.0.0.0/24
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setScanTargets('172.16.0.0/24')}
                      >
                        172.16.0.0/24
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              </div>
              <ScanHistoryPanel />
            </div>
          )}
        </TabsContent>

        {/* ═══════════════════════════════════════════════════════════ */}
        {/* CONTROLLERS TAB */}
        {/* ═══════════════════════════════════════════════════════════ */}
        <TabsContent value="controllers" className="space-y-6 mt-6">
          {/* Controller stats */}
          {controllerStats && (
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <Card>
                <CardContent noOffset>
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">{t('DiscoveryPage.controllerStats.totalFound')}</p>
                      <p className="text-2xl font-bold">{controllerStats.totalDevices}</p>
                    </div>
                    <Server className="h-8 w-8 text-muted-foreground" />
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent noOffset>
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">{t('DiscoveryPage.controllerStats.newDevices')}</p>
                      <p className="text-2xl font-bold text-emerald-500">
                        {controllerStats.newDevices}
                      </p>
                    </div>
                    <CheckCircle className="h-8 w-8 text-emerald-500" />
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent noOffset>
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">{t('DiscoveryPage.controllerStats.updated')}</p>
                      <p className="text-2xl font-bold text-blue-500">
                        {controllerStats.updatedDevices}
                      </p>
                    </div>
                    <RefreshCw className="h-8 w-8 text-blue-500" />
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent noOffset>
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">{t('DiscoveryPage.controllerStats.failed')}</p>
                      <p className="text-2xl font-bold text-red-500">
                        {controllerStats.failedControllers}
                      </p>
                    </div>
                    <AlertTriangle className="h-8 w-8 text-red-500" />
                  </div>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Controls */}
          <Card>
            <CardHeader>
              <CardTitle>{t('DiscoveryPage.controllerDiscovery.title')}</CardTitle>
              <CardDescription>
                {t('DiscoveryPage.controllerDiscovery.description')}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap items-center gap-4">
                <div className="w-56">
                  <Select value={selectedController} onValueChange={setSelectedController}>
                    <SelectTrigger>
                      <SelectValue placeholder={t('DiscoveryPage.controllerDiscovery.allControllers')} />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">{t('DiscoveryPage.controllerDiscovery.allControllers')}</SelectItem>
                      {controllers.map((c) => (
                        <SelectItem key={c.id} value={c.id}>
                          {c.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <SearchBar
                  value={controllerSearch}
                  onChange={setControllerSearch}
                  placeholder={t('DiscoveryPage.controllerDiscovery.searchPlaceholder')}
                />

                <Button
                  onClick={handleControllerDiscover}
                  disabled={controllerDiscoveryStatus === 'running'}
                  className="gap-2"
                >
                  {controllerDiscoveryStatus === 'running' ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      {t('DiscoveryPage.controllerDiscovery.discovering')}
                    </>
                  ) : (
                    <>
                      <Play className="h-4 w-4" />
                      {t('DiscoveryPage.controllerDiscovery.startDiscovery')}
                    </>
                  )}
                </Button>

                <Button variant="outline" onClick={() => refetchControllers()} className="gap-2">
                  <RefreshCw className="h-4 w-4" />
                  {t('DiscoveryPage.controllerDiscovery.refresh')}
                </Button>
              </div>

              {controllerProgressMsg && (
                <div className="mt-4 p-4 bg-muted rounded-lg flex items-center gap-3">
                  {controllerDiscoveryStatus === 'running' && (
                    <Loader2 className="h-5 w-5 animate-spin text-primary" />
                  )}
                  {controllerDiscoveryStatus === 'completed' && (
                    <CheckCircle className="h-5 w-5 text-emerald-500" />
                  )}
                  {controllerDiscoveryStatus === 'failed' && (
                    <AlertTriangle className="h-5 w-5 text-red-500" />
                  )}
                  <span>{controllerProgressMsg}</span>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Controllers Table */}
          <Card>
            <CardHeader>
              <CardTitle>{t('DiscoveryPage.controllersTable.title', { count: filteredControllers.length })}</CardTitle>
            </CardHeader>
            <CardContent>
              {controllersLoading ? (
                <div className="space-y-2">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <div key={i} className="flex items-center gap-4 px-4 py-3 border-b border-border/30 last:border-0">
                      <Skeleton className="h-4 w-32" />
                      <Skeleton className="h-4 w-20" />
                      <Skeleton className="h-4 w-40" />
                      <Skeleton className="h-5 w-16 rounded-full" />
                      <Skeleton className="h-4 w-24" />
                      <Skeleton className="h-8 w-8 rounded-md ml-auto" />
                    </div>
                  ))}
                </div>
              ) : filteredControllers.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  {t('DiscoveryPage.controllersTable.empty')}
                </div>
              ) : (
                <div className="rounded-md border">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b bg-muted/50">
                        <th className="py-3 px-4 text-left font-medium">{t('DiscoveryPage.controllersTable.columns.name')}</th>
                        <th className="py-3 px-4 text-left font-medium">{t('DiscoveryPage.controllersTable.columns.type')}</th>
                        <th className="py-3 px-4 text-left font-medium">{t('DiscoveryPage.controllersTable.columns.host')}</th>
                        <th className="py-3 px-4 text-left font-medium">{t('DiscoveryPage.controllersTable.columns.status')}</th>
                        <th className="py-3 px-4 text-left font-medium">{t('DiscoveryPage.controllersTable.columns.lastSync')}</th>
                        <th className="py-3 px-4 text-right font-medium">{t('DiscoveryPage.controllersTable.columns.actions')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredControllers.map((controller) => (
                        <tr key={controller.id} className="border-b hover:bg-muted/30">
                          <td className="py-3 px-4 font-medium">{controller.name}</td>
                          <td className="py-3 px-4">
                            <Badge variant="outline" className="text-xs">
                              {controller.type}
                            </Badge>
                          </td>
                          <td className="py-3 px-4 text-muted-foreground">{controller.host}</td>
                          <td className="py-3 px-4">
                            <span
                              className={cn(
                                'inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium',
                                controller.status === 'online'
                                  ? 'bg-emerald-500/10 text-emerald-500'
                                  : controller.status === 'error'
                                  ? 'bg-red-500/10 text-red-500'
                                  : 'bg-muted text-muted-foreground',
                              )}
                            >
                              <span
                                className={cn(
                                  'w-1.5 h-1.5 rounded-full',
                                  controller.status === 'online'
                                    ? 'bg-emerald-500'
                                    : controller.status === 'error'
                                    ? 'bg-red-500'
                                    : 'bg-muted-foreground',
                                )}
                              />
                              {controller.status}
                            </span>
                          </td>
                          <td className="py-3 px-4 text-muted-foreground">
                            {controller.last_sync
                              ? new Date(controller.last_sync).toLocaleString()
                              : t('DiscoveryPage.controllersTable.never')}
                          </td>
                          <td className="py-3 px-4 text-right">
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => discoverControllerMutation.mutate(controller.id)}
                              disabled={controllerDiscoveryStatus === 'running'}
                            >
                              <Radar className="h-4 w-4" />
                            </Button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Drivers */}
          {drivers.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>{t('DiscoveryPage.drivers.title', { count: drivers.length })}</CardTitle>
                <CardDescription>
                  {t('DiscoveryPage.drivers.description')}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                  {drivers.map((driver) => (
                    <div
                      key={driver.id}
                      className="flex items-center gap-3 p-3 rounded-lg border hover:bg-muted/30"
                    >
                      <div
                        className={cn(
                          'w-10 h-10 rounded-lg flex items-center justify-center',
                          VENDOR_COLORS[driver.vendor] || 'bg-muted text-muted-foreground',
                        )}
                      >
                        <Server className="h-5 w-5" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="font-medium text-sm truncate">{driver.name}</p>
                        <p className="text-xs text-muted-foreground">
                          {driver.device_types?.join(', ')}
                        </p>
                      </div>
                      <Badge variant="outline" className="text-xs shrink-0">
                        {driver.version || 'v1'}
                      </Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ═══════════════════════════════════════════════════════════ */}
        {/* AGENT SCAN TAB */}
        {/* ═══════════════════════════════════════════════════════════ */}
        <TabsContent value="agent" className="space-y-6 mt-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Bot className="h-5 w-5 text-purple-500" />
                {t('DiscoveryPage.agentScan.title')}
              </CardTitle>
              <CardDescription>
                {t('DiscoveryPage.agentScan.description')}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {agentsLoading ? (
                <Skeleton className="h-10 w-full" />
              ) : onlineAgents.length === 0 ? (
                <EmptyState
                  icon={Bot}
                  title={t('DiscoveryPage.agentScan.noAgentsTitle')}
                  description={t('DiscoveryPage.agentScan.noAgentsDescription')}
                  variant="compact"
                />
              ) : (
                <>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">
                      {t('DiscoveryPage.agentScan.agentLabel')}
                    </label>
                    <Select
                      value={selectedAgentId}
                      onValueChange={setSelectedAgentId}
                      disabled={agentScanMutation.isPending}
                    >
                      <SelectTrigger className="sm:w-72">
                        <SelectValue placeholder={t('DiscoveryPage.agentScan.agentPlaceholder')} />
                      </SelectTrigger>
                      <SelectContent>
                        {onlineAgents.map((agent) => (
                          <SelectItem key={agent.id} value={agent.id}>
                            <div className="flex items-center gap-2">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                              {agent.name}
                              {agent.site_name && (
                                <span className="text-xs text-muted-foreground">
                                  · {agent.site_name}
                                </span>
                              )}
                            </div>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="flex flex-col sm:flex-row gap-3">
                    <div className="flex-1">
                      <Input
                        placeholder={t('DiscoveryPage.agentScan.targetPlaceholder')}
                        value={agentScanTarget}
                        onChange={(e) => setAgentScanTarget(e.target.value)}
                        disabled={agentScanMutation.isPending}
                      />
                    </div>
                    <Button
                      className="gap-2"
                      disabled={
                        agentScanMutation.isPending ||
                        !agentScanTarget.trim() ||
                        !selectedAgentId
                      }
                      onClick={() => {
                        const targets = agentScanTarget
                          .split(/[,\n]+/)
                          .map((t) => t.trim())
                          .filter(Boolean);
                        agentScanMutation.mutate({ agentId: selectedAgentId, targets });
                      }}
                    >
                      {agentScanMutation.isPending ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <Play className="h-4 w-4" />
                      )}
                      {t('DiscoveryPage.agentScan.dispatch')}
                    </Button>
                  </div>
                </>
              )}

              {agentTaskId && (
                <div className="p-4 rounded-lg bg-muted/50 space-y-2">
                  <div className="flex items-center gap-2 text-sm">
                    <Loader2 className="h-4 w-4 animate-spin text-primary" />
                    <span className="font-medium">{t('DiscoveryPage.agentScan.inProgress')}</span>
                  </div>
                  <p className="text-xs text-muted-foreground font-mono">
                    {t('DiscoveryPage.agentScan.taskId', { id: agentTaskId })}
                  </p>
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
                <div className="p-4 rounded-lg border">
                  <div className="flex items-center gap-2 mb-2">
                    <Network className="h-4 w-4 text-blue-500" />
                    <span className="text-sm font-medium">{t('DiscoveryPage.agentScan.l2Probes.title')}</span>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    {t('DiscoveryPage.agentScan.l2Probes.description')}
                  </p>
                </div>
                <div className="p-4 rounded-lg border">
                  <div className="flex items-center gap-2 mb-2">
                    <Globe className="h-4 w-4 text-green-500" />
                    <span className="text-sm font-medium">{t('DiscoveryPage.agentScan.protocolDiscovery.title')}</span>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    {t('DiscoveryPage.agentScan.protocolDiscovery.description')}
                  </p>
                </div>
                <div className="p-4 rounded-lg border">
                  <div className="flex items-center gap-2 mb-2">
                    <Fingerprint className="h-4 w-4 text-purple-500" />
                    <span className="text-sm font-medium">{t('DiscoveryPage.agentScan.deepFingerprint.title')}</span>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    {t('DiscoveryPage.agentScan.deepFingerprint.description')}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Show scan history here too */}
          <ScanHistoryPanel />
        </TabsContent>

        {/* ═══════════════════════════════════════════════════════════ */}
        {/* DISCOVERED HOSTS TAB, persistent table fed by agents */}
        {/* ═══════════════════════════════════════════════════════════ */}
        <TabsContent value="discovered" className="space-y-6 mt-6">
          <AgentDiscoveriesTab siteId={selectedSiteId || undefined} />
        </TabsContent>

        {/* ═══════════════════════════════════════════════════════════ */}
        {/* TOPOLOGY TAB, React Flow render of subnet + LLDP graph */}
        {/* ═══════════════════════════════════════════════════════════ */}
        <TabsContent value="topology" className="space-y-6 mt-6">
          <TopologyDiscoveryTab siteId={selectedSiteId || undefined} />
        </TabsContent>
      </Tabs>

      {/* ═══════════════════════════════════════════════════════════ */}
      {/* DIALOGS */}
      {/* ═══════════════════════════════════════════════════════════ */}

      {/* Adopt Device Dialog */}
      <AdoptDeviceDialog
        device={adoptDevice}
        open={adoptOpen}
        onOpenChange={setAdoptOpen}
        drivers={drivers}
        siteId={selectedSiteId ?? sites[0]?.id ?? ''}
        onAdopted={() => {
          toast({
            title: t('DiscoveryPage.toast.deviceAdopted.title'),
            description: t('DiscoveryPage.toast.deviceAdopted.description', { ip: adoptDevice?.ip }),
          });
          queryClient.invalidateQueries({ queryKey: ['devices'] });
        }}
      />

      {/* Device Details Dialog */}
      <DeviceDetailsDialog
        device={selectedDevice}
        open={detailsOpen}
        onOpenChange={setDetailsOpen}
        onAdopt={(d: DiscoveredDevice) => {
          setDetailsOpen(false);
          handleAdoptClick(d);
        }}
      />
    </div>
  );
}
