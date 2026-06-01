// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · PBX Detail Page
 *
 * Enterprise-grade PBX management dashboard with tabbed sections.
 * Visual design: V1 enterprise aesthetic · bottom-border tab navigation,
 * semantic StatsCards with sub-values, trunk status panels with registration
 * dot indicators, queue metric cards, and native HTML extension tables.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Server, ArrowLeft,
  Users, PhoneCall, GitBranch, Layers, Voicemail,
  Settings, Activity, Plus, Trash2, Plug, ExternalLink,
  Phone, Hash,
  Play, Square, ListOrdered, Save, Eye,
  Loader2, Headphones,
  Shield, ClipboardList, AlertTriangle,
  // Interactive sync progress icons.
  CheckCircle, XCircle, RefreshCw,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { SectionBoundary } from '@/components/SectionBoundary';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { type DataTableColumn } from '@/components/ui/data-table';
import { InlineErrorBanner } from '@/components/ui/empty-state';
import { PageHeader } from '@/components/layout';
import { PendingChangesDrawer } from '@/components/gateways/PendingChangesDrawer';
import { Breadcrumb } from '@/components/ui/breadcrumb';
import { StatusBadge, type StatusVariant } from '@/components/ui/status-indicator';
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import {
  Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription,
} from '@/components/ui/sheet';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import { voipApi, stagePbxChange } from '@/lib/api';
import { pendingChangesQueryKey } from '@/components/gateways/PendingChangesDrawer';
import { cn } from '@/lib/utils';
import { PBXTypeBadge } from './components';
import { useToast } from '@/hooks/use-toast';
import type {
  PBXSystem, PBXDashboard, Extension, RingGroup,
  Trunk, Queue, IVR, ActiveCall, VoicemailBox,
} from './types';
import { PBXDidsTab } from './pbx-tabs/PBXDidsTab';
import { PBXVoicemailTab } from './pbx-tabs/PBXVoicemailTab';
import { PBXExtensionsTab } from './pbx-tabs/PBXExtensionsTab';
import { PBXTrunksTab } from './pbx-tabs/PBXTrunksTab';
import { PBXRingGroupsTab } from './pbx-tabs/PBXRingGroupsTab';
import { PBXQueuesTab } from './pbx-tabs/PBXQueuesTab';
import { PBXIvrTab } from './pbx-tabs/PBXIvrTab';
import { PBXActiveCallsTab } from './pbx-tabs/PBXActiveCallsTab';
import { PBXConfigTab } from './pbx-tabs/PBXConfigTab';
import { PBXOverviewTab } from './pbx-tabs/PBXOverviewTab';
import { PBXSettingsTab } from './pbx-tabs/PBXSettingsTab';


// =============================================================================
// Main Page
// =============================================================================

// FreePBX exposes no write mutation for trunks (the live GraphQL schema has
// only removeSipStationKeyAndDeleteTrunk, not add/update), so the trunk
// create/edit/delete UI would always fail at the transport. Keep trunks
// read-only until a real write path exists; flip to true if one is added.
const TRUNK_WRITE_SUPPORTED = false;

export default function PBXDetailPage() {
  const { t } = useTranslation('voip');
  const { id: pbxId, tab: urlTab } = useParams<{ id: string; tab?: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const VALID_TABS = ['overview', 'extensions', 'trunks', 'ring-groups', 'queues', 'ivr', 'dids', 'active-calls', 'voicemail', 'config', 'settings'] as const;
  const activeTab = VALID_TABS.includes(urlTab as any) ? urlTab! : 'overview';
  const setActiveTab = (tab: string) => navigate(`/voip/pbx/${pbxId}/${tab}`, { replace: true });

  const { toast } = useToast();

  useEffect(() => {
    // Guard: only redirect if we are still on a PBX-detail route. Without this,
    // an exiting page kept alive by <AnimatePresence mode="wait"> can fire this
    // effect with a stale-empty pbxId and trap the user.
    if (!window.location.pathname.startsWith('/voip/pbx/')) return;
    if (!pbxId) navigate('/voip/pbx', { replace: true });
  }, [pbxId, navigate]);

  // ── Queries ──

  const { data: pbxRes, isError: pbxError } = useQuery({
    queryKey: ['pbx', pbxId],
    queryFn: () => voipApi.getPBXById(pbxId!),
    enabled: !!pbxId,
  });
  const pbx: PBXSystem | null = pbxRes?.data ?? null;

  const { data: dashRes, isError: dashError } = useQuery({
    queryKey: ['pbx-dashboard', pbxId],
    queryFn: () => voipApi.getPBXDashboard(pbxId!),
    refetchInterval: 30_000,
    enabled: !!pbxId,
  });
  const dash: PBXDashboard | null = dashRes?.data ?? null;

  const { data: extRes, isLoading: extLoading, isError: extError, refetch: refetchExt } = useQuery({
    queryKey: ['pbx-extensions', pbxId],
    queryFn: () => voipApi.getExtensions(pbxId!, { limit: 500 }),
    enabled: !!pbxId && (activeTab === 'extensions' || activeTab === 'overview'),
  });
  const extensions: Extension[] = extRes?.data?.items ?? [];

  const { data: trunkRes, isLoading: trunkLoading, isError: trunkError, refetch: refetchTrunks } = useQuery({
    queryKey: ['pbx-trunks', pbxId],
    queryFn: () => voipApi.getPBXTrunks(pbxId!),
    enabled: !!pbxId && (activeTab === 'trunks' || activeTab === 'overview'),
  });
  const trunks: Trunk[] = trunkRes?.data?.items ?? [];

  const { data: rgRes, isLoading: rgLoading, isError: rgError } = useQuery({
    queryKey: ['pbx-ring-groups', pbxId],
    queryFn: () => voipApi.getPBXRingGroups(pbxId!),
    enabled: !!pbxId && activeTab === 'ring-groups',
  });
  const ringGroups: RingGroup[] = rgRes?.data?.items ?? [];

  const { data: queueRes, isLoading: queueLoading, isError: queueError } = useQuery({
    queryKey: ['pbx-queues', pbxId],
    queryFn: () => voipApi.getPBXQueues(pbxId!),
    enabled: !!pbxId && (activeTab === 'queues' || activeTab === 'overview'),
  });
  const queues: Queue[] = queueRes?.data?.items ?? [];

  const { data: ivrRes, isLoading: ivrLoading, isError: ivrError } = useQuery({
    queryKey: ['pbx-ivrs', pbxId],
    queryFn: () => voipApi.getPBXIVRs(pbxId!),
    enabled: !!pbxId && activeTab === 'ivr',
  });
  const ivrs: IVR[] = ivrRes?.data?.items ?? [];

  const { data: callsRes, isLoading: callsLoading, isError: callsError, refetch: refetchCalls } = useQuery({
    queryKey: ['pbx-active-calls', pbxId],
    queryFn: () => voipApi.getPBXActiveCalls(pbxId!),
    enabled: !!pbxId && activeTab === 'active-calls',
    refetchInterval: activeTab === 'active-calls' ? 5_000 : false,
  });
  const activeCalls: ActiveCall[] = callsRes?.data?.items ?? [];

  const { data: vmRes, isLoading: vmLoading, isError: vmError } = useQuery({
    queryKey: ['pbx-voicemail-boxes', pbxId],
    queryFn: () => voipApi.getPBXVoicemailBoxes(pbxId!),
    enabled: !!pbxId && activeTab === 'voicemail',
  });
  const voicemailBoxes: VoicemailBox[] = vmRes?.data?.items ?? [];

  const { data: didRes, isLoading: didLoading, isError: didError } = useQuery({
    queryKey: ['pbx-dids', pbxId],
    queryFn: () => voipApi.getPBXDids(pbxId!),
    enabled: !!pbxId && activeTab === 'dids',
  });
  const dids: any[] = didRes?.data?.items ?? [];

  // ── Full Config query (config tab) ──
  const { data: configRes, isLoading: configLoading, isError: configError } = useQuery({
    queryKey: ['pbx-full-config', pbxId],
    queryFn: () => voipApi.getPBXFullConfig(pbxId!),
    enabled: !!pbxId && activeTab === 'config',
  });
  const fullConfig = configRes?.data ?? null;

  // ── Mutations ──

  // ── Background sync state (canonical pattern) ──
  // The POST /voip/pbx/{id}/sync endpoint returns 202 with task_id
  // and dispatches a Celery task. The worker emits pbx.sync.*
  // events through publish_adapter_event → WebSocket → useWebSocket
  // dispatches the CustomEvent we listen for below.
  type SyncProgress = {
    stage: string;
    current: number;
    total: number;
    percent: number;
    message: string | null;
    data: Record<string, unknown>;
  } | null;
  const [syncProgress, setSyncProgress] = useState<SyncProgress>(null);
  const [syncStatus, setSyncStatus] = useState<'idle' | 'running' | 'completed' | 'failed'>('idle');
  // Staged-write review/apply drawer (FreePBX config CRUD flows through it).
  const [pendingOpen, setPendingOpen] = useState(false);
  // Extension edit -> stages a pbx.extension.update change (never live-writes).
  const [editExt, setEditExt] = useState<Extension | null>(null);
  const [editExtForm, setEditExtForm] = useState<{ name: string; outboundcid: string }>({
    name: '',
    outboundcid: '',
  });
  // Ring-group edit -> stages a pbx.ring_group.update change.
  const [editRg, setEditRg] = useState<RingGroup | null>(null);
  const [editRgDesc, setEditRgDesc] = useState('');
  // Ring-group create -> stages a pbx.ring_group.create change.
  const [createRgOpen, setCreateRgOpen] = useState(false);
  const [createRgForm, setCreateRgForm] = useState({
    groupNumber: '',
    description: '',
    strategy: 'ringall',
    extensionList: '',
  });
  // Inbound-route (DID) create -> stages a pbx.inbound_route.create change.
  const [createDidOpen, setCreateDidOpen] = useState(false);
  const [createDidForm, setCreateDidForm] = useState({
    extension: '',
    cidnum: '',
    description: '',
    destination: '',
  });

  const syncMutation = useMutation({
    mutationFn: () => voipApi.syncPBX(pbxId!),
    onSuccess: (res) => {
      const d = res?.data;
      // 202 Accepted, task queued. Real progress arrives via WS.
      setSyncStatus('running');
      setSyncProgress({
        stage: 'queued',
        current: 0,
        total: 6,
        percent: 0,
        message: d?.message ?? t('PBXDetailPage.sync.queuedConnecting'),
        data: {},
      });
      toast({ title: t('PBXDetailPage.sync.started'), description: d?.message ?? t('PBXDetailPage.sync.watchingProgress') });
    },
    onError: () => {
      setSyncStatus('failed');
      toast({ title: t('PBXDetailPage.sync.failed'), variant: 'destructive' });
    },
  });

  // Listen for pbx.sync.* events scoped to THIS PBX.
  useEffect(() => {
    if (!pbxId) return;
    const handler = (e: Event) => {
      const ce = e as CustomEvent<{ type: string; data: Record<string, unknown> }>;
      const data = ce.detail?.data || {};
      // Filter to this PBX only, events carry pbx_id in the payload.
      if (String(data.pbx_id) !== String(pbxId)) return;

      const type = ce.detail.type;
      if (type === 'pbx.sync.started') {
        setSyncStatus('running');
        setSyncProgress({
          stage: 'connecting', current: 0, total: 6, percent: 0,
          message: t('PBXDetailPage.sync.connecting'), data: {},
        });
      } else if (type === 'pbx.sync.progress') {
        setSyncProgress({
          stage: String(data.stage ?? ''),
          current: Number(data.current ?? 0),
          total: Number(data.total ?? 6),
          percent: Number(data.percent ?? 0),
          message: (data.message as string) ?? null,
          data: (data.data as Record<string, unknown>) ?? {},
        });
      } else if (type === 'pbx.sync.completed') {
        setSyncStatus('completed');
        setSyncProgress({
          stage: 'done', current: 6, total: 6, percent: 100,
          message: t('PBXDetailPage.sync.complete'),
          data: (data.result as Record<string, unknown>) ?? {},
        });
        toast({ title: t('PBXDetailPage.sync.complete'), description: t('PBXDetailPage.sync.completeDescription') });
        // Auto-dismiss progress card after 5s.
        window.setTimeout(() => { setSyncStatus('idle'); setSyncProgress(null); }, 5000);
        // Refresh all PBX-scoped queries.
        queryClient.invalidateQueries({ queryKey: ['pbx-dashboard', pbxId] });
        queryClient.invalidateQueries({ queryKey: ['pbx-extensions', pbxId] });
        queryClient.invalidateQueries({ queryKey: ['pbx-ring-groups', pbxId] });
        queryClient.invalidateQueries({ queryKey: ['pbx-trunks', pbxId] });
        queryClient.invalidateQueries({ queryKey: ['pbx-queues', pbxId] });
        queryClient.invalidateQueries({ queryKey: ['pbx-ivrs', pbxId] });
        queryClient.invalidateQueries({ queryKey: ['pbx-dids', pbxId] });
        queryClient.invalidateQueries({ queryKey: ['pbx-voicemail-boxes', pbxId] });
        queryClient.invalidateQueries({ queryKey: ['pbx-full-config', pbxId] });
      } else if (type === 'pbx.sync.failed') {
        setSyncStatus('failed');
        setSyncProgress((prev) => prev ? { ...prev, stage: 'failed',
          message: (data.error as string) ?? t('PBXDetailPage.sync.failed') } : null);
        toast({ title: t('PBXDetailPage.sync.failed'), description: (data.error as string) ?? t('PBXDetailPage.sync.unknownError'),
                variant: 'destructive' });
      }
    };
    window.addEventListener('freesdn:pbx-sync', handler);
    return () => window.removeEventListener('freesdn:pbx-sync', handler);
  }, [pbxId, queryClient, toast, t]);

  const connectMutation = useMutation({
    mutationFn: () => voipApi.connectPBX(pbxId!),
    onSuccess: (res) => {
      const d = res?.data;
      if (d?.status === 'connected') {
        toast({ title: t('PBXDetailPage.toast.pbxConnected') });
      } else {
        toast({ title: d?.message || t('PBXDetailPage.toast.connectionFailed'), variant: 'destructive' });
      }
      queryClient.invalidateQueries({ queryKey: ['pbx-dashboard', pbxId] });
    },
    onError: () => toast({ title: t('PBXDetailPage.toast.connectionTestFailed'), variant: 'destructive' }),
  });

  const reloadMutation = useMutation({
    mutationFn: () => voipApi.reloadPBXConfig(pbxId!),
    onSuccess: () => {
      toast({ title: t('PBXDetailPage.toast.configReloaded') });
      // Reload clears the server-side needs_reload flag; refetch so the
      // "Apply Config to activate" banner disappears.
      queryClient.invalidateQueries({ queryKey: ['pbx-dashboard', pbxId] });
    },
    onError: () => toast({ title: t('PBXDetailPage.toast.reloadFailed'), variant: 'destructive' }),
  });

  const hangupMutation = useMutation({
    mutationFn: (channel: string) => voipApi.hangupCall(pbxId!, channel),
    onSuccess: () => {
      toast({ title: t('PBXDetailPage.toast.callTerminated') });
      refetchCalls();
    },
    onError: () => toast({ title: t('PBXDetailPage.toast.hangupFailed'), variant: 'destructive' }),
  });

  const deletePBXMutation = useMutation({
    mutationFn: () => voipApi.deletePBX(pbxId!),
    onSuccess: () => {
      toast({ title: t('PBXDetailPage.toast.pbxDeleted') });
      navigate('/voip/pbx');
    },
  });

  const updatePBXMutation = useMutation({
    mutationFn: (data: any) => voipApi.updatePBX(pbxId!, data),
    onSuccess: () => {
      toast({ title: t('PBXDetailPage.toast.settingsSaved') });
      queryClient.invalidateQueries({ queryKey: ['pbx', pbxId] });
    },
    onError: () => toast({ title: t('PBXDetailPage.toast.settingsSaveFailed'), variant: 'destructive' }),
  });

  // ── Detail Sheet State ──
  const [selectedExtension, setSelectedExtension] = useState<Extension | null>(null);
  const [selectedTrunk, setSelectedTrunk] = useState<Trunk | null>(null);
  const [selectedQueue, setSelectedQueue] = useState<Queue | null>(null);
  const [selectedRingGroup, setSelectedRingGroup] = useState<RingGroup | null>(null);
  const [selectedIVR, setSelectedIVR] = useState<IVR | null>(null);
  const [selectedVoicemail, setSelectedVoicemail] = useState<VoicemailBox | null>(null);

  // Fetch live extension detail when selected
  const { data: extDetailRes } = useQuery({
    queryKey: ['pbx-extension-detail', pbxId, selectedExtension?.extension_number],
    queryFn: () => voipApi.getPBXExtensionDetail(pbxId!, selectedExtension!.extension_number),
    enabled: !!pbxId && !!selectedExtension,
  });
  const extensionDetail = extDetailRes?.data ?? null;

  // ── Extension Dialog State ──
  const [showExtDialog, setShowExtDialog] = useState(false);
  const [extForm, setExtForm] = useState({
    extension_number: '', display_name: '', caller_id_name: '',
    caller_id_number: '', voicemail_enabled: true, voicemail_pin: '', password: '',
  });

  const createExtMutation = useMutation({
    // Stage a pbx.extension.create (reviewed + applied via the drawer) rather
    // than writing the live PBX directly — uniform with every other write.
    mutationFn: (data: any) =>
      stagePbxChange({
        pbxId: pbxId!,
        domain: 'extensions',
        feature: 'pbx.extension.create',
        operation: 'create',
        targetId: String(data.extension_number),
        payload: {
          name: data.display_name || undefined,
          callerID: data.caller_id_number || data.caller_id_name || undefined,
          vmEnable: !!data.voicemail_enabled,
          vmPassword: data.voicemail_pin || undefined,
        },
        notes: 'Created via PBX UI',
      }),
    onSuccess: () => {
      toast({ title: t('PBXDetailPage.editExt.staged') });
      setShowExtDialog(false);
      setExtForm({ extension_number: '', display_name: '', caller_id_name: '', caller_id_number: '', voicemail_enabled: true, voicemail_pin: '', password: '' });
      queryClient.invalidateQueries({ queryKey: pendingChangesQueryKey('freepbx', pbxId!) });
      setPendingOpen(true);
    },
    onError: (err: any) => toast({ title: err?.response?.data?.detail || t('PBXDetailPage.toast.extensionCreateFailed'), variant: 'destructive' }),
  });

  const deleteExtMutation = useMutation({
    // Stage a pbx.extension.delete for review rather than deleting the live
    // extension immediately.
    mutationFn: (extNumber: string) =>
      stagePbxChange({
        pbxId: pbxId!,
        domain: 'extensions',
        feature: 'pbx.extension.delete',
        operation: 'delete',
        targetId: extNumber,
        notes: 'Deleted via PBX UI',
      }),
    onSuccess: () => {
      toast({ title: t('PBXDetailPage.editExt.staged') });
      queryClient.invalidateQueries({ queryKey: pendingChangesQueryKey('freepbx', pbxId!) });
      setPendingOpen(true);
    },
    onError: (err: any) => toast({ title: err?.response?.data?.detail || t('PBXDetailPage.toast.extensionDeleteFailed'), variant: 'destructive' }),
  });

  // Stage an extension UPDATE through the staged-write pipeline. This records
  // a pending change (reviewed + applied via the Pending Changes drawer under
  // the ADAPTER_READ_ONLY + force dual-gate) — it NEVER live-writes the PBX.
  const stageExtUpdate = useMutation({
    mutationFn: () =>
      stagePbxChange({
        pbxId: pbxId!,
        domain: 'extensions',
        feature: 'pbx.extension.update',
        operation: 'update',
        targetId: editExt!.extension_number,
        payload: {
          name: editExtForm.name,
          outboundcid: editExtForm.outboundcid,
        },
        notes: 'Edited via PBX UI',
      }),
    onSuccess: () => {
      toast({ title: t('PBXDetailPage.editExt.staged') });
      queryClient.invalidateQueries({
        queryKey: pendingChangesQueryKey('freepbx', pbxId!),
      });
      setEditExt(null);
      setPendingOpen(true);
    },
    onError: (err: any) =>
      toast({
        title: t('PBXDetailPage.editExt.stageFailed'),
        description: err?.response?.data?.detail || err?.message,
        variant: 'destructive',
      }),
  });

  // Stage a ring-group UPDATE (description only — members/strategy untouched).
  const stageRgUpdate = useMutation({
    mutationFn: () =>
      stagePbxChange({
        pbxId: pbxId!,
        domain: 'ring-groups',
        feature: 'pbx.ring_group.update',
        operation: 'update',
        targetId: String(editRg!.group_number || editRg!.extension_number || ''),
        payload: { description: editRgDesc },
        notes: 'Edited via PBX UI',
      }),
    onSuccess: () => {
      toast({ title: t('PBXDetailPage.editExt.staged') });
      queryClient.invalidateQueries({
        queryKey: pendingChangesQueryKey('freepbx', pbxId!),
      });
      setEditRg(null);
      setPendingOpen(true);
    },
    onError: (err: any) =>
      toast({
        title: t('PBXDetailPage.editExt.stageFailed'),
        description: err?.response?.data?.detail || err?.message,
        variant: 'destructive',
      }),
  });

  // Stage a ring-group CREATE.
  const stageRgCreate = useMutation({
    mutationFn: () =>
      stagePbxChange({
        pbxId: pbxId!,
        domain: 'ring-groups',
        feature: 'pbx.ring_group.create',
        operation: 'create',
        targetId: createRgForm.groupNumber,
        payload: {
          grpnum: createRgForm.groupNumber,
          description: createRgForm.description,
          strategy: createRgForm.strategy,
          extensionList: createRgForm.extensionList,
        },
        notes: 'Created via PBX UI',
      }),
    onSuccess: () => {
      toast({ title: t('PBXDetailPage.editExt.staged') });
      queryClient.invalidateQueries({ queryKey: pendingChangesQueryKey('freepbx', pbxId!) });
      setCreateRgOpen(false);
      setCreateRgForm({ groupNumber: '', description: '', strategy: 'ringall', extensionList: '' });
      setPendingOpen(true);
    },
    onError: (err: any) =>
      toast({
        title: t('PBXDetailPage.editExt.stageFailed'),
        description: err?.response?.data?.detail || err?.message,
        variant: 'destructive',
      }),
  });

  // Stage a ring-group DELETE.
  const stageRgDelete = useMutation({
    mutationFn: (grpnum: string) =>
      stagePbxChange({
        pbxId: pbxId!,
        domain: 'ring-groups',
        feature: 'pbx.ring_group.delete',
        operation: 'delete',
        targetId: grpnum,
        notes: 'Deleted via PBX UI',
      }),
    onSuccess: () => {
      toast({ title: t('PBXDetailPage.editExt.staged') });
      queryClient.invalidateQueries({ queryKey: pendingChangesQueryKey('freepbx', pbxId!) });
      setPendingOpen(true);
    },
    onError: (err: any) =>
      toast({
        title: t('PBXDetailPage.editExt.stageFailed'),
        description: err?.response?.data?.detail || err?.message,
        variant: 'destructive',
      }),
  });

  // Stage an inbound-route (DID) CREATE.
  const stageDidCreate = useMutation({
    mutationFn: () =>
      stagePbxChange({
        pbxId: pbxId!,
        domain: 'inbound-routes',
        feature: 'pbx.inbound_route.create',
        operation: 'create',
        targetId: createDidForm.extension || undefined,
        payload: {
          extension: createDidForm.extension || undefined,
          cidnum: createDidForm.cidnum || undefined,
          description: createDidForm.description || undefined,
          destination: createDidForm.destination,
        },
        notes: 'Created via PBX UI',
      }),
    onSuccess: () => {
      toast({ title: t('PBXDetailPage.editExt.staged') });
      queryClient.invalidateQueries({ queryKey: pendingChangesQueryKey('freepbx', pbxId!) });
      setCreateDidOpen(false);
      setCreateDidForm({ extension: '', cidnum: '', description: '', destination: '' });
      setPendingOpen(true);
    },
    onError: (err: any) =>
      toast({
        title: t('PBXDetailPage.editExt.stageFailed'),
        description: err?.response?.data?.detail || err?.message,
        variant: 'destructive',
      }),
  });

  // Stage an inbound-route (DID) DELETE. FreePBX keys routes by
  // (extension, cidnum); we stage the slash-free extension as the target and
  // carry cidnum in the payload so the apply path can rebuild the composite id
  // (the raw "ext/cid" id contains a "/", which the staging id-validator
  // rejects).
  const stageDidDelete = useMutation({
    mutationFn: (route: { extension: string; cidnum?: string }) =>
      stagePbxChange({
        pbxId: pbxId!,
        domain: 'inbound-routes',
        feature: 'pbx.inbound_route.delete',
        operation: 'delete',
        targetId: route.extension,
        payload: route.cidnum ? { cidnum: route.cidnum } : undefined,
        notes: 'Deleted via PBX UI',
      }),
    onSuccess: () => {
      toast({ title: t('PBXDetailPage.editExt.staged') });
      queryClient.invalidateQueries({ queryKey: pendingChangesQueryKey('freepbx', pbxId!) });
      setPendingOpen(true);
    },
    onError: (err: any) =>
      toast({
        title: t('PBXDetailPage.editExt.stageFailed'),
        description: err?.response?.data?.detail || err?.message,
        variant: 'destructive',
      }),
  });

  // ── Trunk Detail / Edit State ──
  const trunkId = selectedTrunk?.trunkid ?? selectedTrunk?.trunk_id ?? selectedTrunk?.channelid;
  const { data: trunkDetailRes } = useQuery({
    queryKey: ['pbx-trunk-detail', pbxId, trunkId],
    queryFn: () => voipApi.getPBXTrunkDetail(pbxId!, String(trunkId)),
    enabled: !!pbxId && !!trunkId,
  });
  const trunkDetail: Trunk | null = trunkDetailRes?.data ?? null;

  const [trunkEditMode, setTrunkEditMode] = useState(false);
  const [trunkEditForm, setTrunkEditForm] = useState<Record<string, any>>({});

  // Populate edit form when trunk detail loads
  useEffect(() => {
    if (trunkDetail && trunkEditMode) return; // don't overwrite while editing
    if (trunkDetail) {
      setTrunkEditForm({
        name: trunkDetail.name || '',
        outcid: trunkDetail.outcid || '',
        maxchans: trunkDetail.maxchans ?? trunkDetail.max_channels ?? '',
        keepcid: trunkDetail.keepcid || 'off',
        disabled: trunkDetail.disabled || 'off',
        failover: trunkDetail.failover || '',
        dialoutprefix: trunkDetail.dialoutprefix || '',
        host: trunkDetail.host || '',
        port: trunkDetail.port || trunkDetail.sip_server_port || '',
        username: trunkDetail.username || '',
        secret: trunkDetail.secret || '',
        registration: trunkDetail.registration || '',
        aor_contact: trunkDetail.aor_contact || '',
        match: trunkDetail.match || '',
        transport: trunkDetail.transport || '',
        contact_user: trunkDetail.contact_user || '',
        codecs: trunkDetail.codecs || '',
        sip_server: trunkDetail.sip_server || '',
        sip_server_port: trunkDetail.sip_server_port || '',
        provider: trunkDetail.provider || '',
      });
    }
  }, [trunkDetail, trunkEditMode]);

  const updateTrunkMutation = useMutation({
    mutationFn: (data: Record<string, any>) => voipApi.updatePBXTrunk(pbxId!, String(trunkId), data),
    onSuccess: () => {
      toast({ title: t('PBXDetailPage.toast.trunkSettingsSaved') });
      setTrunkEditMode(false);
      refetchTrunks();
      queryClient.invalidateQueries({ queryKey: ['pbx-trunk-detail', pbxId, trunkId] });
      queryClient.invalidateQueries({ queryKey: ['pbx-dashboard', pbxId] });
    },
    onError: (err: any) => toast({
      title: err?.response?.data?.detail || t('PBXDetailPage.toast.trunkUpdateFailed'),
      variant: 'destructive',
    }),
  });

  const deleteTrunkMutation = useMutation({
    mutationFn: (id: string) => voipApi.deletePBXTrunk(pbxId!, id),
    onSuccess: () => {
      toast({ title: t('PBXDetailPage.toast.trunkDeleted') });
      setSelectedTrunk(null);
      refetchTrunks();
      queryClient.invalidateQueries({ queryKey: ['pbx-dashboard', pbxId] });
    },
    onError: (err: any) => toast({
      title: err?.response?.data?.detail || t('PBXDetailPage.toast.trunkDeleteFailed'),
      variant: 'destructive',
    }),
  });

  // ── Trunk Create Dialog ──
  const [showTrunkDialog, setShowTrunkDialog] = useState(false);
  const defaultTrunkForm = {
    name: '', technology: 'pjsip', host: '', port: '5060',
    username: '', secret: '', outcid: '', maxchans: '',
    provider: '', codecs: 'ulaw,alaw', transport: '',
  };
  const [trunkForm, setTrunkForm] = useState(defaultTrunkForm);

  const createTrunkMutation = useMutation({
    mutationFn: (data: Record<string, any>) => voipApi.createPBXTrunk(pbxId!, data),
    onSuccess: () => {
      toast({ title: t('PBXDetailPage.toast.trunkCreated') });
      setShowTrunkDialog(false);
      setTrunkForm(defaultTrunkForm);
      refetchTrunks();
      queryClient.invalidateQueries({ queryKey: ['pbx-dashboard', pbxId] });
    },
    onError: (err: any) => toast({
      title: err?.response?.data?.detail || t('PBXDetailPage.toast.trunkCreateFailed'),
      variant: 'destructive',
    }),
  });

  // ── Originate Call Dialog ──
  const [showCallDialog, setShowCallDialog] = useState(false);
  const [callForm, setCallForm] = useState({ extension: '', destination: '' });

  const originateMutation = useMutation({
    mutationFn: (data: { extension: string; destination: string }) =>
      voipApi.originateCall(pbxId!, data),
    onSuccess: () => {
      toast({ title: t('PBXDetailPage.toast.callOriginated') });
      setShowCallDialog(false);
      setCallForm({ extension: '', destination: '' });
    },
    onError: (err: any) => toast({ title: err?.response?.data?.detail || t('PBXDetailPage.toast.callOriginateFailed'), variant: 'destructive' }),
  });

  // ── Early return (after all hooks) ──
  if (!pbxId) return null;

  if (!pbx && !dash) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const pbxName = dash?.name || pbx?.name || t('PBXDetailPage.pbxFallbackName');
  const pbxStatus = dash?.status || 'unknown';
  const hasQueryError = pbxError || dashError || extError || trunkError || rgError || queueError || ivrError || callsError || vmError || didError || configError;

  // ── Column Definitions ──

  const extensionColumns: DataTableColumn<Extension>[] = [
    {
      id: 'extension_number',
      header: t('PBXDetailPage.columns.extension'),
      accessorFn: (row) => parseInt(row.extension_number) || 0,
      cell: (row) => (
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded bg-primary/10">
            <Hash className="h-3.5 w-3.5 text-primary" />
          </div>
          <span className="font-mono font-medium">{row.extension_number}</span>
        </div>
      ),
      sortable: true,
    },
    {
      id: 'display_name',
      header: t('PBXDetailPage.columns.name'),
      accessorFn: (row) => (row.display_name || '').toLowerCase(),
      cell: (row) => <span className="font-medium">{row.display_name || '-'}</span>,
      sortable: true,
    },
    {
      id: 'caller_id',
      header: t('PBXDetailPage.columns.callerId'),
      cell: (row) => (
        <span className="text-sm text-muted-foreground">
          {row.caller_id_name ? `${row.caller_id_name} <${row.caller_id_number || row.extension_number}>` : '-'}
        </span>
      ),
    },
    {
      id: 'voicemail',
      header: t('PBXDetailPage.columns.voicemail'),
      cell: (row) => (
        row.voicemail_enabled
          ? <StatusBadge variant="success" hideIcon size="sm">{t('PBXDetailPage.common.enabled')}</StatusBadge>
          : <StatusBadge variant="neutral" hideIcon size="sm">{t('PBXDetailPage.common.disabled')}</StatusBadge>
      ),
    },
    {
      id: 'bound_phone',
      header: t('PBXDetailPage.columns.phone'),
      // Populated by /voip/pbx/{id}/extensions when the extension is
      // linked to a discovered phone (via auto-link or manual onboard).
      // Click cell to jump to the phone detail page so the operator
      // can drive directly from extension → device.
      cell: (row) => {
        const bound = row.bound_phones?.[0];
        if (!bound) return <span className="text-xs text-muted-foreground">-</span>;
        const isOnline = bound.status === 'online' || bound.status === 'registered';
        return (
          <button
            type="button"
            onClick={(e) => { e.stopPropagation(); navigate(`/voip/phones/${bound.id}`); }}
            className="flex flex-col items-start gap-0.5 text-left hover:underline"
          >
            <div className="flex items-center gap-1.5">
              <span className={cn(
                'h-1.5 w-1.5 rounded-full',
                isOnline ? 'bg-success' : 'bg-muted-foreground/40',
              )} />
              <span className="font-mono text-xs">{bound.ip_address}</span>
            </div>
            <span className="text-[10px] text-muted-foreground">
              {bound.model || bound.vendor || bound.mac_address}
            </span>
          </button>
        );
      },
    },
    {
      id: 'tech',
      header: t('PBXDetailPage.columns.tech'),
      cell: (row) => {
        const tech = (row.settings as any)?.tech;
        return tech ? <Badge variant="outline" className="text-[10px]">{tech}</Badge> : <span className="text-muted-foreground text-xs">-</span>;
      },
    },
    {
      id: 'recording',
      header: t('PBXDetailPage.columns.recording'),
      cell: (row) => {
        const rec = (row.settings as any)?.recording;
        return rec && rec !== 'dontcare'
          ? <Badge variant="secondary" className="text-[10px]">{rec}</Badge>
          : <span className="text-muted-foreground text-xs">-</span>;
      },
    },
    {
      id: 'status',
      header: t('PBXDetailPage.columns.status'),
      cell: (row) => (
        row.is_active
          ? <StatusBadge variant="success" hideIcon size="sm">{t('PBXDetailPage.common.active')}</StatusBadge>
          : <StatusBadge variant="error" hideIcon size="sm">{t('PBXDetailPage.common.inactive')}</StatusBadge>
      ),
    },
    {
      id: 'actions',
      header: '',
      cell: (row) => (
        <Button
          variant="ghost" size="icon" className="h-8 w-8 text-red-500 hover:text-red-600"
          onClick={() => {
            if (confirm(t('PBXDetailPage.confirm.deleteExtension', { number: row.extension_number }))) {
              deleteExtMutation.mutate(row.extension_number);
            }
          }}
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      ),
    },
  ];

  const trunkColumns: DataTableColumn<Trunk>[] = [
    {
      id: 'name',
      header: t('PBXDetailPage.columns.trunk'),
      accessorFn: (row) => (row.name || '').toLowerCase(),
      cell: (row) => (
        <div className="flex items-center gap-3">
          <div className={cn('w-3 h-3 rounded-full', (() => {
            const s = (row.status || '').toLowerCase();
            if (s.includes('ok') || s.includes('registered') || s.includes('online')) return 'bg-emerald-500';
            if (s.includes('disabled')) return 'bg-muted-foreground';
            if (s.includes('configured')) return 'bg-amber-500';
            return 'bg-red-500';
          })())} />
          <div>
            <p className="font-medium">{row.name}</p>
            <p className="text-xs text-muted-foreground">{row.tech || row.technology || row.trunk_type || 'SIP'}</p>
          </div>
        </div>
      ),
      sortable: true,
    },
    { id: 'sip_server', header: t('PBXDetailPage.columns.sipServer'), cell: (row) => <span className="font-mono text-sm truncate max-w-[200px] block">{(row as any).sip_server || (row as any).host || '-'}</span> },
    { id: 'outcid', header: t('PBXDetailPage.columns.outboundCid'), cell: (row) => <span className="font-mono text-sm">{(row as any).outcid || '-'}</span> },
    {
      id: 'status',
      header: t('PBXDetailPage.columns.status'),
      cell: (row) => {
        const s = (row.status || '').toLowerCase();
        if (s.includes('ok') || s.includes('registered') || s.includes('online')) {
          return <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-emerald-500/10 text-emerald-600">{t('PBXDetailPage.trunkStatus.registered')}</span>;
        }
        if (s.includes('disabled')) {
          return <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-muted text-muted-foreground">{t('PBXDetailPage.trunkStatus.disabled')}</span>;
        }
        if (s.includes('configured')) {
          return <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-amber-500/10 text-amber-600">{t('PBXDetailPage.trunkStatus.configured')}</span>;
        }
        return <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-muted text-muted-foreground">{row.status || t('PBXDetailPage.common.unknown')}</span>;
      },
    },
    {
      id: 'channels',
      header: t('PBXDetailPage.columns.channels'),
      cell: (row) => <span className="text-sm font-mono">{row.channels_used ?? 0}{row.max_channels ? ` / ${row.max_channels}` : ''}</span>,
    },
  ];

  const queueColumns: DataTableColumn<Queue>[] = [
    {
      id: 'name',
      header: t('PBXDetailPage.columns.queue'),
      accessorFn: (row) => (row.display_name || row.name || '').toLowerCase(),
      cell: (row) => (
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded bg-cyan-100 dark:bg-cyan-900/30">
            <ListOrdered className="h-3.5 w-3.5 text-cyan-600" />
          </div>
          <div>
            <p className="font-medium">{row.display_name || row.name}</p>
            <p className="text-xs text-muted-foreground">{row.strategy || 'ringall'}</p>
          </div>
        </div>
      ),
      sortable: true,
    },
    { id: 'members', header: t('PBXDetailPage.columns.members'), cell: (row) => <Badge variant="outline">{row.member_count ?? row.members?.length ?? 0}</Badge> },
    {
      id: 'waiting',
      header: t('PBXDetailPage.columns.waiting'),
      cell: (row) => (
        <span className={cn('font-medium', (row.callers_waiting ?? 0) > 0 ? 'text-amber-600' : 'text-muted-foreground')}>
          {row.callers_waiting ?? 0}
        </span>
      ),
    },
    { id: 'completed', header: t('PBXDetailPage.columns.completed'), cell: (row) => <span className="text-sm">{row.completed ?? 0}</span> },
    { id: 'abandoned', header: t('PBXDetailPage.columns.abandoned'), cell: (row) => <span className="text-sm text-red-500">{row.abandoned ?? 0}</span> },
    {
      id: 'service_level',
      header: t('PBXDetailPage.columns.serviceLevel'),
      cell: (row) => <span className="text-sm">{row.service_level != null ? `${Math.round(row.service_level)}%` : '-'}</span>,
    },
  ];

  const ivrColumns: DataTableColumn<IVR>[] = [
    {
      id: 'name',
      header: t('PBXDetailPage.columns.ivrMenu'),
      accessorFn: (row) => (row.name || '').toLowerCase(),
      cell: (row) => (
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded bg-amber-100 dark:bg-amber-900/30">
            <Layers className="h-3.5 w-3.5 text-amber-600" />
          </div>
          <div>
            <p className="font-medium">{row.name}</p>
            {row.description && <p className="text-xs text-muted-foreground">{row.description}</p>}
          </div>
        </div>
      ),
      sortable: true,
    },
    { id: 'timeout', header: t('PBXDetailPage.columns.timeout'), cell: (row) => <span className="text-sm">{row.timeout ?? 10}s</span> },
    {
      id: 'direct_dial',
      header: t('PBXDetailPage.columns.directDial'),
      cell: (row) => row.direct_dial
        ? <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-emerald-500/10 text-emerald-600">{t('PBXDetailPage.common.yes')}</span>
        : <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-muted text-muted-foreground">{t('PBXDetailPage.common.no')}</span>,
    },
    {
      id: 'entries',
      header: t('PBXDetailPage.columns.options'),
      cell: (row) => <Badge variant="outline">{row.entries?.length ?? 0}</Badge>,
    },
  ];

  const callColumns: DataTableColumn<ActiveCall>[] = [
    {
      id: 'channel',
      header: t('PBXDetailPage.columns.channel'),
      cell: (row) => <span className="font-mono text-xs">{row.channel}</span>,
    },
    {
      id: 'caller',
      header: t('PBXDetailPage.columns.caller'),
      cell: (row) => (
        <div>
          <p className="font-medium text-sm">{row.caller_id_name || row.caller_id_num || '-'}</p>
          {row.caller_id_num && row.caller_id_name && (
            <p className="text-xs text-muted-foreground">{row.caller_id_num}</p>
          )}
        </div>
      ),
    },
    {
      id: 'connected',
      header: t('PBXDetailPage.columns.connectedTo'),
      cell: (row) => (
        <div>
          <p className="font-medium text-sm">{row.connected_line_name || row.connected_line_num || '-'}</p>
          {row.connected_line_num && row.connected_line_name && (
            <p className="text-xs text-muted-foreground">{row.connected_line_num}</p>
          )}
        </div>
      ),
    },
    {
      id: 'state',
      header: t('PBXDetailPage.columns.state'),
      cell: (row) => {
        const s = (row.state || '').toLowerCase();
        if (s === 'up') return <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-emerald-500/10 text-emerald-600">{t('PBXDetailPage.callState.up')}</span>;
        if (s === 'ringing') return <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-amber-500/10 text-amber-600">{t('PBXDetailPage.callState.ringing')}</span>;
        return <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-muted text-muted-foreground">{row.state || '-'}</span>;
      },
    },
    {
      id: 'duration',
      header: t('PBXDetailPage.columns.duration'),
      cell: (row) => {
        const d = row.duration ?? 0;
        const min = Math.floor(d / 60);
        const sec = d % 60;
        return <span className="font-mono text-sm">{min}:{sec.toString().padStart(2, '0')}</span>;
      },
    },
    {
      id: 'actions',
      header: '',
      cell: (row) => (
        <Button
          variant="ghost" size="icon" className="h-8 w-8 text-red-500 hover:text-red-600"
          onClick={() => hangupMutation.mutate(row.channel)}
          disabled={hangupMutation.isPending}
        >
          <Square className="h-4 w-4" />
        </Button>
      ),
    },
  ];

  const vmColumns: DataTableColumn<VoicemailBox>[] = [
    {
      id: 'mailbox',
      header: t('PBXDetailPage.columns.mailbox'),
      accessorFn: (row) => parseInt(row.mailbox) || 0,
      cell: (row) => (
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded bg-blue-100 dark:bg-blue-900/30">
            <Voicemail className="h-3.5 w-3.5 text-blue-600" />
          </div>
          <span className="font-mono font-medium">{row.mailbox}</span>
        </div>
      ),
      sortable: true,
    },
    { id: 'name', header: t('PBXDetailPage.columns.name'), cell: (row) => <span className="font-medium">{row.name || '-'}</span> },
    { id: 'email', header: t('PBXDetailPage.columns.email'), cell: (row) => <span className="text-sm text-muted-foreground">{row.email || '-'}</span> },
    {
      id: 'new',
      header: t('PBXDetailPage.columns.new'),
      cell: (row) => (
        <span className={cn('font-medium', (row.new_messages ?? 0) > 0 ? 'text-red-600' : 'text-muted-foreground')}>
          {row.new_messages ?? 0}
        </span>
      ),
    },
    { id: 'old', header: t('PBXDetailPage.columns.old'), cell: (row) => <span className="text-sm">{row.old_messages ?? 0}</span> },
  ];

  const didColumns: DataTableColumn<any>[] = [
    {
      id: 'extension',
      header: t('PBXDetailPage.columns.didRoute'),
      accessorFn: (row) => (row.extension || row.did || '').toLowerCase(),
      cell: (row) => (
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded bg-purple-100 dark:bg-purple-900/30">
            <Phone className="h-3.5 w-3.5 text-purple-600" />
          </div>
          <div>
            <p className="font-mono font-medium">{row.extension || row.did || '-'}</p>
            {row.description && <p className="text-xs text-muted-foreground">{row.description}</p>}
          </div>
        </div>
      ),
      sortable: true,
    },
    { id: 'cidnum', header: t('PBXDetailPage.columns.cidMatch'), cell: (row) => <span className="font-mono text-sm">{row.cidnum || t('PBXDetailPage.common.any')}</span> },
    {
      id: 'destination',
      header: t('PBXDetailPage.columns.destination'),
      cell: (row) => <span className="text-sm truncate max-w-[180px] block">{row.destination || '-'}</span>,
    },
    { id: 'grppre', header: t('PBXDetailPage.columns.cidPrefix'), cell: (row) => row.grppre ? <Badge variant="outline" className="text-xs font-mono">{row.grppre}</Badge> : <span className="text-muted-foreground text-xs">-</span> },
    { id: 'alertinfo', header: t('PBXDetailPage.columns.alertInfo'), cell: (row) => <span className="text-xs">{row.alertinfo || '-'}</span> },
    { id: 'mohclass', header: t('PBXDetailPage.columns.moh'), cell: (row) => <span className="text-xs">{row.mohclass || t('PBXDetailPage.common.default')}</span> },
    { id: 'privacyman', header: t('PBXDetailPage.columns.privacy'), cell: (row) => <Badge variant="outline" className="text-xs">{row.privacyman || 'off'}</Badge> },
    {
      id: 'actions',
      header: '',
      cell: (row) => (
        <Button
          variant="ghost"
          size="sm"
          className="h-7 w-7 p-0 text-destructive"
          aria-label={t('PBXDetailPage.common.delete')}
          onClick={() => {
            const ext = String(row.extension ?? '');
            if (
              ext &&
              confirm(
                t('PBXDetailPage.confirm.deleteInboundRoute', {
                  route: row.extension || row.description || ext,
                }),
              )
            ) {
              stageDidDelete.mutate({ extension: ext, cidnum: row.cidnum });
            }
          }}
        >
          <Trash2 className="h-3.5 w-3.5" />
        </Button>
      ),
    },
  ];

  const rgColumns: DataTableColumn<RingGroup>[] = [
    {
      id: 'name',
      header: t('PBXDetailPage.columns.ringGroup'),
      accessorFn: (row) => (row.name || '').toLowerCase(),
      cell: (row) => (
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded bg-amber-100 dark:bg-amber-900/30">
            <Users className="h-3.5 w-3.5 text-amber-600" />
          </div>
          <div>
            <p className="font-medium">{row.name}</p>
            <p className="text-xs text-muted-foreground font-mono">#{row.group_number || row.extension_number}</p>
          </div>
        </div>
      ),
      sortable: true,
    },
    {
      id: 'strategy',
      header: t('PBXDetailPage.columns.strategy'),
      cell: (row) => <Badge variant="outline" className="text-xs capitalize">{row.ring_strategy}</Badge>,
    },
    { id: 'ring_time', header: t('PBXDetailPage.columns.ringTime'), cell: (row) => <span className="text-sm">{row.ring_time}s</span> },
    { id: 'members', header: t('PBXDetailPage.columns.members'), cell: (row) => <Badge variant="outline">{row.members?.length ?? 0}</Badge> },
    {
      id: 'status',
      header: t('PBXDetailPage.columns.status'),
      cell: (row) => (
        row.is_active
          ? <StatusBadge variant="success" hideIcon size="sm">{t('PBXDetailPage.common.active')}</StatusBadge>
          : <StatusBadge variant="error" hideIcon size="sm">{t('PBXDetailPage.common.inactive')}</StatusBadge>
      ),
    },
  ];

  // ── Tab configuration ──
  const tabConfig = [
    { id: 'overview', label: t('PBXDetailPage.tabs.overview'), icon: Server },
    { id: 'extensions', label: t('PBXDetailPage.tabs.extensions'), icon: Hash },
    { id: 'trunks', label: t('PBXDetailPage.tabs.trunks'), icon: GitBranch },
    { id: 'ring-groups', label: t('PBXDetailPage.tabs.ringGroups'), icon: Users },
    { id: 'queues', label: t('PBXDetailPage.tabs.queues'), icon: ListOrdered },
    { id: 'ivr', label: t('PBXDetailPage.tabs.ivr'), icon: Layers },
    { id: 'dids', label: t('PBXDetailPage.tabs.dids'), icon: Phone },
    { id: 'active-calls', label: t('PBXDetailPage.tabs.activeCalls'), icon: PhoneCall },
    { id: 'voicemail', label: t('PBXDetailPage.tabs.voicemail'), icon: Voicemail },
    { id: 'config', label: t('PBXDetailPage.tabs.config'), icon: Shield },
    { id: 'settings', label: t('PBXDetailPage.tabs.settings'), icon: Settings },
  ] as const;

  const pbxStatusVariant: StatusVariant =
    pbxStatus === 'online' ? 'online' : pbxStatus === 'offline' ? 'offline' : 'unknown';

  const headerHost = `${dash?.ip_address || pbx?.ip_address}:${dash?.api_port || pbx?.api_port}`;
  const headerDescription = dash?.asterisk_version
    ? t('PBXDetailPage.header.withAsterisk', { host: headerHost, version: dash.asterisk_version })
    : headerHost;

  return (
    <div className="space-y-6">
      {/* Live sync progress card, reference async pattern. Mounts
          when a sync is queued or in flight and unmounts itself ~5s
          after completion. Per-stage WebSocket events drive the bar.

          Stage indicator + animated bar + streaming per-resource tiles
          are the reference UX every long-running adapter sync should
          mirror (Omada full sync, Proxmox cluster scan, NVR import,
          etc.). Keep the SYNC_STAGES list in lock-step with the
          ``_emit("<stage>", ...)`` calls in service.sync_pbx. */}
      {syncProgress && (() => {
        const SYNC_STAGES = [
          { key: 'connecting',  label: t('PBXDetailPage.syncStages.connect') },
          { key: 'extensions',  label: t('PBXDetailPage.syncStages.extensions') },
          { key: 'ring_groups', label: t('PBXDetailPage.syncStages.ringGroups') },
          { key: 'live_data',   label: t('PBXDetailPage.syncStages.liveData') },
          { key: 'persisting',  label: t('PBXDetailPage.syncStages.save') },
          { key: 'done',        label: t('PBXDetailPage.syncStages.done') },
        ] as const;
        const currentIdx = Math.max(0, SYNC_STAGES.findIndex(s => s.key === syncProgress.stage));
        const accent =
          syncStatus === 'failed'    ? 'destructive' :
          syncStatus === 'completed' ? 'success'     :
          'primary';
        const headerLabel =
          syncStatus === 'completed' ? t('PBXDetailPage.sync.complete')                             :
          syncStatus === 'failed'    ? t('PBXDetailPage.sync.failed')                               :
          syncProgress.stage === 'queued' ? t('PBXDetailPage.sync.queuedWaiting')                    :
          t('PBXDetailPage.sync.syncingStep', { current: currentIdx + 1, total: SYNC_STAGES.length });

        // Pull tiles from either the per-stage ``count`` emit or the
        // final ``summary`` dict on the ``done`` event. We render
        // tiles in a stable order so the layout doesn't shuffle as
        // events stream in. Unknown keys (future-proof) fall through
        // and render at the end.
        const TILE_ORDER = [
          'extensions', 'ring_groups', 'trunks', 'queues', 'ivrs', 'dids',
          'voicemail_boxes', 'followme', 'announcements', 'paging_groups',
          'blacklist', 'certificates', 'admin_users', 'modules',
        ] as const;
        const tiles: Array<{ label: string; value: number | string }> = [];
        const summary = (syncProgress.data?.summary as Record<string, unknown> | undefined);
        if (summary && typeof summary === 'object') {
          const seen = new Set<string>();
          for (const key of TILE_ORDER) {
            if (key in summary) {
              tiles.push({
                label: key.replace(/_/g, ' '),
                value: Number(summary[key] ?? 0),
              });
              seen.add(key);
            }
          }
          for (const [k, v] of Object.entries(summary)) {
            if (!seen.has(k)) tiles.push({ label: k.replace(/_/g, ' '), value: String(v) });
          }
        } else if ('count' in (syncProgress.data ?? {})) {
          tiles.push({
            label: syncProgress.stage.replace(/_/g, ' '),
            value: Number(syncProgress.data.count ?? 0),
          });
        }

        return (
          <div className={cn(
            'rounded-lg border p-4 transition-all duration-300',
            accent === 'destructive' ? 'border-destructive/40 bg-destructive/5'
              : accent === 'success' ? 'border-success/40 bg-success/5'
              : 'border-primary/30 bg-primary/5',
          )}>
            {/* Header row: icon, title + message, percent */}
            <div className="flex items-center gap-3 mb-3">
              {syncStatus === 'completed'
                ? <CheckCircle className="h-5 w-5 text-success shrink-0" />
                : syncStatus === 'failed'
                  ? <XCircle className="h-5 w-5 text-destructive shrink-0" />
                  : <RefreshCw className="h-5 w-5 text-primary animate-spin shrink-0" />}
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium truncate">{headerLabel}</div>
                <div className="text-xs text-muted-foreground truncate" title={syncProgress.message ?? syncProgress.stage}>
                  {syncProgress.message ?? syncProgress.stage}
                </div>
              </div>
              <div className={cn(
                'text-sm font-mono tabular-nums',
                accent === 'destructive' ? 'text-destructive'
                  : accent === 'success' ? 'text-success'
                  : 'text-primary',
              )}>
                {syncProgress.percent}%
              </div>
            </div>

            {/* Stepper, 6 named stages with a visual dot per stage.
                Active stage is filled + ring; completed stages are
                solid; future stages are muted. This is the part that
                turns a generic progress bar into a "you are here"
                story. */}
            <div className="flex items-center gap-1 mb-2">
              {SYNC_STAGES.map((s, i) => {
                const isDone     = syncStatus === 'completed' || i < currentIdx;
                const isCurrent  = syncStatus !== 'completed' && syncStatus !== 'failed' && i === currentIdx;
                const isFailed   = syncStatus === 'failed' && i === currentIdx;
                return (
                  <div key={s.key} className="flex-1 flex flex-col items-center gap-1 min-w-0">
                    <div className={cn(
                      'h-2 w-2 rounded-full transition-all',
                      isFailed ? 'bg-destructive ring-2 ring-destructive/30'
                        : isCurrent ? 'bg-primary ring-2 ring-primary/30 animate-pulse'
                        : isDone ? (accent === 'success' ? 'bg-success' : 'bg-primary')
                        : 'bg-muted-foreground/30',
                    )} />
                    <div className={cn(
                      'text-[10px] leading-none truncate w-full text-center',
                      isCurrent ? 'text-primary font-medium'
                        : isDone ? 'text-foreground'
                        : 'text-muted-foreground',
                    )}>
                      {s.label}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Animated progress bar */}
            <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
              <div
                className={cn(
                  'h-full transition-all duration-500 ease-out',
                  accent === 'destructive' ? 'bg-destructive'
                    : accent === 'success' ? 'bg-success'
                    : 'bg-primary',
                )}
                style={{ width: `${Math.max(syncProgress.percent, syncStatus === 'running' ? 4 : 0)}%` }}
              />
            </div>

            {/* Live resource tiles, counts stream in as the sync
                progresses. The final ``done`` event carries the full
                summary; intermediate emits surface the current
                stage's count so the operator sees momentum. */}
            {tiles.length > 0 && (
              <div className="mt-3 grid grid-cols-3 sm:grid-cols-4 lg:grid-cols-7 gap-2 text-xs">
                {tiles.map((t) => (
                  <div key={t.label} className="rounded border bg-background/60 px-2 py-1.5 text-center">
                    <div className="text-base font-semibold tabular-nums">{t.value}</div>
                    <div className="text-[10px] text-muted-foreground capitalize truncate" title={t.label}>
                      {t.label}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })()}

      <PageHeader
        icon={Server}
        title={pbxName}
        description={headerDescription}
        breadcrumbs={
          <Breadcrumb
            items={[
              { label: t('PBXDetailPage.breadcrumb.pbxSystems'), href: '/voip/pbx' },
              { label: pbxName },
            ]}
          />
        }
        onRefresh={() => syncMutation.mutate()}
        refreshing={syncMutation.isPending}
        actions={
          <>
            <PBXTypeBadge type={(pbx?.pbx_type || dash?.pbx_type || 'freepbx') as any} />
            <StatusBadge variant={pbxStatusVariant} />
          </>
        }
        secondaryActions={[
          {
            label: t('PBXDetailPage.actions.pendingChanges'),
            icon: ClipboardList,
            onClick: () => setPendingOpen(true),
          },
          {
            label: t('PBXDetailPage.actions.testConnection'),
            icon: connectMutation.isPending ? Loader2 : Plug,
            loading: connectMutation.isPending,
            onClick: () => connectMutation.mutate(),
          },
          {
            label: t('PBXDetailPage.actions.applyConfig'),
            icon: Activity,
            loading: reloadMutation.isPending,
            onClick: () => reloadMutation.mutate(),
          },
          {
            label: t('PBXDetailPage.actions.webUi'),
            icon: ExternalLink,
            disabled: !pbx?.ip_address && !dash?.ip_address,
            onClick: () => {
              const host = pbx?.ip_address || dash?.ip_address;
              const port = pbx?.api_port || dash?.api_port;
              if (host) window.open(`https://${host}:${port}`, '_blank', 'noopener,noreferrer');
            },
          },
        ]}
        primaryAction={{
          label: t('PBXDetailPage.actions.backToPbx'),
          icon: ArrowLeft,
          variant: 'outline',
          onClick: () => navigate('/voip/pbx'),
        }}
      />

      {/* Staged config changes: stage -> review -> apply (dual-gated). */}
      {pbxId && (
        <PendingChangesDrawer
          open={pendingOpen}
          onOpenChange={setPendingOpen}
          vendor="freepbx"
          gatewayId={pbxId}
          gatewayName={pbxName}
          // An apply mutates the live PBX; the backend refreshes that entity's
          // synced snapshot, so refetch the device-state lists to show it
          // immediately (no manual re-sync needed).
          onApplied={() => {
            for (const key of [
              'pbx-extensions',
              'pbx-ring-groups',
              'pbx-trunks',
              'pbx-queues',
              'pbx-ivrs',
              'pbx-dids',
              'pbx-voicemail-boxes',
              'pbx-dashboard',
              'pbx-full-config',
            ]) {
              queryClient.invalidateQueries({ queryKey: [key, pbxId] });
            }
          }}
        />
      )}

      {/* Edit extension -> stage a pbx.extension.update (review + apply later). */}
      <Dialog open={!!editExt} onOpenChange={(v) => { if (!v) setEditExt(null); }}>
        <DialogContent className="sm:max-w-[440px]">
          <DialogHeader>
            <DialogTitle>
              {t('PBXDetailPage.editExt.title', { number: editExt?.extension_number })}
            </DialogTitle>
            <DialogDescription>{t('PBXDetailPage.editExt.description')}</DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-1">
            <div className="space-y-1.5">
              <Label htmlFor="edit-ext-name">{t('PBXDetailPage.fields.displayName')}</Label>
              <Input
                id="edit-ext-name"
                value={editExtForm.name}
                onChange={(e) => setEditExtForm((f) => ({ ...f, name: e.target.value }))}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="edit-ext-cid">{t('PBXDetailPage.editExt.outboundCid')}</Label>
              <Input
                id="edit-ext-cid"
                value={editExtForm.outboundcid}
                onChange={(e) => setEditExtForm((f) => ({ ...f, outboundcid: e.target.value }))}
                placeholder={t('PBXDetailPage.editExt.outboundCidPlaceholder')}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditExt(null)}>
              {t('PBXDetailPage.common.cancel')}
            </Button>
            <Button onClick={() => stageExtUpdate.mutate()} disabled={stageExtUpdate.isPending}>
              {stageExtUpdate.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : null}
              {t('PBXDetailPage.editExt.stageButton')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit ring group -> stage a pbx.ring_group.update (description). */}
      <Dialog open={!!editRg} onOpenChange={(v) => { if (!v) setEditRg(null); }}>
        <DialogContent className="sm:max-w-[440px]">
          <DialogHeader>
            <DialogTitle>
              {t('PBXDetailPage.editRg.title', {
                number: editRg?.group_number || editRg?.extension_number,
              })}
            </DialogTitle>
            <DialogDescription>{t('PBXDetailPage.editExt.description')}</DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-1">
            <div className="space-y-1.5">
              <Label htmlFor="edit-rg-desc">{t('PBXDetailPage.editRg.descLabel')}</Label>
              <Input
                id="edit-rg-desc"
                value={editRgDesc}
                onChange={(e) => setEditRgDesc(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditRg(null)}>
              {t('PBXDetailPage.common.cancel')}
            </Button>
            <Button onClick={() => stageRgUpdate.mutate()} disabled={stageRgUpdate.isPending}>
              {stageRgUpdate.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : null}
              {t('PBXDetailPage.editExt.stageButton')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Create ring group -> stage a pbx.ring_group.create. */}
      <Dialog open={createRgOpen} onOpenChange={setCreateRgOpen}>
        <DialogContent className="sm:max-w-[460px]">
          <DialogHeader>
            <DialogTitle>{t('PBXDetailPage.createRg.title')}</DialogTitle>
            <DialogDescription>{t('PBXDetailPage.editExt.description')}</DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-1">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="rg-num">{t('PBXDetailPage.createRg.groupNumber')}</Label>
                <Input
                  id="rg-num"
                  value={createRgForm.groupNumber}
                  onChange={(e) => setCreateRgForm((f) => ({ ...f, groupNumber: e.target.value }))}
                  placeholder="600"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="rg-strat">{t('PBXDetailPage.columns.strategy')}</Label>
                <Input
                  id="rg-strat"
                  value={createRgForm.strategy}
                  onChange={(e) => setCreateRgForm((f) => ({ ...f, strategy: e.target.value }))}
                />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="rg-desc">{t('PBXDetailPage.editRg.descLabel')}</Label>
              <Input
                id="rg-desc"
                value={createRgForm.description}
                onChange={(e) => setCreateRgForm((f) => ({ ...f, description: e.target.value }))}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="rg-list">{t('PBXDetailPage.createRg.members')}</Label>
              <Input
                id="rg-list"
                value={createRgForm.extensionList}
                onChange={(e) => setCreateRgForm((f) => ({ ...f, extensionList: e.target.value }))}
                placeholder="200-201-202"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateRgOpen(false)}>
              {t('PBXDetailPage.common.cancel')}
            </Button>
            <Button
              onClick={() => stageRgCreate.mutate()}
              disabled={stageRgCreate.isPending || !createRgForm.groupNumber}
            >
              {stageRgCreate.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : null}
              {t('PBXDetailPage.editExt.stageButton')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Create inbound route (DID) -> stage a pbx.inbound_route.create. */}
      <Dialog open={createDidOpen} onOpenChange={setCreateDidOpen}>
        <DialogContent className="sm:max-w-[460px]">
          <DialogHeader>
            <DialogTitle>{t('PBXDetailPage.createDid.title')}</DialogTitle>
            <DialogDescription>{t('PBXDetailPage.editExt.description')}</DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-1">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="did-ext">{t('PBXDetailPage.createDid.did')}</Label>
                <Input
                  id="did-ext"
                  value={createDidForm.extension}
                  onChange={(e) => setCreateDidForm((f) => ({ ...f, extension: e.target.value }))}
                  placeholder="15551234567"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="did-cid">{t('PBXDetailPage.createDid.cid')}</Label>
                <Input
                  id="did-cid"
                  value={createDidForm.cidnum}
                  onChange={(e) => setCreateDidForm((f) => ({ ...f, cidnum: e.target.value }))}
                  placeholder={t('PBXDetailPage.common.any')}
                />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="did-desc">{t('PBXDetailPage.editRg.descLabel')}</Label>
              <Input
                id="did-desc"
                value={createDidForm.description}
                onChange={(e) => setCreateDidForm((f) => ({ ...f, description: e.target.value }))}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="did-dest">{t('PBXDetailPage.createDid.destination')}</Label>
              <Input
                id="did-dest"
                value={createDidForm.destination}
                onChange={(e) => setCreateDidForm((f) => ({ ...f, destination: e.target.value }))}
                placeholder="from-did-direct,200,1"
              />
              <p className="text-xs text-muted-foreground">
                {t('PBXDetailPage.createDid.destinationHint')}
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateDidOpen(false)}>
              {t('PBXDetailPage.common.cancel')}
            </Button>
            <Button
              onClick={() => stageDidCreate.mutate()}
              disabled={stageDidCreate.isPending || !createDidForm.destination}
            >
              {stageDidCreate.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : null}
              {t('PBXDetailPage.editExt.stageButton')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {hasQueryError && (
        <InlineErrorBanner>
          {t('PBXDetailPage.errors.partialLoad')}
        </InlineErrorBanner>
      )}

      {/* Pending-reload banner: a staged change applied to the FreePBX DB but
          not yet reloaded into the running Asterisk. Mirrors FreePBX's own
          "Apply Config" bar so the change isn't silently inert. */}
      {dash?.needs_reload && (
        <div className="flex items-center justify-between gap-3 rounded-md border border-amber-500/40 bg-amber-500/10 px-4 py-3">
          <div className="flex items-center gap-2.5">
            <AlertTriangle className="h-4 w-4 text-amber-600 dark:text-amber-500 shrink-0" />
            <p className="text-sm text-foreground">{t('PBXDetailPage.reloadBanner.message')}</p>
          </div>
          <Button
            size="sm"
            onClick={() => reloadMutation.mutate()}
            disabled={reloadMutation.isPending}
          >
            {reloadMutation.isPending ? (
              <RefreshCw className="h-3.5 w-3.5 mr-1.5 animate-spin" />
            ) : (
              <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
            )}
            {t('PBXDetailPage.actions.applyConfig')}
          </Button>
        </div>
      )}

      {/* ── V1-style bottom-border tab navigation ── */}
      <div className="border-b border-border">
        <nav className="flex gap-1 -mb-px overflow-x-auto">
          {tabConfig.map(({ id, label, icon: TabIcon }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className={cn(
                'flex items-center gap-2 py-3 px-3 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
                activeTab === id
                  ? 'border-primary text-primary'
                  : 'border-transparent text-muted-foreground hover:text-foreground hover:border-border',
              )}
            >
              <TabIcon className="h-4 w-4" />
              {label}
              {id === 'active-calls' && (dash?.active_calls ?? 0) > 0 && (
                <span className="px-1.5 py-0.5 text-xs bg-destructive text-destructive-foreground rounded-full">
                  {dash?.active_calls}
                </span>
              )}
            </button>
          ))}
        </nav>
      </div>

      {/* ── Tab Content ── */}
      <SectionBoundary resetKeys={[activeTab]}>
      <div>
        {/* ──────────── Overview ──────────── */}
        {activeTab === 'overview' && (
          <PBXOverviewTab
            pbx={pbx}
            dash={dash}
            extensions={extensions}
            trunks={trunks}
            queues={queues}
            onSync={() => syncMutation.mutate()}
            onNavigateToExtensions={() => setActiveTab('extensions')}
          />
        )}

        {/* ──────────── Extensions ──────────── */}
        {activeTab === 'extensions' && (
          <PBXExtensionsTab
            extensions={extensions}
            extensionColumns={extensionColumns}
            extLoading={extLoading}
            onRefresh={() => refetchExt()}
            onCreate={() => setShowExtDialog(true)}
            onSelectExtension={setSelectedExtension}
            onSync={() => syncMutation.mutate()}
          />
        )}

        {/* ──────────── Trunks ──────────── */}
        {activeTab === 'trunks' && (
          <PBXTrunksTab
            trunks={trunks}
            trunkColumns={trunkColumns}
            trunkLoading={trunkLoading}
            onRefresh={() => refetchTrunks()}
            onCreate={TRUNK_WRITE_SUPPORTED ? () => setShowTrunkDialog(true) : undefined}
            onSelectTrunk={setSelectedTrunk}
          />
        )}

        {/* ──────────── Ring Groups ──────────── */}
        {activeTab === 'ring-groups' && (
          <PBXRingGroupsTab
            ringGroups={ringGroups}
            rgColumns={rgColumns}
            rgLoading={rgLoading}
            onSelectRingGroup={setSelectedRingGroup}
            onCreate={() => setCreateRgOpen(true)}
          />
        )}

        {/* ──────────── Queues ──────────── */}
        {activeTab === 'queues' && (
          <PBXQueuesTab
            queues={queues}
            queueColumns={queueColumns}
            queueLoading={queueLoading}
            onSelectQueue={setSelectedQueue}
          />
        )}

        {/* ──────────── IVR ──────────── */}
        {activeTab === 'ivr' && (
          <PBXIvrTab
            ivrs={ivrs}
            ivrColumns={ivrColumns}
            ivrLoading={ivrLoading}
            onSelectIVR={setSelectedIVR}
          />
        )}

        {/* ──────────── DIDs ──────────── */}
        {activeTab === 'dids' && (
          <PBXDidsTab
            dids={dids}
            didColumns={didColumns}
            didLoading={didLoading}
            onSync={() => syncMutation.mutate()}
            onCreate={() => setCreateDidOpen(true)}
          />
        )}

        {/* ──────────── Active Calls ──────────── */}
        {activeTab === 'active-calls' && (
          <PBXActiveCallsTab
            activeCalls={activeCalls}
            callColumns={callColumns}
            callsLoading={callsLoading}
            onRefresh={() => refetchCalls()}
            onOriginate={() => setShowCallDialog(true)}
          />
        )}

        {/* ──────────── Voicemail ──────────── */}
        {activeTab === 'voicemail' && (
          <PBXVoicemailTab
            voicemailBoxes={voicemailBoxes}
            vmColumns={vmColumns}
            vmLoading={vmLoading}
            onSelectVoicemail={setSelectedVoicemail}
          />
        )}

        {/* ──────────── PBX Config ──────────── */}
        {activeTab === 'config' && (
          <PBXConfigTab
            fullConfig={fullConfig}
            configLoading={configLoading}
            isSyncing={syncMutation.isPending}
            onSync={() => syncMutation.mutate()}
          />
        )}

        {/* ──────────── Settings ──────────── */}
        {activeTab === 'settings' && (
          <PBXSettingsTab
            pbx={pbx}
            pbxName={pbxName}
            updatePBXMutation={updatePBXMutation}
            connectMutation={connectMutation}
            deletePBXMutation={deletePBXMutation}
          />
        )}
      </div>
      </SectionBoundary>

      {/* ── Create Extension Dialog ── */}
      <Dialog open={showExtDialog} onOpenChange={(v) => { setShowExtDialog(v); if (!v) setExtForm({ extension_number: '', display_name: '', caller_id_name: '', caller_id_number: '', voicemail_enabled: true, voicemail_pin: '', password: '' }); }}>
        <DialogContent className="sm:max-w-[480px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Hash className="h-5 w-5" /> {t('PBXDetailPage.extDialog.title')}
            </DialogTitle>
            <DialogDescription>
              {t('PBXDetailPage.extDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-2">
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label>{t('PBXDetailPage.extDialog.extensionNumber')}</Label>
                <Input placeholder="100" value={extForm.extension_number}
                  onChange={(e) => setExtForm({ ...extForm, extension_number: e.target.value })} />
              </div>
              <div className="grid gap-2">
                <Label>{t('PBXDetailPage.extDialog.displayName')}</Label>
                <Input placeholder={t('PBXDetailPage.extDialog.namePlaceholder')} value={extForm.display_name}
                  onChange={(e) => setExtForm({ ...extForm, display_name: e.target.value })} />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label>{t('PBXDetailPage.extDialog.callerIdName')}</Label>
                <Input placeholder={t('PBXDetailPage.extDialog.namePlaceholder')} value={extForm.caller_id_name}
                  onChange={(e) => setExtForm({ ...extForm, caller_id_name: e.target.value })} />
              </div>
              <div className="grid gap-2">
                <Label>{t('PBXDetailPage.extDialog.callerIdNumber')}</Label>
                <Input placeholder="100" value={extForm.caller_id_number}
                  onChange={(e) => setExtForm({ ...extForm, caller_id_number: e.target.value })} />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label>{t('PBXDetailPage.extDialog.sipPassword')}</Label>
                <Input type="password" placeholder="••••••••" value={extForm.password}
                  onChange={(e) => setExtForm({ ...extForm, password: e.target.value })} />
              </div>
              <div className="grid gap-2">
                <Label>{t('PBXDetailPage.extDialog.voicemailPin')}</Label>
                <Input placeholder="1234" value={extForm.voicemail_pin}
                  onChange={(e) => setExtForm({ ...extForm, voicemail_pin: e.target.value })} />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowExtDialog(false)}>{t('PBXDetailPage.common.cancel')}</Button>
            <Button onClick={() => createExtMutation.mutate(extForm)}
              disabled={!extForm.extension_number || !extForm.display_name || createExtMutation.isPending}
            >
              {createExtMutation.isPending
                ? <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                : <Plus className="h-4 w-4 mr-2" />}
              {t('PBXDetailPage.common.create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Create Trunk Dialog ── */}
      <Dialog open={showTrunkDialog} onOpenChange={(v) => { setShowTrunkDialog(v); if (!v) setTrunkForm(defaultTrunkForm); }}>
        <DialogContent className="sm:max-w-[540px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <GitBranch className="h-5 w-5" /> {t('PBXDetailPage.trunkDialog.title')}
            </DialogTitle>
            <DialogDescription>
              {t('PBXDetailPage.trunkDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-2">
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label>{t('PBXDetailPage.trunkDialog.trunkName')}</Label>
                <Input placeholder={t('PBXDetailPage.trunkDialog.trunkNamePlaceholder')} value={trunkForm.name}
                  onChange={(e) => setTrunkForm({ ...trunkForm, name: e.target.value })} />
              </div>
              <div className="grid gap-2">
                <Label>{t('PBXDetailPage.trunkDialog.technology')}</Label>
                <Select value={trunkForm.technology} onValueChange={(v) => setTrunkForm({ ...trunkForm, technology: v })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="pjsip">PJSIP</SelectItem>
                    <SelectItem value="sip">{t('PBXDetailPage.trunkDialog.sipLegacy')}</SelectItem>
                    <SelectItem value="iax2">IAX2</SelectItem>
                    <SelectItem value="dahdi">DAHDI</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
              <div className="grid gap-2 col-span-2">
                <Label>{t('PBXDetailPage.trunkDialog.hostSipServer')}</Label>
                <Input placeholder="sip.provider.com" value={trunkForm.host}
                  onChange={(e) => setTrunkForm({ ...trunkForm, host: e.target.value })} />
              </div>
              <div className="grid gap-2">
                <Label>{t('PBXDetailPage.trunkDialog.port')}</Label>
                <Input placeholder="5060" value={trunkForm.port}
                  onChange={(e) => setTrunkForm({ ...trunkForm, port: e.target.value })} />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label>{t('PBXDetailPage.trunkDialog.username')}</Label>
                <Input placeholder="sip_user" value={trunkForm.username}
                  onChange={(e) => setTrunkForm({ ...trunkForm, username: e.target.value })} />
              </div>
              <div className="grid gap-2">
                <Label>{t('PBXDetailPage.trunkDialog.secretPassword')}</Label>
                <Input type="password" placeholder="••••••••" value={trunkForm.secret}
                  onChange={(e) => setTrunkForm({ ...trunkForm, secret: e.target.value })} />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label>{t('PBXDetailPage.trunkDialog.outboundCid')}</Label>
                <Input placeholder='"Name" <number>' value={trunkForm.outcid}
                  onChange={(e) => setTrunkForm({ ...trunkForm, outcid: e.target.value })} />
              </div>
              <div className="grid gap-2">
                <Label>{t('PBXDetailPage.trunkDialog.maxChannels')}</Label>
                <Input type="number" placeholder={t('PBXDetailPage.common.unlimited')} value={trunkForm.maxchans}
                  onChange={(e) => setTrunkForm({ ...trunkForm, maxchans: e.target.value })} />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label>{t('PBXDetailPage.trunkDialog.codecs')}</Label>
                <Input placeholder="ulaw,alaw,g729" value={trunkForm.codecs}
                  onChange={(e) => setTrunkForm({ ...trunkForm, codecs: e.target.value })} />
              </div>
              <div className="grid gap-2">
                <Label>{t('PBXDetailPage.trunkDialog.transport')}</Label>
                <Select value={trunkForm.transport || 'auto'} onValueChange={(v) => setTrunkForm({ ...trunkForm, transport: v === 'auto' ? '' : v })}>
                  <SelectTrigger><SelectValue placeholder={t('PBXDetailPage.common.auto')} /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="auto">{t('PBXDetailPage.common.auto')}</SelectItem>
                    <SelectItem value="udp">UDP</SelectItem>
                    <SelectItem value="tcp">TCP</SelectItem>
                    <SelectItem value="tls">TLS</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="grid gap-2">
              <Label>{t('PBXDetailPage.trunkDialog.provider')}</Label>
              <Input placeholder={t('PBXDetailPage.trunkDialog.providerPlaceholder')} value={trunkForm.provider}
                onChange={(e) => setTrunkForm({ ...trunkForm, provider: e.target.value })} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowTrunkDialog(false)}>{t('PBXDetailPage.common.cancel')}</Button>
            <Button
              onClick={() => createTrunkMutation.mutate(trunkForm)}
              disabled={!trunkForm.name || !trunkForm.host || createTrunkMutation.isPending}
            >
              {createTrunkMutation.isPending
                ? <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                : <Plus className="h-4 w-4 mr-2" />}
              {t('PBXDetailPage.trunkDialog.createTrunk')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Originate Call Dialog ── */}
      <Dialog open={showCallDialog} onOpenChange={(v) => { setShowCallDialog(v); if (!v) setCallForm({ extension: '', destination: '' }); }}>
        <DialogContent className="sm:max-w-[400px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Phone className="h-5 w-5" /> {t('PBXDetailPage.callDialog.title')}
            </DialogTitle>
            <DialogDescription>
              {t('PBXDetailPage.callDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-2">
            <div className="grid gap-2">
              <Label>{t('PBXDetailPage.callDialog.fromExtension')}</Label>
              <Input placeholder="100" value={callForm.extension}
                onChange={(e) => setCallForm({ ...callForm, extension: e.target.value })} />
            </div>
            <div className="grid gap-2">
              <Label>{t('PBXDetailPage.callDialog.destination')}</Label>
              <Input placeholder={t('PBXDetailPage.callDialog.destinationPlaceholder')} value={callForm.destination}
                onChange={(e) => setCallForm({ ...callForm, destination: e.target.value })} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCallDialog(false)}>{t('PBXDetailPage.common.cancel')}</Button>
            <Button onClick={() => originateMutation.mutate(callForm)}
              disabled={!callForm.extension || !callForm.destination || originateMutation.isPending}
            >
              {originateMutation.isPending
                ? <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                : <Play className="h-4 w-4 mr-2" />}
              {t('PBXDetailPage.callDialog.callButton')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ════════════════════════════════════════════════════════════════════
           DETAIL SHEET DRAWERS · Enterprise-grade entity inspection panels
         ════════════════════════════════════════════════════════════════════ */}

      {/* ── Extension Detail Sheet ── */}
      <Sheet open={!!selectedExtension} onOpenChange={(open) => !open && setSelectedExtension(null)}>
        <SheetContent className="sm:max-w-[560px] overflow-y-auto">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-primary/10">
                <Hash className="h-5 w-5 text-primary" />
              </div>
              <div>
                <span className="font-mono">{t('PBXDetailPage.extSheet.extPrefix')} {selectedExtension?.extension_number}</span>
                <p className="text-sm font-normal text-muted-foreground mt-0.5">
                  {selectedExtension?.display_name || t('PBXDetailPage.extSheet.unnamed')}
                </p>
              </div>
            </SheetTitle>
            <SheetDescription>
              {t('PBXDetailPage.extSheet.description')}
            </SheetDescription>
          </SheetHeader>

          {selectedExtension && (() => {
            const s = (selectedExtension.settings || {}) as Record<string, any>;
            return (
            <div className="space-y-6 mt-6">
              {/* Status Banner */}
              <div className={cn(
                'flex items-center gap-3 p-3 rounded-lg border',
                selectedExtension.is_active
                  ? 'bg-emerald-500/5 border-emerald-500/20'
                  : 'bg-red-500/5 border-red-500/20',
              )}>
                <div className={cn(
                  'w-3 h-3 rounded-full',
                  selectedExtension.is_active ? 'bg-emerald-500' : 'bg-red-500',
                )} />
                <span className={cn(
                  'text-sm font-medium',
                  selectedExtension.is_active ? 'text-emerald-600' : 'text-red-600',
                )}>
                  {selectedExtension.is_active ? t('PBXDetailPage.common.active') : t('PBXDetailPage.common.inactive')}
                </span>
                {(s.tech || selectedExtension.ext_type) && (
                  <Badge variant="outline" className="ml-auto text-xs">
                    {s.tech || selectedExtension.ext_type}
                  </Badge>
                )}
                {s.devicetype && (
                  <Badge variant="secondary" className="text-xs">{s.devicetype}</Badge>
                )}
              </div>

              {/* Identity */}
              <div className="space-y-3">
                <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.identity')}</h4>
                <div className="grid grid-cols-2 gap-y-3 gap-x-4">
                  <DetailRow label={t('PBXDetailPage.fields.extension')} value={s.extension || selectedExtension.extension_number} mono />
                  <DetailRow label={t('PBXDetailPage.fields.displayName')} value={s.name || selectedExtension.display_name} />
                  <DetailRow label={t('PBXDetailPage.fields.sipName')} value={s.sipname} />
                  <DetailRow label={t('PBXDetailPage.fields.description')} value={s.description} />
                  <DetailRow label={t('PBXDetailPage.fields.user')} value={s.user} mono />
                  <DetailRow label={t('PBXDetailPage.fields.technology')} value={s.tech} />
                  <DetailRow label={t('PBXDetailPage.fields.dialString')} value={s.dial} mono />
                </div>
              </div>

              <Separator />

              {/* Credentials */}
              <div className="space-y-3">
                <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.credentials')}</h4>
                <div className="grid grid-cols-2 gap-y-3 gap-x-4">
                  <DetailRow label={t('PBXDetailPage.fields.sipPassword')} value={s.password ? '••••••••' : '-'} />
                  <DetailRow label={t('PBXDetailPage.fields.voicemail')} value={s.voicemail || (selectedExtension.voicemail_enabled ? t('PBXDetailPage.common.enabled') : t('PBXDetailPage.common.disabled'))} />
                </div>
              </div>

              <Separator />

              {/* Caller ID */}
              <div className="space-y-3">
                <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.callerId')}</h4>
                <div className="grid grid-cols-2 gap-y-3 gap-x-4">
                  <DetailRow label={t('PBXDetailPage.fields.outboundCid')} value={s.outboundcid} mono />
                  <DetailRow label={t('PBXDetailPage.fields.emergencyCid')} value={s.emergency_cid} mono />
                  <DetailRow label={t('PBXDetailPage.fields.noAnswerCid')} value={s.noanswer_cid} mono />
                  <DetailRow label={t('PBXDetailPage.fields.busyCid')} value={s.busy_cid} mono />
                  <DetailRow label={t('PBXDetailPage.fields.unavailableCid')} value={s.chanunavail_cid} mono />
                </div>
              </div>

              <Separator />

              {/* Call Routing */}
              <div className="space-y-3">
                <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.callRouting')}</h4>
                <div className="grid grid-cols-2 gap-y-3 gap-x-4">
                  <DetailRow label={t('PBXDetailPage.fields.ringTimer')} value={s.ringtimer ? `${s.ringtimer}s` : undefined} />
                  <DetailRow label={t('PBXDetailPage.fields.noAnswerDest')} value={s.noanswer_dest} mono />
                  <DetailRow label={t('PBXDetailPage.fields.busyDest')} value={s.busy_dest} mono />
                  <DetailRow label={t('PBXDetailPage.fields.unavailDest')} value={s.chanunavail_dest} mono />
                  <DetailRow label={t('PBXDetailPage.fields.noAnswerAction')} value={s.noanswer} />
                  <DetailRow label={t('PBXDetailPage.fields.mohClass')} value={s.mohclass} />
                </div>
              </div>

              <Separator />

              {/* Recording */}
              <div className="space-y-3">
                <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.recording')}</h4>
                <div className="grid grid-cols-2 gap-y-3 gap-x-4">
                  <DetailRow label={t('PBXDetailPage.fields.policy')} value={s.recording} />
                  <DetailRow label={t('PBXDetailPage.fields.onDemand')} value={s.recording_ondemand} />
                  <DetailRow label={t('PBXDetailPage.fields.priority')} value={s.recording_priority} />
                  <DetailRow label={t('PBXDetailPage.fields.inboundExternal')} value={s.recording_in_external} />
                  <DetailRow label={t('PBXDetailPage.fields.outboundExternal')} value={s.recording_out_external} />
                  <DetailRow label={t('PBXDetailPage.fields.inboundInternal')} value={s.recording_in_internal} />
                  <DetailRow label={t('PBXDetailPage.fields.outboundInternal')} value={s.recording_out_internal} />
                </div>
              </div>

              <Separator />

              {/* Features */}
              <div className="space-y-3">
                <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.features')}</h4>
                <div className="grid grid-cols-2 gap-y-3 gap-x-4">
                  <DetailRow label={t('PBXDetailPage.fields.answerMode')} value={s.answermode} />
                  <DetailRow label={t('PBXDetailPage.fields.intercom')} value={s.intercom} />
                  <DetailRow label={t('PBXDetailPage.fields.cwTone')} value={s.cwtone} />
                  <DetailRow label={t('PBXDetailPage.fields.hintOverride')} value={s.hint_override} />
                </div>
                {/* Feature flags from nested settings */}
                {s.settings && typeof s.settings === 'object' && (
                  <div className="flex flex-wrap gap-2 mt-2">
                    {Object.entries(s.settings as Record<string, string>).map(([k, v]) => (
                      <Badge key={k} variant={v === 'ENABLED' || v === 'enabled' ? 'default' : 'outline'} className="text-[10px]">
                        {k.toUpperCase()}: {v}
                      </Badge>
                    ))}
                  </div>
                )}
              </div>

              <Separator />

              {/* Live Data from Adapter */}
              {extensionDetail?.live && (
                <>
                  <div className="space-y-3">
                    <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">
                      {t('PBXDetailPage.sections.liveFreepbxData')}
                    </h4>
                    <div className="bg-muted/50 rounded-lg p-3 space-y-2 text-sm">
                      {Object.entries(extensionDetail.live as Record<string, unknown>).map(([key, val]) => (
                        <div key={key} className="flex justify-between">
                          <span className="text-muted-foreground capitalize">{key.replace(/_/g, ' ')}</span>
                          <span className="font-mono text-xs truncate max-w-[200px]">{String(val ?? '-')}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  <Separator />
                </>
              )}

              {/* Actions */}
              <div className="flex gap-2 pt-2">
                <Button
                  variant="outline"
                  size="sm"
                  className="flex-1"
                  onClick={() => {
                    setCallForm({ extension: selectedExtension.extension_number, destination: '' });
                    setShowCallDialog(true);
                    setSelectedExtension(null);
                  }}
                >
                  <Phone className="h-4 w-4 mr-2" /> {t('PBXDetailPage.callDialog.callButton')}
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="flex-1"
                  onClick={() => {
                    const s = (selectedExtension.settings || {}) as Record<string, any>;
                    setEditExtForm({
                      name: s.name || selectedExtension.display_name || '',
                      outboundcid: s.outboundcid || '',
                    });
                    setEditExt(selectedExtension);
                    setSelectedExtension(null);
                  }}
                >
                  <Settings className="h-4 w-4 mr-2" /> {t('PBXDetailPage.editExt.button')}
                </Button>
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() => {
                    if (confirm(t('PBXDetailPage.confirm.deleteExtension', { number: selectedExtension.extension_number }))) {
                      deleteExtMutation.mutate(selectedExtension.extension_number);
                      setSelectedExtension(null);
                    }
                  }}
                >
                  <Trash2 className="h-4 w-4 mr-2" /> {t('PBXDetailPage.common.delete')}
                </Button>
              </div>
            </div>
            );
          })()}
        </SheetContent>
      </Sheet>

      {/* ── Trunk Detail Sheet ── */}
      <Sheet open={!!selectedTrunk} onOpenChange={(open) => {
        if (!open) { setSelectedTrunk(null); setTrunkEditMode(false); }
      }}>
        <SheetContent className="sm:max-w-[560px] overflow-y-auto">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-100 dark:bg-purple-900/30">
                <GitBranch className="h-5 w-5 text-purple-600" />
              </div>
              <div className="flex-1 min-w-0">
                <span>{(trunkDetail ?? selectedTrunk)?.name}</span>
                <p className="text-sm font-normal text-muted-foreground mt-0.5">
                  {t('PBXDetailPage.trunkSheet.techTrunk', { tech: (trunkDetail ?? selectedTrunk)?.technology || (trunkDetail ?? selectedTrunk)?.tech || (trunkDetail ?? selectedTrunk)?.trunk_type || 'SIP' })}
                </p>
              </div>
              {TRUNK_WRITE_SUPPORTED && (
                <Button
                  variant={trunkEditMode ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setTrunkEditMode(!trunkEditMode)}
                >
                  {trunkEditMode
                    ? <><Eye className="h-4 w-4 mr-1" /> {t('PBXDetailPage.common.view')}</>
                    : <><Settings className="h-4 w-4 mr-1" /> {t('PBXDetailPage.common.edit')}</>}
                </Button>
              )}
            </SheetTitle>
            <SheetDescription>
              {trunkEditMode ? t('PBXDetailPage.trunkSheet.editDescription') : t('PBXDetailPage.trunkSheet.viewDescription')}
              {(trunkDetail as any)?._source && (
                <Badge variant="outline" className="ml-2 text-[10px]">
                  {(trunkDetail as any)._source === 'live' ? t('PBXDetailPage.common.live') : t('PBXDetailPage.common.cached')}
                </Badge>
              )}
            </SheetDescription>
          </SheetHeader>

          {selectedTrunk && (() => {
            const trunkObj = trunkDetail ?? selectedTrunk;
            const s = (trunkObj.status || '').toLowerCase();
            const isUp = s.includes('ok') || s.includes('registered') || s.includes('online');
            const isDisabled = s.includes('disabled');
            const isConfigured = s.includes('configured');
            const tech = trunkObj.technology || trunkObj.tech || trunkObj.trunk_type || 'SIP';

            const bannerClasses = isUp
              ? 'bg-emerald-500/5 border-emerald-500/20'
              : isDisabled
                ? 'bg-muted border-border'
                : isConfigured
                  ? 'bg-amber-500/5 border-amber-500/20'
                  : 'bg-red-500/5 border-red-500/20';
            const dotColor = isUp ? 'bg-emerald-500' : isDisabled ? 'bg-muted-foreground' : isConfigured ? 'bg-amber-500' : 'bg-red-500';
            const textColor = isUp ? 'text-emerald-600' : isDisabled ? 'text-muted-foreground' : isConfigured ? 'text-amber-600' : 'text-red-600';
            const statusLabel = isUp ? t('PBXDetailPage.trunkStatus.registered') : isDisabled ? t('PBXDetailPage.trunkStatus.disabled') : isConfigured ? t('PBXDetailPage.trunkStatus.configured') : (trunkObj.status || t('PBXDetailPage.common.unknown'));

            // ── VIEW MODE ──
            if (!trunkEditMode) {
              return (
                <div className="space-y-6 mt-6">
                  {/* Status Banner */}
                  <div className={cn(
                    'flex items-center gap-3 p-3 rounded-lg border',
                    bannerClasses,
                  )}>
                    <div className={cn('w-3 h-3 rounded-full', dotColor)} />
                    <span className={cn('text-sm font-medium', textColor)}>
                      {statusLabel}
                    </span>
                    <Badge variant="outline" className="ml-auto text-xs">{tech}</Badge>
                  </div>

                  {/* Identity */}
                  <div className="space-y-3">
                    <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.identity')}</h4>
                    <div className="grid grid-cols-2 gap-y-3 gap-x-4">
                      <DetailRow label={t('PBXDetailPage.fields.trunkName')} value={trunkObj.name} />
                      <DetailRow label={t('PBXDetailPage.fields.trunkId')} value={String(trunkObj.trunkid ?? trunkObj.trunk_id ?? trunkObj.channelid ?? '-')} mono />
                      <DetailRow label={t('PBXDetailPage.fields.technology')} value={tech} />
                      <DetailRow label={t('PBXDetailPage.fields.provider')} value={trunkObj.provider} />
                      <DetailRow label={t('PBXDetailPage.fields.outboundCid')} value={trunkObj.outcid} mono />
                      <DetailRow label={t('PBXDetailPage.fields.keepCid')} value={trunkObj.keepcid === 'on' ? t('PBXDetailPage.common.yes') : trunkObj.keepcid === 'off' ? t('PBXDetailPage.common.no') : trunkObj.keepcid} />
                      <DetailRow label={t('PBXDetailPage.fields.disabled')} value={trunkObj.disabled === 'on' ? t('PBXDetailPage.common.yes') : t('PBXDetailPage.common.no')} />
                      <DetailRow label={t('PBXDetailPage.fields.failoverTrunk')} value={trunkObj.failover} />
                      <DetailRow label={t('PBXDetailPage.fields.dialOutPrefix')} value={trunkObj.dialoutprefix} mono />
                    </div>
                  </div>

                  <Separator />

                  {/* Connection */}
                  <div className="space-y-3">
                    <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.connection')}</h4>
                    <div className="grid grid-cols-2 gap-y-3 gap-x-4">
                      <DetailRow label={t('PBXDetailPage.fields.sipServer')} value={trunkObj.sip_server || trunkObj.host} mono />
                      <DetailRow label={t('PBXDetailPage.fields.port')} value={String(trunkObj.sip_server_port || trunkObj.port || '5060')} mono />
                      <DetailRow label={t('PBXDetailPage.fields.username')} value={trunkObj.username} mono />
                      <DetailRow label={t('PBXDetailPage.fields.secret')} value={trunkObj.secret ? '••••••••' : undefined} />
                      <DetailRow label={t('PBXDetailPage.fields.transport')} value={trunkObj.transport} />
                      <DetailRow label={t('PBXDetailPage.fields.context')} value={trunkObj.context} mono />
                      <DetailRow label={t('PBXDetailPage.fields.fromDomain')} value={trunkObj.from_domain} mono />
                      <DetailRow label={t('PBXDetailPage.fields.fromUser')} value={trunkObj.from_user} mono />
                    </div>
                  </div>

                  <Separator />

                  {/* Authentication & Registration */}
                  <div className="space-y-3">
                    <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.authentication')}</h4>
                    <div className="grid grid-cols-2 gap-y-3 gap-x-4">
                      <DetailRow label={t('PBXDetailPage.fields.authentication')} value={trunkObj.authentication} />
                      <DetailRow label={t('PBXDetailPage.fields.registration')} value={trunkObj.registration} />
                      <DetailRow label={t('PBXDetailPage.fields.pjsipLine')} value={trunkObj.pjsip_line === 'true' ? t('PBXDetailPage.common.yes') : trunkObj.pjsip_line === 'false' ? t('PBXDetailPage.common.no') : trunkObj.pjsip_line} />
                      <DetailRow label={t('PBXDetailPage.fields.authRejectionPermanent')} value={trunkObj.auth_rejection_permanent} />
                      <DetailRow label={t('PBXDetailPage.fields.expiration')} value={trunkObj.expiration ? `${trunkObj.expiration}s` : undefined} />
                      <DetailRow label={t('PBXDetailPage.fields.identifyBy')} value={trunkObj.identify_by} />
                    </div>
                  </div>

                  <Separator />

                  {/* Media & Codecs */}
                  <div className="space-y-3">
                    <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.mediaCodecs')}</h4>
                    <div className="grid grid-cols-2 gap-y-3 gap-x-4">
                      <DetailRow label={t('PBXDetailPage.fields.codecs')} value={trunkObj.codecs} mono />
                      <DetailRow label={t('PBXDetailPage.fields.dtmfMode')} value={trunkObj.dtmfmode} />
                      <DetailRow label={t('PBXDetailPage.fields.mediaEncryption')} value={trunkObj.media_encryption} />
                      <DetailRow label={t('PBXDetailPage.fields.rtpSymmetric')} value={trunkObj.rtp_symmetric} />
                      <DetailRow label={t('PBXDetailPage.fields.forceRport')} value={trunkObj.force_rport} />
                      <DetailRow label={t('PBXDetailPage.fields.t38Udptl')} value={trunkObj.t38_udptl} />
                    </div>
                  </div>

                  <Separator />

                  {/* Advanced */}
                  <div className="space-y-3">
                    <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.advanced')}</h4>
                    <div className="grid grid-cols-2 gap-y-3 gap-x-4">
                      <DetailRow label={t('PBXDetailPage.fields.qualifyFrequency')} value={trunkObj.qualify_frequency ? `${trunkObj.qualify_frequency}s` : undefined} />
                      <DetailRow label={t('PBXDetailPage.fields.sendConnectedLine')} value={trunkObj.send_connected_line} />
                      <DetailRow label={t('PBXDetailPage.fields.trustRpid')} value={trunkObj.trust_rpid} />
                      <DetailRow label={t('PBXDetailPage.fields.sendRpid')} value={trunkObj.sendrpid} />
                      <DetailRow label={t('PBXDetailPage.fields.faxDetect')} value={trunkObj.fax_detect} />
                      <DetailRow label={t('PBXDetailPage.fields.allowUnauthOptions')} value={trunkObj.allow_unauthenticated_options} />
                      <DetailRow label={t('PBXDetailPage.fields.maxRetries')} value={trunkObj.max_retries != null ? String(trunkObj.max_retries) : undefined} />
                      <DetailRow label={t('PBXDetailPage.fields.retryInterval')} value={trunkObj.retry_interval ? `${trunkObj.retry_interval}s` : undefined} />
                    </div>
                  </div>

                  <Separator />

                  {/* Channel Usage */}
                  <div className="space-y-3">
                    <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.channels')}</h4>
                    <div className="p-4 bg-muted rounded-lg">
                      <div className="flex items-end gap-3">
                        <p className="text-3xl font-bold">{trunkObj.channels_used ?? 0}</p>
                        <p className="text-lg text-muted-foreground mb-0.5">
                          / {trunkObj.max_channels || trunkObj.maxchans || '\u221e'}
                        </p>
                      </div>
                      <p className="text-sm text-muted-foreground mt-1">{t('PBXDetailPage.trunkSheet.activeChannels')}</p>
                      {(trunkObj.max_channels || trunkObj.maxchans) && Number(trunkObj.max_channels || trunkObj.maxchans) > 0 && (
                        <div className="mt-3 h-2 bg-background rounded-full overflow-hidden">
                          <div
                            className={cn(
                              'h-full rounded-full transition-all',
                              ((trunkObj.channels_used ?? 0) / Number(trunkObj.max_channels || trunkObj.maxchans)) > 0.8
                                ? 'bg-red-500' : 'bg-emerald-500',
                            )}
                            style={{ width: `${Math.min(100, ((trunkObj.channels_used ?? 0) / Number(trunkObj.max_channels || trunkObj.maxchans)) * 100)}%` }}
                          />
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Raw Settings */}
                  {trunkObj.settings && Object.keys(trunkObj.settings).length > 0 && (
                    <>
                      <Separator />
                      <div className="space-y-3">
                        <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.rawSettings')}</h4>
                        <div className="bg-muted/50 rounded-lg p-3 space-y-2 text-sm max-h-[300px] overflow-y-auto">
                          {Object.entries(trunkObj.settings).map(([key, val]) => (
                            <div key={key} className="flex justify-between">
                              <span className="text-muted-foreground capitalize">{key.replace(/_/g, ' ')}</span>
                              <span className="font-mono text-xs truncate max-w-[200px]">{String(val ?? '-')}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </>
                  )}

                  {/* Actions — trunks are read-only unless the PBX exposes a
                      trunk write API (FreePBX currently does not). */}
                  {TRUNK_WRITE_SUPPORTED ? (
                    <div className="flex gap-2 pt-2">
                      <Button
                        variant="outline"
                        size="sm"
                        className="flex-1"
                        onClick={() => setTrunkEditMode(true)}
                      >
                        <Settings className="h-4 w-4 mr-2" /> {t('PBXDetailPage.trunkSheet.editSettings')}
                      </Button>
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => {
                          if (confirm(t('PBXDetailPage.confirm.deleteTrunk', { name: trunkObj.name }))) {
                            deleteTrunkMutation.mutate(String(trunkObj.trunkid ?? trunkObj.trunk_id ?? trunkObj.channelid));
                          }
                        }}
                        disabled={deleteTrunkMutation.isPending}
                      >
                        {deleteTrunkMutation.isPending
                          ? <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                          : <Trash2 className="h-4 w-4 mr-2" />}
                        {t('PBXDetailPage.common.delete')}
                      </Button>
                    </div>
                  ) : (
                    <div className="flex items-start gap-2 pt-2 text-xs text-muted-foreground">
                      <Eye className="h-3.5 w-3.5 mt-0.5 shrink-0" />
                      <p>{t('PBXDetailPage.trunkSheet.readOnlyNote')}</p>
                    </div>
                  )}
                </div>
              );
            }

            // ── EDIT MODE ──
            return (
              <div className="space-y-5 mt-6">
                {/* General */}
                <div className="space-y-3">
                  <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.general')}</h4>
                  <div className="grid gap-3">
                    <div className="grid gap-1.5">
                      <Label className="text-xs">{t('PBXDetailPage.fields.trunkName')}</Label>
                      <Input value={trunkEditForm.name} onChange={(e) => setTrunkEditForm({ ...trunkEditForm, name: e.target.value })} />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="grid gap-1.5">
                        <Label className="text-xs">{t('PBXDetailPage.fields.outboundCid')}</Label>
                        <Input placeholder='"Name" <number>' value={trunkEditForm.outcid}
                          onChange={(e) => setTrunkEditForm({ ...trunkEditForm, outcid: e.target.value })} />
                      </div>
                      <div className="grid gap-1.5">
                        <Label className="text-xs">{t('PBXDetailPage.trunkDialog.maxChannels')}</Label>
                        <Input type="number" placeholder={t('PBXDetailPage.common.unlimited')} value={trunkEditForm.maxchans}
                          onChange={(e) => setTrunkEditForm({ ...trunkEditForm, maxchans: e.target.value })} />
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="grid gap-1.5">
                        <Label className="text-xs">{t('PBXDetailPage.fields.keepCid')}</Label>
                        <Select value={trunkEditForm.keepcid} onValueChange={(v) => setTrunkEditForm({ ...trunkEditForm, keepcid: v })}>
                          <SelectTrigger><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="off">{t('PBXDetailPage.common.no')}</SelectItem>
                            <SelectItem value="on">{t('PBXDetailPage.common.yes')}</SelectItem>
                            <SelectItem value="cnum">{t('PBXDetailPage.trunkEdit.callerIdNumberOnly')}</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="grid gap-1.5">
                        <Label className="text-xs">{t('PBXDetailPage.fields.disabled')}</Label>
                        <Select value={trunkEditForm.disabled} onValueChange={(v) => setTrunkEditForm({ ...trunkEditForm, disabled: v })}>
                          <SelectTrigger><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="off">{t('PBXDetailPage.common.no')}</SelectItem>
                            <SelectItem value="on">{t('PBXDetailPage.trunkEdit.yesDisabled')}</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="grid gap-1.5">
                        <Label className="text-xs">{t('PBXDetailPage.fields.dialOutPrefix')}</Label>
                        <Input placeholder={t('PBXDetailPage.trunkEdit.dialOutPrefixPlaceholder')} value={trunkEditForm.dialoutprefix}
                          onChange={(e) => setTrunkEditForm({ ...trunkEditForm, dialoutprefix: e.target.value })} />
                      </div>
                      <div className="grid gap-1.5">
                        <Label className="text-xs">{t('PBXDetailPage.fields.provider')}</Label>
                        <Input placeholder={t('PBXDetailPage.trunkEdit.providerNamePlaceholder')} value={trunkEditForm.provider}
                          onChange={(e) => setTrunkEditForm({ ...trunkEditForm, provider: e.target.value })} />
                      </div>
                    </div>
                    <div className="grid gap-1.5">
                      <Label className="text-xs">{t('PBXDetailPage.fields.failoverTrunk')}</Label>
                      <Input placeholder={t('PBXDetailPage.trunkEdit.failoverPlaceholder')} value={trunkEditForm.failover}
                        onChange={(e) => setTrunkEditForm({ ...trunkEditForm, failover: e.target.value })} />
                    </div>
                  </div>
                </div>

                <Separator />

                {/* Connection / SIP */}
                <div className="space-y-3">
                  <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.connectionSip')}</h4>
                  <div className="grid gap-3">
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                      <div className="grid gap-1.5 col-span-2">
                        <Label className="text-xs">{t('PBXDetailPage.trunkDialog.hostSipServer')}</Label>
                        <Input placeholder="sip.provider.com" value={trunkEditForm.host || trunkEditForm.sip_server}
                          onChange={(e) => setTrunkEditForm({ ...trunkEditForm, host: e.target.value, sip_server: e.target.value })} />
                      </div>
                      <div className="grid gap-1.5">
                        <Label className="text-xs">{t('PBXDetailPage.fields.port')}</Label>
                        <Input placeholder="5060" value={trunkEditForm.port || trunkEditForm.sip_server_port}
                          onChange={(e) => setTrunkEditForm({ ...trunkEditForm, port: e.target.value, sip_server_port: e.target.value })} />
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="grid gap-1.5">
                        <Label className="text-xs">{t('PBXDetailPage.fields.username')}</Label>
                        <Input value={trunkEditForm.username}
                          onChange={(e) => setTrunkEditForm({ ...trunkEditForm, username: e.target.value })} />
                      </div>
                      <div className="grid gap-1.5">
                        <Label className="text-xs">{t('PBXDetailPage.trunkDialog.secretPassword')}</Label>
                        <Input type="password" placeholder="••••••••" value={trunkEditForm.secret}
                          onChange={(e) => setTrunkEditForm({ ...trunkEditForm, secret: e.target.value })} />
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="grid gap-1.5">
                        <Label className="text-xs">{t('PBXDetailPage.fields.transport')}</Label>
                        <Select value={trunkEditForm.transport || 'auto'} onValueChange={(v) => setTrunkEditForm({ ...trunkEditForm, transport: v === 'auto' ? '' : v })}>
                          <SelectTrigger><SelectValue placeholder={t('PBXDetailPage.common.auto')} /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="auto">{t('PBXDetailPage.common.auto')}</SelectItem>
                            <SelectItem value="udp">UDP</SelectItem>
                            <SelectItem value="tcp">TCP</SelectItem>
                            <SelectItem value="tls">TLS</SelectItem>
                            <SelectItem value="ws">WS</SelectItem>
                            <SelectItem value="wss">WSS</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="grid gap-1.5">
                        <Label className="text-xs">{t('PBXDetailPage.fields.codecs')}</Label>
                        <Input placeholder="ulaw,alaw,g729" value={trunkEditForm.codecs}
                          onChange={(e) => setTrunkEditForm({ ...trunkEditForm, codecs: e.target.value })} />
                      </div>
                    </div>
                  </div>
                </div>

                <Separator />

                {/* PJSIP / Registration */}
                <div className="space-y-3">
                  <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.pjsipRegistration')}</h4>
                  <div className="grid gap-3">
                    <div className="grid gap-1.5">
                      <Label className="text-xs">{t('PBXDetailPage.fields.registrationString')}</Label>
                      <Input placeholder="user:pass@host/ext" value={trunkEditForm.registration}
                        onChange={(e) => setTrunkEditForm({ ...trunkEditForm, registration: e.target.value })} />
                    </div>
                    <div className="grid gap-1.5">
                      <Label className="text-xs">{t('PBXDetailPage.fields.aorContact')}</Label>
                      <Input placeholder="sip:user@host:port" value={trunkEditForm.aor_contact}
                        onChange={(e) => setTrunkEditForm({ ...trunkEditForm, aor_contact: e.target.value })} />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="grid gap-1.5">
                        <Label className="text-xs">{t('PBXDetailPage.fields.matchIpCidr')}</Label>
                        <Input placeholder="203.0.113.0/24" value={trunkEditForm.match}
                          onChange={(e) => setTrunkEditForm({ ...trunkEditForm, match: e.target.value })} />
                      </div>
                      <div className="grid gap-1.5">
                        <Label className="text-xs">{t('PBXDetailPage.fields.contactUser')}</Label>
                        <Input value={trunkEditForm.contact_user}
                          onChange={(e) => setTrunkEditForm({ ...trunkEditForm, contact_user: e.target.value })} />
                      </div>
                    </div>
                  </div>
                </div>

                {/* Save / Cancel */}
                <div className="flex gap-2 pt-3 sticky bottom-0 bg-background pb-4">
                  <Button
                    variant="outline"
                    size="sm"
                    className="flex-1"
                    onClick={() => setTrunkEditMode(false)}
                  >
                    {t('PBXDetailPage.common.cancel')}
                  </Button>
                  <Button
                    size="sm"
                    className="flex-1"
                    disabled={updateTrunkMutation.isPending}
                    onClick={() => updateTrunkMutation.mutate(trunkEditForm)}
                  >
                    {updateTrunkMutation.isPending
                      ? <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      : <Save className="h-4 w-4 mr-2" />}
                    {t('PBXDetailPage.common.saveChanges')}
                  </Button>
                </div>
              </div>
            );
          })()}
        </SheetContent>
      </Sheet>

      {/* ── Queue Detail Sheet ── */}
      <Sheet open={!!selectedQueue} onOpenChange={(open) => !open && setSelectedQueue(null)}>
        <SheetContent className="sm:max-w-[520px] overflow-y-auto">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-cyan-100 dark:bg-cyan-900/30">
                <ListOrdered className="h-5 w-5 text-cyan-600" />
              </div>
              <div>
                <span>{selectedQueue?.display_name || selectedQueue?.name}</span>
                <p className="text-sm font-normal text-muted-foreground mt-0.5">
                  {t('PBXDetailPage.queueSheet.strategyLabel', { strategy: selectedQueue?.strategy || 'ringall' })}
                </p>
              </div>
            </SheetTitle>
            <SheetDescription>{t('PBXDetailPage.queueSheet.description')}</SheetDescription>
          </SheetHeader>

          {selectedQueue && (
            <div className="space-y-6 mt-6">
              {/* Real-time Metrics */}
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                <div className="p-3 bg-muted rounded-lg text-center">
                  <p className="text-2xl font-bold text-primary">
                    {selectedQueue.member_count ?? selectedQueue.members?.length ?? 0}
                  </p>
                  <p className="text-xs text-muted-foreground">{t('PBXDetailPage.queueSheet.agents')}</p>
                </div>
                <div className="p-3 bg-muted rounded-lg text-center">
                  <p className={cn(
                    'text-2xl font-bold',
                    (selectedQueue.callers_waiting ?? 0) > 0 ? 'text-amber-600' : 'text-muted-foreground',
                  )}>
                    {selectedQueue.callers_waiting ?? 0}
                  </p>
                  <p className="text-xs text-muted-foreground">{t('PBXDetailPage.columns.waiting')}</p>
                </div>
                <div className="p-3 bg-muted rounded-lg text-center">
                  <p className="text-2xl font-bold text-emerald-600">
                    {selectedQueue.service_level != null ? `${Math.round(selectedQueue.service_level)}%` : '-'}
                  </p>
                  <p className="text-xs text-muted-foreground">{t('PBXDetailPage.columns.serviceLevel')}</p>
                </div>
              </div>

              <Separator />

              {/* Performance Stats */}
              <div className="space-y-3">
                <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.performance')}</h4>
                <div className="grid grid-cols-2 gap-y-3 gap-x-4">
                  <DetailRow label={t('PBXDetailPage.columns.completed')} value={String(selectedQueue.completed ?? 0)} />
                  <DetailRow label={t('PBXDetailPage.columns.abandoned')} value={String(selectedQueue.abandoned ?? 0)} />
                  <DetailRow label={t('PBXDetailPage.fields.avgHoldTime')} value={selectedQueue.holdtime != null ? `${selectedQueue.holdtime}s` : '-'} />
                  <DetailRow label={t('PBXDetailPage.fields.avgTalkTime')} value={selectedQueue.talk_time != null ? `${selectedQueue.talk_time}s` : '-'} />
                  <DetailRow label={t('PBXDetailPage.fields.callsTaken')} value={String(selectedQueue.calls_taken ?? 0)} />
                  <DetailRow label={t('PBXDetailPage.columns.strategy')} value={selectedQueue.strategy || 'ringall'} />
                </div>
              </div>

              <Separator />

              {/* Members List */}
              <div className="space-y-3">
                <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">
                  {t('PBXDetailPage.queueSheet.queueMembers', { count: selectedQueue.members?.length ?? 0 })}
                </h4>
                {selectedQueue.members && selectedQueue.members.length > 0 ? (
                  <div className="space-y-2">
                    {selectedQueue.members.map((member: any, i: number) => {
                      const memberStr = typeof member === 'string' ? member : (member?.interface || member?.name || JSON.stringify(member));
                      return (
                        <div key={i} className="flex items-center gap-3 p-2 bg-muted rounded-lg">
                          <Headphones className="h-4 w-4 text-muted-foreground" />
                          <span className="text-sm font-mono">{memberStr}</span>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground py-2">{t('PBXDetailPage.queueSheet.noMembers')}</p>
                )}
              </div>

              {/* Settings */}
              {selectedQueue.settings && Object.keys(selectedQueue.settings).length > 0 && (
                <>
                  <Separator />
                  <div className="space-y-3">
                    <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.settings')}</h4>
                    <div className="bg-muted/50 rounded-lg p-3 space-y-2 text-sm">
                      {Object.entries(selectedQueue.settings).map(([key, val]) => (
                        <div key={key} className="flex justify-between">
                          <span className="text-muted-foreground capitalize">{key.replace(/_/g, ' ')}</span>
                          <span className="font-mono text-xs truncate max-w-[200px]">{String(val ?? '-')}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              )}
            </div>
          )}
        </SheetContent>
      </Sheet>

      {/* ── Ring Group Detail Sheet ── */}
      <Sheet open={!!selectedRingGroup} onOpenChange={(open) => !open && setSelectedRingGroup(null)}>
        <SheetContent className="sm:max-w-[520px] overflow-y-auto">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-amber-100 dark:bg-amber-900/30">
                <Users className="h-5 w-5 text-amber-600" />
              </div>
              <div>
                <span>{selectedRingGroup?.name}</span>
                <p className="text-sm font-normal text-muted-foreground mt-0.5">
                  #{selectedRingGroup?.group_number || selectedRingGroup?.extension_number}
                </p>
              </div>
            </SheetTitle>
            <SheetDescription>{t('PBXDetailPage.ringGroupSheet.description')}</SheetDescription>
          </SheetHeader>

          {selectedRingGroup && (
            <div className="space-y-6 mt-6">
              {/* Status */}
              <div className={cn(
                'flex items-center gap-3 p-3 rounded-lg border',
                selectedRingGroup.is_active
                  ? 'bg-emerald-500/5 border-emerald-500/20'
                  : 'bg-red-500/5 border-red-500/20',
              )}>
                <div className={cn(
                  'w-3 h-3 rounded-full',
                  selectedRingGroup.is_active ? 'bg-emerald-500' : 'bg-red-500',
                )} />
                <span className={cn(
                  'text-sm font-medium',
                  selectedRingGroup.is_active ? 'text-emerald-600' : 'text-red-600',
                )}>
                  {selectedRingGroup.is_active ? t('PBXDetailPage.common.active') : t('PBXDetailPage.common.inactive')}
                </span>
              </div>

              {/* Configuration */}
              <div className="space-y-3">
                <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.configuration')}</h4>
                <div className="grid grid-cols-2 gap-y-3 gap-x-4">
                  <DetailRow label={t('PBXDetailPage.fields.groupNumber')} value={selectedRingGroup.group_number} mono />
                  <DetailRow label={t('PBXDetailPage.fields.extension')} value={selectedRingGroup.extension_number} mono />
                  <DetailRow label={t('PBXDetailPage.columns.strategy')} value={selectedRingGroup.ring_strategy} />
                  <DetailRow label={t('PBXDetailPage.columns.ringTime')} value={`${selectedRingGroup.ring_time}s`} />
                </div>
              </div>

              {selectedRingGroup.description && (
                <>
                  <Separator />
                  <div className="space-y-2">
                    <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.description')}</h4>
                    <p className="text-sm">{selectedRingGroup.description}</p>
                  </div>
                </>
              )}

              <Separator />

              {/* Members */}
              <div className="space-y-3">
                <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">
                  {t('PBXDetailPage.ringGroupSheet.membersCount', { count: selectedRingGroup.members?.length ?? 0 })}
                </h4>
                {selectedRingGroup.members && selectedRingGroup.members.length > 0 ? (
                  <div className="space-y-2">
                    {selectedRingGroup.members.map((member, i) => {
                      const memberStr = typeof member === 'string' ? member : String(member);
                      // Try to find matching extension name
                      const ext = extensions.find(e => e.extension_number === memberStr);
                      return (
                        <div key={i} className="flex items-center justify-between p-2 bg-muted rounded-lg">
                          <div className="flex items-center gap-3">
                            <Hash className="h-4 w-4 text-muted-foreground" />
                            <span className="text-sm font-mono">{memberStr}</span>
                          </div>
                          {ext && (
                            <span className="text-sm text-muted-foreground">{ext.display_name}</span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground py-2">{t('PBXDetailPage.ringGroupSheet.noMembers')}</p>
                )}
              </div>

              {/* Actions */}
              <div className="flex gap-2 pt-2">
                <Button
                  variant="outline"
                  size="sm"
                  className="flex-1"
                  onClick={() => {
                    setEditRgDesc(selectedRingGroup.description || '');
                    setEditRg(selectedRingGroup);
                    setSelectedRingGroup(null);
                  }}
                >
                  <Settings className="h-4 w-4 mr-2" /> {t('PBXDetailPage.editExt.button')}
                </Button>
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() => {
                    const grp = String(
                      selectedRingGroup.group_number || selectedRingGroup.extension_number || '',
                    );
                    if (confirm(t('PBXDetailPage.confirm.deleteRingGroup', { number: grp }))) {
                      stageRgDelete.mutate(grp);
                      setSelectedRingGroup(null);
                    }
                  }}
                >
                  <Trash2 className="h-4 w-4 mr-2" /> {t('PBXDetailPage.common.delete')}
                </Button>
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>

      {/* ── IVR Detail Sheet ── */}
      <Sheet open={!!selectedIVR} onOpenChange={(open) => !open && setSelectedIVR(null)}>
        <SheetContent className="sm:max-w-[520px] overflow-y-auto">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-amber-100 dark:bg-amber-900/30">
                <Layers className="h-5 w-5 text-amber-600" />
              </div>
              <div>
                <span>{selectedIVR?.name}</span>
                {selectedIVR?.description && (
                  <p className="text-sm font-normal text-muted-foreground mt-0.5">
                    {selectedIVR.description}
                  </p>
                )}
              </div>
            </SheetTitle>
            <SheetDescription>{t('PBXDetailPage.ivrSheet.description')}</SheetDescription>
          </SheetHeader>

          {selectedIVR && (
            <div className="space-y-6 mt-6">
              {/* Configuration */}
              <div className="space-y-3">
                <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.configuration')}</h4>
                <div className="grid grid-cols-2 gap-y-3 gap-x-4">
                  <DetailRow label={t('PBXDetailPage.columns.timeout')} value={`${selectedIVR.timeout ?? 10}s`} />
                  <DetailRow
                    label={t('PBXDetailPage.columns.directDial')}
                    value={selectedIVR.direct_dial ? t('PBXDetailPage.common.enabled') : t('PBXDetailPage.common.disabled')}
                  />
                  {selectedIVR.announcement && (
                    <DetailRow label={t('PBXDetailPage.fields.announcement')} value={selectedIVR.announcement} />
                  )}
                </div>
              </div>

              <Separator />

              {/* Menu Options */}
              <div className="space-y-3">
                <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">
                  {t('PBXDetailPage.ivrSheet.menuOptions', { count: selectedIVR.entries?.length ?? 0 })}
                </h4>
                {selectedIVR.entries && selectedIVR.entries.length > 0 ? (
                  <div className="space-y-2">
                    {selectedIVR.entries.map((entry: any, i: number) => (
                      <div key={i} className="flex items-center gap-3 p-3 bg-muted rounded-lg">
                        <div className="flex items-center justify-center w-8 h-8 rounded-full bg-primary/10 text-primary font-bold text-sm">
                          {entry.selection ?? entry.digit ?? i}
                        </div>
                        <div className="flex-1">
                          <p className="text-sm font-medium">
                            {entry.dest || entry.destination || t('PBXDetailPage.ivrSheet.noDestination')}
                          </p>
                          {entry.ivr_ret && (
                            <p className="text-xs text-muted-foreground">{t('PBXDetailPage.ivrSheet.returnLabel', { value: entry.ivr_ret })}</p>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground py-2">{t('PBXDetailPage.ivrSheet.noMenuOptions')}</p>
                )}
              </div>

              {/* Settings */}
              {selectedIVR.settings && Object.keys(selectedIVR.settings).length > 0 && (
                <>
                  <Separator />
                  <div className="space-y-3">
                    <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.settings')}</h4>
                    <div className="bg-muted/50 rounded-lg p-3 space-y-2 text-sm">
                      {Object.entries(selectedIVR.settings).map(([key, val]) => (
                        <div key={key} className="flex justify-between">
                          <span className="text-muted-foreground capitalize">{key.replace(/_/g, ' ')}</span>
                          <span className="font-mono text-xs truncate max-w-[200px]">{String(val ?? '-')}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              )}
            </div>
          )}
        </SheetContent>
      </Sheet>

      {/* ── Voicemail Detail Sheet ── */}
      <Sheet open={!!selectedVoicemail} onOpenChange={(open) => !open && setSelectedVoicemail(null)}>
        <SheetContent className="sm:max-w-[520px] overflow-y-auto">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-100 dark:bg-blue-900/30">
                <Voicemail className="h-5 w-5 text-blue-600" />
              </div>
              <div>
                <span className="font-mono">{t('PBXDetailPage.columns.mailbox')} {selectedVoicemail?.mailbox}</span>
                <p className="text-sm font-normal text-muted-foreground mt-0.5">
                  {selectedVoicemail?.name || t('PBXDetailPage.common.unnamed')}
                </p>
              </div>
            </SheetTitle>
            <SheetDescription>{t('PBXDetailPage.voicemailSheet.description')}</SheetDescription>
          </SheetHeader>

          {selectedVoicemail && (
            <div className="space-y-6 mt-6">
              {/* Message Counts */}
              <div className="grid grid-cols-2 gap-3">
                <div className="p-4 bg-muted rounded-lg text-center">
                  <p className={cn(
                    'text-3xl font-bold',
                    (selectedVoicemail.new_messages ?? 0) > 0 ? 'text-red-600' : 'text-muted-foreground',
                  )}>
                    {selectedVoicemail.new_messages ?? 0}
                  </p>
                  <p className="text-sm text-muted-foreground">{t('PBXDetailPage.voicemailSheet.newMessages')}</p>
                </div>
                <div className="p-4 bg-muted rounded-lg text-center">
                  <p className="text-3xl font-bold text-muted-foreground">
                    {selectedVoicemail.old_messages ?? 0}
                  </p>
                  <p className="text-sm text-muted-foreground">{t('PBXDetailPage.voicemailSheet.oldMessages')}</p>
                </div>
              </div>

              <Separator />

              {/* Details */}
              <div className="space-y-3">
                <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.details')}</h4>
                <div className="grid grid-cols-2 gap-y-3 gap-x-4">
                  <DetailRow label={t('PBXDetailPage.columns.mailbox')} value={selectedVoicemail.mailbox} mono />
                  <DetailRow label={t('PBXDetailPage.fields.context')} value={selectedVoicemail.context || t('PBXDetailPage.common.default')} />
                  <DetailRow label={t('PBXDetailPage.columns.name')} value={selectedVoicemail.name} />
                  <DetailRow label={t('PBXDetailPage.columns.email')} value={selectedVoicemail.email} />
                </div>
              </div>

              {/* Settings */}
              {selectedVoicemail.settings && Object.keys(selectedVoicemail.settings).length > 0 && (
                <>
                  <Separator />
                  <div className="space-y-3">
                    <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('PBXDetailPage.sections.settings')}</h4>
                    <div className="bg-muted/50 rounded-lg p-3 space-y-2 text-sm">
                      {Object.entries(selectedVoicemail.settings).map(([key, val]) => (
                        <div key={key} className="flex justify-between">
                          <span className="text-muted-foreground capitalize">{key.replace(/_/g, ' ')}</span>
                          <span className="font-mono text-xs truncate max-w-[200px]">{String(val ?? '-')}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              )}
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}

// =============================================================================
// Shared Detail Row Component
// =============================================================================

function DetailRow({ label, value, mono }: { label: string; value?: string | null; mono?: boolean }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className={cn('text-sm font-medium mt-0.5', mono && 'font-mono')}>
        {value || '-'}
      </p>
    </div>
  );
}
