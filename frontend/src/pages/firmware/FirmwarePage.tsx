/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  HardDrive,
  Download,
  Upload,
  RefreshCw,
  MoreVertical,
  CheckCircle,
  Clock,
  Play,
  Settings,
  Plus,
  Trash2,
  Edit,
  ArrowUpCircle,
  Calendar,
  Shield,
  History,
  Package,
  XCircle,
  Loader2,
  AlertTriangle,
  Camera,
  Globe,
  Lock,
  Network,
  Phone,
  Plug,
  Radio,
  Server,
  Thermometer,
  type LucideIcon,
} from 'lucide-react';
import { PageHeader } from '@/components/layout';
import { useToast } from '@/hooks/use-toast';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { EmptyState } from '@/components/ui/empty-state';
import { SearchBar } from '@/components/ui/search-bar';
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
  DropdownMenuSeparator,
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
import { Checkbox } from '@/components/ui/checkbox';
import { Textarea } from '@/components/ui/textarea';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { firmwareApi, FirmwareSummary, type FirmwareSchedule } from '@/lib/api';
import { useSiteStore } from '@/stores/siteStore';
import { BatchProgressDialog, BatchDeviceStatus } from '@/components/ui/batch-progress-dialog';

const DEVICES_PAGE_SIZE = 50;

// Helper functions
const formatBytes = (bytes: number) => {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
};

const getStatusIcon = (status: string) => {
  switch (status) {
    case 'running':
      return <Loader2 className="h-4 w-4 animate-spin text-blue-500" />;
    case 'completed':
      return <CheckCircle className="h-4 w-4 text-green-500" />;
    case 'failed':
      return <XCircle className="h-4 w-4 text-red-500" />;
    case 'pending':
    case 'scheduled':
      return <Clock className="h-4 w-4 text-warning" />;
    default:
      return <Clock className="h-4 w-4 text-muted-foreground" />;
  }
};

const getDeviceTypeIcon = (type: string): LucideIcon => {
  switch (type) {
    case 'access_point':
      return Radio;
    case 'switch':
      return Network;
    case 'camera':
      return Camera;
    case 'router':
      return Globe;
    case 'nvr':
    case 'dvr':
      return Server;
    case 'gateway':
    case 'firewall':
      return Shield;
    case 'access_control':
      return Lock;
    case 'intercom':
    case 'voip_phone':
      return Phone;
    case 'iot':
      return Plug;
    case 'sensor':
      return Thermometer;
    default:
      return Package;
  }
};

/** Inline device-type icon · small (h-3.5) for inline labels. */
function DeviceTypeIcon({ type, className }: { type: string | null | undefined; className?: string }) {
  const Icon = getDeviceTypeIcon(type ?? 'unknown');
  return <Icon className={className ?? 'inline h-3.5 w-3.5 mr-1'} aria-hidden="true" />;
}

export default function FirmwarePage() {
  const { t } = useTranslation('firmware');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const navigate = useNavigate();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const [searchParams] = useSearchParams();
  const { tab: urlTab } = useParams<{ tab?: string }>();
  const activeTab = ['devices', 'repository', 'jobs', 'schedules'].includes(urlTab || '') ? urlTab! : 'devices';
  const setActiveTab = (v: string) => navigate(v === 'devices' ? '/firmware' : `/firmware/${v}`, { replace: true });
  const [searchQuery, setSearchQuery] = useState('');
  const [filterVendor, setFilterVendor] = useState<string | null>(null);
  const [filterType, setFilterType] = useState<string | null>(
    searchParams.get('device_type') || null
  );
  const [showUpdatesOnly, setShowUpdatesOnly] = useState(false);
  const [devicesPage, setDevicesPage] = useState(1);
  const [selectedDevices, setSelectedDevices] = useState<string[]>([]);
  const [viewMode, setViewMode] = useState<'table' | 'grouped'>('table');
  const [expandedJob, setExpandedJob] = useState<string | null>(null);
  const [batchProgressOpen, setBatchProgressOpen] = useState(false);
  const [batchDevices, setBatchDevices] = useState<BatchDeviceStatus[]>([]);
  
  // Dialogs
  const [upgradeDialogOpen, setUpgradeDialogOpen] = useState(false);
  const [scheduleDialogOpen, setScheduleDialogOpen] = useState(false);
  const [editingScheduleId, setEditingScheduleId] = useState<string | null>(null);
  const [releaseNotesOpen, setReleaseNotesOpen] = useState(false);
  const [selectedFirmware, setSelectedFirmware] = useState<FirmwareSummary | null>(null);
  const [uploadDialogOpen, setUploadDialogOpen] = useState(false);

  // Upload form
  const [uploadForm, setUploadForm] = useState({
    file: null as File | null,
    vendor: '',
    model: '',
    version: '',
    release_type: 'stable',
  });

  // API queries
  const { data: summary, isLoading: summaryLoading, isError: summaryError } = useQuery({
    queryKey: ['firmware', 'summary', selectedSiteId],
    queryFn: () => firmwareApi.getSummary(selectedSiteId || undefined).then(r => r.data),
    staleTime: 30000,
  });

  const { data: deviceStatusResp, isLoading: devicesLoading, isError: devicesError } = useQuery({
    queryKey: [
      'firmware', 'devices', 'status',
      selectedSiteId, filterType, filterVendor, showUpdatesOnly, searchQuery, devicesPage,
    ],
    queryFn: () =>
      firmwareApi
        .listDeviceStatus({
          site_id: selectedSiteId || undefined,
          device_type: filterType || undefined,
          vendor: filterVendor || undefined,
          update_available: showUpdatesOnly || undefined,
          search: searchQuery.trim() || undefined,
          page: devicesPage,
          page_size: DEVICES_PAGE_SIZE,
        })
        .then(r => r.data),
    staleTime: 30000,
  });
  const deviceStatus = deviceStatusResp?.items ?? [];
  const devicesTotal = deviceStatusResp?.total ?? 0;
  const devicesTotalPages = Math.max(1, Math.ceil(devicesTotal / DEVICES_PAGE_SIZE));

  const { data: firmwares, isLoading: firmwaresLoading, isError: firmwaresError } = useQuery({
    queryKey: ['firmware', 'repository'],
    queryFn: () => firmwareApi.listFirmwares().then(r => r.data?.items ?? []),
    staleTime: 60000,
  });

  const { data: jobs, isLoading: _jobsLoading, isError: jobsError } = useQuery({
    queryKey: ['firmware', 'jobs'],
    queryFn: () => firmwareApi.listJobs().then(r => r.data?.items ?? []),
    staleTime: 10000,
    // There is no WS push for firmware job progress, so poll while any job is
    // non-terminal (mirrors the CamerasPage events conditional-refetch pattern).
    // FirmwareJobStatus terminal states are completed/failed/cancelled/
    // partially_failed; pending + running are the only in-flight states, so we
    // poll while one exists and stop once every job is terminal (no idle poll).
    refetchInterval: (query) => {
      const data = (query.state.data ?? []) as Array<{ status: string }>;
      const active = data.some((j) => ['pending', 'running'].includes(j.status));
      return active ? 5000 : false;
    },
  });

  const { data: schedules, isLoading: schedulesLoading, isError: schedulesError } = useQuery({
    queryKey: ['firmware', 'schedules'],
    queryFn: () => firmwareApi.listSchedules().then(r => r.data?.items ?? []),
    staleTime: 60000,
  });

  // Upgrade form
  const [upgradeForm, setUpgradeForm] = useState({
    firmware_id: '',
    scheduled_at: '',
    backup_before: true,
    rollback_on_failure: false,
  });

  // Schedule form
  const [scheduleForm, setScheduleForm] = useState({
    name: '',
    description: '',
    device_type: '' as string,
    vendor: '' as string,
    auto_latest: true,
    frequency: 'weekly',
    day_of_week: 6,
    time_of_day: '02:00',
    backup_before: true,
    rollback_on_failure: true,
    notify_before: true,
    is_enabled: true,
  });

  // Summary stats from API
  const totalDevices = summary?.total_devices || 0;
  const upToDate = summary?.up_to_date || 0;
  const updatesAvailable = summary?.update_available || 0;
  const criticalUpdates = summary?.critical_updates || 0;

  // Filtering. Search/site/type/vendor/updates are all applied server-side
  // (see the listDeviceStatus query above); these guards are a harmless
  // secondary filter over the returned page.
  const filteredDevices = (deviceStatus || []).filter(device => {
    if (filterVendor && device.vendor !== filterVendor) return false;
    if (filterType && device.device_type !== filterType) return false;
    if (showUpdatesOnly && !device.update_available) return false;
    return true;
  });

  // Mutations
  const hasQueryError = summaryError || devicesError || firmwaresError || jobsError || schedulesError;

  const checkUpdatesMut = useMutation({
    mutationFn: (deviceIds?: string[]) => firmwareApi.checkUpdates(deviceIds?.length ? { device_ids: deviceIds } : undefined),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firmware'] });
    },
    onError: (err: Error) => {
      toast({ title: t('FirmwarePage.toasts.operationFailed'), description: err.message, variant: 'destructive' });
    },
  });

  const errDetail = (err: any) => err?.response?.data?.detail || err?.message || t('FirmwarePage.toasts.unknownError');

  // Schedule create
  const createScheduleMut = useMutation({
    mutationFn: () =>
      firmwareApi.createSchedule({
        name: scheduleForm.name,
        description: scheduleForm.description || undefined,
        is_enabled: scheduleForm.is_enabled,
        device_type: scheduleForm.device_type || undefined,
        vendor: scheduleForm.vendor || undefined,
        auto_latest: scheduleForm.auto_latest,
        release_type: 'stable',
        frequency: scheduleForm.frequency,
        time_of_day: scheduleForm.time_of_day,
        day_of_week: scheduleForm.frequency === 'weekly' ? scheduleForm.day_of_week : undefined,
        backup_before: scheduleForm.backup_before,
        rollback_on_failure: scheduleForm.rollback_on_failure,
        max_concurrent: 1,
        batch_size: 5,
        delay_between_batches: 60,
        notify_before: scheduleForm.notify_before,
        notify_before_hours: 24,
        notify_on_complete: true,
        notify_on_failure: true,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firmware', 'schedules'] });
      toast({ title: t('common:success'), description: t('FirmwarePage.schedules.create') });
      setScheduleDialogOpen(false);
      setEditingScheduleId(null);
      setScheduleForm({
        name: '', description: '', device_type: '', vendor: '', auto_latest: true,
        frequency: 'weekly', day_of_week: 6, time_of_day: '02:00', backup_before: true,
        rollback_on_failure: true, notify_before: true, is_enabled: true,
      });
    },
    onError: (err: any) => {
      toast({ title: t('FirmwarePage.toasts.operationFailed'), description: errDetail(err), variant: 'destructive' });
    },
  });

  // Schedule update (edit)
  const updateScheduleMut = useMutation({
    mutationFn: (id: string) =>
      firmwareApi.updateSchedule(id, {
        name: scheduleForm.name,
        description: scheduleForm.description || undefined,
        is_enabled: scheduleForm.is_enabled,
        device_type: scheduleForm.device_type || undefined,
        vendor: scheduleForm.vendor || undefined,
        auto_latest: scheduleForm.auto_latest,
        frequency: scheduleForm.frequency,
        time_of_day: scheduleForm.time_of_day,
        day_of_week: scheduleForm.frequency === 'weekly' ? scheduleForm.day_of_week : undefined,
        backup_before: scheduleForm.backup_before,
        rollback_on_failure: scheduleForm.rollback_on_failure,
        notify_before: scheduleForm.notify_before,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firmware', 'schedules'] });
      toast({ title: t('common:success'), description: t('FirmwarePage.actions.edit') });
      setScheduleDialogOpen(false);
      setEditingScheduleId(null);
      setScheduleForm({
        name: '', description: '', device_type: '', vendor: '', auto_latest: true,
        frequency: 'weekly', day_of_week: 6, time_of_day: '02:00', backup_before: true,
        rollback_on_failure: true, notify_before: true, is_enabled: true,
      });
    },
    onError: (err: any) => {
      toast({ title: t('FirmwarePage.toasts.operationFailed'), description: errDetail(err), variant: 'destructive' });
    },
  });

  const toggleScheduleMut = useMutation({
    mutationFn: (id: string) => firmwareApi.toggleSchedule(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['firmware', 'schedules'] }),
    onError: (err: any) => {
      toast({ title: t('FirmwarePage.toasts.operationFailed'), description: errDetail(err), variant: 'destructive' });
    },
  });

  const runScheduleNowMut = useMutation({
    mutationFn: (id: string) => firmwareApi.runScheduleNow(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firmware'] });
      toast({ title: t('common:success'), description: t('FirmwarePage.actions.runNow') });
    },
    onError: (err: any) => {
      toast({ title: t('FirmwarePage.toasts.operationFailed'), description: errDetail(err), variant: 'destructive' });
    },
  });

  const deleteScheduleMut = useMutation({
    mutationFn: (id: string) => firmwareApi.deleteSchedule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firmware', 'schedules'] });
      toast({ title: t('common:success'), description: t('FirmwarePage.actions.delete') });
    },
    onError: (err: any) => {
      toast({ title: t('FirmwarePage.toasts.operationFailed'), description: errDetail(err), variant: 'destructive' });
    },
  });

  // Job actions
  const cancelJobMut = useMutation({
    mutationFn: (jobId: string) => firmwareApi.cancelJob(jobId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firmware', 'jobs'] });
      toast({ title: t('common:success'), description: t('FirmwarePage.actions.cancel') });
    },
    onError: (err: any) => {
      toast({ title: t('FirmwarePage.toasts.operationFailed'), description: errDetail(err), variant: 'destructive' });
    },
  });

  const retryJobMut = useMutation({
    mutationFn: (jobId: string) => firmwareApi.retryJob(jobId, true),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firmware', 'jobs'] });
      toast({ title: t('common:success'), description: t('FirmwarePage.actions.retryFailed') });
    },
    onError: (err: any) => {
      toast({ title: t('FirmwarePage.toasts.operationFailed'), description: errDetail(err), variant: 'destructive' });
    },
  });

  // Repository cache (download)
  const cacheFirmwareMut = useMutation({
    mutationFn: (id: string) => firmwareApi.cacheFirmware(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firmware', 'repository'] });
      toast({ title: t('common:success'), description: t('FirmwarePage.repository.cached') });
    },
    onError: (err: any) => {
      toast({ title: t('FirmwarePage.toasts.operationFailed'), description: errDetail(err), variant: 'destructive' });
    },
  });

  // Upload firmware
  const resetUploadForm = () =>
    setUploadForm({ file: null, vendor: '', model: '', version: '', release_type: 'stable' });

  const uploadFirmwareMut = useMutation({
    mutationFn: (data: { file: File; vendor: string; model: string; version: string; release_type: string }) =>
      firmwareApi.uploadFirmware(data.file, {
        vendor: data.vendor,
        model: data.model,
        version: data.version,
        release_type: data.release_type,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firmware', 'repository'] });
      toast({ title: t('common:success'), description: t('FirmwarePage.actions.uploadFirmware') });
      setUploadDialogOpen(false);
      resetUploadForm();
    },
    onError: (err: any) => {
      toast({ title: t('FirmwarePage.toasts.operationFailed'), description: errDetail(err), variant: 'destructive' });
    },
  });

  const handleSubmitUpload = () => {
    if (!uploadForm.file || !uploadForm.vendor.trim() || !uploadForm.model.trim() || !uploadForm.version.trim()) {
      toast({ title: t('FirmwarePage.toasts.validationError'), variant: 'destructive' });
      return;
    }
    uploadFirmwareMut.mutate({
      file: uploadForm.file,
      vendor: uploadForm.vendor.trim(),
      model: uploadForm.model.trim(),
      version: uploadForm.version.trim(),
      release_type: uploadForm.release_type,
    });
  };

  const handleEditSchedule = (schedule: FirmwareSchedule) => {
    setEditingScheduleId(schedule.id);
    setScheduleForm({
      name: schedule.name,
      description: schedule.description || '',
      device_type: schedule.device_type || '',
      vendor: schedule.vendor || '',
      auto_latest: schedule.auto_latest,
      frequency: schedule.frequency,
      day_of_week: schedule.day_of_week ?? 6,
      time_of_day: schedule.time_of_day || '02:00',
      backup_before: schedule.backup_before,
      rollback_on_failure: schedule.rollback_on_failure,
      notify_before: schedule.notify_before,
      is_enabled: schedule.is_enabled,
    });
    setScheduleDialogOpen(true);
  };

  const handleSubmitSchedule = () => {
    if (!scheduleForm.name.trim()) {
      toast({ title: t('FirmwarePage.toasts.validationError'), variant: 'destructive' });
      return;
    }
    if (editingScheduleId) {
      updateScheduleMut.mutate(editingScheduleId);
    } else {
      createScheduleMut.mutate();
    }
  };

  const handleUpgrade = (devices: string[]) => {
    setSelectedDevices(devices);
    setUpgradeDialogOpen(true);
  };

  const handleStartUpgrade = async () => {
    if (!upgradeForm.firmware_id) {
      toast({ title: t('FirmwarePage.toasts.validationError'), description: t('FirmwarePage.toasts.selectFirmware'), variant: 'destructive' });
      return;
    }

    // Initialize batch progress with running status directly
    const batchItems: BatchDeviceStatus[] = selectedDevices.map(id => {
      const dev = (deviceStatus || []).find(d => d.device_id === id);
      return { id, name: dev?.device_name || id, status: 'running' as const };
    });
    setBatchDevices(batchItems);
    setUpgradeDialogOpen(false);
    setUpgradeForm({ firmware_id: '', scheduled_at: '', backup_before: true, rollback_on_failure: false });
    setBatchProgressOpen(true);

    try {
      const result = await firmwareApi.createJob({
        device_ids: selectedDevices,
        firmware_id: upgradeForm.firmware_id,
        scheduled_at: upgradeForm.scheduled_at || undefined,
        backup_before: upgradeForm.backup_before,
        rollback_on_failure: upgradeForm.rollback_on_failure,
      });
      // If job was created successfully, mark based on response
      const jobData = (result?.data as unknown) as Record<string, unknown> | undefined;
      const deviceResults = jobData?.devices;
      if (Array.isArray(deviceResults)) {
        setBatchDevices(prev => prev.map(d => {
          const dr = (deviceResults as Array<Record<string, unknown>>).find((r) => r.device_id === d.id);
          return dr ? { ...d, status: dr.status === 'failed' ? 'failed' as const : 'success' as const, message: String(dr.message || '') } : { ...d, status: 'success' as const };
        }));
      } else {
        setBatchDevices(prev => prev.map(d => ({ ...d, status: 'success' as const, message: t('FirmwarePage.batch.jobCreated') })));
      }
      queryClient.invalidateQueries({ queryKey: ['firmware'] });
    } catch (error) {
      setBatchDevices(prev => prev.map(d => ({ ...d, status: 'failed' as const, message: t('FirmwarePage.batch.failedToStart') })));
      toast({ title: t('FirmwarePage.toasts.upgradeFailed'), description: error instanceof Error ? error.message : t('FirmwarePage.toasts.unknownError'), variant: 'destructive' });
    }
    setSelectedDevices([]);
  };

  const handleCheckSelected = () => {
    checkUpdatesMut.mutate(selectedDevices);
  };

  const updatableSelected = selectedDevices.filter(id =>
    (deviceStatus || []).find(d => d.device_id === id && d.update_available)
  );

  return (
    <div className="space-y-6">
        {/* Header */}
        <PageHeader
          title={t('FirmwarePage.header.title')}
          description={t('FirmwarePage.header.description')}
          icon={HardDrive}
          onRefresh={() => queryClient.invalidateQueries({ queryKey: ['firmware'] })}
          refreshing={summaryLoading}
          secondaryActions={[
            {
              label: t('FirmwarePage.actions.uploadFirmware'),
              icon: Upload,
              onClick: () => setUploadDialogOpen(true),
            }
          ]}
        />

      {hasQueryError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('FirmwarePage.errors.partialLoad')}</span>
          </CardContent>
        </Card>
      )}

      {/* Summary Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('FirmwarePage.stats.totalDevices')}</CardTitle>
            <HardDrive className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalDevices}</div>
            <p className="text-xs text-muted-foreground">
              {t('FirmwarePage.stats.managedDevices')}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('FirmwarePage.stats.upToDate')}</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{upToDate}</div>
            <Progress
              value={totalDevices > 0 ? (upToDate / totalDevices) * 100 : 0}
              className="mt-2 h-2 [&>div]:bg-green-500"
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('FirmwarePage.stats.updatesAvailable')}</CardTitle>
            <ArrowUpCircle className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-600">{updatesAvailable}</div>
            <p className="text-xs text-muted-foreground">
              {t('FirmwarePage.stats.devicesNeedUpdating')}
            </p>
          </CardContent>
        </Card>

        <Card className={criticalUpdates > 0 ? 'border-red-500' : ''}>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('FirmwarePage.stats.criticalUpdates')}</CardTitle>
            <Shield className={`h-4 w-4 ${criticalUpdates > 0 ? 'text-red-500' : 'text-muted-foreground'}`} />
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${criticalUpdates > 0 ? 'text-red-600' : ''}`}>
              {criticalUpdates}
            </div>
            <p className="text-xs text-muted-foreground">
              {t('FirmwarePage.stats.securityUpdatesPending')}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Active Jobs Banner */}
      {jobs && jobs.filter(j => j.status === 'running').length > 0 && (
        <Card className="border-blue-500 bg-blue-50 dark:bg-blue-950/20">
          <CardContent noOffset className="py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <Loader2 className="h-6 w-6 animate-spin text-blue-500" />
                <div>
                  <h3 className="font-medium">{t('FirmwarePage.banner.upgradeInProgress')}</h3>
                  <p className="text-sm text-muted-foreground">
                    {t('FirmwarePage.banner.devicesCompleted', { completed: jobs[0].successful, total: jobs[0].total_devices })}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <Progress value={jobs[0].progress} className="w-32 h-3" />
                <span className="text-sm font-medium">{jobs[0].progress}%</span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    const running = jobs.find(j => j.status === 'running');
                    setActiveTab('jobs');
                    if (running) setExpandedJob(running.id);
                  }}
                >
                  {t('FirmwarePage.actions.viewDetails')}
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Main Content */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="devices">
            <HardDrive className="mr-2 h-4 w-4" />
            {t('FirmwarePage.tabs.devices')}
          </TabsTrigger>
          <TabsTrigger value="repository">
            <Package className="mr-2 h-4 w-4" />
            {t('FirmwarePage.tabs.repository')}
          </TabsTrigger>
          <TabsTrigger value="jobs">
            <History className="mr-2 h-4 w-4" />
            {t('FirmwarePage.tabs.jobs')}
          </TabsTrigger>
          <TabsTrigger value="schedules">
            <Calendar className="mr-2 h-4 w-4" />
            {t('FirmwarePage.tabs.schedules')}
          </TabsTrigger>
        </TabsList>

        {/* Devices Tab */}
        <TabsContent value="devices" className="space-y-4">
          {/* Toolbar */}
          <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
            <div className="flex items-center gap-2 w-full sm:w-auto">
              <SearchBar
                value={searchQuery}
                onChange={(v) => { setSearchQuery(v); setDevicesPage(1); }}
                placeholder={t('FirmwarePage.filters.searchPlaceholder')}
              />
              <Select
                value={filterVendor || 'all'}
                onValueChange={(v) => { setFilterVendor(v === 'all' ? null : v); setDevicesPage(1); }}
              >
                <SelectTrigger className="w-32">
                  <SelectValue placeholder={t('FirmwarePage.filters.vendor')} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{t('FirmwarePage.filters.allVendors')}</SelectItem>
                  <SelectItem value="TP-Link">TP-Link</SelectItem>
                  <SelectItem value="Hikvision">Hikvision</SelectItem>
                </SelectContent>
              </Select>
              <Select
                value={filterType || 'all'}
                onValueChange={(v) => { setFilterType(v === 'all' ? null : v); setDevicesPage(1); }}
              >
                <SelectTrigger className="w-40">
                  <SelectValue placeholder={t('FirmwarePage.filters.type')} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{t('FirmwarePage.deviceTypes.all')}</SelectItem>
                  <SelectItem value="access_point">{t('FirmwarePage.deviceTypes.accessPoint')}</SelectItem>
                  <SelectItem value="switch">{t('FirmwarePage.deviceTypes.switch')}</SelectItem>
                  <SelectItem value="router">{t('FirmwarePage.deviceTypes.router')}</SelectItem>
                  <SelectItem value="gateway">{t('FirmwarePage.deviceTypes.gateway')}</SelectItem>
                  <SelectItem value="firewall">{t('FirmwarePage.deviceTypes.firewall')}</SelectItem>
                  <SelectItem value="camera">{t('FirmwarePage.deviceTypes.camera')}</SelectItem>
                  <SelectItem value="nvr">{t('FirmwarePage.deviceTypes.nvr')}</SelectItem>
                  <SelectItem value="dvr">{t('FirmwarePage.deviceTypes.dvr')}</SelectItem>
                  <SelectItem value="access_control">{t('FirmwarePage.deviceTypes.accessControl')}</SelectItem>
                  <SelectItem value="intercom">{t('FirmwarePage.deviceTypes.intercom')}</SelectItem>
                  <SelectItem value="voip_phone">{t('FirmwarePage.deviceTypes.voipPhone')}</SelectItem>
                  <SelectItem value="iot">{t('FirmwarePage.deviceTypes.iot')}</SelectItem>
                  <SelectItem value="sensor">{t('FirmwarePage.deviceTypes.sensor')}</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2">
                <Checkbox
                  id="updates-only"
                  checked={showUpdatesOnly}
                  onCheckedChange={(checked) => { setShowUpdatesOnly(!!checked); setDevicesPage(1); }}
                />
                <Label htmlFor="updates-only" className="text-sm">
                  {t('FirmwarePage.filters.updatesOnly')}
                </Label>
              </div>
              <div className="flex rounded-md border bg-muted/50 p-0.5">
                <Button
                  variant={viewMode === 'table' ? 'secondary' : 'ghost'}
                  size="sm"
                  className="h-7 px-2.5 text-xs"
                  onClick={() => setViewMode('table')}
                >
                  {t('FirmwarePage.viewMode.table')}
                </Button>
                <Button
                  variant={viewMode === 'grouped' ? 'secondary' : 'ghost'}
                  size="sm"
                  className="h-7 px-2.5 text-xs"
                  onClick={() => setViewMode('grouped')}
                >
                  {t('FirmwarePage.viewMode.byVersion')}
                </Button>
              </div>
            </div>
          </div>

          {/* Bulk Action Bar */}
          {selectedDevices.length > 0 && (
            <div className="flex items-center justify-between rounded-lg border bg-muted/50 px-4 py-3">
              <div className="flex items-center gap-2">
                <Badge variant="secondary" className="text-sm">
                  {t('FirmwarePage.bulk.selected', { count: selectedDevices.length })}
                </Badge>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setSelectedDevices([])}
                >
                  {t('FirmwarePage.bulk.deselectAll')}
                </Button>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={handleCheckSelected}
                  disabled={checkUpdatesMut.isPending}
                >
                  {checkUpdatesMut.isPending ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <RefreshCw className="mr-2 h-4 w-4" />
                  )}
                  {t('FirmwarePage.actions.checkForUpdates')}
                </Button>
                <Button
                  size="sm"
                  onClick={() => handleUpgrade(updatableSelected)}
                  disabled={updatableSelected.length === 0}
                >
                  <ArrowUpCircle className="mr-2 h-4 w-4" />
                  {updatableSelected.length > 0
                    ? t('FirmwarePage.actions.upgradeCount', { count: updatableSelected.length })
                    : t('FirmwarePage.actions.upgrade')}
                </Button>
              </div>
            </div>
          )}

          {/* Devices Table View */}
          {viewMode === 'table' && (
          <Card>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-12">
                    <Checkbox
                      checked={
                        filteredDevices.length > 0 &&
                        selectedDevices.length === filteredDevices.length
                      }
                      onCheckedChange={(checked) => {
                        if (checked) {
                          setSelectedDevices(filteredDevices.map(d => d.device_id));
                        } else {
                          setSelectedDevices([]);
                        }
                      }}
                    />
                  </TableHead>
                  <TableHead>{t('FirmwarePage.table.device')}</TableHead>
                  <TableHead>{t('FirmwarePage.table.type')}</TableHead>
                  <TableHead>{t('FirmwarePage.table.currentVersion')}</TableHead>
                  <TableHead>{t('FirmwarePage.table.latestVersion')}</TableHead>
                  <TableHead>{t('FirmwarePage.table.status')}</TableHead>
                  <TableHead>{t('FirmwarePage.table.lastChecked')}</TableHead>
                  <TableHead className="text-right">{t('FirmwarePage.table.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {devicesLoading && (
                  <TableRow>
                    <TableCell colSpan={8} className="py-8">
                      <div className="flex items-center justify-center text-muted-foreground">
                        <RefreshCw className="mr-2 h-5 w-5 animate-spin" />
                        {t('common:loading')}
                      </div>
                    </TableCell>
                  </TableRow>
                )}
                {!devicesLoading && filteredDevices.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center py-8 text-muted-foreground">
                      {devicesError ? t('FirmwarePage.errors.partialLoad') : t('common:noResults')}
                    </TableCell>
                  </TableRow>
                )}
                {!devicesLoading && filteredDevices.map((device) => (
                  <TableRow key={device.device_id}>
                    <TableCell>
                      <Checkbox
                        checked={selectedDevices.includes(device.device_id)}
                        onCheckedChange={(checked) => {
                          if (checked) {
                            setSelectedDevices([...selectedDevices, device.device_id]);
                          } else {
                            setSelectedDevices(selectedDevices.filter(id => id !== device.device_id));
                          }
                        }}
                      />
                    </TableCell>
                    <TableCell>
                      <div>
                        <div className="font-medium">{device.device_name}</div>
                        <div className="text-sm text-muted-foreground">
                          {device.vendor} {device.model}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        <DeviceTypeIcon type={device.device_type} />
                        {(device.device_type ?? 'unknown').replace('_', ' ')}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono">{device.current_version}</TableCell>
                    <TableCell>
                      {device.latest_version ? (
                        <span className="font-mono">{device.latest_version}</span>
                      ) : (
                        <span className="text-muted-foreground">-</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {device.is_up_to_date ? (
                        <Badge variant="outline" className="bg-success/10 text-success border-success/20">
                          <CheckCircle className="mr-1 h-3 w-3" />
                          {t('FirmwarePage.status.upToDate')}
                        </Badge>
                      ) : device.critical_update_available ? (
                        <Badge variant="destructive">
                          <Shield className="mr-1 h-3 w-3" />
                          {t('FirmwarePage.status.critical')}
                        </Badge>
                      ) : (
                        <Badge variant="secondary">
                          <ArrowUpCircle className="mr-1 h-3 w-3" />
                          {t('FirmwarePage.status.updateAvailable')}
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      {device.last_checked_at ? (
                        new Date(device.last_checked_at).toLocaleDateString()
                      ) : (
                        <span className="text-muted-foreground">{t('FirmwarePage.common.never')}</span>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon">
                            <MoreVertical className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          {device.update_available && (
                            <>
                              <DropdownMenuItem onClick={() => handleUpgrade([device.device_id])}>
                                <ArrowUpCircle className="mr-2 h-4 w-4" />
                                {t('FirmwarePage.actions.upgradeNow')}
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                            </>
                          )}
                          <DropdownMenuItem
                            onClick={() => checkUpdatesMut.mutate([device.device_id])}
                          >
                            <RefreshCw className="mr-2 h-4 w-4" />
                            {t('FirmwarePage.actions.checkForUpdates')}
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
          )}

          {/* Grouped by Version View */}
          {viewMode === 'grouped' && (
          <div className="space-y-4">
            {(() => {
              // Group devices by current firmware version
              const versionGroups = new Map<string, typeof filteredDevices>();
              filteredDevices.forEach(device => {
                const ver = device.current_version || t('FirmwarePage.common.unknown');
                if (!versionGroups.has(ver)) versionGroups.set(ver, []);
                versionGroups.get(ver)!.push(device);
              });
              // Sort: versions with updates first, then alphabetically
              const sorted = [...versionGroups.entries()].sort(([aVer, aDevs], [bVer, bDevs]) => {
                const aHasUpdates = aDevs.some(d => d.update_available);
                const bHasUpdates = bDevs.some(d => d.update_available);
                if (aHasUpdates !== bHasUpdates) return aHasUpdates ? -1 : 1;
                return aVer.localeCompare(bVer);
              });
              return sorted.map(([version, devices]) => {
                const hasUpdates = devices.some(d => d.update_available);
                const hasCritical = devices.some(d => d.critical_update_available);
                const latestVer = devices.find(d => d.latest_version)?.latest_version;
                return (
                  <Card key={version} className={hasCritical ? 'border-red-300' : hasUpdates ? 'border-yellow-300' : ''}>
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <CardTitle className="text-base font-mono">v{version}</CardTitle>
                          <Badge variant="secondary">{t('FirmwarePage.grouped.deviceCount', { count: devices.length })}</Badge>
                          {hasCritical ? (
                            <Badge variant="destructive"><Shield className="mr-1 h-3 w-3" />{t('FirmwarePage.grouped.criticalUpdateNeeded')}</Badge>
                          ) : hasUpdates ? (
                            <Badge variant="outline" className="text-yellow-700 border-yellow-300 bg-yellow-50">
                              <ArrowUpCircle className="mr-1 h-3 w-3" />
                              {t('FirmwarePage.grouped.updateTo', { version: latestVer || t('FirmwarePage.grouped.latest') })}
                            </Badge>
                          ) : (
                            <Badge variant="outline" className="bg-success/10 text-success border-success/20">
                              <CheckCircle className="mr-1 h-3 w-3" />{t('FirmwarePage.status.upToDate')}
                            </Badge>
                          )}
                        </div>
                        {hasUpdates && (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleUpgrade(devices.filter(d => d.update_available).map(d => d.device_id))}
                          >
                            <ArrowUpCircle className="mr-2 h-4 w-4" />
                            {t('FirmwarePage.grouped.upgradeAll', { count: devices.filter(d => d.update_available).length })}
                          </Button>
                        )}
                      </div>
                    </CardHeader>
                    <CardContent className="pt-0">
                      <div className="flex flex-wrap gap-2">
                        {devices.map(d => (
                          <div key={d.device_id} className="flex items-center gap-1.5 rounded-md border bg-muted/30 px-2.5 py-1.5 text-sm">
                            <DeviceTypeIcon type={d.device_type} className="h-3.5 w-3.5 text-muted-foreground" />
                            <span className="font-medium">{d.device_name}</span>
                            <span className="text-xs text-muted-foreground">{d.model}</span>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                );
              });
            })()}
          </div>
          )}

          {/* Pagination (server-side) */}
          {devicesTotalPages > 1 && (
            <div className="flex items-center justify-between rounded-lg border bg-muted/50 px-4 py-3">
              <p className="text-xs text-muted-foreground">
                {t('common:pagination.page', { current: devicesPage, total: devicesTotalPages })}
              </p>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setDevicesPage((p) => Math.max(1, p - 1))}
                  disabled={devicesPage === 1 || devicesLoading}
                >
                  {t('common:previous')}
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setDevicesPage((p) => Math.min(devicesTotalPages, p + 1))}
                  disabled={devicesPage >= devicesTotalPages || devicesLoading}
                >
                  {t('common:next')}
                </Button>
              </div>
            </div>
          )}
        </TabsContent>

        {/* Repository Tab */}
        <TabsContent value="repository" className="space-y-4">
          {firmwaresLoading && (
            <div className="flex items-center justify-center py-8">
              <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
              <span className="ml-2 text-muted-foreground">{t('FirmwarePage.repository.loading')}</span>
            </div>
          )}
          {!firmwaresLoading && (!firmwares || firmwares.length === 0) && (
            <Card>
              <EmptyState
                icon={Package}
                title={t('FirmwarePage.repository.emptyTitle')}
                description={t('FirmwarePage.repository.emptyDescription')}
              />
            </Card>
          )}
          {firmwares && firmwares.length > 0 && (
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {firmwares.map((firmware) => (
              <Card key={firmware.id} className="relative">
                {firmware.is_critical && (
                  <div className="absolute top-2 right-2">
                    <Badge variant="destructive" className="text-xs">
                      <Shield className="mr-1 h-3 w-3" />
                      {t('FirmwarePage.repository.security')}
                    </Badge>
                  </div>
                )}
                <CardHeader className="pb-2">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
                      <DeviceTypeIcon type={firmware.device_type || 'unknown'} className="h-5 w-5" />
                    </div>
                    <div>
                      <CardTitle className="text-lg">{firmware.vendor} {firmware.model}</CardTitle>
                      <CardDescription>v{firmware.version}</CardDescription>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex flex-wrap gap-2">
                    <Badge variant="outline">{firmware.release_type}</Badge>
                    {firmware.is_latest && (
                      <Badge variant="outline" className="bg-success/10 text-success border-success/20">{t('FirmwarePage.repository.latest')}</Badge>
                    )}
                    {firmware.is_recommended && (
                      <Badge variant="outline" className="bg-info/10 text-info border-info/20">{t('FirmwarePage.repository.recommended')}</Badge>
                    )}
                    {firmware.is_cached && (
                      <Badge variant="outline" className="bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/20">{t('FirmwarePage.repository.cached')}</Badge>
                    )}
                  </div>

                  <div className="text-sm space-y-1">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">{t('FirmwarePage.repository.released')}</span>
                      <span>{firmware.release_date ? new Date(firmware.release_date).toLocaleDateString() : t('FirmwarePage.common.notAvailable')}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">{t('FirmwarePage.repository.size')}</span>
                      <span>{formatBytes(firmware.file_size_bytes || 0)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">{t('FirmwarePage.repository.installed')}</span>
                      <span>{t('FirmwarePage.repository.installedCount', { upToDate: firmware.devices_up_to_date, total: firmware.device_count })}</span>
                    </div>
                  </div>

                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      className="flex-1"
                      onClick={() => {
                        setSelectedFirmware(firmware);
                        setReleaseNotesOpen(true);
                      }}
                    >
                      {t('FirmwarePage.repository.releaseNotes')}
                    </Button>
                    {!firmware.is_cached && (
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={cacheFirmwareMut.isPending && cacheFirmwareMut.variables === firmware.id}
                        onClick={() => cacheFirmwareMut.mutate(firmware.id)}
                      >
                        {cacheFirmwareMut.isPending && cacheFirmwareMut.variables === firmware.id ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <Download className="h-4 w-4" />
                        )}
                      </Button>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
          )}
        </TabsContent>

        {/* Jobs Tab */}
        <TabsContent value="jobs" className="space-y-4">
          <Card>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('FirmwarePage.jobs.status')}</TableHead>
                  <TableHead>{t('FirmwarePage.jobs.version')}</TableHead>
                  <TableHead>{t('FirmwarePage.jobs.devices')}</TableHead>
                  <TableHead>{t('FirmwarePage.jobs.progress')}</TableHead>
                  <TableHead>{t('FirmwarePage.jobs.started')}</TableHead>
                  <TableHead>{t('FirmwarePage.jobs.initiatedBy')}</TableHead>
                  <TableHead className="text-right">{t('FirmwarePage.table.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {jobs?.map((job) => (
                  <React.Fragment key={job.id}>
                    <TableRow
                      className="cursor-pointer hover:bg-muted/50"
                      onClick={() => setExpandedJob(expandedJob === job.id ? null : job.id)}
                    >
                      <TableCell>
                        <div className="flex items-center gap-2">
                          {getStatusIcon(job.status)}
                          <span className="capitalize">{job.status}</span>
                        </div>
                      </TableCell>
                      <TableCell className="font-mono">{job.firmware_version}</TableCell>
                      <TableCell>
                        {job.successful} / {job.total_devices}
                        {job.failed > 0 && (
                          <span className="text-red-600 ml-2">{t('FirmwarePage.jobs.failedCount', { count: job.failed })}</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Progress value={job.progress} className="w-24 h-2" />
                          <span className="text-sm">{job.progress}%</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        {job.started_at ? new Date(job.started_at).toLocaleString() : '-'}
                      </TableCell>
                      <TableCell>{job.created_by || '-'}</TableCell>
                      <TableCell className="text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon" onClick={(e) => e.stopPropagation()}>
                              <MoreVertical className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => setExpandedJob(expandedJob === job.id ? null : job.id)}>
                              <Settings className="mr-2 h-4 w-4" />
                              {expandedJob === job.id ? t('FirmwarePage.actions.hideDetails') : t('FirmwarePage.actions.viewDetails')}
                            </DropdownMenuItem>
                            {job.status === 'running' && (
                              <DropdownMenuItem
                                className="text-destructive"
                                onClick={() => cancelJobMut.mutate(job.id)}
                              >
                                <XCircle className="mr-2 h-4 w-4" />
                                {t('FirmwarePage.actions.cancel')}
                              </DropdownMenuItem>
                            )}
                            {job.status === 'failed' && (
                              <DropdownMenuItem onClick={() => retryJobMut.mutate(job.id)}>
                                <RefreshCw className="mr-2 h-4 w-4" />
                                {t('FirmwarePage.actions.retryFailed')}
                              </DropdownMenuItem>
                            )}
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                    {/* Expanded per-device rollout detail */}
                    {expandedJob === job.id && (
                      <TableRow>
                        <TableCell colSpan={7} className="bg-muted/30 p-4">
                          <div className="space-y-3">
                            <div className="flex items-center gap-4 text-sm">
                              <span className="font-medium">{t('FirmwarePage.rollout.title')}</span>
                              <div className="flex items-center gap-3 text-xs text-muted-foreground">
                                <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-green-500" />{t('FirmwarePage.rollout.completed', { count: job.successful })}</span>
                                <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-blue-500 animate-pulse" />{t('FirmwarePage.rollout.inProgress', { count: Math.max(0, job.total_devices - job.successful - job.failed - (job.skipped || 0)) })}</span>
                                <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-red-500" />{t('FirmwarePage.rollout.failed', { count: job.failed })}</span>
                                <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-muted-foreground" />{t('FirmwarePage.rollout.pending')}</span>
                              </div>
                            </div>
                            {/* Per-device progress bar */}
                            <div className="flex h-3 rounded-full overflow-hidden bg-muted">
                              {job.successful > 0 && (
                                <div className="bg-green-500 transition-all" style={{ width: `${(job.successful / job.total_devices) * 100}%` }} />
                              )}
                              {(job.total_devices - job.successful - job.failed - (job.skipped || 0)) > 0 && (
                                <div className="bg-blue-500 animate-pulse transition-all" style={{ width: `${((job.total_devices - job.successful - job.failed - (job.skipped || 0)) / job.total_devices) * 100}%` }} />
                              )}
                              {job.failed > 0 && (
                                <div className="bg-red-500 transition-all" style={{ width: `${(job.failed / job.total_devices) * 100}%` }} />
                              )}
                            </div>
                            {/* Per-device status grid */}
                            {(job as any).devices && Array.isArray((job as any).devices) ? (
                              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                                {(job as any).devices.map((dr: any) => (
                                  <div key={dr.device_id || dr.device_name} className="flex items-center justify-between rounded-md border px-3 py-2 text-sm">
                                    <div className="flex items-center gap-2">
                                      {dr.status === 'completed' || dr.status === 'success' ? (
                                        <CheckCircle className="h-4 w-4 text-green-500" />
                                      ) : dr.status === 'running' || dr.status === 'upgrading' ? (
                                        <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />
                                      ) : dr.status === 'failed' ? (
                                        <XCircle className="h-4 w-4 text-red-500" />
                                      ) : (
                                        <Clock className="h-4 w-4 text-muted-foreground" />
                                      )}
                                      <span className="font-medium">{dr.device_name || dr.device_id}</span>
                                    </div>
                                    <span className="text-xs text-muted-foreground capitalize">{dr.status}</span>
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <p className="text-xs text-muted-foreground">
                                {t('FirmwarePage.rollout.perDeviceHint')}
                              </p>
                            )}
                            {/* Timing info */}
                            <div className="flex gap-6 text-xs text-muted-foreground pt-1">
                              {job.started_at && <span>{t('FirmwarePage.rollout.startedAt', { time: new Date(job.started_at).toLocaleString() })}</span>}
                              {job.completed_at && <span>{t('FirmwarePage.rollout.completedAt', { time: new Date(job.completed_at).toLocaleString() })}</span>}
                              {job.backup_before && <span className="flex items-center gap-1"><CheckCircle className="h-3 w-3 text-green-500" />{t('FirmwarePage.rollout.backupBeforeUpgrade')}</span>}
                              {job.rollback_on_failure && <span className="flex items-center gap-1"><RefreshCw className="h-3 w-3" />{t('FirmwarePage.rollout.autoRollbackEnabled')}</span>}
                            </div>
                          </div>
                        </TableCell>
                      </TableRow>
                    )}
                  </React.Fragment>
                ))}
                {(!jobs || jobs.length === 0) && (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                      {t('FirmwarePage.jobs.empty')}
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </Card>
        </TabsContent>

        {/* Schedules Tab */}
        <TabsContent value="schedules" className="space-y-4">
          <div className="flex justify-end">
            <Button onClick={() => { setEditingScheduleId(null); setScheduleDialogOpen(true); }}>
              <Plus className="mr-2 h-4 w-4" />
              {t('FirmwarePage.schedules.create')}
            </Button>
          </div>

          {schedulesLoading && (
            <div className="flex items-center justify-center py-8">
              <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
              <span className="ml-2 text-muted-foreground">{t('FirmwarePage.schedules.loading')}</span>
            </div>
          )}

          {!schedulesLoading && (!schedules || schedules.length === 0) && (
            <Card>
              <EmptyState
                icon={Calendar}
                title={t('FirmwarePage.schedules.emptyTitle')}
                description={t('FirmwarePage.schedules.emptyDescription')}
              />
            </Card>
          )}

          {schedules && schedules.length > 0 && (
          <div className="grid gap-4">
            {schedules.map((schedule) => (
              <Card key={schedule.id}>
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Switch
                        checked={schedule.is_enabled}
                        disabled={toggleScheduleMut.isPending}
                        onCheckedChange={() => toggleScheduleMut.mutate(schedule.id)}
                      />
                      <div>
                        <CardTitle className="text-lg">{schedule.name}</CardTitle>
                        <CardDescription>{schedule.description}</CardDescription>
                      </div>
                    </div>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon">
                          <MoreVertical className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => handleEditSchedule(schedule)}>
                          <Edit className="mr-2 h-4 w-4" />
                          {t('FirmwarePage.actions.edit')}
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => runScheduleNowMut.mutate(schedule.id)}>
                          <Play className="mr-2 h-4 w-4" />
                          {t('FirmwarePage.actions.runNow')}
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          className="text-destructive"
                          onClick={() => {
                            if (window.confirm(`${t('FirmwarePage.actions.delete')}: ${schedule.name}`)) {
                              deleteScheduleMut.mutate(schedule.id);
                            }
                          }}
                        >
                          <Trash2 className="mr-2 h-4 w-4" />
                          {t('FirmwarePage.actions.delete')}
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div>
                      <span className="text-muted-foreground">{t('FirmwarePage.schedules.target')}</span>
                      <div className="font-medium">
                        {schedule.device_type || t('FirmwarePage.schedules.allTypes')}
                      </div>
                    </div>
                    <div>
                      <span className="text-muted-foreground">{t('FirmwarePage.schedules.schedule')}</span>
                      <div className="font-medium capitalize">
                        {t('FirmwarePage.schedules.frequencyAt', { frequency: schedule.frequency, time: schedule.time_of_day })}
                      </div>
                    </div>
                    <div>
                      <span className="text-muted-foreground">{t('FirmwarePage.schedules.totalRuns')}</span>
                      <div className="font-medium">{schedule.total_runs}</div>
                    </div>
                    <div>
                      <span className="text-muted-foreground">{t('FirmwarePage.schedules.lastRun')}</span>
                      <div className="font-medium flex items-center gap-1">
                        {schedule.last_run_at && (
                          <CheckCircle className="h-3 w-3 text-green-500" />
                        )}
                        {schedule.last_run_at ? new Date(schedule.last_run_at).toLocaleDateString() : t('FirmwarePage.common.never')}
                      </div>
                    </div>
                  </div>
                  {schedule.next_run_at && (
                    <div className="mt-3 flex items-center gap-2 text-sm text-muted-foreground">
                      <Clock className="h-4 w-4" />
                      {t('FirmwarePage.schedules.nextRun', { time: new Date(schedule.next_run_at).toLocaleString() })}
                    </div>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
          )}
        </TabsContent>
      </Tabs>

      {/* Upgrade Dialog */}
      <Dialog open={upgradeDialogOpen} onOpenChange={setUpgradeDialogOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>{t('FirmwarePage.upgradeDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('FirmwarePage.upgradeDialog.description', { count: selectedDevices.length })}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label>{t('FirmwarePage.upgradeDialog.targetFirmware')}</Label>
              <Select
                value={upgradeForm.firmware_id}
                onValueChange={(v) => setUpgradeForm({ ...upgradeForm, firmware_id: v })}
              >
                <SelectTrigger>
                  <SelectValue placeholder={t('FirmwarePage.upgradeDialog.selectFirmwarePlaceholder')} />
                </SelectTrigger>
                <SelectContent>
                  {firmwares?.map((fw) => (
                    <SelectItem key={fw.id} value={fw.id}>
                      {fw.vendor} {fw.model} v{fw.version}
                      {fw.is_critical && ` ${t('FirmwarePage.upgradeDialog.criticalSuffix')}`}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>{t('FirmwarePage.upgradeDialog.scheduleOptional')}</Label>
              <Input
                type="datetime-local"
                value={upgradeForm.scheduled_at}
                onChange={(e) => setUpgradeForm({ ...upgradeForm, scheduled_at: e.target.value })}
              />
              <p className="text-xs text-muted-foreground">
                {t('FirmwarePage.upgradeDialog.leaveEmptyHint')}
              </p>
            </div>

            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <Label>{t('FirmwarePage.upgradeDialog.backupBefore')}</Label>
                  <p className="text-xs text-muted-foreground">
                    {t('FirmwarePage.upgradeDialog.backupBeforeHint')}
                  </p>
                </div>
                <Switch
                  checked={upgradeForm.backup_before}
                  onCheckedChange={(checked) => setUpgradeForm({ ...upgradeForm, backup_before: checked })}
                />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <Label>{t('FirmwarePage.upgradeDialog.rollbackOnFailure')}</Label>
                  <p className="text-xs text-muted-foreground">
                    {t('FirmwarePage.upgradeDialog.rollbackOnFailureHint')}
                  </p>
                </div>
                <Switch
                  checked={upgradeForm.rollback_on_failure}
                  onCheckedChange={(checked) => setUpgradeForm({ ...upgradeForm, rollback_on_failure: checked })}
                />
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setUpgradeDialogOpen(false)}>
              {t('FirmwarePage.actions.cancel')}
            </Button>
            <Button onClick={handleStartUpgrade}>
              {upgradeForm.scheduled_at ? t('FirmwarePage.upgradeDialog.scheduleUpgrade') : t('FirmwarePage.upgradeDialog.startUpgrade')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Upload Firmware Dialog */}
      <Dialog
        open={uploadDialogOpen}
        onOpenChange={(open) => {
          setUploadDialogOpen(open);
          if (!open) resetUploadForm();
        }}
      >
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>{t('FirmwarePage.uploadDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('FirmwarePage.uploadDialog.description')}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label>{t('FirmwarePage.uploadDialog.file')}</Label>
              <Input
                type="file"
                onChange={(e) => {
                  const file = e.target.files?.[0] ?? null;
                  setUploadForm((prev) => ({
                    ...prev,
                    file,
                    // Pre-fill version from the filename if the user hasn't typed one yet
                    version: prev.version || (file ? file.name : ''),
                  }));
                }}
              />
              {uploadForm.file && (
                <p className="text-xs text-muted-foreground">
                  {uploadForm.file.name} · {formatBytes(uploadForm.file.size)}
                </p>
              )}
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>{t('FirmwarePage.uploadDialog.vendor')}</Label>
                <Input
                  value={uploadForm.vendor}
                  onChange={(e) => setUploadForm({ ...uploadForm, vendor: e.target.value })}
                  placeholder={t('FirmwarePage.uploadDialog.vendorPlaceholder')}
                />
              </div>
              <div className="space-y-2">
                <Label>{t('FirmwarePage.uploadDialog.model')}</Label>
                <Input
                  value={uploadForm.model}
                  onChange={(e) => setUploadForm({ ...uploadForm, model: e.target.value })}
                  placeholder={t('FirmwarePage.uploadDialog.modelPlaceholder')}
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label>{t('FirmwarePage.uploadDialog.version')}</Label>
              <Input
                value={uploadForm.version}
                onChange={(e) => setUploadForm({ ...uploadForm, version: e.target.value })}
                placeholder={t('FirmwarePage.uploadDialog.versionPlaceholder')}
              />
            </div>

            <div className="space-y-2">
              <Label>{t('FirmwarePage.uploadDialog.releaseType')}</Label>
              <Select
                value={uploadForm.release_type}
                onValueChange={(v) => setUploadForm({ ...uploadForm, release_type: v })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="stable">{t('FirmwarePage.uploadDialog.releaseTypes.stable')}</SelectItem>
                  <SelectItem value="beta">{t('FirmwarePage.uploadDialog.releaseTypes.beta')}</SelectItem>
                  <SelectItem value="rc">{t('FirmwarePage.uploadDialog.releaseTypes.rc')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setUploadDialogOpen(false)}>
              {t('FirmwarePage.actions.cancel')}
            </Button>
            <Button
              onClick={handleSubmitUpload}
              disabled={
                uploadFirmwareMut.isPending ||
                !uploadForm.file ||
                !uploadForm.vendor.trim() ||
                !uploadForm.model.trim() ||
                !uploadForm.version.trim()
              }
            >
              {uploadFirmwareMut.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              <Upload className="mr-2 h-4 w-4" />
              {t('FirmwarePage.actions.uploadFirmware')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Release Notes Dialog */}
      <Dialog open={releaseNotesOpen} onOpenChange={setReleaseNotesOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>
              {selectedFirmware?.vendor} {selectedFirmware?.model} v{selectedFirmware?.version}
            </DialogTitle>
            <DialogDescription>
              {t('FirmwarePage.releaseNotesDialog.released', { date: selectedFirmware?.release_date ? new Date(selectedFirmware.release_date).toLocaleDateString() : '' })}
            </DialogDescription>
          </DialogHeader>

          <div className="prose prose-sm dark:prose-invert max-h-96 overflow-y-auto">
            <div className="whitespace-pre-wrap">
              {selectedFirmware?.release_notes || t('FirmwarePage.releaseNotesDialog.noNotes')}
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setReleaseNotesOpen(false)}>
              {t('FirmwarePage.actions.close')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Schedule Dialog */}
      <Dialog
        open={scheduleDialogOpen}
        onOpenChange={(open) => {
          setScheduleDialogOpen(open);
          if (!open) setEditingScheduleId(null);
        }}
      >
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{editingScheduleId ? t('FirmwarePage.actions.edit') : t('FirmwarePage.scheduleDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('FirmwarePage.scheduleDialog.description')}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 max-h-96 overflow-y-auto">
            <div className="space-y-2">
              <Label>{t('FirmwarePage.scheduleDialog.name')}</Label>
              <Input
                value={scheduleForm.name}
                onChange={(e) => setScheduleForm({ ...scheduleForm, name: e.target.value })}
                placeholder={t('FirmwarePage.scheduleDialog.namePlaceholder')}
              />
            </div>

            <div className="space-y-2">
              <Label>{t('FirmwarePage.scheduleDialog.descriptionLabel')}</Label>
              <Textarea
                value={scheduleForm.description}
                onChange={(e) => setScheduleForm({ ...scheduleForm, description: e.target.value })}
                placeholder={t('FirmwarePage.scheduleDialog.descriptionPlaceholder')}
                rows={2}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>{t('FirmwarePage.scheduleDialog.scheduleType')}</Label>
                <Select
                  value={scheduleForm.frequency}
                  onValueChange={(v) => setScheduleForm({ ...scheduleForm, frequency: v })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="weekly">{t('FirmwarePage.scheduleDialog.frequency.weekly')}</SelectItem>
                    <SelectItem value="monthly">{t('FirmwarePage.scheduleDialog.frequency.monthly')}</SelectItem>
                    <SelectItem value="on_release">{t('FirmwarePage.scheduleDialog.frequency.onRelease')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {scheduleForm.frequency === 'weekly' && (
                <div className="space-y-2">
                  <Label>{t('FirmwarePage.scheduleDialog.dayOfWeek')}</Label>
                  <Select
                    value={String(scheduleForm.day_of_week)}
                    onValueChange={(v) => setScheduleForm({ ...scheduleForm, day_of_week: Number(v) })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'].map((day, i) => (
                        <SelectItem key={i} value={String(i)}>{t(`FirmwarePage.days.${day}`)}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )}
            </div>

            <div className="space-y-2">
              <Label>{t('FirmwarePage.scheduleDialog.time')}</Label>
              <Input
                type="time"
                value={scheduleForm.time_of_day}
                onChange={(e) => setScheduleForm({ ...scheduleForm, time_of_day: e.target.value })}
              />
            </div>

            <div className="flex items-center justify-between">
              <div>
                <Label>{t('FirmwarePage.scheduleDialog.autoLatest')}</Label>
                <p className="text-xs text-muted-foreground">
                  {t('FirmwarePage.scheduleDialog.autoLatestHint')}
                </p>
              </div>
              <Switch
                checked={scheduleForm.auto_latest}
                onCheckedChange={(checked) => setScheduleForm({ ...scheduleForm, auto_latest: checked })}
              />
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setScheduleDialogOpen(false)}>
              {t('FirmwarePage.actions.cancel')}
            </Button>
            <Button
              onClick={handleSubmitSchedule}
              disabled={createScheduleMut.isPending || updateScheduleMut.isPending}
            >
              {(createScheduleMut.isPending || updateScheduleMut.isPending) && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              {editingScheduleId ? t('FirmwarePage.actions.edit') : t('FirmwarePage.schedules.create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Batch Progress Dialog */}
      <BatchProgressDialog
        open={batchProgressOpen}
        onOpenChange={setBatchProgressOpen}
        title={t('FirmwarePage.batch.title')}
        description={t('FirmwarePage.batch.description')}
        devices={batchDevices}
        onCancel={() => {
          setBatchDevices(prev => prev.map(d => d.status === 'running' || d.status === 'pending' ? { ...d, status: 'failed' as const, message: t('FirmwarePage.batch.cancelled') } : d));
        }}
        onRetryFailed={() => {
          const failedIds = batchDevices.filter(d => d.status === 'failed').map(d => d.id);
          setSelectedDevices(failedIds);
          setBatchProgressOpen(false);
          setUpgradeDialogOpen(true);
        }}
      />
      </div>
  );
}
